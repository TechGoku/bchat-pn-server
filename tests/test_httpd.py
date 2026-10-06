import asyncio
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import logging
logging.disable(logging.CRITICAL)  # fault-injection tests log on purpose

from bchatpn.httpd import HttpServer, Limits, Request
from bchatpn.obs import Metrics


async def echo(req: Request):
    return 200, "application/octet-stream", req.method.encode() + b" " + req.path.encode() + b"\n" + req.body


async def raw(port, payload: bytes, *, read=True, timeout=3.0) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(payload)
    await writer.drain()
    out = b""
    if read:
        try:
            out = await asyncio.wait_for(reader.read(), timeout)
        except asyncio.TimeoutError:
            out = b"<timeout>"
    writer.close()
    return out


def status_of(resp: bytes) -> int:
    return int(resp.split(b" ", 2)[1])


class HttpdTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.metrics = Metrics()
        self.limits = Limits(max_header_bytes=2048, max_body_bytes=1000, read_timeout=0.4,
                             handler_timeout=2.0, max_connections=3)
        self.server = HttpServer(echo, "127.0.0.1", 0, self.limits, metrics=self.metrics)
        await self.server.start()
        self.port = self.server.port

    async def asyncTearDown(self):
        await self.server.stop(1.0)

    async def test_post_roundtrip_and_query_string_is_stripped(self):
        r = await raw(self.port, b"POST /a/b?x=1 HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello")
        self.assertEqual(status_of(r), 200)
        self.assertTrue(r.endswith(b"POST /a/b\nhello"))
        self.assertIn(b"Connection: close", r)

    async def test_http10_clients_work(self):
        r = await raw(self.port, b"POST /x HTTP/1.0\r\nContent-Length: 2\r\n\r\nhi")
        self.assertEqual(status_of(r), 200)

    async def test_method_not_allowed(self):
        self.assertEqual(status_of(await raw(self.port, b"GET / HTTP/1.1\r\n\r\n")), 405)

    async def test_oversize_declared_body_is_refused_before_it_is_read(self):
        r = await raw(self.port, b"POST / HTTP/1.1\r\nContent-Length: 1001\r\n\r\n")  # no body sent
        self.assertEqual(status_of(r), 413)

    async def test_header_too_large(self):
        r = await raw(self.port, b"POST / HTTP/1.1\r\nX-Pad: " + b"a" * 5000 + b"\r\n\r\n")
        self.assertEqual(status_of(r), 431)

    async def test_too_many_headers(self):
        hdrs = b"".join(b"X-%d: v\r\n" % i for i in range(150))
        r = await raw(self.port, b"POST / HTTP/1.1\r\n" + hdrs + b"\r\n")
        self.assertEqual(status_of(r), 431)

    async def test_request_smuggling_guards(self):
        cases = [
            b"POST / HTTP/1.1\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            b"POST / HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\nabc",
            b"POST / HTTP/1.1\r\nContent-Length: abc\r\n\r\n",
            b"POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n",
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            b"POST / HTTP/1.1\r\nBad Header : x\r\n\r\n",
            b"POST /\r\n\r\n",
            b"POST / FTP/1.1\r\n\r\n",
        ]
        for c in cases:
            self.assertEqual(status_of(await raw(self.port, c)), 400, c)

    async def test_unsupported_transfer_encoding(self):
        r = await raw(self.port, b"POST / HTTP/1.1\r\nTransfer-Encoding: gzip\r\n\r\n")
        self.assertEqual(status_of(r), 501)

    async def test_chunked_body(self):
        r = await raw(self.port, b"POST /c HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"
                                 b"5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nTrailer: x\r\n\r\n")
        self.assertEqual(status_of(r), 200)
        self.assertTrue(r.endswith(b"hello world"))

    async def test_chunked_limits_and_garbage(self):
        big = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n" + b"3e9\r\n" + b"a" * 1001 + b"\r\n0\r\n\r\n"
        self.assertEqual(status_of(await raw(self.port, big)), 413)
        bad_size = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n"
        self.assertEqual(status_of(await raw(self.port, bad_size)), 400)
        bad_crlf = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabcXX0\r\n\r\n"
        self.assertEqual(status_of(await raw(self.port, bad_crlf)), 400)

    async def test_expect_100_continue(self):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        writer.write(b"POST / HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 4\r\n\r\n")
        await writer.drain()
        first = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2)
        self.assertTrue(first.startswith(b"HTTP/1.1 100"))
        writer.write(b"body")
        await writer.drain()
        rest = await asyncio.wait_for(reader.read(), 2)
        self.assertEqual(status_of(rest), 200)
        writer.close()

    async def test_slow_client_is_cut_off(self):
        r = await raw(self.port, b"POST / HTTP/1.1\r\nContent-Le", timeout=2.0)  # never finishes the headers
        self.assertEqual(status_of(r), 408)

    async def test_stalled_body_is_cut_off(self):
        r = await raw(self.port, b"POST / HTTP/1.1\r\nContent-Length: 50\r\n\r\nonly-some", timeout=2.0)
        self.assertEqual(status_of(r), 408)

    async def test_connection_cap_sheds_with_503_and_recovers(self):
        idle = []
        for _ in range(3):
            idle.append(await asyncio.open_connection("127.0.0.1", self.port))
        await asyncio.sleep(0.05)
        r = await raw(self.port, b"POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n")
        self.assertEqual(status_of(r), 503)
        for _, w in idle:
            w.close()
        await asyncio.sleep(0.1)
        self.assertEqual(status_of(await raw(self.port, b"POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n")), 200)

    async def test_a_rejection_stays_readable_when_the_client_sends_after_we_replied(self):
        # The server answers 503 without reading (connection cap). Closing straight away risks a TCP reset
        # that can destroy the reply; lingering on error paths avoids it. NOTE: on loopback this cannot fail
        # deterministically (the event loop drains the socket before close), so this documents and exercises
        # the late-client path rather than proving the linger; mutation testing confirms it is not pinned.
        idle = [await asyncio.open_connection("127.0.0.1", self.port) for _ in range(3)]
        await asyncio.sleep(0.05)
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        await asyncio.sleep(0.1)  # the server has already replied by now
        writer.write(b"POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(), 3)
        self.assertEqual(status_of(data), 503)
        writer.close()
        for _, w in idle:
            w.close()

    async def test_a_crashing_handler_returns_500_and_the_server_survives(self):
        async def boom(req):
            raise RuntimeError("bug")

        s = HttpServer(boom, "127.0.0.1", 0, self.limits)
        await s.start()
        try:
            self.assertEqual(status_of(await raw(s.port, b"POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n")), 500)
            self.assertEqual(status_of(await raw(s.port, b"POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n")), 500)
        finally:
            await s.stop(1.0)

    async def test_handler_timeout(self):
        async def slow(req):
            await asyncio.sleep(5)
            return 200, "text/plain", b"late"

        s = HttpServer(slow, "127.0.0.1", 0, Limits(handler_timeout=0.2, read_timeout=1.0))
        await s.start()
        try:
            self.assertEqual(status_of(await raw(s.port, b"POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n")), 503)
        finally:
            await s.stop(1.0)

    async def test_rejections_are_counted(self):
        await raw(self.port, b"GET / HTTP/1.1\r\n\r\n")
        self.assertEqual(self.metrics.get("http_rejected", server="http", reason="405"), 1)

    async def test_concurrent_requests(self):
        results = await asyncio.gather(*[
            raw(self.port, b"POST /n HTTP/1.1\r\nContent-Length: 3\r\n\r\n%03d" % i) for i in range(2)
        ])
        self.assertTrue(all(status_of(r) == 200 for r in results))

    async def test_stop_waits_for_in_flight_then_cancels(self):
        started = asyncio.Event()

        async def hang(req):
            started.set()
            await asyncio.sleep(30)
            return 200, "text/plain", b""

        s = HttpServer(hang, "127.0.0.1", 0, Limits(handler_timeout=60.0))
        await s.start()
        task = asyncio.create_task(raw(s.port, b"POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n", timeout=5.0))
        await started.wait()
        t0 = asyncio.get_running_loop().time()
        await s.stop(0.3)
        self.assertLess(asyncio.get_running_loop().time() - t0, 3.0)
        await task


if __name__ == "__main__":
    unittest.main()
