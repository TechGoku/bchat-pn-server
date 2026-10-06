"""A small, strict, dependency-free asyncio HTTP/1.1 server.

It exists because the onion ingress needs almost nothing from HTTP (one POST, a body, a reply), and
every framework layer between the socket and the handler is latency and attack surface. It is not a
general web server: one request per connection (`Connection: close`, which is also what the legacy
server did), hard caps on everything, and a deadline on every read.

Handled for compatibility with whatever the exit node's HTTP client sends: Content-Length bodies,
chunked bodies, and `Expect: 100-continue`.
Rejected outright (request smuggling guards): Content-Length together with Transfer-Encoding, and
duplicate or malformed Content-Length.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from dataclasses import dataclass
from http import HTTPStatus
from typing import Awaitable, Callable, Iterable

from .obs import Metrics

log = logging.getLogger("bchatpn.http")

_MAX_HEADERS = 100


@dataclass(slots=True)
class Request:
    method: str
    path: str
    headers: dict[str, str]  # lower-case names
    body: bytes


Response = tuple[int, str, bytes]  # (status, content-type, body)
Handler = Callable[[Request], Awaitable[Response]]


@dataclass(frozen=True)
class Limits:
    max_header_bytes: int = 16 * 1024
    max_body_bytes: int = 64 * 1024
    read_timeout: float = 10.0
    handler_timeout: float = 30.0
    max_connections: int = 4096


class _HttpError(Exception):
    def __init__(self, status: int) -> None:
        self.status = status


class HttpServer:
    def __init__(
        self,
        handler: Handler,
        host: str,
        port: int,
        limits: Limits,
        *,
        name: str = "http",
        allowed_methods: Iterable[str] = ("POST",),
        metrics: Metrics | None = None,
    ) -> None:
        self._handler = handler
        self._host = host
        self._port = port
        self._limits = limits
        self._name = name
        self._allowed = frozenset(allowed_methods)
        self._metrics = metrics
        self._server: asyncio.AbstractServer | None = None
        self._tasks: set[asyncio.Task[None]] = set()
        self.port = port  # actual bound port (useful when port=0)

    @property
    def active_connections(self) -> int:
        return len(self._tasks)

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._on_connection,
            self._host,
            self._port,
            limit=self._limits.max_header_bytes,
            backlog=1024,
            reuse_address=True,
        )
        self.port = self._server.sockets[0].getsockname()[1]
        log.info("%s listening on %s:%d", self._name, self._host, self.port)

    async def stop(self, grace: float) -> None:
        """Stop accepting, give in-flight requests `grace` seconds, then cancel the rest."""
        if self._server is not None:
            self._server.close()
        pending = list(self._tasks)
        if pending:
            _, still = await asyncio.wait(pending, timeout=grace)
            for task in still:
                task.cancel()
            if still:
                await asyncio.wait(still, timeout=1.0)
        self._server = None

    # ------------------------------------------------------------------------------------------
    def _inc(self, name: str, **labels: str) -> None:
        if self._metrics is not None:
            self._metrics.inc(name, server=self._name, **labels)

    async def _on_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        assert task is not None
        if len(self._tasks) >= self._limits.max_connections:
            self._inc("http_rejected", reason="max_connections")
            await self._write(writer, 503, "text/plain", b"busy\n", reader)
            return
        self._tasks.add(task)
        try:
            await self._serve_one(reader, writer)
        except asyncio.CancelledError:
            with contextlib.suppress(Exception):
                writer.close()
            raise
        except Exception:  # never let one connection take the server down
            log.exception("%s: unexpected error handling connection", self._name)
            self._inc("http_rejected", reason="internal")
            await self._write(writer, 500, "text/plain", b"internal error\n", reader)
        finally:
            self._tasks.discard(task)

    async def _serve_one(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            async with asyncio.timeout(self._limits.read_timeout):
                request = await self._read_request(reader, writer)
        except TimeoutError:
            self._inc("http_rejected", reason="read_timeout")
            await self._write(writer, 408, "text/plain", b"request timeout\n", reader)
            return
        except _HttpError as e:
            self._inc("http_rejected", reason=str(e.status))
            await self._write(writer, e.status, "text/plain", HTTPStatus(e.status).phrase.encode() + b"\n", reader)
            return
        except (asyncio.IncompleteReadError, ConnectionError):
            self._inc("http_rejected", reason="disconnect")
            with contextlib.suppress(Exception):
                writer.close()
            return

        try:
            async with asyncio.timeout(self._limits.handler_timeout):
                status, ctype, body = await self._handler(request)
        except TimeoutError:
            self._inc("http_rejected", reason="handler_timeout")
            status, ctype, body = 503, "text/plain", b"timeout\n"
        await self._write(writer, status, ctype, body)

    async def _read_request(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> Request:
        try:
            head = await reader.readuntil(b"\r\n\r\n")
        except asyncio.LimitOverrunError:
            raise _HttpError(431) from None
        lines = head[:-4].split(b"\r\n")
        if len(lines) > _MAX_HEADERS + 1:
            raise _HttpError(431)

        parts = lines[0].split(b" ")
        if len(parts) != 3 or not parts[2].startswith(b"HTTP/1."):
            raise _HttpError(400)
        try:
            method = parts[0].decode("ascii")
            target = parts[1].decode("ascii")
        except UnicodeDecodeError:
            raise _HttpError(400) from None
        path = target.split("?", 1)[0]

        headers: dict[str, str] = {}
        for raw in lines[1:]:
            name, sep, value = raw.partition(b":")
            if not sep or not name or name != name.strip():
                raise _HttpError(400)
            try:
                key = name.decode("ascii").lower()
                val = value.decode("latin-1").strip()
            except UnicodeDecodeError:
                raise _HttpError(400) from None
            if key in ("content-length", "transfer-encoding") and key in headers:
                raise _HttpError(400)  # duplicates are a smuggling vector
            headers[key] = val

        if method not in self._allowed:
            raise _HttpError(405)

        te = headers.get("transfer-encoding")
        cl = headers.get("content-length")
        if te is not None and cl is not None:
            raise _HttpError(400)

        if headers.get("expect", "").lower() == "100-continue":
            writer.write(b"HTTP/1.1 100 Continue\r\n\r\n")
            await writer.drain()

        if te is not None:
            if te.lower() != "chunked":
                raise _HttpError(501)
            body = await self._read_chunked(reader)
        elif cl is not None:
            if not cl.isascii() or not cl.isdigit() or len(cl) > 9:
                raise _HttpError(400)
            n = int(cl)
            if n > self._limits.max_body_bytes:
                raise _HttpError(413)
            body = await reader.readexactly(n) if n else b""
        else:
            body = b""
        return Request(method=method, path=path, headers=headers, body=body)

    async def _read_chunked(self, reader: asyncio.StreamReader) -> bytes:
        out = bytearray()
        try:
            while True:
                line = await reader.readline()
                if not line.endswith(b"\n"):
                    raise _HttpError(400)
                try:
                    size = int(line.split(b";", 1)[0].strip(), 16)
                except ValueError:
                    raise _HttpError(400) from None
                if size < 0:
                    raise _HttpError(400)
                if size == 0:
                    for _ in range(32):  # discard trailers
                        trailer = await reader.readline()
                        if trailer in (b"\r\n", b"\n", b""):
                            break
                    return bytes(out)
                if len(out) + size > self._limits.max_body_bytes:
                    raise _HttpError(413)
                out += await reader.readexactly(size)
                if await reader.readexactly(2) != b"\r\n":
                    raise _HttpError(400)
        except ValueError:  # StreamReader.readline raises ValueError when a line exceeds the limit
            raise _HttpError(400) from None

    async def _write(
        self,
        writer: asyncio.StreamWriter,
        status: int,
        ctype: str,
        body: bytes,
        reader: asyncio.StreamReader | None = None,
    ) -> None:
        """Send the response and close. Pass `reader` when the request may not have been fully read
        (every error path): closing a socket that still has unread inbound data makes TCP send an RST,
        which can destroy the response before the client reads it. So we half-close, swallow the rest
        of what the client is sending for a moment, and only then close."""
        try:
            phrase = HTTPStatus(status).phrase
        except ValueError:
            phrase = "Unknown"
        head = (
            f"HTTP/1.1 {status} {phrase}\r\n"
            f"Content-Type: {ctype}\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("latin-1")
        try:
            writer.write(head + body)
            # Replies are tiny, so the kernel normally takes them immediately; only wait (under a deadline,
            # so a client that never reads cannot pin us) when something is actually buffered.
            if writer.transport.get_write_buffer_size():
                async with asyncio.timeout(self._limits.read_timeout):
                    await writer.drain()
            if reader is not None:
                writer.write_eof()
                await self._linger(reader)
        except (TimeoutError, ConnectionError, OSError):
            pass
        finally:
            with contextlib.suppress(Exception):
                writer.close()  # flushes anything still buffered, then closes; no need to await it

    @staticmethod
    async def _linger(reader: asyncio.StreamReader, seconds: float = 0.25, max_bytes: int = 65536) -> None:
        total = 0
        try:
            async with asyncio.timeout(seconds):
                while total < max_bytes:
                    chunk = await reader.read(4096)
                    if not chunk:
                        return
                    total += len(chunk)
        except (TimeoutError, ConnectionError, OSError):
            pass
