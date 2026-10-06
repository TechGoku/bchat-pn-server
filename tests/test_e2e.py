"""End to end: real sockets, real onion requests built by the independent client port, real SQLite.

Includes the independence proof: the server runs as ONE process, started with nothing but a few
environment variables, and needs no other service, bot, broker or helper process.
"""

import asyncio
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(__file__))
ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)

import logging
logging.disable(logging.CRITICAL)  # fault-injection tests log on purpose

import clientcrypto as cc
from bchatpn.app import App
from bchatpn.config import Config
from bchatpn.providers.logonly import LogOnlyProvider

A, B, G = "bd" + "aa" * 32, "bd" + "bb" * 32, "bd" + "99" * 32
TOK = "fcm:" + "x" * 140


def write_key(directory):
    path = os.path.join(directory, "x25519.key")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(fd, os.urandom(32).hex().encode() + b"\n")
    os.close(fd)
    return path


async def http(port, path, body=b"", method="POST", headers=""):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(f"{method} {path} HTTP/1.1\r\nHost: x\r\nContent-Length: {len(body)}\r\n{headers}\r\n".encode() + body)
    await writer.drain()
    raw = await asyncio.wait_for(reader.read(), 10)
    writer.close()
    head, _, payload = raw.partition(b"\r\n\r\n")
    return int(head.split(b" ")[1]), payload


class Client:
    """What an app does: one onion request per call."""

    def __init__(self, port, pub_hex):
        self.port, self.pub = port, pub_hex

    async def call(self, endpoint, args, v=2):
        if v == 2:
            body, key = cc.v2_request(self.pub, endpoint, args)
            status, out = await http(self.port, "/beldex/v2/lsrpc", body)
            assert status == 200, status
            return cc.parse_v2_reply(out, key)
        body, key = cc.v4_request(self.pub, endpoint, args)
        status, out = await http(self.port, "/beldex/v4/lsrpc", body)
        assert status == 200, status
        info, raw = cc.parse_v4_reply(out, key)
        return info["code"], json.loads(raw)


class EndToEnd(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.key = write_key(self.dir.name)
        self.db = os.path.join(self.dir.name, "pn.db")
        self.provider = LogOnlyProvider(record=True)

    def cfg(self, **kw):
        base = dict(listen_host="127.0.0.1", listen_port=0, admin_host="127.0.0.1", admin_port=0,
                    key_file=self.key, db_path=self.db, log_only=True, workers=4, shutdown_grace=5.0)
        base.update(kw)
        return Config(**base)

    async def start(self, **kw):
        app = App(self.cfg(**kw), providers=[self.provider])
        await app.start()
        return app, Client(app.public.port, app.onion.public_key_hex)

    async def test_register_notify_push_and_persistence_across_restart(self):
        app, c = await self.start()
        self.assertEqual((await c.call("register_legacy_groups_only",
                                       {"token": TOK, "pubKey": A, "device": "android",
                                        "legacyGroupPublicKeys": [G]}))[1]["code"], 1)
        self.assertEqual((await c.call("notify", {"data": "QUJD", "send_to": A}))[1]["code"], 1)
        self.assertEqual((await c.call("notify", {"data": "REVG", "send_to": G}, v=4))[1]["code"], 1)
        await app.stop()  # graceful: queue drained, store flushed
        self.assertEqual(self.provider.sent, [(TOK, "QUJD"), (TOK, "REVG")])

        # restart on the same database: registrations survived, and push still works
        app2, c2 = await self.start()
        self.assertEqual(app2.registry.tokens_of(A), {TOK: "android"})
        self.assertEqual(app2.registry.members_of(G), {A})
        await c2.call("notify", {"data": "R0hJ", "send_to": A})
        await app2.stop()
        self.assertEqual(self.provider.sent[-1], (TOK, "R0hJ"))

    async def test_admin_endpoints(self):
        app, c = await self.start(admin_token="s3cret")
        await c.call("register", {"token": TOK, "pubKey": A})
        await c.call("notify", {"data": "QUJD", "send_to": A})
        status, body = await http(app.admin.port, "/healthz", method="GET")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["status"], "ok")
        status, _ = await http(app.admin.port, "/metrics", method="GET")
        self.assertEqual(status, 401)
        status, body = await http(app.admin.port, "/metrics", method="GET", headers="Authorization: Bearer s3cret\r\n")
        self.assertEqual(status, 200)
        text = body.decode()
        for needle in ('bchatpn_requests{code="1",endpoint="notify"} 1', "bchatpn_notify_accepted 1",
                       "bchatpn_device_tokens 1", "bchatpn_request_seconds_count", "bchatpn_queue_depth"):
            self.assertIn(needle, text)
        self.assertEqual((await http(app.admin.port, "/metrics", method="POST"))[0], 405)  # admin is GET-only
        self.assertEqual((await http(app.public.port, "/healthz", method="GET"))[0], 405)  # public is POST-only
        await app.stop()

    async def test_health_goes_unavailable_once_stopping(self):
        app, _ = await self.start()
        ok, _ = app._health()
        self.assertTrue(ok)
        await app.stop()
        ok, _ = app._health()
        self.assertFalse(ok)

    async def test_busy_server_tells_the_app_to_retry(self):
        slow = LogOnlyProvider(record=True)

        async def hang(token, data):
            await asyncio.sleep(30)

        slow.send = hang
        app = App(self.cfg(queue_size=1, workers=1, shutdown_grace=0.3), providers=[slow])
        await app.start()
        c = Client(app.public.port, app.onion.public_key_hex)
        await c.call("register", {"token": TOK, "pubKey": A})
        results = [await c.call("notify", {"data": f"m{i:04d}", "send_to": A}) for i in range(4)]
        statuses = [(s, b["code"], b["message"]) for s, b in results]
        self.assertEqual(statuses[0], (200, 1, "Success"))
        self.assertIn((400, 0, "Busy"), statuses)  # queue of 1 + one in flight: the rest are refused, not dropped
        await app.stop()

    async def test_many_concurrent_apps(self):
        app, c = await self.start()
        await c.call("register", {"token": TOK, "pubKey": A})
        results = await asyncio.gather(*[c.call("notify", {"data": f"d{i:05d}", "send_to": A}) for i in range(200)])
        self.assertTrue(all(b["code"] == 1 or b["message"] == "Rate limited" for _, b in results))
        await app.stop()
        self.assertEqual(len(self.provider.sent), len(set(self.provider.sent)))  # nothing duplicated

    async def test_garbage_and_wrong_key_clients_are_refused_without_hurting_the_server(self):
        app, c = await self.start()
        self.assertEqual((await http(app.public.port, "/beldex/v2/lsrpc", os.urandom(300)))[0], 400)
        self.assertEqual((await http(app.public.port, "/beldex/v4/lsrpc", b""))[0], 400)
        other = Client(app.public.port, "11" * 32)  # client that pinned some other server's key
        body, _ = cc.v2_request(other.pub, "register", {"token": TOK, "pubKey": A})
        self.assertEqual((await http(app.public.port, "/beldex/v2/lsrpc", body))[0], 400)
        self.assertEqual((await c.call("register", {"token": TOK, "pubKey": A}))[1]["code"], 1)  # still fine
        await app.stop()

    async def test_unusable_key_file_is_a_clear_startup_error(self):
        os.chmod(self.key, 0o644)
        from bchatpn.config import ConfigError

        with self.assertRaisesRegex(ConfigError, "chmod 600"):
            App(self.cfg(), providers=[self.provider])


def _free_port():
    import socket

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class StandaloneProcess(unittest.TestCase):
    """The server as an operator runs it: `python -m bchatpn serve`, configured only by environment."""

    def run_cli(self, *args, env=None, timeout=30):
        return subprocess.run([sys.executable, "-m", "bchatpn", *args], cwd=ROOT, env=env,
                              capture_output=True, text=True, timeout=timeout)

    def test_runs_alone_from_a_stripped_environment_and_shuts_down_cleanly(self):
        with tempfile.TemporaryDirectory() as d:
            key = os.path.join(d, "key")
            r = self.run_cli("keygen", key, env={"PATH": os.environ["PATH"]})
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(oct(os.stat(key).st_mode & 0o777), "0o600")
            pub = r.stdout.strip().split()[-1]
            self.assertEqual(self.run_cli("pubkey", key, env={"PATH": os.environ["PATH"]}).stdout.strip(), pub)
            self.assertEqual(self.run_cli("keygen", key, env={"PATH": os.environ["PATH"]}).returncode, 2)  # no overwrite

            port, admin = _free_port(), _free_port()
            env = {  # nothing but PATH and BCHATPN_*: no config file, no credentials, no network services
                "PATH": os.environ["PATH"],
                "BCHATPN_LOG_ONLY": "true", "BCHATPN_KEY_FILE": key, "BCHATPN_DB_PATH": os.path.join(d, "pn.db"),
                "BCHATPN_LISTEN_HOST": "127.0.0.1", "BCHATPN_LISTEN_PORT": str(port),
                "BCHATPN_ADMIN_PORT": str(admin),
            }
            proc = subprocess.Popen([sys.executable, "-m", "bchatpn", "serve"], cwd=ROOT, env=env,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                deadline = time.time() + 15
                while time.time() < deadline:
                    try:
                        status, body = asyncio.run(http(admin, "/healthz", method="GET"))
                        if status == 200:
                            break
                    except OSError:
                        time.sleep(0.1)
                else:
                    self.fail("server did not become healthy: " + proc.stderr.read())

                async def exercise():
                    c = Client(port, pub)
                    assert (await c.call("register", {"token": TOK, "pubKey": A}))[1]["code"] == 1
                    assert (await c.call("notify", {"data": "QUJD", "send_to": A}))[1]["code"] == 1

                asyncio.run(exercise())

                # one process: no children, a single listener pair
                with open(f"/proc/{proc.pid}/task/{proc.pid}/children") as fh:
                    children = fh.read().split()
                self.assertEqual(children, [])
            finally:
                proc.send_signal(signal.SIGTERM)
                out, err = proc.communicate(timeout=20)
            self.assertEqual(proc.returncode, 0, err)
            self.assertIn("stopped", err)
            self.assertTrue(os.path.exists(os.path.join(d, "pn.db")))

    def test_bad_configuration_exits_with_a_clear_message_not_a_traceback(self):
        r = self.run_cli("serve", env={"PATH": os.environ["PATH"]})
        self.assertEqual(r.returncode, 2)
        self.assertIn("no push provider configured", r.stderr)
        self.assertNotIn("Traceback", r.stderr)

    def test_core_imports_no_third_party_service_libraries(self):
        code = ("import sys, bchatpn.app, bchatpn.api, bchatpn.dispatch, bchatpn.providers.logonly;"
                "bad=[m for m in ('httpx','requests','aiohttp','flask','tornado','telepot','telegram','firebase_admin',"
                "'aioapns','psycopg2','pqxx','oxenmq','redis','uwsgi','pyfcm') if m in sys.modules];"
                "print(bad); sys.exit(1 if bad else 0)")
        r = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_sources_contain_no_embedded_secrets_or_third_party_endpoints(self):
        import re

        offenders = []
        for base, _, files in os.walk(os.path.join(ROOT, "bchatpn")):
            for f in files:
                if f.endswith(".py"):
                    with open(os.path.join(base, f)) as fh:
                        text = fh.read()
                    for pat in (r"api\.telegram", r"telepot", r"AAH[A-Za-z0-9_-]{30,}", r"-----BEGIN [A-Z ]*PRIVATE KEY",
                                r"password\s*=\s*['\"][^'\"]+['\"]"):
                        if re.search(pat, text):
                            offenders.append((f, pat))
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()
