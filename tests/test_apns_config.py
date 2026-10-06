import asyncio
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import logging
logging.disable(logging.CRITICAL)  # fault-injection tests log on purpose

from bchatpn.config import Config, ConfigError, load_config
from bchatpn.providers.apns import ApnsProvider, HttpxTransport, build_payload, map_status
from bchatpn.providers.base import Result

TOKEN = "ab" * 32


class FakeTransport:
    def __init__(self, status=200, body=b"", exc=None):
        self.status, self.body, self.exc = status, body, exc
        self.requests = []
        self.closed = False

    async def post(self, url, headers, body, timeout):
        self.requests.append((url, headers, body, timeout))
        if self.exc:
            raise self.exc
        return self.status, self.body

    async def aclose(self):
        self.closed = True


# Copied verbatim from the legacy server (tools/pushNotificationHandler.py: generate_ios_notification)
# so a change in what iOS clients receive shows up as a test failure.
def legacy_ios_payload(encrypted_data):
    alert = {'title': 'Bchat', 'body': 'You\'ve got a new message'}
    aps = {'alert': alert, 'badge': 1, 'sound': 'default', 'mutable-content': 1, 'category': 'SECRET'}
    return {'aps': aps, 'ENCRYPTED_DATA': encrypted_data, 'remote': 1}


class Apns(unittest.IsolatedAsyncioTestCase):
    def test_payload_is_identical_to_what_the_legacy_server_sent(self):
        self.assertEqual(json.loads(build_payload("QUJD")), legacy_ios_payload("QUJD"))

    def test_payload_is_compact_json(self):
        self.assertNotIn(b" ", build_payload("QUJD").replace(b"You've got a new message", b""))

    async def test_request_shape_production(self):
        t = FakeTransport()
        r = await ApnsProvider(t, topic="com.beldex.bchat").send(TOKEN, "QUJD")
        self.assertEqual(r, Result.OK)
        url, headers, body, _ = t.requests[0]
        self.assertEqual(url, f"https://api.push.apple.com/3/device/{TOKEN}")
        self.assertEqual(headers["apns-topic"], "com.beldex.bchat")
        self.assertEqual(headers["apns-push-type"], "alert")
        self.assertEqual(headers["apns-priority"], "10")
        self.assertEqual(json.loads(body)["ENCRYPTED_DATA"], "QUJD")

    async def test_sandbox_host(self):
        t = FakeTransport()
        await ApnsProvider(t, sandbox=True).send(TOKEN, "x")
        self.assertTrue(t.requests[0][0].startswith("https://api.sandbox.push.apple.com/"))

    async def test_hostile_tokens_never_reach_the_network_or_the_url(self):
        t = FakeTransport()
        p = ApnsProvider(t)
        for bad in ("../../etc", "ab/cd?x=1", "zz" * 32, "", "ab" * 3, "ab" * 101, "ab cd" * 10):
            self.assertEqual(await p.send(bad, "x"), Result.INVALID_TOKEN, bad)
        self.assertEqual(t.requests, [])

    async def test_oversize_payload_is_not_sent_and_does_not_condemn_the_token(self):
        t = FakeTransport()
        self.assertEqual(await ApnsProvider(t).send(TOKEN, "A" * 5000), Result.FAIL)
        self.assertEqual(t.requests, [])

    def test_status_mapping(self):
        def reason(r):
            return json.dumps({"reason": r}).encode()

        table = [
            (200, b"", Result.OK),
            (410, reason("Unregistered"), Result.INVALID_TOKEN),
            (410, b"", Result.INVALID_TOKEN),
            (400, reason("BadDeviceToken"), Result.INVALID_TOKEN),
            (400, reason("DeviceTokenNotForTopic"), Result.FAIL),  # config mismatch: must not prune
            (400, reason("BadTopic"), Result.FAIL),
            (400, reason("PayloadEmpty"), Result.FAIL),
            (400, b"not json", Result.FAIL),
            (403, reason("BadCertificate"), Result.FAIL),
            (413, reason("PayloadTooLarge"), Result.FAIL),
            (429, reason("TooManyRequests"), Result.RETRY),
            (500, reason("InternalServerError"), Result.RETRY),
            (503, reason("ServiceUnavailable"), Result.RETRY),
            (502, b"", Result.RETRY),
            (404, b"", Result.FAIL),
        ]
        for status, body, want in table:
            self.assertEqual(map_status(status, body), want, (status, body))

    async def test_transport_errors_are_transient(self):
        for exc in (ConnectionResetError("x"), asyncio.TimeoutError(), OSError("tls"), RuntimeError("h2")):
            self.assertEqual(await ApnsProvider(FakeTransport(exc=exc)).send(TOKEN, "x"), Result.RETRY)

    async def test_close_closes_the_transport(self):
        t = FakeTransport()
        await ApnsProvider(t).aclose()
        self.assertTrue(t.closed)

    def test_real_transport_explains_the_missing_optional_dependency(self):
        try:
            import httpx  # noqa: F401
        except ImportError:
            with self.assertRaisesRegex(RuntimeError, r"httpx\[http2\]"):
                HttpxTransport("/nonexistent.pem")
        else:
            self.skipTest("httpx is installed")


class ConfigTests(unittest.TestCase):
    def test_refuses_to_run_with_no_provider(self):
        with self.assertRaisesRegex(ConfigError, "no push provider"):
            load_config(env={})

    def test_environment_only_is_enough(self):
        cfg = load_config(env={"BCHATPN_LOG_ONLY": "true", "BCHATPN_LISTEN_PORT": "8080",
                               "BCHATPN_RATE_PER_SEC": "2.5", "BCHATPN_LOG_JSON": "no"})
        self.assertEqual((cfg.listen_port, cfg.rate_per_sec, cfg.log_json, cfg.log_only), (8080, 2.5, False, True))

    def test_toml_then_environment_overrides(self):
        with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as f:
            f.write('log_only = true\nlisten_port = 9000\napns_topic = "com.example"\n')
        self.addCleanup(os.unlink, f.name)
        cfg = load_config(f.name, env={"BCHATPN_LISTEN_PORT": "9001"})
        self.assertEqual((cfg.listen_port, cfg.apns_topic), (9001, "com.example"))

    def test_config_path_from_environment(self):
        with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as f:
            f.write("log_only = true\nworkers = 3\n")
        self.addCleanup(os.unlink, f.name)
        self.assertEqual(load_config(env={"BCHATPN_CONFIG": f.name}).workers, 3)

    def test_typos_and_bad_values_are_errors_not_silently_ignored(self):
        with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as f:
            f.write("log_only = true\nlisen_port = 1\n")
        self.addCleanup(os.unlink, f.name)
        with self.assertRaisesRegex(ConfigError, "unknown config key"):
            load_config(f.name, env={})
        for env in ({"BCHATPN_LISTEN_PORT": "abc"}, {"BCHATPN_LISTEN_PORT": "99999"},
                    {"BCHATPN_WORKERS": "0"}, {"BCHATPN_LOG_ONLY": "maybe"}, {"BCHATPN_LOG_LEVEL": "LOUD"},
                    {"BCHATPN_DATA_MAX": "999999"}):
            with self.assertRaises(ConfigError, msg=str(env)):
                load_config(env={"BCHATPN_LOG_ONLY": "true", **env})

    def test_missing_or_invalid_file(self):
        with self.assertRaisesRegex(ConfigError, "not found"):
            load_config("/nonexistent.toml", env={})
        with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as f:
            f.write("this is = = not toml")
        self.addCleanup(os.unlink, f.name)
        with self.assertRaisesRegex(ConfigError, "not valid TOML"):
            load_config(f.name, env={})

    def test_apns_cert_alone_satisfies_the_provider_requirement(self):
        self.assertEqual(load_config(env={"BCHATPN_APNS_CERT_FILE": "/x.pem"}).apns_cert_file, "/x.pem")

    def test_no_secret_has_a_default(self):
        d = Config()
        self.assertEqual((d.admin_token, d.apns_cert_file, d.apns_key_file), ("", "", ""))


if __name__ == "__main__":
    unittest.main()
