import asyncio
import base64
import json
import os
import sys
import tempfile
import unittest
import urllib.parse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import logging
logging.disable(logging.CRITICAL)  # fault-injection tests log on purpose

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from bchatpn.config import ConfigError, load_config
from bchatpn.providers.base import Result
from bchatpn.providers.fcm import (
    FcmConfigError,
    FcmProvider,
    ServiceAccount,
    build_assertion,
    build_payload,
    map_status,
)

TOKEN = "fA1b2C3d4E5:APA91bH" + "x" * 100  # shaped like a real FCM registration token
TOKEN_URI = "https://oauth2.example.test/token"
SEND = "https://fcm.googleapis.com/v1/projects/bchat-test/messages:send"

_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_PEM = _KEY.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
).decode()


def sa_doc(**over):
    d = {
        "type": "service_account",
        "project_id": "bchat-test",
        "client_email": "push@bchat-test.iam.gserviceaccount.com",
        "private_key": _PEM,
        "token_uri": TOKEN_URI,
    }
    d.update(over)
    return d


def account():
    return ServiceAccount("bchat-test", "push@bchat-test.iam.gserviceaccount.com", _KEY, TOKEN_URI)


def fcm_err(http, status, code=None, fields=()):
    details = []
    if code:
        details.append({"@type": "type.googleapis.com/google.firebase.fcm.v1.FcmError", "errorCode": code})
    if fields:
        details.append({"fieldViolations": [{"field": f} for f in fields]})
    return json.dumps({"error": {"code": http, "status": status, "details": details}}).encode()


class FakeGoogle:
    """Routes the OAuth token endpoint and the FCM send endpoint."""

    def __init__(self, send_replies=None, auth_replies=None):
        self.send_replies = list(send_replies or [])
        self.auth_replies = list(auth_replies or [])
        self.auth_calls, self.send_calls = [], []
        self.closed = False

    async def post(self, url, headers, body, timeout):
        if url == TOKEN_URI:
            self.auth_calls.append((headers, body))
            if self.auth_replies:
                r = self.auth_replies.pop(0)
                if isinstance(r, Exception):
                    raise r
                return r
            n = len(self.auth_calls)
            return 200, json.dumps({"access_token": f"at-{n}", "expires_in": 3600}).encode()
        self.send_calls.append((url, headers, body, timeout))
        r = self.send_replies.pop(0) if self.send_replies else (200, b"{}")
        if isinstance(r, Exception):
            raise r
        return r

    async def aclose(self):
        self.closed = True


class Clock:
    def __init__(self, t=1_700_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


def b64url_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class Payload(unittest.TestCase):
    def test_identical_to_what_the_legacy_server_sent(self):
        # legacy: messaging.Message(data={'ENCRYPTED_DATA': d}, token=t, android=AndroidConfig(priority='high'))
        msg = json.loads(build_payload(TOKEN, "QUJD"))["message"]
        self.assertEqual(msg, {"token": TOKEN, "data": {"ENCRYPTED_DATA": "QUJD"}, "android": {"priority": "high"}})

    def test_data_key_is_the_one_the_app_reads(self):
        # PushReceiver.kt: else -> this["ENCRYPTED_DATA"]?.let(Base64::decode)
        self.assertIn(b'"ENCRYPTED_DATA"', build_payload(TOKEN, "x"))


class Assertion(unittest.TestCase):
    def test_jwt_is_a_valid_rs256_assertion_for_the_firebase_scope(self):
        jwt = build_assertion(account(), 1_700_000_000.0).decode()
        h, c, s = jwt.split(".")
        self.assertEqual(json.loads(b64url_decode(h)), {"alg": "RS256", "typ": "JWT"})
        claims = json.loads(b64url_decode(c))
        self.assertEqual(claims["iss"], "push@bchat-test.iam.gserviceaccount.com")
        self.assertEqual(claims["scope"], "https://www.googleapis.com/auth/firebase.messaging")
        self.assertEqual(claims["aud"], TOKEN_URI)
        self.assertEqual((claims["iat"], claims["exp"]), (1_700_000_000, 1_700_003_600))
        # raises InvalidSignature if the signature does not verify under the matching public key
        _KEY.public_key().verify(b64url_decode(s), f"{h}.{c}".encode(), padding.PKCS1v15(), hashes.SHA256())


class StatusMapping(unittest.TestCase):
    def test_table(self):
        cases = [
            (200, b"{}", Result.OK),
            (404, fcm_err(404, "NOT_FOUND", "UNREGISTERED"), Result.INVALID_TOKEN),
            (404, b"", Result.INVALID_TOKEN),
            (400, fcm_err(400, "INVALID_ARGUMENT", fields=["message.token"]), Result.INVALID_TOKEN),
            (400, fcm_err(400, "INVALID_ARGUMENT", fields=["message.data"]), Result.FAIL),
            (400, b"not json", Result.FAIL),
            (403, fcm_err(403, "PERMISSION_DENIED", "SENDER_ID_MISMATCH"), Result.FAIL),
            (401, fcm_err(401, "UNAUTHENTICATED"), Result.FAIL),
            (429, fcm_err(429, "RESOURCE_EXHAUSTED", "QUOTA_EXCEEDED"), Result.RETRY),
            (500, fcm_err(500, "INTERNAL", "INTERNAL"), Result.RETRY),
            (503, fcm_err(503, "UNAVAILABLE", "UNAVAILABLE"), Result.RETRY),
        ]
        for status, body, want in cases:
            self.assertEqual(map_status(status, body), want, (status, body))


class Provider(unittest.IsolatedAsyncioTestCase):
    def make(self, g=None, clock=None):
        g = g or FakeGoogle()
        return g, FcmProvider(account(), g, clock=clock or Clock())

    async def test_request_shape(self):
        g, p = self.make()
        self.assertEqual(await p.send(TOKEN, "QUJD"), Result.OK)
        url, headers, body, _ = g.send_calls[0]
        self.assertEqual(url, SEND)
        self.assertEqual(headers["authorization"], "Bearer at-1")
        self.assertEqual(json.loads(body)["message"]["data"]["ENCRYPTED_DATA"], "QUJD")
        form = urllib.parse.parse_qs(g.auth_calls[0][1].decode())
        self.assertEqual(form["grant_type"], ["urn:ietf:params:oauth:grant-type:jwt-bearer"])

    async def test_access_token_is_cached_across_sends(self):
        g, p = self.make()
        for _ in range(5):
            await p.send(TOKEN, "x")
        self.assertEqual(len(g.auth_calls), 1)

    async def test_concurrent_first_sends_share_one_refresh(self):
        g, p = self.make()
        rs = await asyncio.gather(*(p.send(TOKEN, "x") for _ in range(20)))
        self.assertTrue(all(r is Result.OK for r in rs))
        self.assertEqual(len(g.auth_calls), 1)

    async def test_access_token_is_renewed_before_it_expires(self):
        clock = Clock()
        g, p = self.make(clock=clock)
        await p.send(TOKEN, "x")
        clock.t += 3600 - 60  # inside the 120 s safety margin
        await p.send(TOKEN, "x")
        self.assertEqual(len(g.auth_calls), 2)
        self.assertEqual(g.send_calls[1][1]["authorization"], "Bearer at-2")

    async def test_a_401_refreshes_the_token_and_retries_once(self):
        g, p = self.make(FakeGoogle(send_replies=[(401, fcm_err(401, "UNAUTHENTICATED")), (200, b"{}")]))
        self.assertEqual(await p.send(TOKEN, "x"), Result.OK)
        self.assertEqual([c[1]["authorization"] for c in g.send_calls], ["Bearer at-1", "Bearer at-2"])

    async def test_a_persistent_401_fails_without_pruning_the_device(self):
        g, p = self.make(FakeGoogle(send_replies=[(401, b"{}"), (401, b"{}")]))
        self.assertEqual(await p.send(TOKEN, "x"), Result.FAIL)
        self.assertEqual(len(g.send_calls), 2)

    async def test_unregistered_token_is_pruned(self):
        g, p = self.make(FakeGoogle(send_replies=[(404, fcm_err(404, "NOT_FOUND", "UNREGISTERED"))]))
        self.assertEqual(await p.send(TOKEN, "x"), Result.INVALID_TOKEN)

    async def test_transport_errors_are_retried(self):
        g, p = self.make(FakeGoogle(send_replies=[ConnectionResetError("boom")]))
        self.assertEqual(await p.send(TOKEN, "x"), Result.RETRY)
        g, p = self.make(FakeGoogle(auth_replies=[TimeoutError()]))
        self.assertEqual(await p.send(TOKEN, "x"), Result.RETRY)

    async def test_token_endpoint_verdicts(self):
        g, p = self.make(FakeGoogle(auth_replies=[(503, b"")]))
        self.assertEqual(await p.send(TOKEN, "x"), Result.RETRY)
        g, p = self.make(FakeGoogle(auth_replies=[(400, b'{"error":"invalid_grant"}')]))
        self.assertEqual(await p.send(TOKEN, "x"), Result.FAIL)  # bad credentials: ours, not the token's
        self.assertEqual(g.send_calls, [])

    async def test_a_failed_auth_is_retried_next_time_not_cached(self):
        g, p = self.make(FakeGoogle(auth_replies=[(503, b"")]))
        self.assertEqual(await p.send(TOKEN, "x"), Result.RETRY)
        self.assertEqual(await p.send(TOKEN, "x"), Result.OK)

    async def test_hostile_tokens_never_reach_the_network_or_the_url(self):
        g, p = self.make()
        for bad in ("../../x", "ab/cd?x=1", "short", "", "a b " * 10, "t" * 5000, "tok\r\nHost: evil" + "x" * 30):
            self.assertEqual(await p.send(bad, "x"), Result.INVALID_TOKEN, bad)
        self.assertEqual((g.auth_calls, g.send_calls), ([], []))

    async def test_oversize_data_is_not_sent_and_not_a_token_problem(self):
        g, p = self.make()
        self.assertEqual(await p.send(TOKEN, "A" * 5000), Result.FAIL)
        self.assertEqual(g.send_calls, [])
        self.assertEqual(await p.send(TOKEN, "A" * 4000), Result.OK)

    async def test_serves_android_only_and_closes_its_transport(self):
        g, p = self.make()
        self.assertEqual(p.device_types, frozenset({"android"}))
        await p.aclose()
        self.assertTrue(g.closed)


class Credentials(unittest.TestCase):
    def write(self, doc, mode=0o600):
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as f:
            f.write(doc if isinstance(doc, str) else json.dumps(doc))
        os.chmod(path, mode)
        self.addCleanup(os.unlink, path)
        return path

    def test_loads_a_service_account(self):
        sa = ServiceAccount.load(self.write(sa_doc()))
        self.assertEqual((sa.project_id, sa.token_uri), ("bchat-test", TOKEN_URI))

    def test_default_token_uri(self):
        d = sa_doc()
        del d["token_uri"]
        self.assertEqual(ServiceAccount.load(self.write(d)).token_uri, "https://oauth2.googleapis.com/token")

    def test_refuses_a_group_or_world_readable_key_file(self):
        for mode in (0o640, 0o644, 0o604):
            with self.assertRaisesRegex(FcmConfigError, "chmod 600"):
                ServiceAccount.load(self.write(sa_doc(), mode))

    def test_rejects_malformed_files(self):
        bad = [
            "not json",
            "[]",
            sa_doc(type="authorized_user"),
            sa_doc(project_id=""),
            sa_doc(client_email=None),
            sa_doc(private_key="-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----"),
            sa_doc(token_uri="http://plain.example/token"),
        ]
        for doc in bad:
            with self.assertRaises(FcmConfigError, msg=str(doc)[:60]):
                ServiceAccount.load(self.write(doc))
        with self.assertRaises(FcmConfigError):
            ServiceAccount.load("/nonexistent/fcm.json")


class ConfigWiring(unittest.TestCase):
    def test_fcm_alone_is_a_valid_provider_setup(self):
        cfg = load_config(None, {"BCHATPN_FCM_CREDENTIALS_FILE": "/x/fcm.json"})
        self.assertEqual(cfg.fcm_credentials_file, "/x/fcm.json")

    def test_no_provider_is_still_an_error(self):
        with self.assertRaisesRegex(ConfigError, "no push provider"):
            load_config(None, {})

    def test_build_providers_gives_android_to_fcm_and_the_rest_to_dry_run(self):
        from bchatpn.app import build_providers

        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as f:
            json.dump(sa_doc(), f)
        os.chmod(path, 0o600)
        self.addCleanup(os.unlink, path)
        cfg = load_config(None, {"BCHATPN_FCM_CREDENTIALS_FILE": path, "BCHATPN_LOG_ONLY": "true"})
        ps = {p.name: p.device_types for p in build_providers(cfg)}
        self.assertEqual(ps, {"fcm": frozenset({"android"}), "log": frozenset({"ios", "huawei"})})

    def test_bad_credentials_are_a_startup_error(self):
        from bchatpn.app import build_providers

        cfg = load_config(None, {"BCHATPN_FCM_CREDENTIALS_FILE": "/nonexistent/fcm.json"})
        with self.assertRaises(ConfigError):
            build_providers(cfg)


if __name__ == "__main__":
    unittest.main()
