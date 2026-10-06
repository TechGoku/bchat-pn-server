"""Firebase Cloud Messaging (HTTP v1) for Android devices.

Authentication is a Google service-account JSON (the same file the legacy server loads as
`bchat-android-ios-firebase.json`): we sign a short-lived JWT with its private key (RS256, via
`cryptography`), trade it for an OAuth2 access token, and cache that token until shortly before it
expires. The HTTP transport is standard library only, so FCM adds no dependency to the server.

The network layer is a tiny `Transport` (same shape as the APNs one) so the provider logic -- payload,
token refresh, status -> verdict mapping -- is testable without a network.

The message is identical to the legacy server's, so existing Android clients behave the same:
    {"message": {"token": "<fcm token>", "data": {"ENCRYPTED_DATA": "<data>"}, "android": {"priority": "high"}}}
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import re
import stat
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Protocol

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .base import Result

log = logging.getLogger("bchatpn.fcm")

SCOPE = "https://www.googleapis.com/auth/firebase.messaging"
SEND_URL = "https://fcm.googleapis.com/v1/projects/{project}/messages:send"
DATA_KEY = "ENCRYPTED_DATA"
MAX_DATA = 4096  # FCM caps the whole `data` map (keys + values) at 4 KB
_TOKEN_RE = re.compile(r"[A-Za-z0-9_:\-]{20,4096}")  # FCM registration tokens: no '/', '?', spaces...
_REFRESH_MARGIN = 120.0  # renew the access token this many seconds before it expires


class FcmConfigError(Exception):
    pass


class Transport(Protocol):
    async def post(self, url: str, headers: dict[str, str], body: bytes, timeout: float) -> tuple[int, bytes]: ...

    async def aclose(self) -> None: ...


class UrllibTransport:
    """HTTPS POST on a private thread pool. HTTP/1.1 is all FCM v1 needs; non-2xx is a normal return."""

    def __init__(self, *, max_threads: int = 32) -> None:
        self._pool = ThreadPoolExecutor(max_workers=max_threads, thread_name_prefix="fcm")

    @staticmethod
    def _post(url: str, headers: dict[str, str], body: bytes, timeout: float) -> tuple[int, bytes]:
        if not url.startswith("https://"):
            raise ValueError("refusing a non-https URL")
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (https enforced above)
                return resp.status, resp.read(1 << 20)
        except urllib.error.HTTPError as e:
            try:
                return e.code, e.read(1 << 20)
            finally:
                e.close()

    async def post(self, url: str, headers: dict[str, str], body: bytes, timeout: float) -> tuple[int, bytes]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._pool, self._post, url, headers, body, timeout)

    async def aclose(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)


class ServiceAccount:
    def __init__(self, project_id: str, client_email: str, private_key: rsa.RSAPrivateKey, token_uri: str) -> None:
        self.project_id = project_id
        self.client_email = client_email
        self.private_key = private_key
        self.token_uri = token_uri

    @classmethod
    def load(cls, path: str) -> "ServiceAccount":
        try:
            mode = os.stat(path).st_mode
        except OSError as e:
            raise FcmConfigError(f"cannot read fcm_credentials_file {path}: {e.strerror}") from None
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise FcmConfigError(f"{path} holds a private key and is readable by others: chmod 600 {path}")
        try:
            with open(path, "rb") as f:
                doc = json.load(f)
        except (OSError, ValueError) as e:
            raise FcmConfigError(f"{path} is not a readable JSON file: {e}") from None
        if not isinstance(doc, dict) or doc.get("type") != "service_account":
            raise FcmConfigError(f"{path} is not a Google service-account key (type != service_account)")
        for k in ("project_id", "client_email", "private_key"):
            if not isinstance(doc.get(k), str) or not doc[k]:
                raise FcmConfigError(f"{path}: missing {k!r}")
        token_uri = doc.get("token_uri") or "https://oauth2.googleapis.com/token"
        if not isinstance(token_uri, str) or not token_uri.startswith("https://"):
            raise FcmConfigError(f"{path}: token_uri must be an https URL")
        try:
            key = serialization.load_pem_private_key(doc["private_key"].encode(), password=None)
        except (ValueError, TypeError) as e:
            raise FcmConfigError(f"{path}: private_key is not a valid PEM key: {e}") from None
        if not isinstance(key, rsa.RSAPrivateKey):
            raise FcmConfigError(f"{path}: private_key is not an RSA key")
        return cls(doc["project_id"], doc["client_email"], key, token_uri)


def _b64url(raw: bytes) -> bytes:
    return base64.urlsafe_b64encode(raw).rstrip(b"=")


def build_assertion(sa: ServiceAccount, now: float) -> bytes:
    """The signed JWT we exchange for an access token."""
    header = {"alg": "RS256", "typ": "JWT"}
    claims = {
        "iss": sa.client_email,
        "scope": SCOPE,
        "aud": sa.token_uri,
        "iat": int(now),
        "exp": int(now) + 3600,
    }
    signing_input = b".".join(_b64url(json.dumps(p, separators=(",", ":")).encode()) for p in (header, claims))
    signature = sa.private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return signing_input + b"." + _b64url(signature)


def build_message(token: str, fields: dict[str, str]) -> bytes:
    msg = {"message": {"token": token, "data": fields, "android": {"priority": "high"}}}
    return json.dumps(msg, separators=(",", ":")).encode()


def build_payload(token: str, data: str) -> bytes:
    return build_message(token, {DATA_KEY: data})


def _error_info(body: bytes) -> tuple[str, str, list[str]]:
    """(status, FcmError errorCode, fields named in violations) from an FCM v1 error body."""
    status = code = ""
    fields: list[str] = []
    try:
        err = json.loads(body).get("error", {})
        if isinstance(err, dict):
            status = str(err.get("status", ""))
            for d in err.get("details") or []:
                if not isinstance(d, dict):
                    continue
                if d.get("errorCode"):
                    code = str(d["errorCode"])
                for v in d.get("fieldViolations") or []:
                    if isinstance(v, dict):
                        fields.append(str(v.get("field", "")))
    except (ValueError, AttributeError):
        pass
    return status, code, fields


def map_status(status: int, body: bytes) -> Result:
    if status == 200:
        return Result.OK
    st, code, fields = _error_info(body)
    if code == "UNREGISTERED" or status == 404:  # app uninstalled / token expired
        return Result.INVALID_TOKEN
    if status == 400 and any(f.endswith("message.token") for f in fields):
        return Result.INVALID_TOKEN
    if status == 429 or status >= 500:  # QUOTA_EXCEEDED, UNAVAILABLE, INTERNAL
        return Result.RETRY
    # 400 bad payload, 401/403 credentials or SENDER_ID_MISMATCH (token from another Firebase project):
    # on us or on the payload, not provably on the token, so never prune a device for it.
    log.error("FCM rejected push: http=%d status=%s code=%s", status, st or "-", code or "-")
    return Result.FAIL


class _AccessToken:
    """Caches one OAuth2 access token; concurrent callers share a single refresh."""

    def __init__(self, sa: ServiceAccount, transport: Transport, timeout: float, clock: Callable[[], float]) -> None:
        self._sa, self._transport, self._timeout, self._clock = sa, transport, timeout, clock
        self._token = ""
        self._expires = 0.0
        self._lock = asyncio.Lock()

    def invalidate(self, stale: str) -> None:
        if self._token == stale:
            self._token = ""

    async def get(self) -> str:
        if self._token and self._clock() < self._expires - _REFRESH_MARGIN:
            return self._token
        async with self._lock:
            if self._token and self._clock() < self._expires - _REFRESH_MARGIN:
                return self._token  # someone else refreshed while we waited
            now = self._clock()
            form = urllib.parse.urlencode(
                {
                    "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                    "assertion": build_assertion(self._sa, now).decode(),
                }
            ).encode()
            status, resp = await self._transport.post(
                self._sa.token_uri, {"content-type": "application/x-www-form-urlencoded"}, form, self._timeout
            )
            if status != 200:
                raise _AuthError(status, resp)
            try:
                doc = json.loads(resp)
                self._token = str(doc["access_token"])
                self._expires = now + float(doc.get("expires_in", 3600))
            except (ValueError, KeyError, TypeError):
                raise _AuthError(status, resp) from None
            return self._token


class _AuthError(Exception):
    def __init__(self, status: int, body: bytes) -> None:
        super().__init__(f"token endpoint answered {status}")
        self.status = status
        self.body = body


class FcmProvider:
    name = "fcm"
    device_types = frozenset({"android"})

    def __init__(
        self,
        account: ServiceAccount,
        transport: Transport,
        *,
        max_in_flight: int = 200,
        timeout: float = 10.0,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._url = SEND_URL.format(project=urllib.parse.quote(account.project_id, safe=""))
        self._transport = transport
        self._auth = _AccessToken(account, transport, timeout, clock)
        self.max_in_flight = max_in_flight
        self._timeout = timeout

    async def send(self, token: str, data: str) -> Result:
        return await self._send_fields(token, {DATA_KEY: data})

    async def send_encrypted(self, token: str, enc_payload: str) -> Result:
        """Secure mode: the per-device encrypted push the app decrypts (`enc_payload` + `spns` version)."""
        return await self._send_fields(token, {"enc_payload": enc_payload, "spns": "1"})

    async def _send_fields(self, token: str, fields: dict[str, str]) -> Result:
        if not _TOKEN_RE.fullmatch(token):
            return Result.INVALID_TOKEN  # not an FCM token at all
        size = sum(len(k) + len(v.encode()) for k, v in fields.items())
        if size > MAX_DATA:
            log.warning("payload of %d bytes exceeds the FCM data limit; not sending", size)
            return Result.FAIL
        body = build_message(token, fields)
        # One retry with a fresh access token covers the token expiring between our cache check and FCM's.
        for attempt in (0, 1):
            try:
                access = await self._auth.get()
            except _AuthError as e:
                if e.status == 429 or e.status >= 500:
                    log.warning("FCM auth endpoint trouble: http=%d", e.status)
                    return Result.RETRY
                log.error("FCM credentials rejected by the token endpoint: http=%d %s", e.status, e.body[:200])
                return Result.FAIL
            except Exception as e:  # connection reset, TLS error, timeout...
                log.warning("FCM auth transport error: %s: %s", type(e).__name__, e)
                return Result.RETRY
            headers = {"authorization": f"Bearer {access}", "content-type": "application/json"}
            try:
                status, resp = await self._transport.post(self._url, headers, body, self._timeout)
            except Exception as e:
                log.warning("FCM transport error: %s: %s", type(e).__name__, e)
                return Result.RETRY
            if status == 401 and attempt == 0:
                self._auth.invalidate(access)
                continue
            return map_status(status, resp)
        return Result.FAIL  # unreachable; keeps the type checker honest

    async def aclose(self) -> None:
        await self._transport.aclose()
