"""Apple Push Notification service over HTTP/2.

The network layer is a tiny `Transport` so the provider logic (payload, status -> verdict mapping)
is testable without a network. The real transport needs `pip install httpx[http2]`; it is imported
lazily so the rest of the server has no dependency on it.

The payload is identical to the legacy server's, so existing iOS clients behave the same:
    {"aps": {"alert": {"title": "Bchat", "body": "You've got a new message"}, "badge": 1,
             "sound": "default", "mutable-content": 1, "category": "SECRET"},
     "ENCRYPTED_DATA": "<data>", "remote": 1}
"""

from __future__ import annotations

import json
import logging
import re
import ssl
from typing import Protocol

from .base import Result

log = logging.getLogger("bchatpn.apns")

PROD_HOST = "api.push.apple.com"
SANDBOX_HOST = "api.sandbox.push.apple.com"
MAX_PAYLOAD = 4096  # APNs rejects larger alert payloads
_TOKEN_RE = re.compile(r"[0-9a-fA-F]{16,200}")


class Transport(Protocol):
    async def post(self, url: str, headers: dict[str, str], body: bytes, timeout: float) -> tuple[int, bytes]: ...

    async def aclose(self) -> None: ...


class HttpxTransport:
    """Pooled, multiplexed HTTP/2 client authenticating with a client certificate."""

    def __init__(self, cert_file: str, key_file: str | None = None, *, max_connections: int = 8) -> None:
        try:
            import httpx
        except ImportError as e:
            raise RuntimeError("APNs needs the optional dependency: pip install 'httpx[http2]'") from e
        ctx = ssl.create_default_context()
        ctx.load_cert_chain(cert_file, key_file or None)
        self._client = httpx.AsyncClient(
            http2=True,
            verify=ctx,
            limits=httpx.Limits(max_connections=max_connections, max_keepalive_connections=max_connections),
            timeout=httpx.Timeout(10.0),
        )

    async def post(self, url: str, headers: dict[str, str], body: bytes, timeout: float) -> tuple[int, bytes]:
        resp = await self._client.post(url, headers=headers, content=body, timeout=timeout)
        return resp.status_code, resp.content

    async def aclose(self) -> None:
        await self._client.aclose()


def build_payload(data: str) -> bytes:
    payload = {
        "aps": {
            "alert": {"title": "Bchat", "body": "You've got a new message"},
            "badge": 1,
            "sound": "default",
            "mutable-content": 1,
            "category": "SECRET",
        },
        "ENCRYPTED_DATA": data,
        "remote": 1,
    }
    return json.dumps(payload, separators=(",", ":")).encode()


def map_status(status: int, body: bytes) -> Result:
    if status == 200:
        return Result.OK
    if status == 410:  # Unregistered: the device uninstalled the app or the token expired
        return Result.INVALID_TOKEN
    reason = ""
    try:
        parsed = json.loads(body)
        if isinstance(parsed, dict):
            reason = str(parsed.get("reason", ""))
    except ValueError:
        pass
    if status == 400 and reason == "BadDeviceToken":
        return Result.INVALID_TOKEN
    if status == 429 or status >= 500:
        return Result.RETRY
    # Everything else (403 bad credentials/cert, 413 too large, 400 BadTopic / DeviceTokenNotForTopic...)
    # is on us or on the payload, not on the token: never prune a device for it.
    log.error("APNs rejected push: status=%d reason=%s", status, reason or "-")
    return Result.FAIL


class ApnsProvider:
    name = "apns"
    device_types = frozenset({"ios"})

    def __init__(
        self,
        transport: Transport,
        *,
        topic: str = "com.beldex.bchat",
        sandbox: bool = False,
        max_in_flight: int = 200,
        timeout: float = 10.0,
    ) -> None:
        self._transport = transport
        self._topic = topic
        self._host = SANDBOX_HOST if sandbox else PROD_HOST
        self.max_in_flight = max_in_flight
        self._timeout = timeout

    async def send(self, token: str, data: str) -> Result:
        if not _TOKEN_RE.fullmatch(token):
            return Result.INVALID_TOKEN  # not an APNs token at all; also keeps the URL below safe
        body = build_payload(data)
        if len(body) > MAX_PAYLOAD:
            log.warning("payload of %d bytes exceeds the APNs limit; not sending", len(body))
            return Result.FAIL
        headers = {
            "apns-topic": self._topic,
            "apns-push-type": "alert",
            "apns-priority": "10",
            "content-type": "application/json",
        }
        try:
            status, resp = await self._transport.post(
                f"https://{self._host}/3/device/{token}", headers, body, self._timeout
            )
        except Exception as e:  # connection reset, TLS error, timeout...: all transient
            log.warning("APNs transport error: %s: %s", type(e).__name__, e)
            return Result.RETRY
        return map_status(status, resp)

    async def aclose(self) -> None:
        await self._transport.aclose()
