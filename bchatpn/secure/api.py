"""Signed /subscribe and /unsubscribe, the registration the app already performs against the v2 server.

The app signs `MONITOR || pubkey || sig_ts || data(0|1) || namespaces` (subscribe) or
`UNSUBSCRIBE || pubkey || sig_ts` (unsubscribe) with the account's Ed25519 key and sends the matching
Ed25519 public key. We accept a request only if all of these hold:

  * the Ed25519 key maps to the account id it claims (ed25519 -> x25519 equals the id), so a valid
    signature proves control of that id;
  * the signature verifies over exactly the bytes the app signed;
  * the timestamp is recent (`signature_window`, default 1 hour either side). The v2 server accepts 14
    days because it must hand the signature to the storage nodes; we never do, so a shorter window is
    free and shrinks what a leaked request could be replayed for.

Replies use the JSON shape the app parses (SubscriptionResponse / UnsubscribeResponse), not the legacy
{"code", "message"} body.

Everything else (the legacy register/notify endpoints) is the normal Api. The registry decides what an
unsigned registration is allowed to do.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any, Callable

from ..api import Api, Reply, _TOKEN_RE
from ..config import Config
from ..dispatch import Dispatcher
from ..obs import Metrics, short
from ..onion import OnionServer
from .crypto import ed25519_to_x25519, parse_bytes, verify_signature
from .registry import SecureRegistry

log = logging.getLogger("bchatpn.api")

# Error codes the app knows (Models.kt)
UNPARSEABLE = 1
SERVICE_NOT_AVAILABLE = 2

SERVICES = {"firebase": "android"}  # service name -> device type. APNs is not offered in secure mode.
_PUBKEY_RE = re.compile(r"[0-9a-fA-F]{66}")


class _Rejected(Exception):
    def __init__(self, code: int, message: str, reason: str) -> None:
        self.code, self.message, self.reason = code, message, reason


def _failure(e: _Rejected) -> Reply:
    return Reply(200, 0, e.message, {"error": e.code, "message": e.message})


class SecureApi(Api):
    _registry: SecureRegistry

    def __init__(
        self,
        onion: OnionServer,
        registry: SecureRegistry,
        dispatcher: Dispatcher,
        metrics: Metrics,
        cfg: Config,
        *,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        super().__init__(onion, registry, dispatcher, metrics, cfg, clock=clock)
        self._wall = wall_clock
        self._window = cfg.signature_window
        self._routes["subscribe"] = self._subscribe
        self._routes["unsubscribe"] = self._unsubscribe

    # ---- shared verification -----------------------------------------------------------------
    def _verify(self, args: dict[str, Any], message_for: Callable[[str, int], bytes]) -> str:
        """Check identity, timestamp and signature. Returns the lower-cased account id."""
        pub = args.get("pubkey")
        if not isinstance(pub, str) or not _PUBKEY_RE.fullmatch(pub):
            raise _Rejected(UNPARSEABLE, "Invalid pubkey", "bad_pubkey")
        try:
            ed = parse_bytes(args.get("session_ed25519"), 32)
            signature = parse_bytes(args.get("signature"), 64)
        except ValueError:
            raise _Rejected(UNPARSEABLE, "Invalid session_ed25519 or signature", "bad_encoding") from None
        ts = args.get("sig_ts")
        if isinstance(ts, bool) or not isinstance(ts, int):
            raise _Rejected(UNPARSEABLE, "Invalid sig_ts", "bad_timestamp")
        now = self._wall()
        if ts < now - self._window or ts > now + self._window:
            raise _Rejected(UNPARSEABLE, "Signature timestamp is out of range", "stale_timestamp")
        if ed25519_to_x25519(ed) != bytes.fromhex(pub)[1:]:
            raise _Rejected(UNPARSEABLE, "session_ed25519 does not match pubkey", "id_mismatch")
        if not verify_signature(ed, signature, message_for(pub, ts)):
            raise _Rejected(UNPARSEABLE, "Invalid signature", "bad_signature")
        return pub.lower()

    @staticmethod
    def _token_of(args: dict[str, Any]) -> str:
        info = args.get("service_info")
        token = info.get("token") if isinstance(info, dict) else None
        if not isinstance(token, str) or not _TOKEN_RE.fullmatch(token):
            raise _Rejected(UNPARSEABLE, "Invalid service_info", "bad_token")
        return token

    def _reject(self, endpoint: str, e: _Rejected, args: dict[str, Any]) -> Reply:
        self._metrics.inc(f"{endpoint}_rejected", reason=e.reason)
        pub = args.get("pubkey")
        log.info("%s rejected (%s) account=%s", endpoint, e.reason, short(pub) if isinstance(pub, str) else "-")
        return _failure(e)

    # ---- /subscribe ----------------------------------------------------------------------------
    def _subscribe(self, args: dict[str, Any]) -> Reply:
        try:
            service = args.get("service")
            device = SERVICES.get(service) if isinstance(service, str) else None
            if device is None:
                raise _Rejected(SERVICE_NOT_AVAILABLE, "Unsupported service", "bad_service")
            token = self._token_of(args)
            namespaces = args.get("namespaces")
            if (
                not isinstance(namespaces, list)
                or not 1 <= len(namespaces) <= 16
                or any(isinstance(n, bool) or not isinstance(n, int) or not -32768 <= n <= 32767 for n in namespaces)
                or namespaces != sorted(namespaces)
            ):
                raise _Rejected(UNPARSEABLE, "Invalid namespaces", "bad_namespaces")
            want_data = args.get("data") is True
            try:
                enc_key = parse_bytes(args.get("enc_key"), 32)
            except ValueError:
                raise _Rejected(UNPARSEABLE, "Invalid enc_key", "bad_enc_key") from None

            def message(pub: str, ts: int) -> bytes:
                return f"MONITOR{pub}{ts}{1 if want_data else 0}{','.join(map(str, namespaces))}".encode()

            account = self._verify(args, message)
        except _Rejected as e:
            return self._reject("subscribe", e, args)

        renewed = self._registry.register_signed(token, account, device, enc_key, want_data)
        self._metrics.inc("subscribed", result="renewed" if renewed else "added")
        log.info("subscribe account=%s device=%s token=%s %s", short(account), device, short(token),
                 "renewed" if renewed else "added")
        return Reply(200, 1, "Success", {"success": True, "updated" if renewed else "added": True})

    # ---- /unsubscribe --------------------------------------------------------------------------
    def _unsubscribe(self, args: dict[str, Any]) -> Reply:
        try:
            token = self._token_of(args)
            account = self._verify(args, lambda pub, ts: f"UNSUBSCRIBE{pub}{ts}".encode())
        except _Rejected as e:
            return self._reject("unsubscribe", e, args)
        removed = self._registry.unregister_signed(token, account)
        log.info("unsubscribe account=%s token=%s %s", short(account), short(token), "removed" if removed else "unknown")
        return Reply(200, 1, "Success", {"success": True, "removed": removed})
