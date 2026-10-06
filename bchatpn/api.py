"""The six endpoints the BChat apps already speak, behind the onion ingress.

    register                      {token, pubKey, device?}
    unregister                    {token}
    register_legacy_groups_only   {token, pubKey, device?, legacyGroupPublicKeys[]}
    subscribe_closed_group        {closedGroupPublicKey, pubKey}
    unsubscribe_closed_group      {closedGroupPublicKey, pubKey}
    notify                        {data, send_to}

Reply conventions (what the Android client actually does with them, see OnionRequestAPI.kt):
  * success                      -> status 200, code 1
  * soft refusal (too large, rate limited, group full)
                                 -> status 200, code 0.  The app logs it and does NOT retry.
  * bad input / busy / internal  -> status 400, code 0.  The app retries it (retryIfNeeded), and 400 is
                                    the one rejection status it does not count against its onion path
                                    (a 5xx or 429 here would make it tear down a healthy path).
  * unknown endpoint             -> status 404, code 0   (also exempt from path penalties)

Error messages are fixed strings. Exception details go to the log, never to the client.
"""

from __future__ import annotations

import hashlib
import logging
import re
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Callable

from .config import Config
from .dispatch import Dispatcher
from .httpd import Request, Response
from .obs import Metrics, short
from .onion import OnionError, OnionRequest, OnionServer
from .registry import DEVICE_TYPES, Registry

log = logging.getLogger("bchatpn.api")

V2_PATH = "/beldex/v2/lsrpc"
V4_PATH = "/beldex/v4/lsrpc"

# Bchat ids and closed-group keys are hex ("bd" + 64 hex = 66 chars). Kept lenient on length so a
# different-but-legitimate id form is not rejected; tightening it is a one-line change.
_ID_RE = re.compile(r"[0-9a-fA-F]{32,130}")
_TOKEN_RE = re.compile(r"[\x21-\x7e]{8,4096}")  # printable, no whitespace: APNs/FCM tokens


@dataclass(frozen=True, slots=True)
class Reply:
    status: int
    code: int
    message: str
    body: Any = None  # replaces the default {"code", "message"} JSON body when set


OK = Reply(200, 1, "Success")


class _Invalid(Exception):
    def __init__(self, message: str = "Invalid parameter") -> None:
        self.message = message


class TokenBuckets:
    """Per-key token bucket with a bounded number of tracked keys (least recently used evicted)."""

    def __init__(self, rate: float, burst: float, max_keys: int, clock: Callable[[], float]) -> None:
        self._rate = rate
        self._burst = burst
        self._max = max_keys
        self._clock = clock
        self._state: OrderedDict[str, tuple[float, float]] = OrderedDict()

    def allow(self, key: str) -> bool:
        now = self._clock()
        tokens, last = self._state.pop(key, (self._burst, now))
        tokens = min(self._burst, tokens + (now - last) * self._rate)
        allowed = tokens >= 1.0
        if allowed:
            tokens -= 1.0
        self._state[key] = (tokens, now)
        while len(self._state) > self._max:
            self._state.popitem(last=False)
        return allowed


class Api:
    def __init__(
        self,
        onion: OnionServer,
        registry: Registry,
        dispatcher: Dispatcher,
        metrics: Metrics,
        cfg: Config,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._onion = onion
        self._registry = registry
        self._dispatcher = dispatcher
        self._metrics = metrics
        self._cfg = cfg
        self._clock = clock
        self._buckets = TokenBuckets(cfg.rate_per_sec, cfg.rate_burst, 100_000, clock)
        self._seen: OrderedDict[bytes, float] = OrderedDict()  # idempotency cache for notify
        self._routes: dict[str, Callable[[dict[str, Any]], Reply]] = {
            "register": self._register,
            "unregister": self._unregister,
            "register_legacy_groups_only": self._register_legacy_groups_only,
            "subscribe_closed_group": self._subscribe_closed_group,
            "unsubscribe_closed_group": self._unsubscribe_closed_group,
            "notify": self._notify,
        }

    # ---- HTTP entry point --------------------------------------------------------------------
    async def handle(self, req: Request) -> Response:
        # Synchronous on purpose: decrypt, validate, enqueue and encrypt are all CPU-only, so there is
        # nothing to await and no task switch to pay for.
        t0 = time.perf_counter()
        try:
            return self._handle(req)
        finally:
            self._metrics.observe("request_seconds", time.perf_counter() - t0)

    def _handle(self, req: Request) -> Response:
        if req.path == V2_PATH:
            version = 2
        elif req.path == V4_PATH:
            version = 4
        else:
            return 404, "text/plain", b"not found\n"

        try:
            onion_req = self._onion.open_v2(req.body) if version == 2 else self._onion.open_v4(req.body)
        except OnionError as e:
            self._metrics.inc("onion_rejected")
            log.debug("rejected onion request: %s", e)
            return 400, "text/plain", b"bad request\n"

        reply = self._dispatch(onion_req)
        self._metrics.inc("requests", endpoint=onion_req.endpoint if onion_req.endpoint in self._routes else "unknown",
                          code=str(reply.code))
        if version == 2:
            return 200, "application/json", self._onion.reply_v2(
                onion_req.key, reply.status, reply.code, reply.message, reply.body
            )
        return 200, "application/octet-stream", self._onion.reply_v4(
            onion_req.key, reply.status, reply.code, reply.message, reply.body
        )

    def _dispatch(self, req: OnionRequest) -> Reply:
        fn = self._routes.get(req.endpoint)
        if fn is None:
            return Reply(404, 0, "Not found")
        try:
            return fn(req.args)
        except _Invalid as e:
            return Reply(400, 0, e.message)
        except Exception:
            log.exception("handler %s failed", req.endpoint)
            self._metrics.inc("handler_errors", endpoint=req.endpoint)
            return Reply(400, 0, "Internal error")  # 400, not 5xx: see module docstring

    # ---- validation --------------------------------------------------------------------------
    @staticmethod
    def _id(args: dict[str, Any], key: str) -> str:
        v = args.get(key)
        if not isinstance(v, str) or len(v) % 2 or not _ID_RE.fullmatch(v):
            raise _Invalid("Invalid parameter")
        return v.lower()

    @staticmethod
    def _token(args: dict[str, Any]) -> str:
        v = args.get("token")
        if not isinstance(v, str) or not _TOKEN_RE.fullmatch(v):
            raise _Invalid("Invalid parameter")
        return v

    @staticmethod
    def _device(args: dict[str, Any], token: str) -> str:
        v = args.get("device")
        if v is None:
            return "ios" if len(token) == 64 else "android"  # the legacy server's inference
        if not isinstance(v, str) or v not in DEVICE_TYPES:
            raise _Invalid("Invalid parameter")
        return v

    # ---- endpoints ---------------------------------------------------------------------------
    def _register(self, args: dict[str, Any]) -> Reply:
        token, account = self._token(args), self._id(args, "pubKey")
        device = self._device(args, token)
        self._registry.register(token, account, device, legacy_groups_only=False)
        log.info("register account=%s device=%s token=%s", short(account), device, short(token))
        return OK

    def _register_legacy_groups_only(self, args: dict[str, Any]) -> Reply:
        token, account = self._token(args), self._id(args, "pubKey")
        device = self._device(args, token)
        groups = args.get("legacyGroupPublicKeys", [])
        if not isinstance(groups, list) or len(groups) > self._cfg.max_groups_per_register:
            raise _Invalid("Invalid parameter")
        ids = [self._id({"g": g}, "g") for g in groups]  # validate everything before changing anything
        self._registry.register(token, account, device, legacy_groups_only=True)
        for g in ids:
            if not self._registry.subscribe_group(g, account):
                self._metrics.inc("group_full")
        log.info("register account=%s device=%s token=%s legacy_groups_only groups=%d",
                 short(account), device, short(token), len(ids))
        return OK

    def _unregister(self, args: dict[str, Any]) -> Reply:
        # Idempotent: removing something already gone has reached the desired state.
        token = self._token(args)
        self._registry.unregister(token)
        log.info("unregister token=%s", short(token))
        return OK

    def _subscribe_closed_group(self, args: dict[str, Any]) -> Reply:
        group, member = self._id(args, "closedGroupPublicKey"), self._id(args, "pubKey")
        if not self._registry.subscribe_group(group, member):
            self._metrics.inc("group_full")
            return Reply(200, 0, "Group is full")
        return OK

    def _unsubscribe_closed_group(self, args: dict[str, Any]) -> Reply:
        self._registry.unsubscribe_group(self._id(args, "closedGroupPublicKey"), self._id(args, "pubKey"))
        return OK

    def _notify(self, args: dict[str, Any]) -> Reply:
        send_to = self._id(args, "send_to")
        data = args.get("data")
        if not isinstance(data, str) or not data:
            raise _Invalid("Invalid parameter")
        m = self._metrics

        if len(data) > self._cfg.data_max:
            m.inc("notify_rejected", reason="too_large")
            log.info("notify to=%s rejected: too large (%d chars)", short(send_to), len(data))
            return Reply(200, 0, "Too large")

        # Most notifies are for people who never enabled push: answer without touching the queue.
        if not self._registry.knows(send_to):
            m.inc("notify_untracked")
            log.debug("notify to=%s ignored: recipient has no registered device", short(send_to))  # the common case
            return OK

        now = self._clock()
        key = hashlib.blake2b(send_to.encode() + b"\0" + data.encode(), digest_size=16).digest()
        self._expire_seen(now)
        if key in self._seen:  # the app retried a notify whose reply it never saw
            m.inc("notify_duplicate")
            log.info("notify to=%s ignored: duplicate of a recent notify", short(send_to))
            return OK

        if not self._buckets.allow(send_to):
            m.inc("notify_rejected", reason="rate_limited")
            log.info("notify to=%s rejected: rate limited", short(send_to))
            return Reply(200, 0, "Rate limited")

        if not self._dispatcher.submit(send_to, data):
            m.inc("notify_rejected", reason="busy")
            log.info("notify to=%s rejected: queue full", short(send_to))
            return Reply(400, 0, "Busy")  # the app retries 400s; do not remember the key

        self._seen[key] = now
        m.inc("notify_accepted")
        log.info("notify to=%s accepted (%d chars), queued for push", short(send_to), len(data))
        return OK

    def _expire_seen(self, now: float) -> None:
        ttl = self._cfg.dedupe_ttl
        seen = self._seen
        while seen:
            oldest_key, ts = next(iter(seen.items()))
            if now - ts > ttl or len(seen) > self._cfg.dedupe_max:
                del seen[oldest_key]
            else:
                break
