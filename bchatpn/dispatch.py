"""Turns accepted notifications into pushes, with bounded memory and no stalls.

    submit()  (event loop, O(1), never blocks)  ->  bounded queue  ->  N workers
    worker: resolve recipients from the in-memory registry -> one delivery per device, concurrently

Design rules, each one fixing a legacy failure mode:
  * The queue is bounded. When it is full, submit() returns False and the caller tells the client
    "busy" so the app retries, instead of silently dropping.
  * A queued notification older than `message_ttl` is dropped as stale: the app also polls, so a
    minute-old wake-up is worth nothing, and an unbounded backlog is worse than a dropped push.
  * Only a *definitive* provider verdict removes a device (Result.INVALID_TOKEN). Timeouts and 5xx
    retry with exponential backoff and jitter. A misconfiguration can't mass-delete devices: pruning
    is rate-capped.
  * A per-provider circuit breaker sheds load while a provider is down, so workers don't pile up
    behind it. It half-opens after a cooldown and probes with a single request.
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from collections import deque
from typing import Awaitable, Callable

from .obs import Metrics, short
from .providers.base import Provider, Result
from .registry import Registry

log = logging.getLogger("bchatpn.dispatch")


class Breaker:
    """closed -> (threshold consecutive failures) -> open -> (cooldown) -> half-open probe -> closed/open."""

    def __init__(self, threshold: int, cooldown: float, clock: Callable[[], float]) -> None:
        self._threshold = threshold
        self._cooldown = cooldown
        self._clock = clock
        self._failures = 0
        self._open_until = 0.0
        self._probe_until = 0.0
        self.opened = 0  # times opened, for metrics

    @property
    def state(self) -> str:
        if self._failures < self._threshold:
            return "closed"
        return "open" if self._clock() < self._open_until else "half-open"

    def allow(self) -> bool:
        if self._failures < self._threshold:
            return True
        now = self._clock()
        if now < self._open_until:
            return False
        if now < self._probe_until:  # a probe is already in flight
            return False
        self._probe_until = now + self._cooldown
        return True

    def record(self, ok: bool) -> None:
        if ok:
            self._failures = 0
            return
        self._failures += 1
        if self._failures >= self._threshold:
            if self._failures == self._threshold:
                self.opened += 1
            self._open_until = self._clock() + self._cooldown
            self._probe_until = 0.0


class Dispatcher:
    def __init__(
        self,
        registry: Registry,
        providers: list[Provider],
        metrics: Metrics,
        *,
        queue_size: int = 20000,
        workers: int = 32,
        max_attempts: int = 4,
        backoff_base: float = 0.5,
        backoff_max: float = 30.0,
        send_timeout: float = 15.0,
        message_ttl: float = 60.0,
        breaker_threshold: int = 20,
        breaker_cooldown: float = 10.0,
        prune_per_minute: int = 1000,
        honor_legacy_groups_only: bool = False,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        clock: Callable[[], float] = time.monotonic,
        rng: Callable[[], float] = random.random,
    ) -> None:
        self._registry = registry
        self._metrics = metrics
        self._max_attempts = max_attempts
        self._backoff_base = backoff_base
        self._backoff_max = backoff_max
        self._send_timeout = send_timeout
        self._ttl = message_ttl
        self._prune_cap = prune_per_minute
        self._honor_lgo = honor_legacy_groups_only
        self._sleep = sleep
        self._clock = clock
        self._rng = rng

        self._queue: asyncio.Queue[tuple[str, str, float]] = asyncio.Queue(maxsize=queue_size)
        self._n_workers = workers
        self._workers: list[asyncio.Task[None]] = []
        self._closing = False

        self._by_type: dict[str, Provider] = {}
        self._sems: dict[str, asyncio.Semaphore] = {}
        self._breakers: dict[str, Breaker] = {}
        self._providers = providers
        for p in providers:
            self._sems[p.name] = asyncio.Semaphore(p.max_in_flight)
            self._breakers[p.name] = Breaker(breaker_threshold, breaker_cooldown, clock)
            for t in p.device_types:
                self._by_type.setdefault(t, p)
        self._prunes: deque[float] = deque()

        metrics.gauge("queue_depth", lambda: self._queue.qsize())
        for name, br in self._breakers.items():
            metrics.gauge(f"breaker_open_{name}", lambda br=br: 0 if br.state == "closed" else 1)

    # ---- producer ----------------------------------------------------------------------------
    @property
    def depth(self) -> int:
        return self._queue.qsize()

    def submit(self, send_to: str, data: str) -> bool:
        if self._closing:
            return False
        try:
            self._queue.put_nowait((send_to, data, self._clock()))
        except asyncio.QueueFull:
            return False
        return True

    # ---- lifecycle ---------------------------------------------------------------------------
    async def start(self) -> None:
        self._workers = [asyncio.create_task(self._worker(), name=f"dispatch-{i}") for i in range(self._n_workers)]

    async def stop(self, drain_timeout: float) -> None:
        """Refuse new work, let queued work finish for up to `drain_timeout`, then stop the workers."""
        self._closing = True
        try:
            await asyncio.wait_for(self._queue.join(), drain_timeout)
        except TimeoutError:
            left = self._queue.qsize()
            log.warning("drain timeout: %d queued notifications discarded", left)
            self._metrics.inc("notify_dropped", left, reason="shutdown")
        for w in self._workers:
            w.cancel()
        await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers = []
        for p in self._providers:
            try:
                await p.aclose()
            except Exception:
                log.exception("error closing provider %s", p.name)

    # ---- workers -----------------------------------------------------------------------------
    async def _worker(self) -> None:
        while True:
            send_to, data, enqueued = await self._queue.get()
            try:
                await self._process(send_to, data, enqueued)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("unexpected error processing a notification")
                self._metrics.inc("dispatch_errors")
            finally:
                self._queue.task_done()

    def _targets(self, send_to: str) -> list[tuple[str, str, object]] | None:
        """(token, device_type, extra) for every device to push to; `extra` is opaque and reaches _provider_send."""
        found = self._registry.targets(send_to, self._honor_lgo)
        return None if found is None else [(t, d, None) for t, d in found]

    async def _process(self, send_to: str, data: str, enqueued: float) -> None:
        if self._clock() - enqueued > self._ttl:
            self._metrics.inc("notify_dropped", reason="stale")
            log.info("notify to=%s dropped: queued %.0fs, older than message_ttl", short(send_to), self._clock() - enqueued)
            return
        targets = self._targets(send_to)
        if targets is None:
            self._metrics.inc("notify_untracked")  # unregistered between submit() and now
            return
        if not targets:
            self._metrics.inc("notify_suppressed")
            return
        if len(targets) == 1:
            token, dtype, extra = targets[0]
            await self._deliver(send_to, token, dtype, data, extra)
        else:
            await asyncio.gather(*(self._deliver(send_to, t, d, data, x) for t, d, x in targets))

    async def _provider_send(self, provider: Provider, send_to: str, token: str, data: str, extra: object) -> Result:
        """The one place a push is handed to a provider. Secure mode overrides it to encrypt per device."""
        return await provider.send(token, data)

    async def _deliver(self, send_to: str, token: str, device_type: str, data: str, extra: object = None) -> None:
        provider = self._by_type.get(device_type)
        if provider is None:
            self._metrics.inc("push", provider="none", result="no_provider")
            log.info("push to=%s device=%s token=%s: no provider for this device type",
                     short(send_to), device_type, short(token))
            return
        name = provider.name
        breaker = self._breakers[name]

        for attempt in range(self._max_attempts):
            if not breaker.allow():
                self._metrics.inc("push", provider=name, result="shed")
                log.info("push to=%s provider=%s token=%s: shed, circuit breaker open", short(send_to), name, short(token))
                return
            try:
                async with self._sems[name]:
                    result = await asyncio.wait_for(
                        self._provider_send(provider, send_to, token, data, extra), self._send_timeout
                    )
            except TimeoutError:
                result = Result.RETRY
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("provider %s raised", name)
                result = Result.RETRY

            # The provider answered unless it asked for a retry; OK/INVALID_TOKEN/FAIL all prove it's up.
            breaker.record(result is not Result.RETRY)
            self._metrics.inc("push", provider=name, result=result.value)
            log.info("push to=%s provider=%s device=%s token=%s result=%s attempt=%d/%d",
                     short(send_to), name, device_type, short(token), result.value, attempt + 1, self._max_attempts)

            if result is Result.OK or result is Result.FAIL:
                return
            if result is Result.INVALID_TOKEN:
                self._prune(token)
                return
            if attempt + 1 < self._max_attempts:
                delay = min(self._backoff_max, self._backoff_base * 2**attempt) * (0.5 + 0.5 * self._rng())
                await self._sleep(delay)
        self._metrics.inc("push", provider=name, result="gave_up")
        log.warning("push to=%s provider=%s token=%s: gave up after %d attempts",
                    short(send_to), name, short(token), self._max_attempts)

    def _prune(self, token: str) -> None:
        now = self._clock()
        while self._prunes and now - self._prunes[0] > 60.0:
            self._prunes.popleft()
        if len(self._prunes) >= self._prune_cap:
            self._metrics.inc("push_prune_suppressed")
            if len(self._prunes) == self._prune_cap:
                log.error(
                    "%d device removals in the last minute: suppressing further removals. "
                    "If this is not a real mass-uninstall, check provider configuration (sandbox vs production?)",
                    self._prune_cap,
                )
                self._prunes.append(now)  # log once per window
            return
        self._prunes.append(now)
        if self._registry.remove_token(token) is not None:
            self._metrics.inc("push_pruned")
            log.info("device removed: provider reported token=%s invalid", short(token))
