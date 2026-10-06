"""Wires every component into one process and owns startup/shutdown order.

Nothing else needs to run: no database server, no message broker, no bot, no separate notifier
processes, no web-server front end. `python -m bchatpn serve` is the whole deployment.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from .api import Api
from .config import Config, ConfigError
from .dispatch import Dispatcher
from .httpd import HttpServer, Limits
from .obs import Metrics, make_admin_handler
from .onion import OnionError, OnionServer, load_private_key
from .providers.base import Provider
from .registry import Registry
from .store import Store

log = logging.getLogger("bchatpn")


def build_providers(cfg: Config) -> list[Provider]:
    providers: list[Provider] = []
    if cfg.apns_cert_file:
        from .providers.apns import ApnsProvider, HttpxTransport

        providers.append(
            ApnsProvider(
                HttpxTransport(cfg.apns_cert_file, cfg.apns_key_file or None),
                topic=cfg.apns_topic,
                sandbox=cfg.apns_sandbox,
            )
        )
    if cfg.fcm_credentials_file:
        from .providers.fcm import FcmConfigError, FcmProvider, ServiceAccount, UrllibTransport

        try:
            account = ServiceAccount.load(cfg.fcm_credentials_file)
        except FcmConfigError as e:
            raise ConfigError(str(e)) from None
        providers.append(FcmProvider(account, UrllibTransport()))
    if cfg.log_only:
        from .providers.logonly import LogOnlyProvider

        # A dry-run provider only takes the device types no real provider serves.
        taken = frozenset().union(*(p.device_types for p in providers)) if providers else frozenset()
        providers.append(LogOnlyProvider(frozenset({"ios", "android", "huawei"}) - taken))
    return providers


class App:
    def __init__(self, cfg: Config, *, providers: list[Provider] | None = None) -> None:
        self.cfg = cfg
        self.metrics = Metrics()
        try:
            private_key = load_private_key(cfg.key_file)
            self.onion = OnionServer(private_key)
        except OnionError as e:
            raise ConfigError(str(e)) from None

        dispatcher_cls, api_cls = Dispatcher, Api
        if cfg.secure_mode:
            from .secure import wiring  # loaded only in secure mode

            self.store, self.registry, dispatcher_cls, api_cls = wiring.build(cfg, private_key)
        else:
            self.store = Store(cfg.db_path, commit_interval=cfg.commit_interval)
            self.registry = Registry(
                max_devices=cfg.max_devices_per_account,
                max_group_members=cfg.max_group_members,
                sink=self.store.submit,
            )
        self.providers = providers if providers is not None else build_providers(cfg)
        self.dispatcher = dispatcher_cls(
            self.registry,
            self.providers,
            self.metrics,
            queue_size=cfg.queue_size,
            workers=cfg.workers,
            max_attempts=cfg.max_attempts,
            backoff_base=cfg.backoff_base,
            backoff_max=cfg.backoff_max,
            send_timeout=cfg.send_timeout,
            message_ttl=cfg.message_ttl,
            breaker_threshold=cfg.breaker_threshold,
            breaker_cooldown=cfg.breaker_cooldown,
            prune_per_minute=cfg.prune_per_minute,
            honor_legacy_groups_only=cfg.honor_legacy_groups_only,
        )
        self.api = api_cls(self.onion, self.registry, self.dispatcher, self.metrics, cfg)

        limits = Limits(
            max_header_bytes=cfg.max_header_bytes,
            max_body_bytes=cfg.max_body_bytes,
            read_timeout=cfg.read_timeout,
            handler_timeout=cfg.handler_timeout,
            max_connections=cfg.max_connections,
        )
        self.public = HttpServer(
            self.api.handle, cfg.listen_host, cfg.listen_port, limits, name="public", metrics=self.metrics
        )
        self.admin: HttpServer | None = None
        if cfg.admin_enabled:
            self.admin = HttpServer(
                make_admin_handler(self.metrics, self._health, cfg.admin_token),
                cfg.admin_host,
                cfg.admin_port,
                Limits(max_header_bytes=8192, max_body_bytes=1024, read_timeout=5.0, handler_timeout=5.0, max_connections=64),
                name="admin",
                allowed_methods=("GET",),
            )
        self._running = False
        self._expiry: asyncio.Task | None = None

        m = self.metrics
        if cfg.secure_mode:
            m.gauge("signed_devices", lambda: self.registry.signed_count)  # type: ignore[attr-defined]
        m.gauge("accounts", lambda: self.registry.account_count)
        m.gauge("device_tokens", lambda: self.registry.token_count)
        m.gauge("closed_groups", lambda: self.registry.group_count)
        m.gauge("store_pending", lambda: self.store.pending)
        m.gauge("store_errors", lambda: self.store.errors)
        m.gauge("http_connections", lambda: self.public.active_connections)

    def _health(self) -> tuple[bool, dict[str, Any]]:
        ok = self._running and self.store.alive
        return ok, {
            "queue": self.dispatcher.depth,
            "accounts": self.registry.account_count,
            "store_pending": self.store.pending,
            "store_errors": self.store.errors,
        }

    async def start(self) -> None:
        devices, members = self.store.load()  # also creates the schema; fails fast if the DB is unusable
        self.registry.load(devices, members)
        log.info(
            "loaded %d accounts / %d devices / %d groups; onion public key %s",
            self.registry.account_count,
            self.registry.token_count,
            self.registry.group_count,
            self.onion.public_key_hex,
        )
        self.store.start()
        await self.dispatcher.start()
        await self.public.start()
        if self.admin is not None:
            await self.admin.start()
        if self.cfg.secure_mode and self.cfg.registration_ttl_days > 0:
            self._expiry = asyncio.create_task(self._expire_loop(), name="bchatpn-expiry")
        self._running = True

    async def _expire_loop(self) -> None:
        """Secure mode: drop registrations that were not renewed within registration_ttl_days (hourly sweep)."""
        max_age = self.cfg.registration_ttl_days * 86400.0
        while True:
            try:
                removed = self.registry.expire(max_age)  # type: ignore[attr-defined]
                if removed:
                    self.metrics.inc("registrations_expired", removed)
                    log.info("expired %d registrations not renewed in %d days", removed, self.cfg.registration_ttl_days)
            except Exception:
                log.exception("registration expiry sweep failed")
            await asyncio.sleep(3600)

    async def stop(self) -> None:
        """Stop accepting, finish in-flight requests and queued pushes, flush the store."""
        self._running = False
        if self._expiry is not None:
            self._expiry.cancel()
        await self.public.stop(self.cfg.shutdown_grace)
        await self.dispatcher.stop(self.cfg.shutdown_grace)
        if self.admin is not None:
            await self.admin.stop(1.0)
        self.store.close(timeout=self.cfg.shutdown_grace)
        log.info("stopped")
