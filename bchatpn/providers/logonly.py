"""Dry-run provider: accepts every push and sends nothing. For development, load tests, and for
running the server before push credentials exist. Must be enabled explicitly (log_only = true)."""

from __future__ import annotations

import logging

from .base import Result

log = logging.getLogger("bchatpn.logonly")


class LogOnlyProvider:
    name = "log"
    max_in_flight = 10_000

    def __init__(
        self,
        device_types: frozenset[str] = frozenset({"ios", "android", "huawei"}),
        *,
        record: bool = False,
    ) -> None:
        self.device_types = device_types
        self.count = 0
        self.sent: list[tuple[str, str]] | None = [] if record else None  # tests only: unbounded

    async def send(self, token: str, data: str) -> Result:
        self.count += 1
        if self.sent is not None:
            self.sent.append((token, data))
        log.debug("dry-run push to %s...", token[:8])
        return Result.OK

    async def send_encrypted(self, token: str, enc_payload: str) -> Result:
        self.count += 1
        if self.sent is not None:
            self.sent.append((token, enc_payload))
        log.debug("dry-run encrypted push to %s...", token[:8])
        return Result.OK

    async def aclose(self) -> None:
        pass
