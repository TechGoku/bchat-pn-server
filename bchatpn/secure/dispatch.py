"""Dispatcher for secure mode: identical retry, breaker and pruning logic; only the payload differs.

A signed device gets the per-device encrypted push (`enc_payload`) built with its own key; an unsigned
legacy device (only ever a closed-group member in secure mode) gets the plain legacy push as before.
"""

from __future__ import annotations

import logging

from ..dispatch import Dispatcher
from ..providers.base import Provider, Result
from .crypto import build_enc_payload
from .registry import SecureInfo, SecureRegistry

log = logging.getLogger("bchatpn.dispatch")


class SecureDispatcher(Dispatcher):
    _registry: SecureRegistry

    def _targets(self, send_to: str):  # type: ignore[override]
        return self._registry.targets_ex(send_to)

    async def _provider_send(self, provider: Provider, send_to: str, token: str, data: str, extra: object) -> Result:
        if not isinstance(extra, SecureInfo):
            return await provider.send(token, data)  # legacy device in a closed group
        send_encrypted = getattr(provider, "send_encrypted", None)
        if send_encrypted is None:
            log.error("provider %s cannot send encrypted pushes; not sending", provider.name)
            return Result.FAIL
        try:
            payload = build_enc_payload(send_to, data, extra.enc_key, extra.want_data)
        except ValueError as e:
            log.warning("not sending: %s", e)
            return Result.FAIL
        return await send_encrypted(token, payload)
