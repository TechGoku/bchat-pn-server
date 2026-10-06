"""Registry for secure mode.

Differences from the normal registry, and only these:

  * Account and group ids are replaced by keyed hashes before they are stored or looked up, so neither
    memory-resident state nor the database holds a raw id.
  * A device is either *signed* (registered through a verified `/subscribe`, with its own push key) or
    *unsigned* (registered through the legacy endpoints). Only signed devices receive 1:1 pushes; unsigned
    ones are kept only for legacy closed groups. An unsigned registration can never replace, re-home or
    evict a signed one, so nobody can hijack or knock out someone's pushes without their signature.
  * Every registration carries a timestamp, so stale ones can be expired.

Sink operations (consumed by SecureStore):
    ("sdevice", token, account_key, device_type, enc_key | None, want_data, seen)   upsert one device
    ("device_del", token)                                                           remove one device
    ("member", group_key, member_key) / ("member_del", group_key, member_key)
"""

from __future__ import annotations

import time
from typing import Callable, Iterable

from ..registry import Op, Registry, Sink
from .crypto import Keyer


class SecureInfo:
    __slots__ = ("enc_key", "want_data")

    def __init__(self, enc_key: bytes, want_data: bool) -> None:
        self.enc_key = enc_key
        self.want_data = want_data


class SecureRegistry(Registry):
    def __init__(
        self,
        keyer: Keyer,
        *,
        max_devices: int = 10,
        max_group_members: int = 500,
        sink: Sink | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        super().__init__(max_devices=max_devices, max_group_members=max_group_members, sink=sink)
        self._k = keyer
        self._clock = clock
        self._secure: dict[str, SecureInfo] = {}  # token -> push key, for signed devices only
        self._seen: dict[str, int] = {}  # token -> when it last registered (epoch seconds), all devices

    # ---- loading -----------------------------------------------------------------------------
    def load(self, devices: Iterable[tuple], members: Iterable[tuple[str, str]]) -> None:  # type: ignore[override]
        rows = list(devices)  # (token, account_key, device_type, enc_key | None, want_data, seen)
        super().load(((t, a, d, 0) for t, a, d, *_ in rows), members)
        for token, _a, _d, enc_key, want_data, seen in rows:
            self._seen[token] = int(seen)
            if enc_key is not None:
                self._secure[token] = SecureInfo(enc_key, bool(want_data))

    # ---- emit: the normal-mode device ops are replaced by "sdevice" --------------------------
    def _emit(self, op: Op) -> None:
        if op[0] in ("device", "account_lgo"):
            return
        super()._emit(op)

    # ---- devices -----------------------------------------------------------------------------
    def _make_room(self, account_key: str, token: str, *, signed: bool) -> bool:
        """Free a slot for `token` under the per-account cap. Unsigned devices go first; an unsigned
        registration is refused rather than allowed to evict a signed device."""
        acct = self._accounts.get(account_key)
        if acct is None or token in acct.tokens:
            return True
        while len(acct.tokens) >= self._max_devices:
            victim = next((t for t in acct.tokens if t not in self._secure), None)
            if victim is None:
                if not signed:
                    return False
                victim = next(iter(acct.tokens))
            self._drop_token(victim)
            if self._accounts.get(account_key) is None:
                break
        return True

    def register(self, token: str, account: str, device_type: str, legacy_groups_only: bool = False) -> bool:  # type: ignore[override]
        """Unsigned registration (legacy endpoints). Returns False if it was refused."""
        if token in self._secure:
            return self._token_owner.get(token) == self._k(account)  # no-op for the owner; refused otherwise
        key = self._k(account)
        if not self._make_room(key, token, signed=False):
            return False
        super().register(token, key, device_type, False)
        now = int(self._clock())
        self._seen[token] = now
        self._emit(("sdevice", token, key, device_type, None, True, now))
        return True

    def register_signed(
        self, token: str, account: str, device_type: str, enc_key: bytes, want_data: bool = True
    ) -> bool:
        """Signed registration. Returns True if it renewed an existing signed device, False if it is new."""
        key = self._k(account)
        renewed = token in self._secure and self._token_owner.get(token) == key
        self._make_room(key, token, signed=True)
        super().register(token, key, device_type, False)  # re-homes the token if another account held it
        now = int(self._clock())
        self._secure[token] = SecureInfo(enc_key, want_data)
        self._seen[token] = now
        self._emit(("sdevice", token, key, device_type, enc_key, want_data, now))
        return renewed

    def unregister(self, token: str) -> str | None:
        """Unsigned removal (legacy endpoint): never removes a signed device."""
        if token in self._secure:
            return None
        return super().unregister(token)

    def remove_token(self, token: str) -> str | None:  # type: ignore[override]
        """Internal removal (a provider said the token is dead): removes any device."""
        return Registry.unregister(self, token)

    def unregister_signed(self, token: str, account: str) -> bool:
        """Signed removal: only if the token currently belongs to the signing account."""
        if self._token_owner.get(token) != self._k(account):
            return False
        self._drop_token(token)
        return True

    def _drop_token(self, token: str) -> None:
        self._secure.pop(token, None)
        self._seen.pop(token, None)
        super()._drop_token(token)

    def expire(self, max_age_seconds: float) -> int:
        """Remove every device that has not registered within `max_age_seconds`. Returns how many."""
        cutoff = self._clock() - max_age_seconds
        stale = [t for t, seen in self._seen.items() if seen < cutoff]
        for token in stale:
            self._drop_token(token)
        return len(stale)

    # ---- closed groups: same logic, keyed ids -------------------------------------------------
    def subscribe_group(self, group: str, member: str) -> bool:
        return super().subscribe_group(self._k(group), self._k(member))

    def unsubscribe_group(self, group: str, member: str) -> None:
        super().unsubscribe_group(self._k(group), self._k(member))

    # ---- lookups -----------------------------------------------------------------------------
    def knows(self, send_to: str) -> bool:
        return super().knows(self._k(send_to))

    def targets_ex(self, send_to: str) -> list[tuple[str, str, SecureInfo | None]] | None:
        """Devices to push to, as (token, device_type, push key or None).

        None -> nobody registered for this id.  [] -> registered but nothing to send.
        A 1:1 recipient is reached only through signed devices; a group reaches every member device
        (signed ones with an encrypted push, legacy ones as before).
        """
        key = self._k(send_to)
        acct = self._accounts.get(key)
        if acct is not None:
            return [(t, d, self._secure[t]) for t, d in acct.tokens.items() if t in self._secure]
        members = self._groups.get(key)
        if members is not None:
            out: list[tuple[str, str, SecureInfo | None]] = []
            for member in members:
                m = self._accounts.get(member)
                if m is not None:
                    out.extend((t, d, self._secure.get(t)) for t, d in m.tokens.items())
            return out
        return None

    def targets(self, send_to: str, honor_legacy_groups_only: bool = False) -> list[tuple[str, str]] | None:
        found = self.targets_ex(send_to)
        return None if found is None else [(t, d) for t, d, _ in found]

    # ---- introspection -----------------------------------------------------------------------
    @property
    def signed_count(self) -> int:
        return len(self._secure)

    def tokens_of(self, account: str) -> dict[str, str]:
        return super().tokens_of(self._k(account))

    def members_of(self, group: str) -> set[str]:
        return super().members_of(self._k(group))
