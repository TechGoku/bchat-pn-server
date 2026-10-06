"""In-memory registry of devices and closed groups. This is the hot path: every lookup is a dict hit.

Owned by the event-loop thread (no locks). Every mutation is also emitted to `sink` as a tuple so a
write-behind store can persist it; the registry itself never touches disk.

Sink operations:
    ("device", token, account, device_type, legacy_groups_only)   upsert one device
    ("device_del", token)                                          remove one device
    ("account_lgo", account, flag)                                 set legacy_groups_only for an account
    ("member", group, member) / ("member_del", group, member)
"""

from __future__ import annotations

from typing import Callable, Iterable

DEVICE_TYPES = frozenset({"ios", "android", "huawei"})

Op = tuple
Sink = Callable[[Op], None]


class _Account:
    __slots__ = ("tokens", "lgo")

    def __init__(self, lgo: bool = False) -> None:
        self.tokens: dict[str, str] = {}  # token -> device type; insertion order = recency
        self.lgo = lgo


class Registry:
    def __init__(
        self,
        *,
        max_devices: int = 10,
        max_group_members: int = 500,
        sink: Sink | None = None,
    ) -> None:
        self._max_devices = max_devices
        self._max_members = max_group_members
        self._sink = sink
        self._accounts: dict[str, _Account] = {}
        self._token_owner: dict[str, str] = {}
        self._groups: dict[str, set[str]] = {}

    # ---- loading (startup only; does not emit to the sink) -----------------------------------
    def load(self, devices: Iterable[tuple[str, str, str, int]], members: Iterable[tuple[str, str]]) -> None:
        for token, account, device_type, lgo in devices:
            acct = self._accounts.get(account)
            if acct is None:
                acct = self._accounts[account] = _Account(bool(lgo))
            acct.lgo = acct.lgo or bool(lgo)
            acct.tokens[token] = device_type
            self._token_owner[token] = account
        for group, member in members:
            self._groups.setdefault(group, set()).add(member)

    # ---- emit --------------------------------------------------------------------------------
    def _emit(self, op: Op) -> None:
        if self._sink is not None:
            self._sink(op)

    # ---- devices -----------------------------------------------------------------------------
    def register(self, token: str, account: str, device_type: str, legacy_groups_only: bool = False) -> None:
        owner = self._token_owner.get(token)
        if owner is not None and owner != account:
            self._drop_token(token)  # a token belongs to exactly one account (device changed hands)

        acct = self._accounts.get(account)
        if acct is None:
            acct = self._accounts[account] = _Account(legacy_groups_only)
        acct.tokens.pop(token, None)  # re-insert at the end: most recently registered
        acct.tokens[token] = device_type
        self._token_owner[token] = account
        acct.lgo = legacy_groups_only
        self._emit(("device", token, account, device_type, legacy_groups_only))
        if len(acct.tokens) > 1:
            # keep every row of this account consistent with the flag
            self._emit(("account_lgo", account, legacy_groups_only))

        while len(acct.tokens) > self._max_devices:  # evict the oldest device, never refuse a new one
            oldest = next(iter(acct.tokens))
            self._drop_token(oldest)

    def unregister(self, token: str) -> str | None:
        """Remove a token. Returns the account it belonged to, or None if it was unknown."""
        owner = self._token_owner.get(token)
        if owner is None:
            return None
        self._drop_token(token)
        return owner

    remove_token = unregister  # used by the dispatcher when a provider says a token is dead

    def _drop_token(self, token: str) -> None:
        owner = self._token_owner.pop(token, None)
        if owner is None:
            return
        acct = self._accounts.get(owner)
        if acct is not None:
            acct.tokens.pop(token, None)
            if not acct.tokens:
                del self._accounts[owner]
        self._emit(("device_del", token))

    # ---- closed groups -----------------------------------------------------------------------
    def subscribe_group(self, group: str, member: str) -> bool:
        """Add `member` to `group`. Returns False only if the group is full."""
        members = self._groups.get(group)
        if members is None:
            members = self._groups[group] = set()
        if member in members:
            return True
        if len(members) >= self._max_members:
            if not members:
                del self._groups[group]
            return False
        members.add(member)
        self._emit(("member", group, member))
        return True

    def unsubscribe_group(self, group: str, member: str) -> None:
        members = self._groups.get(group)
        if members is None or member not in members:
            return
        members.discard(member)
        if not members:
            del self._groups[group]
        self._emit(("member_del", group, member))

    # ---- lookups -----------------------------------------------------------------------------
    def knows(self, send_to: str) -> bool:
        """Cheap O(1) check used to short-circuit notifications for recipients nobody registered."""
        return send_to in self._accounts or send_to in self._groups

    def targets(self, send_to: str, honor_legacy_groups_only: bool = False) -> list[tuple[str, str]] | None:
        """Devices to push to for `send_to`, as (token, device_type) pairs.

        None   -> nobody registered for this id
        []     -> registered, but nothing to send (suppressed by legacy_groups_only, or no devices)
        """
        acct = self._accounts.get(send_to)
        if acct is not None:
            if honor_legacy_groups_only and acct.lgo:
                return []
            return list(acct.tokens.items())
        members = self._groups.get(send_to)
        if members is not None:
            out: list[tuple[str, str]] = []
            for member in members:
                m = self._accounts.get(member)
                if m is not None:
                    out.extend(m.tokens.items())
            return out
        return None

    # ---- introspection -----------------------------------------------------------------------
    @property
    def account_count(self) -> int:
        return len(self._accounts)

    @property
    def token_count(self) -> int:
        return len(self._token_owner)

    @property
    def group_count(self) -> int:
        return len(self._groups)

    def tokens_of(self, account: str) -> dict[str, str]:
        acct = self._accounts.get(account)
        return dict(acct.tokens) if acct else {}

    def members_of(self, group: str) -> set[str]:
        return set(self._groups.get(group, ()))
