"""Durable storage for secure mode: the same write-behind SQLite store, with different tables.

What is on disk, and what is not:
    sdevice.tid      keyed hash of the device token         (a lookup key, not the token)
    sdevice.tok      the token, authenticated-encrypted     (needed to send; unreadable without the key)
    sdevice.account  keyed hash of the account id           (never the raw id)
    sdevice.enc      the device's push key, encrypted
    sgroup_member    keyed hashes only

The keys are derived from the server key file (see crypto.SecretKeys). They protect a copied database
or backup; they do not protect against someone who has both the database and the key file, or the
running process.
"""

from __future__ import annotations

import logging
import sqlite3

from cryptography.exceptions import InvalidTag

from ..config import ConfigError
from ..store import Store, _connect
from .crypto import Sealer

log = logging.getLogger("bchatpn.store")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sdevice (
    tid         TEXT PRIMARY KEY,
    tok         BLOB NOT NULL,
    account     TEXT NOT NULL,
    device_type TEXT NOT NULL,
    enc         BLOB,
    want_data   INTEGER NOT NULL DEFAULT 1,
    seen        INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sdevice_account ON sdevice(account);
CREATE TABLE IF NOT EXISTS sgroup_member (
    grp    TEXT NOT NULL,
    member TEXT NOT NULL,
    PRIMARY KEY (grp, member)
) WITHOUT ROWID;
"""


class SecureStoreError(ConfigError):
    pass


class SecureStore(Store):
    def __init__(self, path: str, sealer: Sealer, **kw) -> None:
        super().__init__(path, **kw)
        self._sealer = sealer

    @staticmethod
    def _refuse_plaintext(conn: sqlite3.Connection) -> None:
        present = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for table in ("device", "group_member"):
            if table in present and conn.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone():
                raise SecureStoreError(
                    "this database holds plaintext registrations from normal mode, which secure mode would "
                    "leave on disk. Use a new db_path (devices re-register the next time the app opens) or "
                    "delete the old file."
                )

    def load(self):  # type: ignore[override]
        """Create the schema and return (devices oldest-first, group members), tokens and keys decrypted."""
        conn = _connect(self._path)
        try:
            self._refuse_plaintext(conn)
            conn.executescript(_SCHEMA)
            rows = conn.execute(
                "SELECT tid, tok, account, device_type, enc, want_data, seen FROM sdevice ORDER BY rowid"
            ).fetchall()
            members = conn.execute("SELECT grp, member FROM sgroup_member").fetchall()
        finally:
            conn.close()
        devices = []
        unreadable = 0
        for tid, tok, account, dtype, enc, want, seen in rows:
            try:
                token = self._sealer.unseal(tok, tid).decode()
                enc_key = self._sealer.unseal(enc, tid + ":k") if enc is not None else None
            except (InvalidTag, UnicodeDecodeError):
                unreadable += 1
                continue
            devices.append((token, account, dtype, enc_key, want, seen))
        if unreadable:
            log.error(
                "%d stored registrations could not be decrypted and were skipped: was the key file replaced? "
                "Those devices will register again the next time their app opens.",
                unreadable,
            )
        return devices, members

    def _apply(self, conn: sqlite3.Connection, op: tuple) -> None:  # type: ignore[override]
        kind = op[0]
        if kind == "sdevice":
            _, token, account, dtype, enc_key, want_data, seen = op
            tid = self._sealer.token_id(token)
            conn.execute(
                "INSERT OR REPLACE INTO sdevice(tid, tok, account, device_type, enc, want_data, seen) "
                "VALUES (?,?,?,?,?,?,?)",
                (
                    tid,
                    self._sealer.seal(token.encode(), tid),
                    account,
                    dtype,
                    self._sealer.seal(enc_key, tid + ":k") if enc_key is not None else None,
                    1 if want_data else 0,
                    seen,
                ),
            )
        elif kind == "device_del":
            conn.execute("DELETE FROM sdevice WHERE tid=?", (self._sealer.token_id(op[1]),))
        elif kind == "member":
            conn.execute("INSERT OR IGNORE INTO sgroup_member(grp, member) VALUES (?,?)", (op[1], op[2]))
        elif kind == "member_del":
            conn.execute("DELETE FROM sgroup_member WHERE grp=? AND member=?", (op[1], op[2]))
        else:
            log.error("dropping unknown store op %r", kind)
