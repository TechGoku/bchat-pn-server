"""Durable storage: SQLite in WAL mode behind a write-behind queue.

The event loop never waits on disk. Mutations are queued with `submit()`; one writer thread groups
them into a single transaction every `commit_interval` seconds (or `max_batch` ops), so the crash
window is ~50 ms instead of the legacy server's 3 minutes. `close()` drains everything first.

A failed transaction is rolled back and retried with backoff rather than dropped.
"""

from __future__ import annotations

import logging
import queue
import sqlite3
import threading
import time

log = logging.getLogger("bchatpn.store")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS device (
    token       TEXT PRIMARY KEY,
    account     TEXT NOT NULL,
    device_type TEXT NOT NULL,
    lgo         INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS device_account ON device(account);
CREATE TABLE IF NOT EXISTS group_member (
    grp    TEXT NOT NULL,
    member TEXT NOT NULL,
    PRIMARY KEY (grp, member)
) WITHOUT ROWID;
"""


class _Marker:
    """Queue item used by flush(): set once everything submitted before it is committed."""

    __slots__ = ("event",)

    def __init__(self) -> None:
        self.event = threading.Event()


_STOP = object()


def _connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, isolation_level=None, timeout=5.0)  # autocommit; we manage BEGIN/COMMIT
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")  # durable across process crashes; WAL keeps it consistent
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


class Store:
    def __init__(self, path: str, *, commit_interval: float = 0.05, max_batch: int = 2000) -> None:
        self._path = path
        self._interval = commit_interval
        self._max_batch = max_batch
        self._q: queue.SimpleQueue[object] = queue.SimpleQueue()
        self._thread: threading.Thread | None = None
        self._stopping = threading.Event()
        self.errors = 0
        self.committed_ops = 0
        self.commits = 0

    # ---- startup -----------------------------------------------------------------------------
    def load(self) -> tuple[list[tuple[str, str, str, int]], list[tuple[str, str]]]:
        """Create the schema if needed and return (devices oldest-first, group members)."""
        conn = _connect(self._path)
        try:
            conn.executescript(_SCHEMA)
            devices = conn.execute(
                "SELECT token, account, device_type, lgo FROM device ORDER BY rowid"
            ).fetchall()
            members = conn.execute("SELECT grp, member FROM group_member").fetchall()
        finally:
            conn.close()
        return devices, members

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="bchatpn-store", daemon=True)
        self._thread.start()

    # ---- producer side (any thread, never blocks) --------------------------------------------
    def submit(self, op: tuple) -> None:
        self._q.put(op)

    @property
    def pending(self) -> int:
        return self._q.qsize()

    @property
    def alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def flush(self, timeout: float = 5.0) -> bool:
        """Block until everything submitted so far is committed. Returns False on timeout."""
        marker = _Marker()
        self._q.put(marker)
        return marker.event.wait(timeout)

    def close(self, timeout: float = 10.0) -> bool:
        """Drain and stop. Returns True if the writer finished cleanly within `timeout`."""
        if self._thread is None:
            return True
        self._q.put(_STOP)
        self._thread.join(timeout)
        clean = not self._thread.is_alive()
        if not clean:
            self._stopping.set()
            log.error("store writer did not finish within %.1fs; %d ops may be lost", timeout, self.pending)
        return clean

    # ---- writer thread -----------------------------------------------------------------------
    def _run(self) -> None:
        conn = _connect(self._path)
        try:
            stop = False
            while not stop:
                first = self._q.get()
                batch = [first]
                deadline = time.monotonic() + self._interval
                while len(batch) < self._max_batch and first is not _STOP:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    try:
                        item = self._q.get(timeout=remaining)
                    except queue.Empty:
                        break
                    batch.append(item)
                    if item is _STOP:
                        break
                stop = any(i is _STOP for i in batch)
                ops = [i for i in batch if isinstance(i, tuple)]
                if ops:
                    self._commit(conn, ops)
                for item in batch:
                    if isinstance(item, _Marker):
                        item.event.set()
        finally:
            conn.close()

    def _commit(self, conn: sqlite3.Connection, ops: list[tuple]) -> None:
        attempt = 0
        while True:
            try:
                conn.execute("BEGIN IMMEDIATE")
                for op in ops:
                    self._apply(conn, op)
                conn.execute("COMMIT")
                self.committed_ops += len(ops)
                self.commits += 1
                return
            except sqlite3.Error as e:
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                self.errors += 1
                attempt += 1
                log.error("store commit failed (attempt %d, %d ops): %s", attempt, len(ops), e)
                if self._stopping.is_set():
                    return
                time.sleep(min(5.0, 0.2 * 2**attempt))

    @staticmethod
    def _apply(conn: sqlite3.Connection, op: tuple) -> None:
        kind = op[0]
        if kind == "device":
            conn.execute(
                "INSERT OR REPLACE INTO device(token, account, device_type, lgo) VALUES (?,?,?,?)",
                (op[1], op[2], op[3], 1 if op[4] else 0),
            )
        elif kind == "device_del":
            conn.execute("DELETE FROM device WHERE token=?", (op[1],))
        elif kind == "account_lgo":
            conn.execute("UPDATE device SET lgo=? WHERE account=?", (1 if op[2] else 0, op[1]))
        elif kind == "member":
            conn.execute("INSERT OR IGNORE INTO group_member(grp, member) VALUES (?,?)", (op[1], op[2]))
        elif kind == "member_del":
            conn.execute("DELETE FROM group_member WHERE grp=? AND member=?", (op[1], op[2]))
        else:
            # A malformed op must never wedge the writer in a retry loop: drop it loudly.
            log.error("dropping unknown store op %r", kind)
