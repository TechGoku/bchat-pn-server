import os
import sqlite3
import subprocess
import sys
import tempfile
import textwrap
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import logging
logging.disable(logging.CRITICAL)  # fault-injection tests log on purpose

from bchatpn.registry import Registry
from bchatpn.store import Store

A, B, C = "bd" + "aa" * 32, "bd" + "bb" * 32, "bd" + "cc" * 32
G = "bd" + "99" * 32


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.ops = []
        self.reg = Registry(max_devices=3, max_group_members=2, sink=self.ops.append)

    def test_register_and_lookup(self):
        self.reg.register("t1", A, "ios")
        self.reg.register("t2", A, "android")
        self.assertEqual(self.reg.targets(A), [("t1", "ios"), ("t2", "android")])
        self.assertTrue(self.reg.knows(A))
        self.assertFalse(self.reg.knows(B))
        self.assertIsNone(self.reg.targets(B))

    def test_a_token_belongs_to_one_account(self):
        self.reg.register("t1", A, "ios")
        self.reg.register("t1", B, "ios")  # device changed hands
        self.assertFalse(self.reg.knows(A))  # A had only that token, so it is gone
        self.assertEqual(self.reg.tokens_of(B), {"t1": "ios"})

    def test_reregistering_refreshes_recency_and_device_type(self):
        for t in ("t1", "t2", "t3"):
            self.reg.register(t, A, "android")
        self.reg.register("t1", A, "ios")  # now t2 is the oldest
        self.reg.register("t4", A, "android")  # over the cap of 3: t2 goes
        self.assertEqual(list(self.reg.tokens_of(A)), ["t3", "t1", "t4"])
        self.assertEqual(self.reg.tokens_of(A)["t1"], "ios")

    def test_device_cap_evicts_oldest_and_never_refuses(self):
        for i in range(5):
            self.reg.register(f"t{i}", A, "android")
        self.assertEqual(list(self.reg.tokens_of(A)), ["t2", "t3", "t4"])
        self.assertEqual(self.reg.token_count, 3)
        self.assertIn(("device_del", "t0"), self.ops)
        self.assertIn(("device_del", "t1"), self.ops)

    def test_unregister(self):
        self.reg.register("t1", A, "ios")
        self.assertEqual(self.reg.unregister("t1"), A)
        self.assertIsNone(self.reg.unregister("t1"))
        self.assertFalse(self.reg.knows(A))
        self.assertEqual(self.reg.account_count, 0)

    def test_groups(self):
        self.reg.register("ta", A, "ios")
        self.reg.register("tb", B, "android")
        self.assertTrue(self.reg.subscribe_group(G, A))
        self.assertTrue(self.reg.subscribe_group(G, B))
        self.assertTrue(self.reg.subscribe_group(G, A))  # idempotent
        self.assertFalse(self.reg.subscribe_group(G, C))  # full (cap 2)
        self.assertCountEqual(self.reg.targets(G), [("ta", "ios"), ("tb", "android")])
        self.reg.unsubscribe_group(G, A)
        self.assertEqual(self.reg.targets(G), [("tb", "android")])
        self.reg.unsubscribe_group(G, B)
        self.assertFalse(self.reg.knows(G))  # empty groups do not linger
        self.reg.unsubscribe_group(G, B)  # unknown: no-op, no error

    def test_group_members_without_devices_yield_nothing_to_send(self):
        self.reg.subscribe_group(G, A)
        self.assertEqual(self.reg.targets(G), [])

    def test_a_full_group_that_got_no_members_is_not_left_behind(self):
        reg = Registry(max_group_members=1)
        self.assertTrue(reg.subscribe_group(G, A))
        self.assertFalse(reg.subscribe_group(G, B))
        self.assertEqual(reg.members_of(G), {A})

    def test_account_wins_over_group_for_the_same_id(self):
        self.reg.register("t1", G, "ios")
        self.reg.subscribe_group(G, A)
        self.assertEqual(self.reg.targets(G), [("t1", "ios")])

    def test_legacy_groups_only_flag(self):
        self.reg.register("t1", A, "android", legacy_groups_only=True)
        self.assertEqual(self.reg.targets(A, honor_legacy_groups_only=False), [("t1", "android")])
        self.assertEqual(self.reg.targets(A, honor_legacy_groups_only=True), [])
        self.reg.register("t1", A, "android", legacy_groups_only=False)
        self.assertEqual(self.reg.targets(A, honor_legacy_groups_only=True), [("t1", "android")])

    def test_load_does_not_emit(self):
        self.reg.load([("t1", A, "ios", 1), ("t2", A, "android", 0)], [(G, A)])
        self.assertEqual(self.ops, [])
        self.assertEqual(self.reg.targets(A, honor_legacy_groups_only=True), [])  # flag survives a load
        self.assertEqual(self.reg.members_of(G), {A})


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.db = os.path.join(self.dir.name, "t.db")

    def populate(self, store, n=3):
        reg = Registry(max_devices=10, sink=store.submit)
        for i in range(n):
            reg.register(f"tok{i:04d}", A, "android" if i % 2 else "ios", legacy_groups_only=True)
        reg.subscribe_group(G, A)
        reg.subscribe_group(G, B)
        reg.unsubscribe_group(G, B)
        reg.unregister("tok0001")
        return reg

    def test_roundtrip_preserves_everything_including_recency_order(self):
        s = Store(self.db)
        s.load()
        s.start()
        self.populate(s)
        self.assertTrue(s.close())

        s2 = Store(self.db)
        devices, members = s2.load()
        reg = Registry(max_devices=10)
        reg.load(devices, members)
        self.assertEqual(list(reg.tokens_of(A)), ["tok0000", "tok0002"])
        self.assertEqual(reg.members_of(G), {A})
        self.assertEqual(reg.targets(A, honor_legacy_groups_only=True), [])  # lgo persisted

    def test_flush_makes_data_visible_to_an_independent_reader(self):
        s = Store(self.db)
        s.load()
        s.start()
        self.addCleanup(s.close)
        self.populate(s)
        self.assertTrue(s.flush())
        conn = sqlite3.connect(self.db)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM device").fetchone()[0], 2)
        conn.close()

    def test_a_hard_crash_after_flush_loses_nothing(self):
        script = textwrap.dedent(f"""
            import os, sys
            sys.path.insert(0, {os.path.join(os.path.dirname(__file__), '..')!r})
            from bchatpn.store import Store
            from bchatpn.registry import Registry
            s = Store({self.db!r}); s.load(); s.start()
            reg = Registry(max_devices=1000, sink=s.submit)
            for i in range(500):
                reg.register("tok%04d" % i, "bd" + "%064x" % i, "android")
            assert s.flush(5.0)
            os._exit(1)   # no close(), no atexit: a crash
        """)
        r = subprocess.run([sys.executable, "-c", script], capture_output=True, timeout=30)
        self.assertEqual(r.returncode, 1, r.stderr)
        devices, _ = Store(self.db).load()
        self.assertEqual(len(devices), 500)

    def test_writes_are_grouped_into_few_transactions(self):
        s = Store(self.db, commit_interval=0.2)
        s.load()
        reg = Registry(max_devices=100_000, sink=s.submit)
        for i in range(3000):  # queue everything before the writer starts
            reg.register(f"tok{i:05d}", "bd" + f"{i:064x}", "android")
        s.start()
        self.assertTrue(s.close())
        self.assertEqual(s.committed_ops, 3000)
        self.assertLessEqual(s.commits, 3)  # max_batch=2000 -> 2 commits, never 3000

    def test_a_failed_transaction_is_retried_not_dropped(self):
        s = Store(self.db)
        s.load()
        real = Store._apply
        calls = {"n": 0}

        def flaky(conn, op):
            calls["n"] += 1
            if calls["n"] == 1:
                raise sqlite3.OperationalError("database is locked")
            real(conn, op)

        s._apply = flaky  # instance override
        s.start()
        s.submit(("device", "tok1", A, "ios", False))
        self.assertTrue(s.close(timeout=10))
        self.assertGreaterEqual(s.errors, 1)
        devices, _ = Store(self.db).load()
        self.assertEqual([d[0] for d in devices], ["tok1"])

    def test_a_malformed_op_cannot_wedge_the_writer(self):
        s = Store(self.db)
        s.load()
        s.start()
        s.submit(("nonsense", 1, 2))
        s.submit(("device", "tok1", A, "ios", False))
        self.assertTrue(s.close(timeout=5))
        devices, _ = Store(self.db).load()
        self.assertEqual(len(devices), 1)

    def test_close_without_start_and_double_close(self):
        s = Store(self.db)
        self.assertTrue(s.close())
        s.load()
        s.start()
        self.assertTrue(s.close())

    def test_wal_mode_is_on(self):
        s = Store(self.db)
        s.load()
        conn = sqlite3.connect(self.db)
        self.assertEqual(conn.execute("PRAGMA journal_mode").fetchone()[0].lower(), "wal")
        conn.close()


if __name__ == "__main__":
    unittest.main()
