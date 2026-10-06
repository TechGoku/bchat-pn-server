import asyncio
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import logging
logging.disable(logging.CRITICAL)  # fault-injection tests log on purpose

from bchatpn.dispatch import Breaker, Dispatcher
from bchatpn.obs import Metrics
from bchatpn.providers.base import Result
from bchatpn.registry import Registry

A, B, G = "bd" + "aa" * 32, "bd" + "bb" * 32, "bd" + "99" * 32


class ScriptedProvider:
    """Returns scripted Results per token; records every call."""

    def __init__(self, name="p", types=("ios", "android"), script=None, default=Result.OK, max_in_flight=100):
        self.name = name
        self.device_types = frozenset(types)
        self.max_in_flight = max_in_flight
        self.script = {k: list(v) for k, v in (script or {}).items()}
        self.default = default
        self.calls = []
        self.closed = False
        self.delay = 0.0
        self.raises = None

    async def send(self, token, data):
        self.calls.append((token, data))
        if self.raises:
            raise self.raises
        if self.delay:
            await asyncio.sleep(self.delay)
        q = self.script.get(token)
        return q.pop(0) if q else self.default

    async def aclose(self):
        self.closed = True


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


class DispatchBase(unittest.IsolatedAsyncioTestCase):
    def make(self, provider=None, *, devices=(("t1", A, "android"),), **kw):
        self.ops = []
        self.reg = Registry(max_devices=10, sink=self.ops.append)
        for tok, acct, typ in devices:
            self.reg.register(tok, acct, typ)
        self.metrics = Metrics()
        self.provider = provider or ScriptedProvider()
        self.delays = []
        self.clock = Clock()

        async def fake_sleep(d):
            self.delays.append(d)

        defaults = dict(queue_size=100, workers=4, max_attempts=4, backoff_base=0.5, backoff_max=30.0,
                        send_timeout=1.0, message_ttl=60.0, breaker_threshold=1000, breaker_cooldown=10.0,
                        sleep=fake_sleep, clock=self.clock, rng=lambda: 1.0)
        defaults.update(kw)
        self.d = Dispatcher(self.reg, [self.provider], self.metrics, **defaults)
        return self.d

    async def drain(self):
        await self.d.start()
        await self.d.stop(5.0)


class Delivery(DispatchBase):
    async def test_one_device_one_send(self):
        self.make()
        self.assertTrue(self.d.submit(A, "payload"))
        await self.drain()
        self.assertEqual(self.provider.calls, [("t1", "payload")])
        self.assertEqual(self.metrics.get("push", provider="p", result="ok"), 1)
        self.assertTrue(self.provider.closed)

    async def test_group_fans_out_to_every_member_device(self):
        self.make(devices=(("ta1", A, "ios"), ("ta2", A, "android"), ("tb", B, "android")))
        self.reg.subscribe_group(G, A)
        self.reg.subscribe_group(G, B)
        self.d.submit(G, "m")
        await self.drain()
        self.assertCountEqual([c[0] for c in self.provider.calls], ["ta1", "ta2", "tb"])

    async def test_group_fanout_is_concurrent(self):
        self.make(devices=tuple((f"t{i}", f"bd{i:064x}", "android") for i in range(20)))
        for i in range(20):
            self.reg.subscribe_group(G, f"bd{i:064x}")
        self.provider.delay = 0.05
        self.d.submit(G, "m")
        t0 = asyncio.get_running_loop().time()
        await self.drain()
        self.assertLess(asyncio.get_running_loop().time() - t0, 0.5)  # 20 sequential sends would take 1.0s
        self.assertEqual(len(self.provider.calls), 20)

    async def test_unregistered_recipient_is_counted_not_sent(self):
        self.make()
        self.d.submit(B, "m")
        await self.drain()
        self.assertEqual(self.provider.calls, [])
        self.assertEqual(self.metrics.get("notify_untracked"), 1)

    async def test_device_type_without_a_provider(self):
        self.make(devices=(("t1", A, "huawei"),))
        self.d.submit(A, "m")
        await self.drain()
        self.assertEqual(self.metrics.get("push", provider="none", result="no_provider"), 1)

    async def test_legacy_groups_only_suppression_is_optional(self):
        self.make(honor_legacy_groups_only=True)
        self.reg.register("t1", A, "android", legacy_groups_only=True)
        self.d.submit(A, "m")
        await self.drain()
        self.assertEqual(self.provider.calls, [])
        self.assertEqual(self.metrics.get("notify_suppressed"), 1)

    async def test_the_device_registered_after_submit_still_gets_the_push(self):
        self.make(devices=())
        self.d.submit(A, "m")  # nobody registered yet at submit time
        self.reg.register("late", A, "android")
        await self.drain()
        self.assertEqual(self.provider.calls, [("late", "m")])


class Retry(DispatchBase):
    async def test_transient_failures_retry_with_exponential_backoff_then_succeed(self):
        self.make(ScriptedProvider(script={"t1": [Result.RETRY, Result.RETRY, Result.OK]}))
        self.d.submit(A, "m")
        await self.drain()
        self.assertEqual(len(self.provider.calls), 3)
        self.assertEqual(self.delays, [0.5, 1.0])  # base * 2**attempt, jitter pinned to 1.0
        self.assertEqual(self.reg.targets(A), [("t1", "android")])

    async def test_backoff_is_capped_and_jittered(self):
        self.make(ScriptedProvider(default=Result.RETRY), max_attempts=6, backoff_base=1.0, backoff_max=3.0,
                  rng=lambda: 0.0)
        self.d.submit(A, "m")
        await self.drain()
        self.assertEqual(self.delays, [0.5, 1.0, 1.5, 1.5, 1.5])  # (0.5 + 0.5*0) * min(cap, base*2**n)

    async def test_giving_up_does_not_delete_the_device(self):
        self.make(ScriptedProvider(default=Result.RETRY))
        self.d.submit(A, "m")
        await self.drain()
        self.assertEqual(len(self.provider.calls), 4)
        self.assertEqual(self.metrics.get("push", provider="p", result="gave_up"), 1)
        self.assertEqual(self.reg.targets(A), [("t1", "android")])  # the old server removed it after 3 strikes

    async def test_provider_exception_counts_as_transient(self):
        p = ScriptedProvider()
        p.raises = RuntimeError("boom")
        self.make(p, max_attempts=2)
        self.d.submit(A, "m")
        await self.drain()
        self.assertEqual(len(p.calls), 2)
        self.assertEqual(self.reg.targets(A), [("t1", "android")])

    async def test_provider_hang_is_cut_off_by_the_send_timeout(self):
        p = ScriptedProvider()
        p.delay = 5.0
        self.make(p, max_attempts=2, send_timeout=0.05)
        self.d.submit(A, "m")
        await self.drain()
        self.assertEqual(len(p.calls), 2)
        self.assertEqual(self.metrics.get("push", provider="p", result="retry"), 2)


class Verdicts(DispatchBase):
    async def test_invalid_token_removes_only_that_device_and_persists_the_removal(self):
        self.make(ScriptedProvider(script={"dead": [Result.INVALID_TOKEN]}),
                  devices=(("dead", A, "android"), ("live", A, "android")))
        self.d.submit(A, "m")
        await self.drain()
        self.assertEqual(self.reg.tokens_of(A), {"live": "android"})
        self.assertIn(("device_del", "dead"), self.ops)
        self.assertEqual(self.metrics.get("push_pruned"), 1)
        self.assertEqual(len(self.provider.calls), 2)  # no retry for the dead one

    async def test_fail_is_neither_retried_nor_pruned(self):
        self.make(ScriptedProvider(default=Result.FAIL))
        self.d.submit(A, "m")
        await self.drain()
        self.assertEqual(len(self.provider.calls), 1)
        self.assertEqual(self.reg.targets(A), [("t1", "android")])

    async def test_pruning_is_rate_capped_so_a_misconfiguration_cannot_wipe_everyone(self):
        devs = tuple((f"t{i}", f"bd{i:064x}", "android") for i in range(6))
        self.make(ScriptedProvider(default=Result.INVALID_TOKEN), devices=devs, prune_per_minute=2)
        for _, acct, _ in devs:
            self.d.submit(acct, "m")
        await self.drain()
        self.assertEqual(self.metrics.get("push_pruned"), 2)
        self.assertEqual(self.metrics.get("push_prune_suppressed"), 4)
        self.assertEqual(self.reg.token_count, 4)

    async def test_prune_budget_refills(self):
        devs = tuple((f"t{i}", f"bd{i:064x}", "android") for i in range(4))
        self.make(ScriptedProvider(default=Result.INVALID_TOKEN), devices=devs, prune_per_minute=2)
        await self.d.start()
        for _, acct, _ in devs[:2]:
            self.d.submit(acct, "m")
        await self.d._queue.join()
        self.clock.t += 61
        for _, acct, _ in devs[2:]:
            self.d.submit(acct, "m")
        await self.d.stop(5.0)
        self.assertEqual(self.metrics.get("push_pruned"), 4)


class CircuitBreaker(unittest.TestCase):
    def test_state_machine(self):
        c = Clock()
        b = Breaker(threshold=3, cooldown=10.0, clock=c)
        for _ in range(2):
            b.record(False)
        self.assertTrue(b.allow())  # still closed
        b.record(False)
        self.assertEqual((b.state, b.allow()), ("open", False))
        c.t += 9.9
        self.assertFalse(b.allow())
        c.t += 0.2
        self.assertEqual(b.state, "half-open")
        self.assertTrue(b.allow())  # exactly one probe...
        self.assertFalse(b.allow())  # ...others wait
        b.record(False)  # probe failed: open again
        self.assertEqual(b.state, "open")
        c.t += 10.1
        self.assertTrue(b.allow())
        b.record(True)  # probe succeeded
        self.assertEqual((b.state, b.allow(), b.allow()), ("closed", True, True))
        self.assertEqual(b.opened, 1)

    def test_a_probe_that_never_reports_back_does_not_wedge_the_breaker(self):
        c = Clock()
        b = Breaker(1, 10.0, c)
        b.record(False)
        c.t += 11
        self.assertTrue(b.allow())  # probe granted, then its task is cancelled: no record()
        self.assertFalse(b.allow())
        c.t += 11
        self.assertTrue(b.allow())  # a new probe is allowed after another cooldown

    def test_a_success_in_between_resets_the_count(self):
        b = Breaker(3, 10.0, Clock())
        b.record(False)
        b.record(False)
        b.record(True)
        b.record(False)
        b.record(False)
        self.assertEqual(b.state, "closed")


class BreakerIntegration(DispatchBase):
    async def test_open_breaker_sheds_load_instead_of_stalling_workers(self):
        devs = tuple((f"t{i}", f"bd{i:064x}", "android") for i in range(10))
        p = ScriptedProvider(default=Result.RETRY)
        self.make(p, devices=devs, max_attempts=1, breaker_threshold=3, workers=1)
        for _, acct, _ in devs:
            self.d.submit(acct, "m")
        await self.drain()
        self.assertEqual(len(p.calls), 3)  # 3 failures opened it; the other 7 never reached the provider
        self.assertEqual(self.metrics.get("push", provider="p", result="shed"), 7)

    async def test_breaker_recovers_after_cooldown(self):
        devs = tuple((f"t{i}", f"bd{i:064x}", "android") for i in range(6))
        p = ScriptedProvider(default=Result.RETRY)
        self.make(p, devices=devs, max_attempts=1, breaker_threshold=2, workers=1)
        await self.d.start()
        for _, acct, _ in devs[:3]:
            self.d.submit(acct, "m")
        await self.d._queue.join()
        self.assertEqual(len(p.calls), 2)
        p.default = Result.OK
        self.clock.t += 11
        for _, acct, _ in devs[3:]:
            self.d.submit(acct, "m")
        await self.d.stop(5.0)
        self.assertEqual(self.metrics.get("push", provider="p", result="ok"), 3)


class QueueAndLifecycle(DispatchBase):
    async def test_bounded_queue_pushes_back(self):
        self.make(queue_size=2)
        self.assertEqual([self.d.submit(A, f"m{i}") for i in range(4)], [True, True, False, False])
        self.assertEqual(self.d.depth, 2)

    async def test_stale_notifications_are_dropped_not_sent(self):
        self.make(message_ttl=60.0)
        self.d.submit(A, "old")
        self.clock.t += 61
        await self.drain()
        self.assertEqual(self.provider.calls, [])
        self.assertEqual(self.metrics.get("notify_dropped", reason="stale"), 1)

    async def test_stop_drains_queued_work(self):
        self.make(workers=2)
        for i in range(50):
            self.d.submit(A, f"m{i}")
        await self.drain()
        self.assertEqual(len(self.provider.calls), 50)

    async def test_stop_refuses_new_work_and_does_not_hang_on_a_stuck_provider(self):
        p = ScriptedProvider()
        p.delay = 30.0
        self.make(p, send_timeout=60.0, workers=1)
        self.d.submit(A, "m1")
        self.d.submit(A, "m2")
        await self.d.start()
        await asyncio.sleep(0.05)
        t0 = asyncio.get_running_loop().time()
        stopper = asyncio.create_task(self.d.stop(0.2))
        await asyncio.sleep(0.05)
        self.assertFalse(self.d.submit(A, "late"))  # closing
        await stopper
        self.assertLess(asyncio.get_running_loop().time() - t0, 3.0)
        self.assertEqual(self.metrics.get("notify_dropped", reason="shutdown"), 1)  # m2 never started

    async def test_a_poisoned_registry_entry_does_not_kill_a_worker(self):
        self.make(workers=1)
        orig = self.reg.targets
        calls = {"n": 0}

        def flaky(send_to, honor=False):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("bug")
            return orig(send_to, honor)

        self.reg.targets = flaky
        self.d.submit(A, "first")
        self.d.submit(A, "second")
        await self.drain()
        self.assertEqual(self.provider.calls, [("t1", "second")])
        self.assertEqual(self.metrics.get("dispatch_errors"), 1)


if __name__ == "__main__":
    unittest.main()
