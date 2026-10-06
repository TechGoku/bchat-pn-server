import logging
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from bchatpn.obs import short
from bchatpn.providers.base import Result
from test_api import A, B, DATA, TOK_AND, ApiBase
from test_dispatch import DispatchBase, ScriptedProvider

TOK = "fcm:" + "x" * 140


class LogsOn:
    """The other test modules switch logging off at import; this one needs it on."""

    def setUp(self):
        super().setUp()
        logging.disable(logging.NOTSET)

    def tearDown(self):
        logging.disable(logging.CRITICAL)
        super().tearDown()

    def lines(self, cm):
        return [r.getMessage() for r in cm.records]

    def assertNoSecrets(self, lines, *secrets):
        for line in lines:
            for s in secrets:
                self.assertNotIn(s, line, f"full value leaked into log line: {line!r}")


class Short(unittest.TestCase):
    def test_truncates_long_values_and_leaves_short_ones(self):
        self.assertEqual(short("bd" + "aa" * 32), "bdaaaaaa..")
        self.assertEqual(short("abc"), "abc")
        self.assertEqual(short("12345678"), "12345678")
        self.assertEqual(short("123456789"), "12345678..")


class RegisterLogs(LogsOn, ApiBase):
    async def test_register_is_logged_at_info_without_full_identifiers(self):
        with self.assertLogs("bchatpn.api", "INFO") as cm:
            await self.call("register", {"token": TOK_AND, "pubKey": A, "device": "android"})
        (line,) = self.lines(cm)
        self.assertEqual(line, "register account=bdaaaaaa.. device=android token=fcm:xxxx..")
        self.assertNoSecrets([line], A, TOK_AND)

    async def test_register_legacy_groups_only_logs_group_count(self):
        with self.assertLogs("bchatpn.api", "INFO") as cm:
            await self.call("register_legacy_groups_only",
                            {"token": TOK_AND, "pubKey": A, "device": "android", "legacyGroupPublicKeys": [B, "bd" + "99" * 32]})
        (line,) = self.lines(cm)
        self.assertIn("legacy_groups_only groups=2", line)
        self.assertNoSecrets([line], A, B, TOK_AND)

    async def test_unregister_is_logged(self):
        await self.call("register", {"token": TOK_AND, "pubKey": A, "device": "android"})
        with self.assertLogs("bchatpn.api", "INFO") as cm:
            await self.call("unregister", {"token": TOK_AND})
        self.assertEqual(self.lines(cm), ["unregister token=fcm:xxxx.."])

    async def test_a_rejected_registration_is_not_logged_as_one(self):
        with self.assertNoLogs("bchatpn.api", "INFO"):
            await self.call("register", {"token": "bad token with spaces", "pubKey": A})


class NotifyLogs(LogsOn, ApiBase):
    async def register(self):
        await self.call("register", {"token": TOK_AND, "pubKey": A, "device": "android"})

    async def test_accepted(self):
        await self.register()
        with self.assertLogs("bchatpn.api", "INFO") as cm:
            await self.call("notify", {"send_to": A, "data": DATA})
        (line,) = self.lines(cm)
        self.assertEqual(line, f"notify to=bdaaaaaa.. accepted ({len(DATA)} chars), queued for push")
        self.assertNoSecrets([line], A, DATA)

    async def test_untracked_recipient_is_debug_only(self):
        # Most notifies are for people who never enabled push; logging each at INFO would drown the log.
        with self.assertNoLogs("bchatpn.api", "INFO"):
            await self.call("notify", {"send_to": B, "data": DATA})
        with self.assertLogs("bchatpn.api", "DEBUG") as cm:
            await self.call("notify", {"send_to": B, "data": DATA})
        self.assertIn("no registered device", self.lines(cm)[0])

    async def test_duplicate(self):
        await self.register()
        await self.call("notify", {"send_to": A, "data": DATA})
        with self.assertLogs("bchatpn.api", "INFO") as cm:
            await self.call("notify", {"send_to": A, "data": DATA})
        self.assertIn("duplicate", self.lines(cm)[0])

    async def test_too_large(self):
        await self.register()
        with self.assertLogs("bchatpn.api", "INFO") as cm:
            await self.call("notify", {"send_to": A, "data": "x" * 101})  # data_max=100 in ApiBase
        self.assertIn("too large (101 chars)", self.lines(cm)[0])

    async def test_rate_limited(self):
        await self.register()
        for i in range(3):  # burst of 3
            await self.call("notify", {"send_to": A, "data": f"m{i}"})
        with self.assertLogs("bchatpn.api", "INFO") as cm:
            await self.call("notify", {"send_to": A, "data": "m-over"})
        self.assertIn("rate limited", self.lines(cm)[0])

    async def test_queue_full(self):
        await self.register()
        self.dispatcher.full = True
        with self.assertLogs("bchatpn.api", "INFO") as cm:
            await self.call("notify", {"send_to": A, "data": DATA})
        self.assertIn("queue full", self.lines(cm)[0])


class PushLogs(LogsOn, DispatchBase):
    async def test_successful_push_line(self):
        self.make()
        self.d.submit(A, "payload")
        with self.assertLogs("bchatpn.dispatch", "INFO") as cm:
            await self.drain()
        self.assertEqual(self.lines(cm), ["push to=bdaaaaaa.. provider=p device=android token=t1 result=ok attempt=1/4"])

    async def test_retries_are_visible_attempt_by_attempt(self):
        self.make(ScriptedProvider(script={"t1": [Result.RETRY, Result.RETRY, Result.OK]}))
        self.d.submit(A, "payload")
        with self.assertLogs("bchatpn.dispatch", "INFO") as cm:
            await self.drain()
        got = [(" ".join(l.split()[-2:])) for l in self.lines(cm)]
        self.assertEqual(got, ["result=retry attempt=1/4", "result=retry attempt=2/4", "result=ok attempt=3/4"])

    async def test_giving_up_is_a_warning(self):
        self.make(ScriptedProvider(default=Result.RETRY))
        self.d.submit(A, "payload")
        with self.assertLogs("bchatpn.dispatch", "INFO") as cm:
            await self.drain()
        self.assertEqual(cm.records[-1].levelno, logging.WARNING)
        self.assertIn("gave up after 4 attempts", cm.records[-1].getMessage())

    async def test_invalid_token_logs_the_result_and_the_removal(self):
        self.make(ScriptedProvider(script={"t1": [Result.INVALID_TOKEN]}))
        self.d.submit(A, "payload")
        with self.assertLogs("bchatpn.dispatch", "INFO") as cm:
            await self.drain()
        lines = self.lines(cm)
        self.assertIn("result=invalid_token", lines[0])
        self.assertIn("device removed", lines[1])

    async def test_no_provider_for_the_device_type(self):
        self.make(ScriptedProvider(types=("ios",)), devices=(("t1", A, "android"),))
        self.d.submit(A, "payload")
        with self.assertLogs("bchatpn.dispatch", "INFO") as cm:
            await self.drain()
        self.assertIn("no provider for this device type", self.lines(cm)[0])

    async def test_stale_notification_is_logged_when_dropped(self):
        self.make()
        self.d.submit(A, "payload")
        self.clock.t += 61  # message_ttl=60
        with self.assertLogs("bchatpn.dispatch", "INFO") as cm:
            await self.drain()
        self.assertIn("dropped: queued 61s", self.lines(cm)[0])

    async def test_full_tokens_and_ids_never_reach_the_log(self):
        long_tok = "fcm:" + "y" * 140
        self.make(devices=((long_tok, A, "android"),))
        self.d.submit(A, "payload-secret")
        with self.assertLogs("bchatpn.dispatch", "INFO") as cm:
            await self.drain()
        self.assertNoSecrets(self.lines(cm), long_tok, A, "payload-secret")


if __name__ == "__main__":
    unittest.main()
