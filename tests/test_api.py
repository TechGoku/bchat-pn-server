import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import logging
logging.disable(logging.CRITICAL)  # fault-injection tests log on purpose

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

import clientcrypto as cc
from bchatpn.api import Api, TokenBuckets
from bchatpn.config import Config
from bchatpn.httpd import Request
from bchatpn.obs import Metrics
from bchatpn.onion import OnionServer
from bchatpn.registry import Registry

A, B = "bd" + "aa" * 32, "bd" + "bb" * 32
G = "bd" + "99" * 32
TOK_IOS = "ab" * 32  # 64 chars -> inferred as iOS, like the legacy server
TOK_AND = "fcm:" + "x" * 140
DATA = "QUJDREVGRw=="


class StubDispatcher:
    def __init__(self):
        self.submitted = []
        self.full = False

    def submit(self, send_to, data):
        if self.full:
            return False
        self.submitted.append((send_to, data))
        return True


def android_would_retry(status: int) -> bool:
    """Any non-200 status makes handleResponse reject the promise -> retryIfNeeded retries it."""
    return status != 200


def android_penalizes_onion_path(status: int) -> bool:
    """OnionRequestAPI.kt:420-428: HTTPRequestFailedAtDestinationException is an HTTPRequestFailedException,
    so every failure reaches that chain; only 400 (for server destinations) and 404 are exempt."""
    return status not in (200, 400, 404)


class ApiBase(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.now = [1000.0]
        self.cfg = Config(log_only=True, data_max=100, max_devices_per_account=3, max_group_members=3,
                          rate_per_sec=1.0, rate_burst=3.0, dedupe_ttl=120.0)
        self.onion = OnionServer(X25519PrivateKey.generate())
        self.registry = Registry(max_devices=3, max_group_members=3)
        self.dispatcher = StubDispatcher()
        self.metrics = Metrics()
        self.api = Api(self.onion, self.registry, self.dispatcher, self.metrics, self.cfg, clock=lambda: self.now[0])

    async def call(self, endpoint, args, version=2):
        pub = self.onion.public_key_hex
        if version == 2:
            body, key = cc.v2_request(pub, endpoint, args)
            status, ctype, out = await self.api.handle(Request("POST", "/beldex/v2/lsrpc", {}, body))
            self.assertEqual((status, ctype), (200, "application/json"))
            return cc.parse_v2_reply(out, key)  # (statusInEnvelope, body)
        body, key = cc.v4_request(pub, endpoint, args)
        status, ctype, out = await self.api.handle(Request("POST", "/beldex/v4/lsrpc", {}, body))
        self.assertEqual((status, ctype), (200, "application/octet-stream"))
        info, raw = cc.parse_v4_reply(out, key)
        return info["code"], json.loads(raw)


class Endpoints(ApiBase):
    async def test_register_success_in_both_protocol_versions(self):
        for v in (2, 4):
            self.assertEqual(await self.call("register", {"token": TOK_IOS, "pubKey": A}, v),
                             (200, {"code": 1, "message": "Success"}))
        self.assertEqual(self.registry.tokens_of(A), {TOK_IOS: "ios"})

    async def test_device_type_inference_and_explicit(self):
        await self.call("register", {"token": TOK_AND, "pubKey": A})
        await self.call("register", {"token": "hw" * 20, "pubKey": A, "device": "huawei"})
        self.assertEqual(self.registry.tokens_of(A), {TOK_AND: "android", "hw" * 20: "huawei"})

    async def test_register_legacy_groups_only_exactly_as_the_app_sends_it(self):
        # PushRegistryV1.doRegister parameters
        args = {"token": TOK_AND, "pubKey": A, "device": "android", "legacyGroupPublicKeys": [G]}
        self.assertEqual((await self.call("register_legacy_groups_only", args))[1]["code"], 1)
        self.assertEqual(self.registry.members_of(G), {A})
        self.assertEqual(self.registry.targets(A, honor_legacy_groups_only=True), [])  # flag recorded

    async def test_register_legacy_groups_only_is_all_or_nothing_on_bad_input(self):
        args = {"token": TOK_AND, "pubKey": A, "legacyGroupPublicKeys": [G, "nothex"]}
        status, body = await self.call("register_legacy_groups_only", args)
        self.assertEqual((status, body["code"]), (400, 0))
        self.assertFalse(self.registry.knows(A))
        self.assertFalse(self.registry.knows(G))

    async def test_unregister_is_idempotent(self):
        await self.call("register", {"token": TOK_AND, "pubKey": A})
        self.assertEqual((await self.call("unregister", {"token": TOK_AND}))[1]["code"], 1)
        self.assertEqual((await self.call("unregister", {"token": TOK_AND}))[1]["code"], 1)
        self.assertFalse(self.registry.knows(A))

    async def test_closed_group_subscribe_unsubscribe(self):
        args = {"closedGroupPublicKey": G, "pubKey": A}
        self.assertEqual((await self.call("subscribe_closed_group", args))[1]["code"], 1)
        self.assertEqual(self.registry.members_of(G), {A})
        self.assertEqual((await self.call("unsubscribe_closed_group", args))[1]["code"], 1)
        self.assertEqual((await self.call("unsubscribe_closed_group", args))[1]["code"], 1)  # idempotent
        self.assertFalse(self.registry.knows(G))

    async def test_group_full_is_a_soft_refusal(self):
        for i in range(3):
            await self.call("subscribe_closed_group", {"closedGroupPublicKey": G, "pubKey": "bd" + f"{i:064x}"})
        status, body = await self.call("subscribe_closed_group", {"closedGroupPublicKey": G, "pubKey": B})
        self.assertEqual((status, body), (200, {"code": 0, "message": "Group is full"}))

    async def test_validation_rejects_garbage_without_leaking_details(self):
        bad = [
            ("register", {"token": "short", "pubKey": A}),
            ("register", {"token": TOK_IOS, "pubKey": "nothex!"}),
            ("register", {"token": TOK_IOS, "pubKey": "abc"}),            # odd length
            ("register", {"token": TOK_IOS, "pubKey": "ab" * 100}),       # too long
            ("register", {"token": TOK_IOS}),
            ("register", {"token": 5, "pubKey": A}),
            ("register", {"token": "has space " * 5, "pubKey": A}),
            ("register", {"token": TOK_IOS, "pubKey": A, "device": "blackberry"}),
            ("register", {"token": TOK_IOS, "pubKey": A, "device": 7}),
            ("subscribe_closed_group", {"closedGroupPublicKey": G}),
            ("notify", {"send_to": A}),
            ("notify", {"send_to": A, "data": ""}),
            ("notify", {"send_to": A, "data": 5}),
            ("register_legacy_groups_only", {"token": TOK_IOS, "pubKey": A, "legacyGroupPublicKeys": "x"}),
        ]
        for endpoint, args in bad:
            status, body = await self.call(endpoint, args)
            self.assertEqual((status, body["code"]), (400, 0), (endpoint, args))
            self.assertEqual(body["message"], "Invalid parameter")
        self.assertEqual(self.registry.token_count, 0)

    async def test_too_many_groups_in_one_registration(self):
        cfg = Config(log_only=True, max_groups_per_register=2)
        api = Api(self.onion, self.registry, self.dispatcher, self.metrics, cfg)
        body, key = cc.v2_request(self.onion.public_key_hex, "register_legacy_groups_only",
                                  {"token": TOK_AND, "pubKey": A, "legacyGroupPublicKeys": [G] * 3})
        _, _, out = await api.handle(Request("POST", "/beldex/v2/lsrpc", {}, body))
        self.assertEqual(cc.parse_v2_reply(out, key)[0], 400)

    async def test_unknown_endpoint(self):
        self.assertEqual((await self.call("nope", {}))[0], 404)

    async def test_handler_bug_is_reported_generically(self):
        def boom(args):
            raise RuntimeError("secret internal detail /etc/passwd")

        self.api._routes["register"] = boom
        status, body = await self.call("register", {"token": TOK_IOS, "pubKey": A})
        self.assertEqual((status, body), (400, {"code": 0, "message": "Internal error"}))
        self.assertEqual(self.metrics.get("handler_errors", endpoint="register"), 1)

    async def test_unauthenticated_garbage_gets_a_bare_400(self):
        for path in ("/beldex/v2/lsrpc", "/beldex/v4/lsrpc"):
            status, _, out = await self.api.handle(Request("POST", path, {}, b"\x00" * 100))
            self.assertEqual((status, out), (400, b"bad request\n"))
        self.assertEqual(self.metrics.get("onion_rejected"), 2)

    async def test_unknown_path(self):
        self.assertEqual((await self.api.handle(Request("POST", "/", {}, b"")))[0], 404)


class Notify(ApiBase):
    async def asyncSetUp(self):
        await self.call("register", {"token": TOK_AND, "pubKey": A})

    async def notify(self, data=DATA, send_to=A, v=2):
        return await self.call("notify", {"data": data, "send_to": send_to}, v)

    async def test_registered_recipient_is_enqueued(self):
        self.assertEqual(await self.notify(), (200, {"code": 1, "message": "Success"}))
        self.assertEqual(self.dispatcher.submitted, [(A, DATA)])

    async def test_unregistered_recipient_succeeds_without_touching_the_queue(self):
        self.assertEqual((await self.notify(send_to=B))[1]["code"], 1)
        self.assertEqual(self.dispatcher.submitted, [])
        self.assertEqual(self.metrics.get("notify_untracked"), 1)

    async def test_registered_group_is_enqueued(self):
        await self.call("subscribe_closed_group", {"closedGroupPublicKey": G, "pubKey": A})
        await self.notify(send_to=G)
        self.assertEqual(self.dispatcher.submitted, [(G, DATA)])

    async def test_duplicate_within_ttl_is_acked_but_not_sent_twice(self):
        await self.notify()
        self.now[0] += 5
        self.assertEqual((await self.notify())[1]["code"], 1)
        self.assertEqual(len(self.dispatcher.submitted), 1)
        self.assertEqual(self.metrics.get("notify_duplicate"), 1)

    async def test_same_payload_after_ttl_is_a_new_message(self):
        await self.notify()
        self.now[0] += 121
        await self.notify()
        self.assertEqual(len(self.dispatcher.submitted), 2)

    async def test_distinct_messages_to_the_same_recipient_are_not_deduplicated(self):
        await self.notify("AAAA")
        await self.notify("BBBB")
        self.assertEqual(len(self.dispatcher.submitted), 2)

    async def test_too_large_is_a_soft_refusal(self):
        self.assertEqual(await self.notify("A" * 101), (200, {"code": 0, "message": "Too large"}))
        self.assertEqual(self.dispatcher.submitted, [])

    async def test_rate_limit_is_a_soft_refusal_and_refills(self):
        for i in range(3):  # burst of 3
            self.assertEqual((await self.notify(f"m{i}"))[1]["code"], 1)
        self.assertEqual(await self.notify("m3"), (200, {"code": 0, "message": "Rate limited"}))
        self.now[0] += 2.0  # 1 token/s
        self.assertEqual((await self.notify("m4"))[1]["code"], 1)
        self.assertEqual(len(self.dispatcher.submitted), 4)

    async def test_busy_is_a_retryable_400_and_the_retry_goes_through(self):
        self.dispatcher.full = True
        self.assertEqual(await self.notify(), (400, {"code": 0, "message": "Busy"}))
        self.dispatcher.full = False
        self.assertEqual((await self.notify())[1]["code"], 1)  # not wrongly deduplicated
        self.assertEqual(len(self.dispatcher.submitted), 1)

    async def test_both_versions_agree(self):
        self.assertEqual(await self.notify("v2data", v=2), (200, {"code": 1, "message": "Success"}))
        self.assertEqual(await self.notify("v4data", v=4), (200, {"code": 1, "message": "Success"}))


class AndroidBehaviour(ApiBase):
    """Pins down what the *app* does with each kind of reply (NotifyPNServerJob / OnionRequestAPI.kt)."""

    async def test_busy_makes_the_app_retry_without_penalising_its_onion_path(self):
        await self.call("register", {"token": TOK_AND, "pubKey": A})
        self.dispatcher.full = True
        status, body = await self.call("notify", {"data": DATA, "send_to": A})
        self.assertTrue(android_would_retry(status))
        self.assertFalse(android_penalizes_onion_path(status))

    async def test_internal_error_does_not_make_the_app_tear_down_a_healthy_path(self):
        self.api._routes["register"] = lambda a: 1 / 0
        status, _ = await self.call("register", {"token": TOK_IOS, "pubKey": A})
        self.assertFalse(android_penalizes_onion_path(status))

    async def test_soft_refusals_are_not_retried_by_the_app(self):
        await self.call("register", {"token": TOK_AND, "pubKey": A})
        status, body = await self.call("notify", {"data": "A" * 101, "send_to": A})
        self.assertFalse(android_would_retry(status))  # envelope status 200 -> app only logs code 0

    async def test_success_means_code_nonzero_as_the_app_checks_it(self):
        status, body = await self.call("register", {"token": TOK_IOS, "pubKey": A})
        self.assertEqual(status, 200)
        self.assertNotIn(body["code"], (None, 0))  # PushRegistryV1: `null, 0 -> throw`

    async def test_unknown_endpoint_is_exempt_from_path_penalty(self):
        status, _ = await self.call("nope", {})
        self.assertFalse(android_penalizes_onion_path(status))


class Buckets(unittest.TestCase):
    def test_bounded_memory(self):
        t = [0.0]
        b = TokenBuckets(1.0, 1.0, max_keys=100, clock=lambda: t[0])
        for i in range(10_000):
            b.allow(f"k{i}")
        self.assertLessEqual(len(b._state), 100)

    def test_burst_then_refill(self):
        t = [0.0]
        b = TokenBuckets(2.0, 2.0, 10, lambda: t[0])
        self.assertEqual([b.allow("x") for _ in range(3)], [True, True, False])
        t[0] += 0.5
        self.assertTrue(b.allow("x"))
        self.assertFalse(b.allow("x"))


if __name__ == "__main__":
    unittest.main()
