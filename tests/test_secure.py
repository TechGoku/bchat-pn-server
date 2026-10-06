"""Secure mode. Clients here are independent of the server code: accounts sign with Ed25519 and derive their
id from the seed the way the app does, and pushes are decrypted the way PushReceiver.decrypt does it
(libsodium when present, otherwise the module under test)."""

import asyncio
import base64
import ctypes
import glob
import hashlib
import json
import os
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import logging
logging.disable(logging.CRITICAL)  # fault-injection tests log on purpose

from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.exceptions import InvalidTag

import clientcrypto as cc
from bchatpn.app import App
from bchatpn.config import Config, ConfigError, load_config
from bchatpn.dispatch import Dispatcher
from bchatpn.httpd import Request
from bchatpn.obs import Metrics, setup_logging
from bchatpn.onion import OnionServer, load_private_key
from bchatpn.providers.base import Result
from bchatpn.providers.logonly import LogOnlyProvider
from bchatpn.registry import Registry
from bchatpn.secure.api import SecureApi
from bchatpn.secure import crypto as secure_crypto
from bchatpn.secure.crypto import (
    Keyer,
    Sealer,
    SecretKeys,
    build_enc_payload,
    ed25519_to_x25519,
    hchacha20,
    hchacha20_reference,
    parse_bytes,
    xchacha20poly1305_decrypt,
    xchacha20poly1305_encrypt,
)
from bchatpn.secure.dispatch import SecureDispatcher
from bchatpn.secure.registry import SecureRegistry
from bchatpn.secure.store import SecureStore, SecureStoreError
from bchatpn.store import Store
from test_e2e import Client, http, write_key

NOW = 1_800_000_000.0
TOK1, TOK2, TOK3 = ("fcm:" + c * 140 for c in "abc")
LEGACY_TOK = "fcm:" + "L" * 140
G = "bd" + "99" * 32
DATA = base64.b64encode(b"the encrypted message envelope" * 3).decode()


# ---- independent client side ---------------------------------------------------------------------
def _sodium():
    try:
        lib = ctypes.CDLL("libsodium.so.23")
        lib.sodium_init()
        return lib
    except OSError:
        return None


SODIUM = _sodium()


def android_decrypt(enc_key: bytes, enc_payload_b64: str) -> bytes:
    """PushReceiver.decrypt: nonce = first 24 bytes, XChaCha20-Poly1305, strip trailing zero padding."""
    blob = base64.b64decode(enc_payload_b64)
    nonce, ct = blob[:24], blob[24:]
    if SODIUM is None:
        return xchacha20poly1305_decrypt(enc_key, nonce, ct).rstrip(b"\0")
    out = ctypes.create_string_buffer(len(ct) - 16)
    n = ctypes.c_ulonglong()
    rc = SODIUM.crypto_aead_xchacha20poly1305_ietf_decrypt(
        out, ctypes.byref(n), None, ct, ctypes.c_ulonglong(len(ct)), None, ctypes.c_ulonglong(0), nonce, enc_key
    )
    if rc != 0:
        raise InvalidTag()
    return out.raw[: n.value].rstrip(b"\0")


def read_all(db_path: str) -> bytes:
    """Every byte the database has written: the file, its WAL and shared-memory companions."""
    out = b""
    for p in glob.glob(db_path + "*"):
        with open(p, "rb") as f:
            out += f.read()
    return out


def bdecode_list(plain: bytes):
    """Minimal bencode for the shape the app expects: a list of byte strings."""
    assert plain[:1] == b"l" and plain[-1:] == b"e", plain[:20]
    i, items = 1, []
    while plain[i : i + 1] != b"e":
        colon = plain.index(b":", i)
        n = int(plain[i:colon])
        items.append(plain[colon + 1 : colon + 1 + n])
        i = colon + 1 + n
    assert i == len(plain) - 1
    return items


class Account:
    """An app account: id = "bd" + X25519 public key derived from the Ed25519 seed (sha512 + clamp)."""

    def __init__(self):
        self.sk = Ed25519PrivateKey.generate()
        seed = self.sk.private_bytes(ser.Encoding.Raw, ser.PrivateFormat.Raw, ser.NoEncryption())
        h = bytearray(hashlib.sha512(seed).digest()[:32])
        h[0] &= 248; h[31] &= 127; h[31] |= 64
        x = X25519PrivateKey.from_private_bytes(bytes(h)).public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
        self.id = "bd" + x.hex()
        self.ed_pub = self.sk.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
        self.enc_key = os.urandom(32)

    def sign(self, msg: str) -> str:
        return base64.b64encode(self.sk.sign(msg.encode())).decode()

    def subscribe(self, token, ts=int(NOW), **over):
        """The request PushRegistryV2.register builds."""
        args = {
            "pubkey": self.id, "session_ed25519": self.ed_pub.hex().upper(), "namespaces": [0], "data": True,
            "service": "firebase", "sig_ts": ts,
            # "MONITOR" + id + timestamp + "1" (data) + "0" (the one namespace), exactly as PushRegistryV2 builds it
            "signature": self.sign(f"MONITOR{self.id}{ts}1" + "0"),
            "service_info": {"token": token}, "enc_key": self.enc_key.hex().upper(),
        }
        args.update(over)
        return args

    def unsubscribe(self, token, ts=int(NOW), **over):
        args = {"pubkey": self.id, "session_ed25519": self.ed_pub.hex().upper(), "service": "firebase",
                "sig_ts": ts, "signature": self.sign(f"UNSUBSCRIBE{self.id}{ts}"), "service_info": {"token": token}}
        args.update(over)
        return args


class RecProvider:
    name = "rec"
    device_types = frozenset({"android", "ios"})
    max_in_flight = 50

    def __init__(self):
        self.plain, self.enc = [], []

    async def send(self, token, data):
        self.plain.append((token, data))
        return Result.OK

    async def send_encrypted(self, token, payload):
        self.enc.append((token, payload))
        return Result.OK

    async def aclose(self):
        pass


# ---- crypto ------------------------------------------------------------------------------------
class Crypto(unittest.TestCase):
    def test_hchacha20_known_answer(self):
        # draft-irtf-cfrg-xchacha, section 2.2.1
        key = bytes(range(32))
        nonce = bytes.fromhex("000000090000004a0000000031415927")
        expected = "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc"
        self.assertEqual(hchacha20(key, nonce).hex(), expected)  # the fast one used in production
        self.assertEqual(hchacha20_reference(key, nonce).hex(), expected)  # the slow oracle

    def test_fast_hchacha20_equals_the_reference_everywhere_we_look(self):
        for _ in range(500):
            k, n = os.urandom(32), os.urandom(16)
            self.assertEqual(hchacha20(k, n), hchacha20_reference(k, n))
        for k, n in ((bytes(32), bytes(16)), (b"\xff" * 32, b"\xff" * 16), (bytes(32), b"\xff" * 16)):  # edges
            self.assertEqual(hchacha20(k, n), hchacha20_reference(k, n))
        with self.assertRaises(ValueError):
            hchacha20(bytes(31), bytes(16))
        with self.assertRaises(ValueError):
            hchacha20(bytes(32), bytes(15))

    @unittest.skipIf(SODIUM is None, "libsodium not available")
    def test_xchacha_matches_libsodium(self):
        for size in (0, 1, 15, 64, 700, 2800):
            k, n, p = os.urandom(32), os.urandom(24), os.urandom(size)
            ours = xchacha20poly1305_encrypt(k, n, p)
            out = ctypes.create_string_buffer(size + 16)
            ln = ctypes.c_ulonglong()
            SODIUM.crypto_aead_xchacha20poly1305_ietf_encrypt(out, ctypes.byref(ln), p, ctypes.c_ulonglong(size), None,
                                                              ctypes.c_ulonglong(0), None, n, k)
            self.assertEqual(ours, out.raw[: ln.value], size)

    def test_accelerated_and_python_paths_are_byte_identical(self):
        # Whichever path production uses must produce exactly what the other would (and what the app decrypts).
        for size in list(range(0, 70)) + [255, 256, 257, 700, 2500, 2816]:
            k, n, p = os.urandom(32), os.urandom(24), os.urandom(size)
            fast = xchacha20poly1305_encrypt(k, n, p)
            self.assertEqual(fast, secure_crypto._xchacha_encrypt_py(k, n, p), size)
            self.assertEqual(xchacha20poly1305_decrypt(k, n, fast), p)  # and the Python decrypt reads it

    def test_associated_data_still_goes_through_the_python_path(self):
        k, n = os.urandom(32), os.urandom(24)
        ct = xchacha20poly1305_encrypt(k, n, b"hello", b"aad")
        self.assertEqual(xchacha20poly1305_decrypt(k, n, ct, b"aad"), b"hello")
        with self.assertRaises(InvalidTag):
            xchacha20poly1305_decrypt(k, n, ct, b"other")

    def test_accelerator_can_be_switched_off_and_everything_still_works(self):
        import subprocess
        code = ("import sys; sys.path.insert(0, %r); from bchatpn.secure import crypto as c; "
                "import os; k, n = os.urandom(32), os.urandom(24); "
                "ct = c.xchacha20poly1305_encrypt(k, n, b'x'*300); "
                "assert c.xchacha20poly1305_decrypt(k, n, ct) == b'x'*300; print(c.ACCELERATED)"
                % os.path.join(os.path.dirname(__file__), ".."))
        out = subprocess.run([sys.executable, "-c", code], env={**os.environ, "BCHATPN_NO_LIBSODIUM": "1"},
                             capture_output=True, text=True)
        self.assertEqual((out.returncode, out.stdout.strip()), (0, "False"), out.stderr)

    def test_xchacha_roundtrip_and_tamper(self):
        k, n = os.urandom(32), os.urandom(24)
        ct = xchacha20poly1305_encrypt(k, n, b"hello")
        self.assertEqual(xchacha20poly1305_decrypt(k, n, ct), b"hello")
        with self.assertRaises(InvalidTag):
            xchacha20poly1305_decrypt(k, n, ct[:-1] + bytes([ct[-1] ^ 1]))
        with self.assertRaises(ValueError):
            xchacha20poly1305_encrypt(k, b"short", b"x")

    def test_ed25519_to_x25519_matches_the_real_identity(self):
        for _ in range(100):
            a = Account()
            self.assertEqual(ed25519_to_x25519(a.ed_pub), bytes.fromhex(a.id)[1:])

    def test_a_different_key_does_not_map_to_the_id(self):
        a, b = Account(), Account()
        self.assertNotEqual(ed25519_to_x25519(b.ed_pub), bytes.fromhex(a.id)[1:])

    def test_parse_bytes_accepts_hex_and_base64_of_the_right_length_only(self):
        raw = os.urandom(32)
        for form in (raw.hex(), raw.hex().upper(), base64.b64encode(raw).decode(), base64.urlsafe_b64encode(raw).decode()):
            self.assertEqual(parse_bytes(form, 32), raw)
        for bad in ("", "zz", raw.hex()[:-2], 5, None, base64.b64encode(raw[:16]).decode()):
            with self.assertRaises(ValueError):
                parse_bytes(bad, 32)


class Payload(unittest.TestCase):
    key = os.urandom(32)

    def decode(self, payload, key=None):
        return bdecode_list(android_decrypt(key or self.key, payload))

    def test_the_app_can_decrypt_and_read_it(self):
        payload = build_enc_payload("bd" + "ab" * 32, DATA, self.key)
        meta_json, message = self.decode(payload)
        meta = json.loads(meta_json)
        self.assertEqual((meta["@"], meta["n"], meta["l"]), ("bd" + "ab" * 32, 0, len(base64.b64decode(DATA))))
        self.assertIn("#", meta)
        self.assertNotIn("B", meta)
        self.assertEqual(message, base64.b64decode(DATA))  # exactly the bytes ENCRYPTED_DATA would have decoded to

    def test_length_is_hidden_by_padding(self):
        def size(n):
            return len(base64.b64decode(build_enc_payload("bd" + "ab" * 32, base64.b64encode(os.urandom(n)).decode(), self.key)))

        sizes = {n: size(n) for n in range(40, 400)}
        overhead = 24 + 16  # nonce + tag
        self.assertTrue(all((v - overhead) % 256 == 0 for v in sizes.values()), "sizes snap to 256-byte steps")
        self.assertLessEqual(len(set(sizes.values())), 3)  # 360 different lengths, only a few distinguishable sizes
        self.assertEqual(size(100), size(110))  # nearby lengths are indistinguishable

    def test_each_push_uses_a_fresh_nonce(self):
        a, b = (base64.b64decode(build_enc_payload("bd" + "ab" * 32, DATA, self.key)) for _ in range(2))
        self.assertNotEqual(a[:24], b[:24])
        self.assertNotEqual(a, b)

    def test_wrong_key_cannot_read_it(self):
        payload = build_enc_payload("bd" + "ab" * 32, DATA, self.key)
        with self.assertRaises(InvalidTag):
            android_decrypt(os.urandom(32), payload)

    def test_oversize_message_is_left_out_and_flagged_the_way_the_app_expects(self):
        big = base64.b64encode(os.urandom(3000)).decode()
        meta_json, *rest = self.decode(build_enc_payload("bd" + "ab" * 32, big, self.key))
        meta = json.loads(meta_json)
        self.assertEqual((rest, meta["B"], meta["l"]), ([], True, 3000))

    def test_opting_out_of_data_sends_metadata_only(self):
        meta_json, *rest = self.decode(build_enc_payload("bd" + "ab" * 32, DATA, self.key, want_data=False))
        self.assertEqual(rest, [])
        self.assertTrue(json.loads(meta_json)["B"])

    def test_largest_push_fits_the_fcm_data_limit(self):
        biggest = base64.b64encode(os.urandom(2500)).decode()
        payload = build_enc_payload("bd" + "ab" * 32, biggest, self.key)
        self.assertLess(len("enc_payload") + len(payload) + len("spns") + 1, 4096)

    def test_not_base64_is_refused(self):
        with self.assertRaises(ValueError):
            build_enc_payload("bd" + "ab" * 32, "not base64 !!", self.key)


class Keying(unittest.TestCase):
    def keys(self):
        return SecretKeys(os.urandom(32))

    def test_keyer_is_deterministic_keyed_and_opaque(self):
        k1, k2 = self.keys(), self.keys()
        ident = "bd" + "ab" * 32
        self.assertEqual(Keyer(k1)(ident), Keyer(k1)(ident))
        self.assertNotEqual(Keyer(k1)(ident), Keyer(k2)(ident))  # useless without this server's key
        self.assertNotIn(ident[2:12], Keyer(k1)(ident))
        self.assertEqual(len(Keyer(k1)(ident)), 32)

    def test_sealer_roundtrip_binds_the_value_to_its_row(self):
        s = Sealer(self.keys())
        blob = s.seal(b"secret-token", "tid1")
        self.assertEqual(s.unseal(blob, "tid1"), b"secret-token")
        with self.assertRaises(InvalidTag):
            s.unseal(blob, "tid2")  # moving a blob to another row is detected
        self.assertNotEqual(s.seal(b"secret-token", "tid1"), blob)  # fresh nonce each time

    def test_token_id_is_stable_and_not_the_token(self):
        s = Sealer(self.keys())
        self.assertEqual(s.token_id("abc"), s.token_id("abc"))
        self.assertNotIn("abc", s.token_id("abc"))


# ---- registry ----------------------------------------------------------------------------------
class RegistryRules(unittest.TestCase):
    def setUp(self):
        self.now = [NOW]
        self.ops = []
        self.reg = SecureRegistry(Keyer(SecretKeys(os.urandom(32))), max_devices=3, max_group_members=3,
                                  sink=self.ops.append, clock=lambda: self.now[0])
        self.a, self.b = Account(), Account()

    def signed(self, acct, token):
        return self.reg.register_signed(token, acct.id, "android", acct.enc_key)

    def test_no_raw_id_is_held_anywhere(self):
        self.signed(self.a, TOK1)
        self.reg.subscribe_group(G, self.a.id)
        held = repr((self.reg._accounts.keys(), self.reg._groups, self.ops))
        self.assertNotIn(self.a.id, held)
        self.assertNotIn(self.a.id[2:], held)
        self.assertNotIn(G, held)
        self.assertTrue(self.reg.knows(self.a.id))
        self.assertEqual(self.reg.tokens_of(self.a.id), {TOK1: "android"})

    def test_only_signed_devices_get_one_to_one_pushes(self):
        self.signed(self.a, TOK1)
        self.reg.register(LEGACY_TOK, self.a.id, "android")
        self.assertEqual([t for t, _, _ in self.reg.targets_ex(self.a.id)], [TOK1])

    def test_an_account_with_only_unsigned_devices_is_registered_but_not_reachable(self):
        self.reg.register(LEGACY_TOK, self.a.id, "android")
        self.assertEqual(self.reg.targets_ex(self.a.id), [])
        self.assertIsNone(self.reg.targets_ex(self.b.id))

    def test_an_unsigned_registration_cannot_take_over_or_remove_a_signed_token(self):
        self.signed(self.a, TOK1)
        self.assertFalse(self.reg.register(TOK1, self.b.id, "android"))  # try to re-home victim's token
        self.assertIsNone(self.reg.unregister(TOK1))  # try to remove it
        self.assertEqual(self.reg.tokens_of(self.a.id), {TOK1: "android"})
        self.assertEqual(self.reg.tokens_of(self.b.id), {})
        self.assertTrue(self.reg.register(TOK1, self.a.id, "android"))  # the owner refreshing is a harmless no-op
        self.assertEqual([t for t, _, _ in self.reg.targets_ex(self.a.id)], [TOK1])

    def test_unsigned_registrations_cannot_evict_a_signed_device(self):
        self.signed(self.a, TOK1)
        for i in range(10):
            self.reg.register(f"junk{i:040d}", self.a.id, "android")
        self.assertIn(TOK1, self.reg.tokens_of(self.a.id))
        self.assertLessEqual(len(self.reg.tokens_of(self.a.id)), 3)

    def test_when_every_slot_is_signed_an_unsigned_registration_is_refused(self):
        for t in (TOK1, TOK2, TOK3):
            self.signed(self.a, t)
        self.assertFalse(self.reg.register(LEGACY_TOK, self.a.id, "android"))
        self.assertEqual(set(self.reg.tokens_of(self.a.id)), {TOK1, TOK2, TOK3})

    def test_a_signed_registration_can_rehome_a_token_and_evicts_the_oldest_when_full(self):
        self.signed(self.a, TOK1)
        self.signed(self.b, TOK1)  # the phone changed hands: the new owner signed
        self.assertEqual(self.reg.tokens_of(self.a.id), {})
        self.assertEqual(self.reg.tokens_of(self.b.id), {TOK1: "android"})
        for t in (TOK2, TOK3, "fcm:" + "d" * 140):
            self.signed(self.b, t)
        self.assertEqual(len(self.reg.tokens_of(self.b.id)), 3)
        self.assertNotIn(TOK1, self.reg.tokens_of(self.b.id))

    def test_renewal_is_reported(self):
        self.assertFalse(self.signed(self.a, TOK1))
        self.assertTrue(self.signed(self.a, TOK1))

    def test_signed_unregister_only_for_the_owner(self):
        self.signed(self.a, TOK1)
        self.assertFalse(self.reg.unregister_signed(TOK1, self.b.id))
        self.assertTrue(self.reg.unregister_signed(TOK1, self.a.id))
        self.assertIsNone(self.reg.targets_ex(self.a.id))

    def test_internal_removal_after_a_provider_verdict_removes_signed_devices(self):
        self.signed(self.a, TOK1)
        self.reg.remove_token(TOK1)
        self.assertEqual(self.reg.tokens_of(self.a.id), {})

    def test_group_fanout_mixes_signed_and_legacy_devices(self):
        self.signed(self.a, TOK1)
        self.reg.register(LEGACY_TOK, self.b.id, "android")
        self.reg.subscribe_group(G, self.a.id)
        self.reg.subscribe_group(G, self.b.id)
        got = {t: info is not None for t, _, info in self.reg.targets_ex(G)}
        self.assertEqual(got, {TOK1: True, LEGACY_TOK: False})

    def test_expiry_removes_only_what_was_not_renewed(self):
        self.signed(self.a, TOK1)
        self.reg.register(LEGACY_TOK, self.b.id, "android")
        self.now[0] += 10 * 86400
        self.signed(self.a, TOK2)  # renewed later
        self.now[0] += 25 * 86400
        self.assertEqual(self.reg.expire(30 * 86400), 2)  # TOK1 (35 d) and the legacy device (35 d)
        self.assertEqual(set(self.reg.tokens_of(self.a.id)), {TOK2})
        self.assertEqual(self.reg.tokens_of(self.b.id), {})
        self.assertEqual(self.reg.signed_count, 1)

    def test_normal_mode_ops_never_reach_the_store(self):
        self.signed(self.a, TOK1)
        self.reg.register(LEGACY_TOK, self.b.id, "android")
        self.assertTrue(all(op[0] in ("sdevice", "device_del", "member", "member_del") for op in self.ops), self.ops)


# ---- store -------------------------------------------------------------------------------------
class StoreAtRest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.path = os.path.join(self.dir.name, "pn.db")
        self.keys = SecretKeys(os.urandom(32))

    def open(self, keys=None):
        k = keys or self.keys
        store = SecureStore(self.path, Sealer(k), commit_interval=0.01)
        reg = SecureRegistry(Keyer(k), sink=store.submit)
        devices, members = store.load()
        reg.load(devices, members)
        store.start()
        return store, reg

    def raw_bytes(self):
        return read_all(self.path)

    def test_roundtrip_and_nothing_sensitive_on_disk(self):
        a = Account()
        store, reg = self.open()
        reg.register_signed(TOK1, a.id, "android", a.enc_key)
        reg.register(LEGACY_TOK, a.id, "android")
        reg.subscribe_group(G, a.id)
        self.assertTrue(store.flush())
        store.close()

        blob = self.raw_bytes()
        for secret in (TOK1, LEGACY_TOK, a.id, a.id[2:], G, G[2:], a.enc_key, a.enc_key.hex(), a.enc_key.hex().upper()):
            needle = secret if isinstance(secret, bytes) else secret.encode()
            self.assertNotIn(needle, blob, secret)

        store2, reg2 = self.open()
        self.assertEqual(reg2.tokens_of(a.id), {TOK1: "android", LEGACY_TOK: "android"})
        self.assertEqual([t for t, _, _ in reg2.targets_ex(a.id)], [TOK1])
        self.assertEqual(reg2.targets_ex(a.id)[0][2].enc_key, a.enc_key)
        self.assertEqual(len(reg2.members_of(G)), 1)
        store2.close()

    def test_deletes_are_persisted(self):
        a = Account()
        store, reg = self.open()
        reg.register_signed(TOK1, a.id, "android", a.enc_key)
        reg.unregister_signed(TOK1, a.id)
        store.flush(); store.close()
        store2, reg2 = self.open()
        self.assertIsNone(reg2.targets_ex(a.id))
        store2.close()

    def test_a_different_key_file_cannot_read_the_registrations(self):
        a = Account()
        store, reg = self.open()
        reg.register_signed(TOK1, a.id, "android", a.enc_key)
        store.flush(); store.close()
        store2, reg2 = self.open(SecretKeys(os.urandom(32)))  # key file replaced
        self.assertEqual(reg2.signed_count, 0)
        store2.close()
        with sqlite3.connect(self.path) as c:  # rows are left alone, not destroyed
            self.assertEqual(c.execute("select count(*) from sdevice").fetchone()[0], 1)

    def test_refuses_a_database_that_holds_plaintext_registrations(self):
        plain = Store(self.path, commit_interval=0.01)
        plain.load(); plain.start()
        plain.submit(("device", "tok-plain-1234", "bd" + "aa" * 32, "android", False))
        plain.flush(); plain.close()
        with self.assertRaisesRegex(SecureStoreError, "plaintext registrations"):
            SecureStore(self.path, Sealer(self.keys)).load()
        self.assertTrue(issubclass(SecureStoreError, ConfigError))  # reported as a startup error

    def test_an_empty_plaintext_schema_is_fine(self):
        plain = Store(self.path)
        plain.load()  # creates the empty normal-mode tables
        SecureStore(self.path, Sealer(self.keys)).load()


# ---- the API over the onion ----------------------------------------------------------------------
class SecureBase(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.wall = [NOW]
        self.cfg = Config(log_only=True, secure_mode=True, honor_legacy_groups_only=True, data_max=1000,
                          max_devices_per_account=3, max_group_members=5, rate_per_sec=100.0, rate_burst=100.0,
                          signature_window=3600)
        self.onion = OnionServer(X25519PrivateKey.generate())
        self.registry = SecureRegistry(Keyer(SecretKeys(os.urandom(32))), max_devices=3, max_group_members=5,
                                       clock=lambda: self.wall[0])
        self.metrics = Metrics()
        self.provider = RecProvider()
        self.dispatcher = SecureDispatcher(self.registry, [self.provider], self.metrics, queue_size=100, workers=2,
                                           max_attempts=2, backoff_base=0.01, backoff_max=0.02, send_timeout=2.0,
                                           message_ttl=60.0, honor_legacy_groups_only=True)
        self.api = SecureApi(self.onion, self.registry, self.dispatcher, self.metrics, self.cfg,
                             wall_clock=lambda: self.wall[0])

    async def call(self, endpoint, args, v=4):
        pub = self.onion.public_key_hex
        if v == 4:
            body, key = cc.v4_request(pub, endpoint, args)
            status, _, out = await self.api.handle(Request("POST", "/beldex/v4/lsrpc", {}, body))
            assert status == 200, status
            info, raw = cc.parse_v4_reply(out, key)
            return json.loads(raw)
        body, key = cc.v2_request(pub, endpoint, args)
        status, _, out = await self.api.handle(Request("POST", "/beldex/v2/lsrpc", {}, body))
        assert status == 200, status
        return cc.parse_v2_reply(out, key)[1]

    async def drain(self):
        await self.dispatcher.start()
        await self.dispatcher.stop(5.0)


class Subscribe(SecureBase):
    async def test_a_valid_subscription_is_accepted_in_the_shape_the_app_parses(self):
        a = Account()
        self.assertEqual(await self.call("subscribe", a.subscribe(TOK1)), {"success": True, "added": True})
        self.assertEqual(await self.call("subscribe", a.subscribe(TOK1)), {"success": True, "updated": True})
        self.assertEqual(self.registry.tokens_of(a.id), {TOK1: "android"})
        self.assertEqual(self.metrics.get("subscribed", result="added"), 1)
        self.assertEqual(self.metrics.get("subscribed", result="renewed"), 1)

    async def test_the_reply_has_only_fields_the_app_decoder_knows(self):
        # SubscriptionResponse uses kotlinx Json without ignoreUnknownKeys: a stray key would make it throw.
        a = Account()
        ok = await self.call("subscribe", a.subscribe(TOK1))
        bad = await self.call("subscribe", a.subscribe(TOK1, signature=a.sign("nope")))
        self.assertLessEqual(set(ok), {"error", "message", "success", "added", "updated"})
        self.assertLessEqual(set(bad), {"error", "message", "success", "added", "updated"})
        self.assertEqual(set(bad), {"error", "message"})
        self.assertEqual(bad["error"], 1)

    async def test_works_over_the_v2_onion_format_too(self):
        a = Account()
        self.assertEqual(await self.call("subscribe", a.subscribe(TOK1), v=2), {"success": True, "added": True})

    async def test_rejections(self):
        a, b = Account(), Account()
        ts = int(NOW)
        cases = {
            "signature by someone else": a.subscribe(TOK1, signature=b.sign(f"MONITOR{a.id}{ts}10")),
            "key does not belong to the id": a.subscribe(TOK1, session_ed25519=b.ed_pub.hex()),
            "tampered timestamp": a.subscribe(TOK1, sig_ts=ts + 1),
            "tampered namespaces": a.subscribe(TOK1, namespaces=[0, 1]),
            "data flag flipped": a.subscribe(TOK1, data=False),
            "stale timestamp": a.subscribe(TOK1, ts=ts - 7200, sig_ts=ts - 7200),
            "timestamp far ahead": a.subscribe(TOK1, ts=ts + 7200, sig_ts=ts + 7200),
            "not firebase": a.subscribe(TOK1, service="apns"),
            "unknown service": a.subscribe(TOK1, service="huawei"),
            "unsorted namespaces": a.subscribe(TOK1, namespaces=[1, 0]),
            "no namespaces": a.subscribe(TOK1, namespaces=[]),
            "short pubkey": a.subscribe(TOK1, pubkey=a.id[:-2]),
            "bad enc_key": a.subscribe(TOK1, enc_key="abcd"),
            "bad signature encoding": a.subscribe(TOK1, signature="!!!"),
            "missing token": a.subscribe(TOK1, service_info={}),
            "hostile token": a.subscribe(TOK1, service_info={"token": "a b\r\n"}),
            "bool timestamp": a.subscribe(TOK1, sig_ts=True),
            "string timestamp": a.subscribe(TOK1, sig_ts=str(ts)),
        }
        for name, args in cases.items():
            reply = await self.call("subscribe", args)
            self.assertIn("error", reply, name)
            self.assertNotIn("success", reply, name)
        self.assertEqual(self.registry.signed_count, 0)

    async def test_the_signature_window_is_enforced_from_the_servers_clock(self):
        a = Account()
        old = a.subscribe(TOK1)
        self.wall[0] += 3599
        self.assertIn("success", await self.call("subscribe", old))
        self.wall[0] += 2  # now 3601 s old
        self.assertIn("error", await self.call("subscribe", old))

    async def test_a_signature_for_one_account_cannot_register_another(self):
        a, b = Account(), Account()
        stolen = a.subscribe(TOK1)
        stolen["pubkey"], stolen["session_ed25519"] = b.id, b.ed_pub.hex()
        self.assertIn("error", await self.call("subscribe", stolen))

    async def test_unsubscribe(self):
        a, b = Account(), Account()
        await self.call("subscribe", a.subscribe(TOK1))
        self.assertEqual(await self.call("unsubscribe", b.unsubscribe(TOK1)), {"success": True, "removed": False})
        self.assertIn("error", await self.call("unsubscribe", a.unsubscribe(TOK1, signature=b.sign("x"))))
        self.assertEqual(self.registry.tokens_of(a.id), {TOK1: "android"})
        self.assertEqual(await self.call("unsubscribe", a.unsubscribe(TOK1)), {"success": True, "removed": True})
        self.assertEqual(self.registry.tokens_of(a.id), {})

    async def test_normal_mode_has_no_subscribe_endpoint(self):
        from bchatpn.api import Api
        plain = Api(self.onion, Registry(), self.dispatcher, self.metrics, self.cfg)
        body, key = cc.v4_request(self.onion.public_key_hex, "subscribe", Account().subscribe(TOK1))
        status, _, out = await plain.handle(Request("POST", "/beldex/v4/lsrpc", {}, body))
        info, raw = cc.parse_v4_reply(out, key)
        self.assertEqual(info["code"], 404)


class Delivery(SecureBase):
    async def test_a_signed_device_gets_an_encrypted_push_the_app_can_read(self):
        a = Account()
        await self.call("subscribe", a.subscribe(TOK1))
        self.assertEqual((await self.call("notify", {"send_to": a.id, "data": DATA}, v=2))["code"], 1)
        await self.drain()
        self.assertEqual(self.provider.plain, [])  # never the plain envelope
        ((token, payload),) = self.provider.enc
        self.assertEqual(token, TOK1)
        meta_json, message = bdecode_list(android_decrypt(a.enc_key, payload))
        self.assertEqual(json.loads(meta_json)["@"], a.id)
        self.assertEqual(message, base64.b64decode(DATA))

    async def test_each_device_is_encrypted_to_its_own_key(self):
        a = Account()
        await self.call("subscribe", a.subscribe(TOK1))
        second_key = os.urandom(32)
        await self.call("subscribe", a.subscribe(TOK2, enc_key=second_key.hex()))
        await self.call("notify", {"send_to": a.id, "data": DATA}, v=2)
        await self.drain()
        by_token = dict(self.provider.enc)
        self.assertEqual(bdecode_list(android_decrypt(a.enc_key, by_token[TOK1]))[1], base64.b64decode(DATA))
        self.assertEqual(bdecode_list(android_decrypt(second_key, by_token[TOK2]))[1], base64.b64decode(DATA))
        with self.assertRaises(InvalidTag):
            android_decrypt(a.enc_key, by_token[TOK2])

    async def test_an_attacker_cannot_receive_a_victims_pings_with_the_legacy_endpoints(self):
        victim = Account()
        await self.call("subscribe", victim.subscribe(TOK1))
        # unsigned legacy registrations aimed at the victim's id, both flavours
        await self.call("register", {"token": LEGACY_TOK, "pubKey": victim.id, "device": "android"}, v=2)
        await self.call("register_legacy_groups_only", {"token": "fcm:" + "E" * 140, "pubKey": victim.id,
                                                        "device": "android", "legacyGroupPublicKeys": []}, v=2)
        # ...and an attempt to take over the victim's real token
        await self.call("register", {"token": TOK1, "pubKey": Account().id, "device": "android"}, v=2)
        await self.call("unregister", {"token": TOK1}, v=2)
        await self.call("notify", {"send_to": victim.id, "data": DATA}, v=2)
        await self.drain()
        self.assertEqual([t for t, _ in self.provider.enc], [TOK1])
        self.assertEqual(self.provider.plain, [])

    async def test_flooding_unsigned_registrations_cannot_knock_out_the_victim(self):
        victim = Account()
        await self.call("subscribe", victim.subscribe(TOK1))
        for i in range(20):
            await self.call("register", {"token": f"junk{i:040d}", "pubKey": victim.id, "device": "android"}, v=2)
        await self.call("notify", {"send_to": victim.id, "data": DATA}, v=2)
        await self.drain()
        self.assertEqual([t for t, _ in self.provider.enc], [TOK1])

    async def test_a_legacy_only_account_gets_no_one_to_one_push(self):
        a = Account()
        await self.call("register", {"token": LEGACY_TOK, "pubKey": a.id, "device": "android"}, v=2)
        await self.call("notify", {"send_to": a.id, "data": DATA}, v=2)
        await self.drain()
        self.assertEqual((self.provider.plain, self.provider.enc), ([], []))
        self.assertEqual(self.metrics.get("notify_suppressed"), 1)

    async def test_closed_group_reaches_signed_members_encrypted_and_legacy_members_as_before(self):
        a, b = Account(), Account()
        await self.call("subscribe", a.subscribe(TOK1))
        await self.call("register_legacy_groups_only", {"token": LEGACY_TOK, "pubKey": b.id, "device": "android",
                                                        "legacyGroupPublicKeys": [G]}, v=2)
        await self.call("subscribe_closed_group", {"closedGroupPublicKey": G, "pubKey": a.id}, v=2)
        await self.call("notify", {"send_to": G, "data": DATA}, v=2)
        await self.drain()
        self.assertEqual(self.provider.plain, [(LEGACY_TOK, DATA)])
        self.assertEqual([t for t, _ in self.provider.enc], [TOK1])

    async def test_unknown_recipients_are_still_cheap_and_silent(self):
        before = (self.provider.plain, self.provider.enc)
        self.assertEqual((await self.call("notify", {"send_to": Account().id, "data": DATA}, v=2))["code"], 1)
        await self.drain()
        self.assertEqual((self.provider.plain, self.provider.enc), before)
        self.assertEqual(self.metrics.get("notify_untracked"), 1)

    async def test_bad_data_is_dropped_without_pruning_the_device(self):
        a = Account()
        await self.call("subscribe", a.subscribe(TOK1))
        await self.call("notify", {"send_to": a.id, "data": "not base64 !!"}, v=2)
        await self.drain()
        self.assertEqual(self.provider.enc, [])
        self.assertEqual(self.registry.tokens_of(a.id), {TOK1: "android"})
        self.assertEqual(self.metrics.get("push", provider="rec", result="fail"), 1)

    async def test_a_dead_token_verdict_removes_a_signed_device(self):
        class Dead(RecProvider):
            async def send_encrypted(self, token, payload):
                return Result.INVALID_TOKEN
        self.provider = Dead()
        self.dispatcher = SecureDispatcher(self.registry, [self.provider], self.metrics, queue_size=10, workers=1,
                                           max_attempts=2, backoff_base=0.01, backoff_max=0.02, send_timeout=2.0,
                                           honor_legacy_groups_only=True)
        self.api = SecureApi(self.onion, self.registry, self.dispatcher, self.metrics, self.cfg,
                             wall_clock=lambda: self.wall[0])
        a = Account()
        await self.call("subscribe", a.subscribe(TOK1))
        await self.call("notify", {"send_to": a.id, "data": DATA}, v=2)
        await self.drain()
        self.assertEqual(self.registry.tokens_of(a.id), {})


# ---- configuration -------------------------------------------------------------------------------
class ConfigRules(unittest.TestCase):
    ENV = {"BCHATPN_LOG_ONLY": "true"}

    def test_normal_mode_is_the_default_and_is_unchanged(self):
        c = load_config(None, self.ENV)
        self.assertEqual((c.secure_mode, c.honor_legacy_groups_only, c.log_events), (False, False, True))

    def test_secure_mode_forces_signed_only_one_to_one_and_quiet_logs(self):
        c = load_config(None, {**self.ENV, "BCHATPN_SECURE_MODE": "true"})
        self.assertEqual((c.secure_mode, c.honor_legacy_groups_only, c.log_events), (True, True, False))

    def test_command_line_flag_turns_it_on(self):
        c = load_config(None, self.ENV, overrides={"secure_mode": True})
        self.assertTrue(c.secure_mode)

    def test_log_events_can_be_switched_back_on_explicitly(self):
        c = load_config(None, {**self.ENV, "BCHATPN_SECURE_MODE": "true", "BCHATPN_LOG_EVENTS": "true"})
        self.assertTrue(c.log_events)

    def test_secure_mode_refuses_to_deliver_unsigned_one_to_one(self):
        with self.assertRaisesRegex(ConfigError, "honor_legacy_groups_only"):
            load_config(None, {**self.ENV, "BCHATPN_SECURE_MODE": "true", "BCHATPN_HONOR_LEGACY_GROUPS_ONLY": "false"})

    def test_validation(self):
        for env in ({"BCHATPN_REGISTRATION_TTL_DAYS": "-1"}, {"BCHATPN_SIGNATURE_WINDOW": "5"},
                    {"BCHATPN_SIGNATURE_WINDOW": str(15 * 86400)}):
            with self.assertRaises(ConfigError, msg=str(env)):
                load_config(None, {**self.ENV, **env})
        self.assertEqual(load_config(None, {**self.ENV, "BCHATPN_REGISTRATION_TTL_DAYS": "0"}).registration_ttl_days, 0)

    def test_events_switch_changes_logger_levels(self):
        try:
            setup_logging("INFO", False, events=False)
            self.assertEqual(logging.getLogger("bchatpn.api").level, logging.WARNING)
            self.assertEqual(logging.getLogger("bchatpn.dispatch").level, logging.WARNING)
            setup_logging("INFO", False, events=True)
        finally:
            for n in ("bchatpn.api", "bchatpn.dispatch"):
                logging.getLogger(n).setLevel(logging.NOTSET)
            logging.disable(logging.CRITICAL)


# ---- the whole server, real sockets ---------------------------------------------------------------
class EndToEnd(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.key = write_key(self.dir.name)
        self.db = os.path.join(self.dir.name, "pn.db")
        self.provider = RecProvider()

    def cfg(self, **kw):
        base = dict(listen_host="127.0.0.1", listen_port=0, admin_host="127.0.0.1", admin_port=0, key_file=self.key,
                    db_path=self.db, secure_mode=True, honor_legacy_groups_only=True, workers=4, shutdown_grace=5.0,
                    signature_window=14 * 86400)
        base.update(kw)
        return Config(**base)

    async def start(self, **kw):
        app = App(self.cfg(**kw), providers=[self.provider])
        await app.start()
        return app, Client(app.public.port, app.onion.public_key_hex)

    async def test_subscribe_notify_decrypt_restart_and_nothing_readable_on_disk(self):
        import time
        a = Account()
        now = int(time.time())
        app, c = await self.start()
        r = await c.call("subscribe", a.subscribe(TOK1, ts=now, sig_ts=now,
                                                  signature=a.sign(f"MONITOR{a.id}{now}10")), v=4)
        self.assertEqual(r[1], {"success": True, "added": True})
        await c.call("register_legacy_groups_only", {"token": LEGACY_TOK, "pubKey": a.id, "device": "android",
                                                     "legacyGroupPublicKeys": [G]})
        await c.call("notify", {"send_to": a.id, "data": DATA})
        await app.stop()
        ((token, payload),) = self.provider.enc
        self.assertEqual(token, TOK1)
        self.assertEqual(bdecode_list(android_decrypt(a.enc_key, payload))[1], base64.b64decode(DATA))

        blob = read_all(self.db)
        for secret in (TOK1, LEGACY_TOK, a.id, a.id[2:], G, a.enc_key, a.enc_key.hex()):
            needle = secret if isinstance(secret, bytes) else secret.encode()
            self.assertNotIn(needle, blob)

        app2, c2 = await self.start()  # restart: still registered, still encrypted
        self.assertEqual(app2.registry.signed_count, 1)
        self.provider.enc.clear()
        await c2.call("notify", {"send_to": a.id, "data": DATA})
        await app2.stop()
        self.assertEqual([t for t, _ in self.provider.enc], [TOK1])

    async def test_normal_mode_database_is_refused_by_secure_mode(self):
        plain = App(self.cfg(secure_mode=False, honor_legacy_groups_only=False, log_only=True), providers=[LogOnlyProvider()])
        await plain.start()
        c = Client(plain.public.port, plain.onion.public_key_hex)
        await c.call("register", {"token": TOK1, "pubKey": Account().id})
        await plain.stop()
        secure = App(self.cfg(), providers=[self.provider])
        with self.assertRaisesRegex(ConfigError, "plaintext registrations"):
            await secure.start()

    async def test_expired_registrations_are_swept_at_startup(self):
        priv = load_private_key(self.key)
        keys = SecretKeys(priv.private_bytes(ser.Encoding.Raw, ser.PrivateFormat.Raw, ser.NoEncryption()))
        store = SecureStore(self.db, Sealer(keys), commit_interval=0.01)
        store.load(); store.start()
        a = Account()
        old = int(__import__("time").time()) - 40 * 86400
        store.submit(("sdevice", TOK1, Keyer(keys)(a.id), "android", a.enc_key, True, old))
        store.flush(); store.close()
        app, _ = await self.start(registration_ttl_days=30)
        await asyncio.sleep(0.2)
        self.assertEqual(app.registry.signed_count, 0)
        self.assertEqual(app.metrics.get("registrations_expired"), 1)
        await app.stop()

    async def test_ttl_zero_keeps_registrations_forever(self):
        priv = load_private_key(self.key)
        keys = SecretKeys(priv.private_bytes(ser.Encoding.Raw, ser.PrivateFormat.Raw, ser.NoEncryption()))
        store = SecureStore(self.db, Sealer(keys), commit_interval=0.01)
        store.load(); store.start()
        a = Account()
        store.submit(("sdevice", TOK1, Keyer(keys)(a.id), "android", a.enc_key, True, 1))
        store.flush(); store.close()
        app, _ = await self.start(registration_ttl_days=0)
        await asyncio.sleep(0.1)
        self.assertEqual(app.registry.signed_count, 1)
        await app.stop()

    async def test_metrics_report_signed_devices(self):
        app, c = await self.start()
        import time
        a = Account(); now = int(time.time())
        await c.call("subscribe", a.subscribe(TOK1, ts=now, sig_ts=now, signature=a.sign(f"MONITOR{a.id}{now}10")), v=4)
        status, body = await http(app.admin.port, "/metrics", method="GET")
        self.assertIn(b"bchatpn_signed_devices 1", body)
        await app.stop()


if __name__ == "__main__":
    unittest.main()
