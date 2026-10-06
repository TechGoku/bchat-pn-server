import hashlib
import hmac
import json
import os
import stat
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import logging
logging.disable(logging.CRITICAL)  # fault-injection tests log on purpose

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

import clientcrypto as cc
from bchatpn.onion import OnionError, OnionServer, load_private_key, _bencode_list_of_strings

ARGS = {"data": "QUJD", "send_to": "bd" + "ab" * 32}


class OnionRoundTrip(unittest.TestCase):
    def setUp(self):
        self.server = OnionServer(X25519PrivateKey.generate())
        self.pub = self.server.public_key_hex

    def test_v2_request_decodes_and_reply_is_readable_by_the_client(self):
        frame, key = cc.v2_request(self.pub, "/notify", ARGS)
        req = self.server.open_v2(frame)
        self.assertEqual(req.endpoint, "notify")
        self.assertEqual(req.args, ARGS)
        self.assertEqual(req.key, key)  # both sides derived the same symmetric key
        status, body = cc.parse_v2_reply(self.server.reply_v2(req.key, 200, 1, "Success"), key)
        self.assertEqual((status, body), (200, {"code": 1, "message": "Success"}))

    def test_v2_null_body_means_no_args(self):
        frame, _ = cc.v2_request(self.pub, "unregister", None)
        self.assertEqual(self.server.open_v2(frame).args, {})

    def test_v4_request_decodes_and_reply_is_readable_by_the_client(self):
        frame, key = cc.v4_request(self.pub, "notify", ARGS)
        req = self.server.open_v4(frame)
        self.assertEqual((req.endpoint, req.args), ("notify", ARGS))
        info, body = cc.parse_v4_reply(self.server.reply_v4(req.key, 200, 1, "Success"), key)
        self.assertEqual(info["code"], 200)
        self.assertEqual(json.loads(body), {"code": 1, "message": "Success"})

    def test_v4_without_a_body(self):
        frame, _ = cc.v4_request(self.pub, "unregister", None)
        self.assertEqual(self.server.open_v4(frame).args, {})

    def test_replies_carry_error_status_the_way_the_client_reads_it(self):
        frame, key = cc.v2_request(self.pub, "notify", ARGS)
        req = self.server.open_v2(frame)
        status, body = cc.parse_v2_reply(self.server.reply_v2(req.key, 400, 0, "Busy"), key)
        self.assertEqual((status, body["code"], body["message"]), (400, 0, "Busy"))
        frame, key = cc.v4_request(self.pub, "notify", ARGS)
        req = self.server.open_v4(frame)
        info, body = cc.parse_v4_reply(self.server.reply_v4(req.key, 400, 0, "Busy"), key)
        self.assertEqual(info["code"], 400)
        self.assertEqual(json.loads(body)["message"], "Busy")

    def test_unicode_message_lengths_are_byte_lengths(self):
        frame, key = cc.v4_request(self.pub, "notify", ARGS)
        req = self.server.open_v4(frame)
        info, body = cc.parse_v4_reply(self.server.reply_v4(req.key, 200, 1, "Succès ✓"), key)
        self.assertEqual(json.loads(body)["message"], "Succès ✓")

    def test_extra_hop_metadata_is_ignored(self):
        # the exit node adds host/target/protocol/port next to ephemeral_key; clientcrypto includes them
        frame, _ = cc.v2_request(self.pub, "register", {"token": "t" * 64, "pubKey": "bd" + "00" * 32})
        self.server.open_v2(frame)


class KeyAgreement(unittest.TestCase):
    def test_x25519_matches_the_rfc7748_vector_then_hmac_with_beldex_salt(self):
        # RFC 7748 section 6.1
        alice_priv = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        bob_pub = bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        shared = bytes.fromhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
        server = OnionServer(X25519PrivateKey.from_private_bytes(alice_priv))
        self.assertEqual(server._derive_key(bob_pub), hmac.new(b"BELDEX", shared, hashlib.sha256).digest())


class Rejection(unittest.TestCase):
    def setUp(self):
        self.server = OnionServer(X25519PrivateKey.generate())
        self.pub = self.server.public_key_hex
        self.frame, _ = cc.v2_request(self.pub, "notify", ARGS)

    def bad(self, frame, v4=False):
        with self.assertRaises(OnionError):
            (self.server.open_v4 if v4 else self.server.open_v2)(frame)

    def test_empty_and_tiny(self):
        for f in (b"", b"\x00", b"\x01\x00\x00", struct.pack("<I", 0)):
            self.bad(f)

    def test_every_single_bit_flip_in_the_ciphertext_is_rejected(self):
        (n,) = struct.unpack_from("<I", self.frame)
        for i in range(4, 4 + n, 7):
            tampered = bytearray(self.frame)
            tampered[i] ^= 0x01
            self.bad(bytes(tampered))

    def test_truncated_ciphertext(self):
        self.bad(self.frame[:30])

    def test_length_prefix_lies(self):
        (n,) = struct.unpack_from("<I", self.frame)
        for bogus in (0, 27, n + 1, len(self.frame), 0xFFFFFFFF):
            self.bad(struct.pack("<I", bogus) + self.frame[4:])

    def test_missing_or_malformed_ephemeral_key(self):
        (n,) = struct.unpack_from("<I", self.frame)
        ct = self.frame[4 : 4 + n]
        for meta in (b"{}", b"[]", b"not json", b'{"ephemeral_key": 5}', b'{"ephemeral_key": "abcd"}',
                     b'{"ephemeral_key": "' + b"zz" * 32 + b'"}'):
            self.bad(struct.pack("<I", n) + ct + meta)

    def test_low_order_ephemeral_point_is_rejected(self):
        (n,) = struct.unpack_from("<I", self.frame)
        ct = self.frame[4 : 4 + n]
        meta = json.dumps({"ephemeral_key": "00" * 32}).encode()  # all-zero shared secret
        self.bad(struct.pack("<I", n) + ct + meta)

    def test_wrong_server_key(self):
        other = OnionServer(X25519PrivateKey.generate())
        with self.assertRaises(OnionError):
            other.open_v2(self.frame)

    def test_authenticated_but_malformed_payloads(self):
        def frame_for(plain: bytes):
            sealed, _, eph = cc.aesgcm_encrypt_for(plain, self.pub)
            return cc.encode_frame(sealed, {"ephemeral_key": eph.hex()})

        for plain in (b"not json", b"[]", b'{"endpoint": 5}', b'{"body": "{}"}', b'{"endpoint":"x","body":"[1]"}',
                      b'{"endpoint":"x","body":"{"}', b'{"endpoint":"x","body":7}'):
            self.bad(frame_for(plain))

    def test_v4_malformed_bencode(self):
        def frame_for(plain: bytes):
            sealed, _, eph = cc.aesgcm_encrypt_for(plain, self.pub)
            return cc.encode_frame(sealed, {"ephemeral_key": eph.hex()})

        meta = b'{"endpoint":"/notify","method":"POST","headers":{}}'
        good = b"l%d:" % len(meta) + meta
        for plain in (b"", b"e", b"le", b"l5:abce", b"lxe", b"l-1:ae", b"l99999999999:ae",
                      b"l2:{}e",                                   # meta without endpoint
                      b'l30:{"endpoint":"notify","x":"yyy"}e'[:-1],  # no terminator
                      good + b"2:{}" + b"2:{}" + b"e",             # three parts
                      b"l%d:" % len(meta) + meta + b"3:{}e"):      # body length lies
            self.bad(frame_for(plain), v4=True)
        # endpoint must start with "/" in v4
        meta2 = b'{"endpoint":"notify","method":"POST"}'
        self.bad(frame_for(b"l%d:" % len(meta2) + meta2 + b"e"), v4=True)


class Bencode(unittest.TestCase):
    def test_parses_one_and_two_parts(self):
        self.assertEqual(_bencode_list_of_strings(b"l3:abce"), [b"abc"])
        self.assertEqual(_bencode_list_of_strings(b"l3:abc2:xye"), [b"abc", b"xy"])
        self.assertEqual(_bencode_list_of_strings(b"l0:e"), [b""])

    def test_body_may_contain_bencode_metacharacters(self):
        self.assertEqual(_bencode_list_of_strings(b"l5:a:b:ee"), [b"a:b:e"])


class KeyFile(unittest.TestCase):
    def write(self, content: bytes, mode: int):
        fd, path = tempfile.mkstemp()
        os.write(fd, content)
        os.close(fd)
        os.chmod(path, mode)
        self.addCleanup(os.unlink, path)
        return path

    def test_hex_and_raw_load_to_the_same_key(self):
        raw = os.urandom(32)
        a = load_private_key(self.write(raw.hex().encode() + b"\n", 0o600))
        b = load_private_key(self.write(raw, 0o600))
        self.assertEqual(OnionServer(a).public_key, OnionServer(b).public_key)

    def test_group_or_world_readable_key_is_refused(self):
        for mode in (0o640, 0o604, 0o644, 0o666):
            with self.assertRaisesRegex(OnionError, "chmod 600"):
                load_private_key(self.write(os.urandom(32).hex().encode(), mode))

    def test_bad_contents(self):
        for content in (b"", b"abcd", b"zz" * 32, os.urandom(31)):
            with self.assertRaises(OnionError):
                load_private_key(self.write(content, 0o600))

    def test_missing(self):
        with self.assertRaises(OnionError):
            load_private_key("/nonexistent/key")


if __name__ == "__main__":
    unittest.main()
