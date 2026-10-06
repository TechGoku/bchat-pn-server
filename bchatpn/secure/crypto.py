"""Cryptographic building blocks of secure mode. Only the `cryptography` package; nothing else.

  * XChaCha20-Poly1305 (HChaCha20 here, the AEAD from `cryptography`): the per-device push encryption the
    app already decrypts (PushReceiver.decrypt: 24-byte nonce || ciphertext || tag, no associated data).
  * Ed25519 -> X25519 public key conversion: a subscription's signing key must map to the account id it
    claims, so a valid signature proves control of that id.
  * Keyed hashing of account/group ids and device tokens, and sealing of secrets, for the database.
"""

from __future__ import annotations

import base64
import binascii
import ctypes
import ctypes.util
import hashlib
import json
import os
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature

_M = 0xFFFFFFFF
_P = 2**255 - 19

# Largest message body we put in a push (FCM caps the whole data map at 4 KB and base64 adds a third).
MAX_PUSH_BODY = 2500
PAD_TO = 256  # plaintext is zero-padded to a multiple of this, so a push does not reveal the exact length


# ---- XChaCha20-Poly1305 -------------------------------------------------------------------------
def _quarter(s: list[int], a: int, b: int, c: int, d: int) -> None:
    s[a] = (s[a] + s[b]) & _M; s[d] ^= s[a]; s[d] = ((s[d] << 16) | (s[d] >> 16)) & _M
    s[c] = (s[c] + s[d]) & _M; s[b] ^= s[c]; s[b] = ((s[b] << 12) | (s[b] >> 20)) & _M
    s[a] = (s[a] + s[b]) & _M; s[d] ^= s[a]; s[d] = ((s[d] << 8) | (s[d] >> 24)) & _M
    s[c] = (s[c] + s[d]) & _M; s[b] ^= s[c]; s[b] = ((s[b] << 7) | (s[b] >> 25)) & _M


_SIGMA = struct.unpack("<4I", b"expand 32-byte k")


def hchacha20(key: bytes, nonce16: bytes) -> bytes:
    """HChaCha20 at OpenSSL speed.

    HChaCha20 is ChaCha20's block function with the final "add the input state" step left out, returning
    state words 0-3 and 12-15. OpenSSL's ChaCha20 (counter || nonce as a 16-byte IV, which is exactly where
    HChaCha20 puts its 16 input bytes) returns the block *with* that addition, so subtracting the input
    words back out recovers HChaCha20. A pure-Python version costs ~60 us per push; this ~8 us.
    """
    if len(key) != 32 or len(nonce16) != 16:
        raise ValueError("hchacha20 needs a 32-byte key and a 16-byte nonce")
    block = struct.unpack("<16I", Cipher(algorithms.ChaCha20(key, nonce16), mode=None).encryptor().update(_ZERO_BLOCK))
    n = struct.unpack("<4I", nonce16)
    return struct.pack(
        "<8I",
        *((block[i] - _SIGMA[i]) & _M for i in range(4)),
        *((block[12 + i] - n[i]) & _M for i in range(4)),
    )


_ZERO_BLOCK = bytes(64)


def hchacha20_reference(key: bytes, nonce16: bytes) -> bytes:
    """Straight transcription of the algorithm. Slow; kept as the oracle the fast version is tested against."""
    if len(key) != 32 or len(nonce16) != 16:
        raise ValueError("hchacha20 needs a 32-byte key and a 16-byte nonce")
    s = list(_SIGMA) + list(struct.unpack("<8I", key)) + list(struct.unpack("<4I", nonce16))
    for _ in range(10):
        _quarter(s, 0, 4, 8, 12); _quarter(s, 1, 5, 9, 13); _quarter(s, 2, 6, 10, 14); _quarter(s, 3, 7, 11, 15)
        _quarter(s, 0, 5, 10, 15); _quarter(s, 1, 6, 11, 12); _quarter(s, 2, 7, 8, 13); _quarter(s, 3, 4, 9, 14)
    return struct.pack("<8I", *(s[0:4] + s[12:16]))


def _xchacha_encrypt_py(key: bytes, nonce24: bytes, plaintext: bytes, aad: bytes | None = None) -> bytes:
    return ChaCha20Poly1305(hchacha20(key, nonce24[:16])).encrypt(b"\0\0\0\0" + nonce24[16:], plaintext, aad)


def _load_libsodium():
    """Optional accelerator: libsodium's own XChaCha20-Poly1305 when the system already has it (the app uses
    the same library). Never required: anything unexpected returns None and the Python path is used. It is
    checked against the Python path at load, so a misbehaving library cannot silently produce bad pushes."""
    if os.environ.get("BCHATPN_NO_LIBSODIUM"):
        return None
    try:
        name = ctypes.util.find_library("sodium")
        lib = ctypes.CDLL(name) if name else None
        if lib is None or lib.sodium_init() < 0:
            return None
        fn = lib.crypto_aead_xchacha20poly1305_ietf_encrypt
        fn.restype = ctypes.c_int
        fn.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_ulonglong), ctypes.c_char_p, ctypes.c_ulonglong,
                       ctypes.c_char_p, ctypes.c_ulonglong, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
    except (OSError, AttributeError, TypeError):
        return None
    for n in (0, 1, 255, 700):  # known inputs, both implementations, byte for byte
        k, nonce, pt = bytes(range(32)), bytes(range(24)), bytes(range(256)) * 3
        if _sodium_encrypt(fn, k, nonce, pt[:n]) != _xchacha_encrypt_py(k, nonce, pt[:n]):
            return None
    return fn


def _sodium_encrypt(fn, key: bytes, nonce24: bytes, plaintext: bytes) -> bytes:
    out = ctypes.create_string_buffer(len(plaintext) + 16)
    n = ctypes.c_ulonglong()
    if fn(out, ctypes.byref(n), plaintext, len(plaintext), None, 0, None, nonce24, key) != 0:
        raise ValueError("libsodium refused to encrypt")
    return out.raw[: n.value]


_SODIUM = _load_libsodium()
ACCELERATED = _SODIUM is not None


def xchacha20poly1305_encrypt(key: bytes, nonce24: bytes, plaintext: bytes, aad: bytes | None = None) -> bytes:
    if len(key) != 32 or len(nonce24) != 24:
        raise ValueError("XChaCha20-Poly1305 needs a 32-byte key and a 24-byte nonce")
    if _SODIUM is not None and aad is None:
        return _sodium_encrypt(_SODIUM, key, nonce24, plaintext)
    return _xchacha_encrypt_py(key, nonce24, plaintext, aad)


def xchacha20poly1305_decrypt(key: bytes, nonce24: bytes, ciphertext: bytes, aad: bytes | None = None) -> bytes:
    return ChaCha20Poly1305(hchacha20(key, nonce24[:16])).decrypt(b"\0\0\0\0" + nonce24[16:], ciphertext, aad)


# ---- the push payload the app decodes -----------------------------------------------------------
def build_enc_payload(account: str, data_b64: str, enc_key: bytes, want_data: bool = True) -> str:
    """base64( nonce24 || XChaCha20-Poly1305( pad( bencode([metadata_json, message_bytes]) ) ) ).

    Matches PushReceiver.decrypt: the plaintext is a bencoded list whose first element is the metadata
    JSON and whose optional second element is the message; trailing zero bytes are padding.
    Raises ValueError if `data_b64` is not base64.
    """
    try:
        raw = base64.b64decode(data_b64, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("notification data is not base64") from None
    include = want_data and len(raw) <= MAX_PUSH_BODY
    meta: dict[str, object] = {
        "@": account,
        "#": hashlib.blake2b(raw, digest_size=32).hexdigest(),  # no swarm hash in this flow: a stable stand-in
        "n": 0,
        "l": len(raw),
    }
    if not include:
        meta["B"] = True  # "message not included"; the app then fetches it from the swarm
    meta_json = json.dumps(meta, separators=(",", ":")).encode()
    plain = b"l%d:" % len(meta_json) + meta_json
    if include:
        plain += b"%d:" % len(raw) + raw
    plain += b"e"
    plain += b"\0" * (-len(plain) % PAD_TO)
    nonce = os.urandom(24)
    return base64.b64encode(nonce + xchacha20poly1305_encrypt(enc_key, nonce, plain)).decode("ascii")


# ---- identity ----------------------------------------------------------------------------------
def ed25519_to_x25519(ed_pub: bytes) -> bytes:
    """The birational map from an Ed25519 public key to the X25519 public key of the same identity."""
    y = int.from_bytes(ed_pub, "little") & ((1 << 255) - 1)
    return ((1 + y) * pow(1 - y, _P - 2, _P) % _P).to_bytes(32, "little")


def parse_bytes(value: object, length: int) -> bytes:
    """Bytes given as hex or base64 (the app sends the signature as base64 and keys as hex)."""
    if not isinstance(value, str):
        raise ValueError("expected a string")
    v = value.strip()
    for decode in (bytes.fromhex, lambda s: base64.b64decode(s, validate=True), lambda s: base64.urlsafe_b64decode(s)):
        try:
            out = decode(v)
        except (ValueError, binascii.Error):
            continue
        if len(out) == length:
            return out
    raise ValueError(f"expected {length} bytes as hex or base64")


def verify_signature(ed_pub: bytes, signature: bytes, message: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(ed_pub).verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False


# ---- keyed hashing and sealing for the database --------------------------------------------------
class SecretKeys:
    """Three independent keys derived from the server's own key file, so there is nothing extra to deploy."""

    def __init__(self, master: bytes) -> None:
        okm = HKDF(algorithm=hashes.SHA256(), length=96, salt=None, info=b"bchatpn secure mode v1").derive(master)
        self.id_key, self.token_id_key, self.seal_key = okm[:32], okm[32:64], okm[64:]


class Keyer:
    """Account and group ids -> opaque keys. Deterministic (so lookups work), irreversible without the key."""

    def __init__(self, keys: SecretKeys) -> None:
        self._k = keys.id_key

    def __call__(self, ident: str) -> str:
        return hashlib.blake2b(ident.encode(), key=self._k, digest_size=16).hexdigest()


class Sealer:
    """Device tokens and push keys at rest: a keyed id for lookups plus authenticated encryption for the value."""

    def __init__(self, keys: SecretKeys) -> None:
        self._tid = keys.token_id_key
        self._aead = ChaCha20Poly1305(keys.seal_key)

    def token_id(self, token: str) -> str:
        return hashlib.blake2b(token.encode(), key=self._tid, digest_size=16).hexdigest()

    def seal(self, plaintext: bytes, aad: str) -> bytes:
        nonce = os.urandom(12)
        return nonce + self._aead.encrypt(nonce, plaintext, aad.encode())

    def unseal(self, blob: bytes, aad: str) -> bytes:
        return self._aead.decrypt(blob[:12], blob[12:], aad.encode())
