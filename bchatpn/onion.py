"""Onion-request ingress: framing, key agreement, AES-256-GCM, and the v2/v4 request/reply codecs.

This is wire-compatible with the BChat Android client (OnionRequestEncryption.kt, AESGCM.kt,
OnionRequestAPI.kt) and with the legacy push server.

What the last onion hop POSTs to us:

    | 4 bytes LE: N | N bytes: ciphertext | utf-8 JSON: {"ephemeral_key": "<64 hex>", ...} |

  * ciphertext = IV(12) || AES-256-GCM(plaintext) || tag(16)
  * key        = HMAC-SHA256(key=b"BELDEX", msg=X25519(server_private, ephemeral_public))

v2 plaintext:  JSON  {"endpoint": "notify", "method": "POST", "headers": {...}, "body": "<json string>"}
v2 reply:      HTTP 200, JSON {"result": base64(IV||GCM({"status": S, "body": {"code": C, "message": M}}))}

v4 plaintext:  bencoded list  l<N>:<meta json><M>:<body>e   (meta: endpoint (leading "/"), method, headers)
v4 reply:      raw IV||GCM( l<N>:{"code": S, "headers": {...}}<M>:{"code": C, "message": M}e )

Anything that fails before the plaintext is authenticated yields OnionError and a bare HTTP 400:
we never reveal why, and we never trust unauthenticated bytes.
"""

from __future__ import annotations

import base64
import hmac
import json
import os
import struct
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

IV_LEN = 12
TAG_LEN = 16
KEY_SALT = b"BELDEX"
_MAX_BENCODE_DIGITS = 9


class OnionError(Exception):
    """The request could not be authenticated or parsed. Never shown to the client."""


@dataclass(frozen=True, slots=True)
class OnionRequest:
    key: bytes  # symmetric key for this request; used to seal the reply
    endpoint: str  # normalised: no leading "/"
    method: str
    args: dict[str, Any]


def load_private_key(path: str) -> X25519PrivateKey:
    """Read a key file holding either 32 raw bytes or 64 hex characters.

    Refuses to use a key that other users on the machine can read.
    """
    try:
        st = os.stat(path)
    except FileNotFoundError:
        raise OnionError(f"key file not found: {path}") from None
    if st.st_mode & 0o077:
        raise OnionError(
            f"key file {path} is accessible by group/others (mode {st.st_mode & 0o777:o}); "
            "run: chmod 600 " + path
        )
    with open(path, "rb") as f:
        raw = f.read()
    if len(raw) == 32:
        return X25519PrivateKey.from_private_bytes(raw)
    text = raw.strip()
    try:
        decoded = bytes.fromhex(text.decode("ascii"))
    except (ValueError, UnicodeDecodeError):
        decoded = b""
    if len(decoded) != 32:
        raise OnionError(f"key file {path} must hold 32 raw bytes or 64 hex characters")
    return X25519PrivateKey.from_private_bytes(decoded)


class OnionServer:
    def __init__(self, private_key: X25519PrivateKey) -> None:
        self._sk = private_key
        self.public_key: bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    @property
    def public_key_hex(self) -> str:
        return self.public_key.hex()

    # ---- crypto ------------------------------------------------------------------------------
    def _derive_key(self, ephemeral_pub: bytes) -> bytes:
        try:
            shared = self._sk.exchange(X25519PublicKey.from_public_bytes(ephemeral_pub))
        except ValueError:  # malformed or low-order point
            raise OnionError("bad ephemeral key") from None
        return hmac.new(KEY_SALT, shared, "sha256").digest()

    @staticmethod
    def seal(key: bytes, plaintext: bytes) -> bytes:
        iv = os.urandom(IV_LEN)
        return iv + AESGCM(key).encrypt(iv, plaintext, None)

    @staticmethod
    def _open_sealed(key: bytes, blob: bytes) -> bytes:
        if len(blob) < IV_LEN + TAG_LEN:
            raise OnionError("ciphertext too short")
        try:
            return AESGCM(key).decrypt(blob[:IV_LEN], blob[IV_LEN:], None)
        except InvalidTag:
            raise OnionError("authentication failed") from None

    # ---- framing -----------------------------------------------------------------------------
    def _open_frame(self, frame: bytes) -> tuple[bytes, bytes]:
        if len(frame) < 4:
            raise OnionError("frame too short")
        (n,) = struct.unpack_from("<I", frame, 0)
        if n < IV_LEN + TAG_LEN or n > len(frame) - 4:
            raise OnionError("bad ciphertext length")
        ciphertext = frame[4 : 4 + n]
        try:
            meta = json.loads(frame[4 + n :])
        except (ValueError, UnicodeDecodeError):
            raise OnionError("bad metadata") from None
        if not isinstance(meta, dict):
            raise OnionError("bad metadata")
        eph = meta.get("ephemeral_key")
        if not isinstance(eph, str) or len(eph) != 64:
            raise OnionError("bad ephemeral key")
        try:
            eph_bytes = bytes.fromhex(eph)
        except ValueError:
            raise OnionError("bad ephemeral key") from None
        key = self._derive_key(eph_bytes)
        return key, self._open_sealed(key, ciphertext)

    # ---- request decoding --------------------------------------------------------------------
    def open_v2(self, frame: bytes) -> OnionRequest:
        key, plain = self._open_frame(frame)
        try:
            obj = json.loads(plain)
        except (ValueError, UnicodeDecodeError):
            raise OnionError("bad payload") from None
        if not isinstance(obj, dict):
            raise OnionError("bad payload")
        endpoint = obj.get("endpoint")
        if not isinstance(endpoint, str):
            raise OnionError("bad payload")
        method = obj.get("method", "POST")
        return OnionRequest(
            key=key,
            endpoint=endpoint.lstrip("/"),
            method=method if isinstance(method, str) else "POST",
            args=_args_from_body(obj.get("body")),
        )

    def open_v4(self, frame: bytes) -> OnionRequest:
        key, plain = self._open_frame(frame)
        parts = _bencode_list_of_strings(plain)
        if not 1 <= len(parts) <= 2:
            raise OnionError("bad payload")
        try:
            meta = json.loads(parts[0])
        except (ValueError, UnicodeDecodeError):
            raise OnionError("bad payload") from None
        if not isinstance(meta, dict):
            raise OnionError("bad payload")
        endpoint = meta.get("endpoint")
        if not isinstance(endpoint, str) or not endpoint.startswith("/"):
            raise OnionError("bad payload")
        method = meta.get("method", "POST")
        body = parts[1] if len(parts) == 2 else b""
        try:
            args = _args_from_body(body.decode("utf-8") if body else None)
        except UnicodeDecodeError:
            raise OnionError("bad payload") from None
        return OnionRequest(
            key=key,
            endpoint=endpoint[1:],
            method=method if isinstance(method, str) else "POST",
            args=args,
        )

    # ---- reply encoding ----------------------------------------------------------------------
    @classmethod
    def reply_v2(cls, key: bytes, status: int, code: int, message: str, body: Any = None) -> bytes:
        inner = json.dumps(
            {"status": status, "body": body if body is not None else {"code": code, "message": message}},
            separators=(",", ":"),
        ).encode()
        result = base64.b64encode(cls.seal(key, inner)).decode("ascii")
        return json.dumps({"result": result}, separators=(",", ":")).encode()

    @classmethod
    def reply_v4(cls, key: bytes, status: int, code: int, message: str, body_obj: Any = None) -> bytes:
        meta = json.dumps(
            {"code": status, "headers": {"content-type": "application/json"}}, separators=(",", ":")
        ).encode()
        body = json.dumps(
            body_obj if body_obj is not None else {"code": code, "message": message}, separators=(",", ":")
        ).encode()
        plain = b"l" + b"%d:" % len(meta) + meta + b"%d:" % len(body) + body + b"e"
        return cls.seal(key, plain)


def _args_from_body(body: Any) -> dict[str, Any]:
    """The request body is a JSON *string* (v2 and v4); 'null'/empty means no arguments."""
    if body is None:
        return {}
    if isinstance(body, dict):
        return body
    if not isinstance(body, str):
        raise OnionError("bad body")
    if not body or body == "null":
        return {}
    try:
        parsed = json.loads(body)
    except ValueError:
        raise OnionError("bad body") from None
    if parsed is None:
        return {}
    if not isinstance(parsed, dict):
        raise OnionError("bad body")
    return parsed


def _bencode_list_of_strings(data: bytes) -> list[bytes]:
    """Strict parser for `l<len>:<bytes>...e`: a list of byte strings and nothing else."""
    if len(data) < 2 or data[:1] != b"l" or data[-1:] != b"e":
        raise OnionError("expected bencoded list")
    pos, end = 1, len(data) - 1
    parts: list[bytes] = []
    while pos < end:
        colon = data.find(b":", pos, end)
        digits = data[pos:colon] if colon > pos else b""
        if not digits or not digits.isdigit() or len(digits) > _MAX_BENCODE_DIGITS:
            raise OnionError("bad bencode length prefix")
        start = colon + 1
        stop = start + int(digits)
        if stop > end:
            raise OnionError("bencode length exceeds buffer")
        parts.append(data[start:stop])
        if len(parts) > 2:
            raise OnionError("too many bencode parts")
        pos = stop
    if not parts:
        raise OnionError("empty bencode list")
    return parts
