"""A deliberately independent port of the BChat Android client's onion-request logic.

It imports nothing from `bchatpn`: the point is that a misreading of the protocol on the server side
cannot pass by being wrong in both places. Each function names the Kotlin it mirrors.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import struct

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def aesgcm_encrypt_for(plaintext: bytes, dest_pub_hex: str):
    """AESGCM.encrypt(plaintext, hexEncodedX25519PublicKey) -> (ivAndCiphertext, symmetricKey, ephemeralPub)."""
    eph = X25519PrivateKey.generate()
    shared = eph.exchange(X25519PublicKey.from_public_bytes(bytes.fromhex(dest_pub_hex)))
    key = hmac.new(b"BELDEX", shared, hashlib.sha256).digest()  # AESGCM.generateSymmetricKey
    iv = os.urandom(12)
    sealed = iv + AESGCM(key).encrypt(iv, plaintext, None)
    return sealed, key, eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def aesgcm_decrypt(iv_and_ciphertext: bytes, key: bytes) -> bytes:
    """AESGCM.decrypt"""
    return AESGCM(key).decrypt(iv_and_ciphertext[:12], iv_and_ciphertext[12:], None)


def encode_frame(ciphertext: bytes, meta: dict) -> bytes:
    """OnionRequestEncryption.encode: | 4 bytes LE size N | N bytes ciphertext | json as utf8 |"""
    return struct.pack("<I", len(ciphertext)) + ciphertext + json.dumps(meta).encode()


def _exit_node_frame(sealed: bytes, eph_pub: bytes, target: str) -> bytes:
    """What the last mnode forwards to the destination server: the destination layer's ciphertext plus
    the hop JSON (OnionRequestEncryption.encryptHop for Destination.Server)."""
    return encode_frame(
        sealed,
        {
            "host": "pn.example",
            "target": target,
            "method": "POST",
            "protocol": "http",
            "port": 80,
            "ephemeral_key": eph_pub.hex(),
        },
    )


def v2_request(server_pub_hex: str, endpoint: str, args: dict | None):
    """OnionRequestAPI.generatePayload for Version.V2 (a plain JSON payload), as forwarded by the exit node.

    Returns (http_body, symmetric_key)."""
    body = json.dumps(args) if args is not None else "null"  # request.getBodyForOnionRequest() ?: "null"
    payload = json.dumps(
        {"body": body, "endpoint": endpoint.removeprefix("/"), "method": "POST", "headers": {}}
    ).encode()
    sealed, key, eph = aesgcm_encrypt_for(payload, server_pub_hex)
    return _exit_node_frame(sealed, eph, "/beldex/v2/lsrpc"), key


def v4_request(server_pub_hex: str, endpoint: str, args: dict | None, *, raw_body: bytes | None = None):
    """OnionRequestAPI.generatePayload for Version.V4: l<len>:<json>[<len>:<body>]e"""
    meta = json.dumps({"endpoint": "/" + endpoint.removeprefix("/"), "method": "POST", "headers": {"Content-Type": "application/json"}}).encode()
    prefix = b"l%d:" % len(meta)
    body = raw_body if raw_body is not None else (json.dumps(args).encode() if args is not None else None)
    plain = prefix + meta + (b"%d:" % len(body) + body if body is not None else b"") + b"e"
    sealed, key, eph = aesgcm_encrypt_for(plain, server_pub_hex)
    return _exit_node_frame(sealed, eph, "/beldex/v4/lsrpc"), key


def parse_v2_reply(http_body: bytes, key: bytes):
    """OnionRequestAPI.handleResponse for V2. Returns (statusCode, body map) exactly as the app derives them:
    statusCode = json["status_code"] ?: json["status"]; body = json["body"] (a map, or a JSON string)."""
    outer = json.loads(http_body)
    plaintext = aesgcm_decrypt(base64.b64decode(outer["result"]), key)
    j = json.loads(plaintext.decode())
    status = j.get("status_code", j.get("status"))
    body = j["body"] if "body" in j else j
    if isinstance(body, str):
        body = json.loads(body)
    return int(status), body


def parse_v4_reply(http_body: bytes, key: bytes):
    """OnionRequestAPI.handleResponse for V4, followed byte-for-byte: returns (info map, body bytes)."""
    plaintext = aesgcm_decrypt(http_body, key)
    assert plaintext[:1] == b"l", "Invalid response"
    info_sep = plaintext.index(b":")
    info_len = int(plaintext[1:info_sep].decode("ascii"))
    info_start = len(f"l{info_len}") + 1
    info_end = info_start + info_len
    info = json.loads(plaintext[info_start:info_end])
    # ByteArray.getBody(infoLength, infoEndIndex)
    if len(plaintext) <= info_len + len(str(info_len)) + 2:
        return info, b""
    data_slice = plaintext[info_end + 1 : len(plaintext) - 1]
    sep = data_slice.find(b":")  # Kotlin indexOfFirst returns -1 when absent, and slice(0 until size) follows
    return info, data_slice[sep + 1 :]
