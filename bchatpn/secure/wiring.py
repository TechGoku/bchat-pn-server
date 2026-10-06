"""Builds the secure-mode components for App, so app.py has one small branch and no secure-mode logic."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from ..config import Config
from .api import SecureApi
from .crypto import Keyer, Sealer, SecretKeys
from .dispatch import SecureDispatcher
from .registry import SecureRegistry
from .store import SecureStore


def build(cfg: Config, private_key: X25519PrivateKey):
    """Returns (store, registry, dispatcher class, api class)."""
    keys = SecretKeys(private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
    store = SecureStore(cfg.db_path, Sealer(keys), commit_interval=cfg.commit_interval)
    registry = SecureRegistry(
        Keyer(keys),
        max_devices=cfg.max_devices_per_account,
        max_group_members=cfg.max_group_members,
        sink=store.submit,
    )
    return store, registry, SecureDispatcher, SecureApi
