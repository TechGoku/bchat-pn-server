"""Command line: serve | keygen | pubkey."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import signal
import sys

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

from . import __version__
from .config import ConfigError, load_config
from .obs import setup_logging

log = logging.getLogger("bchatpn")


def _keygen(path: str) -> int:
    key = X25519PrivateKey.generate()
    raw = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)  # never overwrite, never world-readable
    except FileExistsError:
        print(f"refusing to overwrite existing file {path}", file=sys.stderr)
        return 2
    with os.fdopen(fd, "w") as f:
        f.write(raw.hex() + "\n")
    pub = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    print(f"wrote private key to {path} (mode 600)")
    print(f"public key (give this to the app's Server config): {pub.hex()}")
    return 0


def _pubkey(path: str) -> int:
    from .onion import OnionError, OnionServer, load_private_key

    try:
        print(OnionServer(load_private_key(path)).public_key_hex)
    except OnionError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    return 0


async def _serve(config_path: str | None, secure: bool = False) -> int:
    from .app import App

    cfg = load_config(config_path, overrides={"secure_mode": True} if secure else None)
    setup_logging(cfg.log_level, cfg.log_json, events=cfg.log_events)
    if cfg.secure_mode:
        log.info(
            "SECURE MODE: signed subscriptions required for 1:1 push, encrypted pushes, hashed ids and sealed "
            "tokens at rest, registrations expire after %s days, per-message logging %s",
            cfg.registration_ttl_days or "never",
            "on" if cfg.log_events else "off",
        )
    app = App(cfg)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)

    await app.start()
    log.info("bchatpn %s ready", __version__)
    await stop.wait()
    log.info("shutdown requested")
    await app.stop()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="bchatpn", description="BChat push-notification server")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_serve = sub.add_parser("serve", help="run the server (one process, nothing else needed)")
    p_serve.add_argument("--config", help="TOML config file (default: $BCHATPN_CONFIG, else env/defaults only)")
    p_serve.add_argument(
        "--secure",
        action="store_true",
        help="secure mode: signed subscriptions, encrypted pushes, hashed ids and sealed tokens at rest "
        "(also: secure_mode = true / BCHATPN_SECURE_MODE=true)",
    )
    p_key = sub.add_parser("keygen", help="generate the server's X25519 key file")
    p_key.add_argument("path")
    p_pub = sub.add_parser("pubkey", help="print the public key for an existing key file")
    p_pub.add_argument("path")
    args = parser.parse_args(argv)

    if args.cmd == "keygen":
        return _keygen(args.path)
    if args.cmd == "pubkey":
        return _pubkey(args.path)

    try:
        try:
            import uvloop

            uvloop.install()
        except ImportError:
            pass
        return asyncio.run(_serve(args.config, args.secure))
    except ConfigError as e:
        print(f"configuration error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
