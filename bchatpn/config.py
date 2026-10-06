"""Configuration: defaults < TOML file < BCHATPN_* environment variables.

Secrets are never read from source. Keys and certificates are referenced by file path;
the admin token only comes from the environment (or the file, if you must).
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, fields, replace
from typing import Mapping


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class Config:
    # --- public onion-request listener -------------------------------------------------------
    listen_host: str = "0.0.0.0"
    listen_port: int = 5000

    # --- admin listener (/healthz, /metrics); built into the same process ---------------------
    admin_enabled: bool = True
    admin_host: str = "127.0.0.1"
    admin_port: int = 5001
    admin_token: str = ""  # if set, /metrics requires "Authorization: Bearer <token>"

    # --- storage / keys -----------------------------------------------------------------------
    key_file: str = "x25519.key"  # 32 raw bytes or 64 hex chars; must be chmod 600
    db_path: str = "bchatpn.db"
    commit_interval: float = 0.05  # seconds a write batch may wait to be grouped

    # --- providers ----------------------------------------------------------------------------
    log_only: bool = False  # dry-run provider: accept and log, push nothing
    apns_cert_file: str = ""  # PEM client certificate (cert + key, or pair with apns_key_file)
    apns_key_file: str = ""
    apns_topic: str = "com.beldex.bchat"
    apns_sandbox: bool = False
    fcm_credentials_file: str = ""  # Google service-account JSON for Android pushes; must be chmod 600

    # --- dispatch -----------------------------------------------------------------------------
    queue_size: int = 20000
    workers: int = 32
    max_attempts: int = 4
    backoff_base: float = 0.5
    backoff_max: float = 30.0
    send_timeout: float = 15.0
    message_ttl: float = 60.0  # queued notifications older than this are dropped as stale
    breaker_threshold: int = 20
    breaker_cooldown: float = 10.0
    prune_per_minute: int = 1000  # safety valve against mass-pruning on a misconfiguration
    honor_legacy_groups_only: bool = False

    # --- input limits / abuse controls --------------------------------------------------------
    data_max: int = 10 * 1024
    max_devices_per_account: int = 10
    max_group_members: int = 500
    max_groups_per_register: int = 500
    rate_per_sec: float = 20.0  # per recipient id
    rate_burst: float = 100.0
    dedupe_ttl: float = 120.0
    dedupe_max: int = 100_000

    # --- HTTP hardening -----------------------------------------------------------------------
    max_header_bytes: int = 16 * 1024
    max_body_bytes: int = 64 * 1024
    read_timeout: float = 10.0
    handler_timeout: float = 30.0
    max_connections: int = 4096
    shutdown_grace: float = 10.0

    # --- logging ------------------------------------------------------------------------------
    log_level: str = "INFO"
    log_json: bool = True
    log_events: bool = True  # one INFO line per register/notify/push; secure mode turns this off unless set

    # --- secure mode (python3 -m bchatpn serve --secure) --------------------------------------
    secure_mode: bool = False
    registration_ttl_days: int = 30  # secure mode: a registration not renewed within this many days is removed (0 = never)
    signature_window: int = 3600  # secure mode: how old (or how far ahead) a subscribe signature's timestamp may be, seconds


_TYPES = {f.name: f.type for f in fields(Config)}


def _coerce(name: str, raw: object) -> object:
    typ = _TYPES[name]
    try:
        if typ == "bool":
            if isinstance(raw, bool):
                return raw
            s = str(raw).strip().lower()
            if s in ("1", "true", "yes", "on"):
                return True
            if s in ("0", "false", "no", "off"):
                return False
            raise ValueError(raw)
        if typ == "int":
            if isinstance(raw, bool):
                raise ValueError(raw)
            return int(raw)  # type: ignore[arg-type]
        if typ == "float":
            return float(raw)  # type: ignore[arg-type]
        return str(raw)
    except (TypeError, ValueError):
        raise ConfigError(f"invalid value for {name}: {raw!r} (expected {typ})") from None


def validate(cfg: Config) -> Config:
    def need(cond: bool, msg: str) -> None:
        if not cond:
            raise ConfigError(msg)

    need(0 <= cfg.listen_port <= 65535, "listen_port out of range")
    need(0 <= cfg.admin_port <= 65535, "admin_port out of range")
    need(cfg.queue_size >= 1, "queue_size must be >= 1")
    need(cfg.workers >= 1, "workers must be >= 1")
    need(cfg.max_attempts >= 1, "max_attempts must be >= 1")
    need(cfg.backoff_base > 0 and cfg.backoff_max >= cfg.backoff_base, "bad backoff settings")
    need(cfg.data_max >= 1, "data_max must be >= 1")
    need(cfg.max_body_bytes > cfg.data_max, "max_body_bytes must exceed data_max")
    need(cfg.max_devices_per_account >= 1, "max_devices_per_account must be >= 1")
    need(cfg.max_group_members >= 1, "max_group_members must be >= 1")
    need(cfg.rate_per_sec > 0 and cfg.rate_burst >= 1, "bad rate limit settings")
    need(cfg.max_connections >= 1, "max_connections must be >= 1")
    need(cfg.read_timeout > 0 and cfg.handler_timeout > 0, "timeouts must be > 0")
    need(cfg.registration_ttl_days >= 0, "registration_ttl_days must be >= 0")
    need(60 <= cfg.signature_window <= 14 * 86400, "signature_window must be between 60 seconds and 14 days")
    need(
        cfg.log_level.upper() in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"),
        "log_level must be DEBUG/INFO/WARNING/ERROR/CRITICAL",
    )
    need(
        bool(cfg.apns_cert_file or cfg.fcm_credentials_file) or cfg.log_only,
        "no push provider configured: set apns_cert_file and/or fcm_credentials_file, or log_only=true for a dry run",
    )
    return cfg


def load_config(
    path: str | None = None,
    env: Mapping[str, str] | None = None,
    overrides: Mapping[str, object] | None = None,
) -> Config:
    env = os.environ if env is None else env
    path = path or env.get("BCHATPN_CONFIG") or None

    values: dict[str, object] = {}
    if path:
        try:
            with open(path, "rb") as f:
                data = tomllib.load(f)
        except FileNotFoundError:
            raise ConfigError(f"config file not found: {path}") from None
        except tomllib.TOMLDecodeError as e:
            raise ConfigError(f"config file {path} is not valid TOML: {e}") from None
        for k, v in data.items():
            if k not in _TYPES:
                raise ConfigError(f"unknown config key {k!r} in {path}")
            values[k] = _coerce(k, v)

    for name in _TYPES:
        raw = env.get("BCHATPN_" + name.upper())
        if raw is not None:
            values[name] = _coerce(name, raw)

    for name, raw in (overrides or {}).items():  # command-line flags beat everything else
        values[name] = _coerce(name, raw)

    if values.get("secure_mode"):
        # Secure mode only ever delivers 1:1 pushes to signed devices, which is what this flag means.
        if values.get("honor_legacy_groups_only") is False:
            raise ConfigError("secure mode requires honor_legacy_groups_only = true")
        values["honor_legacy_groups_only"] = True
        values.setdefault("log_events", False)  # per-message lines are metadata: opt in with log_events = true

    return validate(replace(Config(), **values))
