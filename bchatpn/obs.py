"""Observability, all in-process: counters/gauges/histogram, Prometheus text, JSON logs, admin handler.

No external service is involved (the legacy server's Telegram bot is deliberately gone): operators
scrape /metrics, probe /healthz, or just read the structured logs.
"""

from __future__ import annotations

import hmac
import json
import logging
import sys
import time
from collections import defaultdict
from typing import Any, Awaitable, Callable

# Request-latency buckets (seconds) for the onion ingress.
_BUCKETS = (0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5)

LabelKey = tuple[tuple[str, str], ...]


class Metrics:
    """Minimal metrics registry. Only touched from the event-loop thread."""

    def __init__(self) -> None:
        self._counters: dict[tuple[str, LabelKey], int] = defaultdict(int)
        self._gauges: dict[str, Callable[[], float]] = {}
        self._hist: dict[str, tuple[list[int], list[float]]] = {}

    def inc(self, name: str, n: int = 1, **labels: str) -> None:
        self._counters[(name, tuple(sorted(labels.items())))] += n

    def get(self, name: str, **labels: str) -> int:
        return self._counters.get((name, tuple(sorted(labels.items()))), 0)

    def gauge(self, name: str, fn: Callable[[], float]) -> None:
        self._gauges[name] = fn

    def observe(self, name: str, seconds: float) -> None:
        counts, agg = self._hist.setdefault(name, ([0] * (len(_BUCKETS) + 1), [0.0, 0.0]))
        for i, bound in enumerate(_BUCKETS):
            if seconds <= bound:
                counts[i] += 1
                break
        else:
            counts[-1] += 1
        agg[0] += seconds
        agg[1] += 1

    def render(self) -> str:
        lines: list[str] = []
        by_name: dict[str, list[tuple[LabelKey, int]]] = defaultdict(list)
        for (name, labels), value in self._counters.items():
            by_name[name].append((labels, value))
        for name in sorted(by_name):
            lines.append(f"# TYPE bchatpn_{name} counter")
            for labels, value in sorted(by_name[name]):
                lines.append(f"bchatpn_{name}{_fmt_labels(labels)} {value}")
        for name in sorted(self._gauges):
            try:
                value = float(self._gauges[name]())
            except Exception:  # a broken gauge must never break /metrics
                continue
            lines.append(f"# TYPE bchatpn_{name} gauge")
            lines.append(f"bchatpn_{name} {value:g}")
        for name in sorted(self._hist):
            counts, (total, n) = self._hist[name]
            lines.append(f"# TYPE bchatpn_{name} histogram")
            cumulative = 0
            for bound, c in zip(_BUCKETS, counts):
                cumulative += c
                lines.append(f'bchatpn_{name}_bucket{{le="{bound:g}"}} {cumulative}')
            cumulative += counts[-1]
            lines.append(f'bchatpn_{name}_bucket{{le="+Inf"}} {cumulative}')
            lines.append(f"bchatpn_{name}_sum {total:g}")
            lines.append(f"bchatpn_{name}_count {int(n)}")
        return "\n".join(lines) + "\n"


def short(value: str, n: int = 8) -> str:
    """First n characters, for log lines: enough to correlate entries, not enough to identify or reuse."""
    return value[:n] + ".." if len(value) > n else value


def _fmt_labels(labels: LabelKey) -> str:
    if not labels:
        return ""
    return "{" + ",".join(f'{k}="{v}"' for k, v in labels) + "}"


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        out: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created))
            + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            out["exc"] = self.formatException(record.exc_info)
        return json.dumps(out, separators=(",", ":"))


def setup_logging(level: str = "INFO", as_json: bool = True, events: bool = True) -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        _JsonFormatter()
        if as_json
        else logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level.upper())
    if not events:
        # The per-message lines (register / notify / push) live on these two loggers at INFO; problems are
        # warnings or errors, which stay visible.
        for name in ("bchatpn.api", "bchatpn.dispatch"):
            logging.getLogger(name).setLevel(logging.WARNING)


def make_admin_handler(
    metrics: Metrics,
    health: Callable[[], tuple[bool, dict[str, Any]]],
    token: str = "",
):
    """Handler for the admin listener. /healthz is open (for probes); /metrics needs the token if set."""
    from .httpd import Request, Response  # local import: obs must not depend on httpd at import time

    async def handler(req: Request) -> Response:
        if req.path == "/healthz":
            ok, info = health()
            return (
                200 if ok else 503,
                "application/json",
                json.dumps({"status": "ok" if ok else "unavailable", **info}).encode(),
            )
        if req.path == "/metrics":
            if token:
                supplied = req.headers.get("authorization", "")
                expected = "Bearer " + token
                if not hmac.compare_digest(supplied.encode(), expected.encode()):
                    return 401, "text/plain", b"unauthorized\n"
            return 200, "text/plain; version=0.0.4", metrics.render().encode()
        return 404, "text/plain", b"not found\n"

    return handler


AsyncHandler = Callable[..., Awaitable[Any]]
