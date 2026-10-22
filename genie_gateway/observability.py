"""Operational plumbing: JSON logs, request IDs, rate limiting, Prometheus-style metrics."""

from __future__ import annotations

import contextvars
import json
import logging
import threading
import time
import uuid
from collections import defaultdict
from typing import Callable

request_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("request_id", default=None)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": round(record.created, 3),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "request_id": request_id_var.get(),
        }
        if record.exc_info:
            entry["exc"] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str)


def configure_logging(level: str, *, json_logs: bool = True) -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter() if json_logs else logging.Formatter("%(levelname)s %(name)s %(message)s"))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)


def new_request_id(incoming: str | None) -> str:
    # Accept a caller-supplied ID only if it is short and printable (avoids log injection).
    if incoming and len(incoming) <= 64 and incoming.isascii() and incoming.replace("-", "").isalnum():
        return incoming
    return uuid.uuid4().hex


class TokenBucketLimiter:
    """Per-key token bucket. `rate_per_minute` tokens refill continuously; burst equals the rate."""

    def __init__(self, rate_per_minute: int, clock: Callable[[], float] = time.monotonic) -> None:
        self._capacity = float(rate_per_minute)
        self._refill_per_sec = rate_per_minute / 60.0
        self._clock = clock
        self._buckets: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> float:
        """Return 0 if the request is allowed, else seconds until the next token."""
        now = self._clock()
        with self._lock:
            tokens, last = self._buckets.get(key, (self._capacity, now))
            tokens = min(self._capacity, tokens + (now - last) * self._refill_per_sec)
            if tokens >= 1:
                self._buckets[key] = (tokens - 1, now)
                self._prune(now)
                return 0.0
            self._buckets[key] = (tokens, now)
            return (1 - tokens) / self._refill_per_sec

    def _prune(self, now: float) -> None:
        if len(self._buckets) > 10_000:
            full_after = self._capacity / self._refill_per_sec
            self._buckets = {k: v for k, v in self._buckets.items() if now - v[1] < full_after}


class Metrics:
    def __init__(self) -> None:
        self._counters: dict[tuple[str, tuple[tuple[str, str], ...]], float] = defaultdict(float)
        self._lock = threading.Lock()

    def inc(self, name: str, value: float = 1.0, **labels: str) -> None:
        key = (name, tuple(sorted(labels.items())))
        with self._lock:
            self._counters[key] += value

    def render(self) -> str:
        lines = ["# TYPE genie_gateway_events_total counter"]
        with self._lock:
            items = sorted(self._counters.items())
        for (name, labels), value in items:
            label_text = ",".join(f'{k}="{v}"' for k, v in labels)
            lines.append(f"{name}{{{label_text}}} {value:g}" if label_text else f"{name} {value:g}")
        return "\n".join(lines) + "\n"
