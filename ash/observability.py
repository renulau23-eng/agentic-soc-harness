"""Structured logging and lightweight metrics with zero external dependencies.

Logs are JSON lines carrying trace/case/run context from a contextvar so every
component logs consistently without threading IDs through signatures.

Metrics are Prometheus-text-format compatible so an on-prem Prometheus can
scrape ``/metrics`` directly.
"""

from __future__ import annotations

import contextvars
import json
import logging
import sys
import threading
import time
from collections import defaultdict
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

_context: contextvars.ContextVar[dict[str, Any]] = contextvars.ContextVar("ash_log_ctx")


def _ctx() -> dict[str, Any]:
    return _context.get({})


REDACT_KEYS = {"api_key", "password", "secret", "token", "authorization", "jwt_secret"}


def bind(**fields: Any) -> contextvars.Token:
    merged = {**_ctx(), **fields}
    return _context.set(merged)


def unbind(token: contextvars.Token) -> None:
    _context.reset(token)


@contextmanager
def log_context(**fields: Any) -> Iterator[None]:
    token = bind(**fields)
    try:
        yield
    finally:
        unbind(token)


def redact(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: ("***" if k.lower() in REDACT_KEYS else redact(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    return obj


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)) + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            **_ctx(),
        }
        extra = getattr(record, "extra_fields", None)
        if extra:
            payload.update(redact(extra))
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


class TextFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        ctx = " ".join(f"{k}={v}" for k, v in _ctx().items())
        extra = getattr(record, "extra_fields", None)
        ex = " " + json.dumps(redact(extra), default=str) if extra else ""
        return f"{record.levelname:<7} {record.name}: {record.getMessage()} {ctx}{ex}"


def configure_logging(level: str = "INFO", json_logs: bool = True) -> None:
    root = logging.getLogger()
    root.handlers.clear()
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter() if json_logs else TextFormatter())
    root.addHandler(handler)
    root.setLevel(level.upper())
    logging.getLogger("uvicorn.access").setLevel("WARNING")


class Logger:
    """Tiny adapter so call sites can do ``log.info("msg", key=value)``."""

    def __init__(self, name: str):
        self._log = logging.getLogger(name)

    def _emit(self, level: int, msg: str, exc_info: bool = False, **fields: Any) -> None:
        self._log.log(level, msg, exc_info=exc_info, extra={"extra_fields": fields} if fields else None)

    def debug(self, msg: str, **f: Any) -> None:
        self._emit(logging.DEBUG, msg, **f)

    def info(self, msg: str, **f: Any) -> None:
        self._emit(logging.INFO, msg, **f)

    def warning(self, msg: str, **f: Any) -> None:
        self._emit(logging.WARNING, msg, **f)

    def error(self, msg: str, exc_info: bool = False, **f: Any) -> None:
        self._emit(logging.ERROR, msg, exc_info=exc_info, **f)


def get_logger(name: str) -> Logger:
    return Logger(name)


# --------------------------------------------------------------------------- #
# Metrics
# --------------------------------------------------------------------------- #


class Metrics:
    """Thread-safe counters and histograms, rendered in Prometheus text format."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[tuple[str, tuple[tuple[str, str], ...]], float] = defaultdict(float)
        self._hist: dict[tuple[str, tuple[tuple[str, str], ...]], list[float]] = defaultdict(list)

    @staticmethod
    def _key(name: str, labels: dict[str, str] | None) -> tuple[str, tuple[tuple[str, str], ...]]:
        return name, tuple(sorted((labels or {}).items()))

    def inc(self, name: str, value: float = 1.0, **labels: str) -> None:
        with self._lock:
            self._counters[self._key(name, labels)] += value

    def observe(self, name: str, value: float, **labels: str) -> None:
        with self._lock:
            self._hist[self._key(name, labels)].append(value)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            counters = {self._fmt(k): v for k, v in self._counters.items()}
            hists = {
                self._fmt(k): {"count": len(v), "sum": sum(v), "max": max(v) if v else 0.0}
                for k, v in self._hist.items()
            }
        return {"counters": counters, "histograms": hists}

    @staticmethod
    def _fmt(key: tuple[str, tuple[tuple[str, str], ...]]) -> str:
        name, labels = key
        if not labels:
            return name
        return name + "{" + ",".join(f'{k}="{v}"' for k, v in labels) + "}"

    def render_prometheus(self) -> str:
        lines: list[str] = []
        snap = self.snapshot()
        for k, v in sorted(snap["counters"].items()):
            lines.append(f"{k} {v}")
        for k, h in sorted(snap["histograms"].items()):
            base, _, labels = k.partition("{")
            lb = "{" + labels if labels else ""
            lines.append(f"{base}_count{lb} {h['count']}")
            lines.append(f"{base}_sum{lb} {h['sum']}")
        return "\n".join(lines) + "\n"

    def reset(self) -> None:
        with self._lock:
            self._counters.clear()
            self._hist.clear()


metrics = Metrics()
