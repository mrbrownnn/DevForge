"""Structured event logging.

Every meaningful thing DevForge does emits a JSON event carrying the fields the
brief requires: ``task_id, agent, workflow, step, tool, timestamp, duration_ms,
status, error, verification``. Events go to two sinks:

* a JSONL file at ``.devforge/runs/<task_id>/events.jsonl`` (durable, per run)
* an optional console sink (human-readable or raw JSON)

There is no global logger singleton: a :class:`RunLogger` is constructed with a
run directory and injected. Metrics/tracing can be added later by attaching
another sink - the event dict is already the natural span payload.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable, Iterator
from datetime import datetime
from pathlib import Path
from typing import Any, TextIO

from devforge.core.models import utcnow
from devforge.observability.redaction import redact_value

EventSink = Callable[[dict[str, Any]], None]


def _json_default(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def jsonl_sink(path: Path) -> EventSink:
    """Append events to a JSONL file, creating parent directories as needed."""
    path.parent.mkdir(parents=True, exist_ok=True)

    def sink(event: dict[str, Any]) -> None:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, default=_json_default) + "\n")

    return sink


def stream_sink(stream: TextIO | None = None) -> EventSink:
    """Write raw JSON events to a stream (default stderr, so stdout stays parseable)."""
    target = stream if stream is not None else sys.stderr

    def sink(event: dict[str, Any]) -> None:
        target.write(json.dumps(event, default=_json_default) + "\n")
        target.flush()

    return sink


class RunLogger:
    """Emits structured events for one task run.

    ``bind`` returns a child logger with extra default fields, which is how the
    orchestrator attaches ``step``/``agent`` without threading them through every
    call site.
    """

    def __init__(self, sinks: list[EventSink] | None = None, **defaults: Any) -> None:
        self._sinks: list[EventSink] = list(sinks or [])
        self._defaults = {k: v for k, v in defaults.items() if v is not None}

    def bind(self, **fields: Any) -> RunLogger:
        merged = {**self._defaults, **{k: v for k, v in fields.items() if v is not None}}
        return RunLogger(self._sinks, **merged)

    def add_sink(self, sink: EventSink) -> None:
        self._sinks.append(sink)

    def emit(self, event: str, **fields: Any) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "timestamp": utcnow().isoformat(),
            "event": event,
            **self._defaults,
            **{k: v for k, v in fields.items() if v is not None},
        }
        # Redact before any sink sees the event (threat T12). One boundary, so a new
        # sink cannot bypass it.
        payload = redact_value(payload)
        for sink in self._sinks:
            sink(payload)
        return payload

    # Convenience wrappers - thin on purpose, so the event vocabulary stays open.

    def info(self, event: str, **fields: Any) -> dict[str, Any]:
        return self.emit(event, level="info", **fields)

    def warn(self, event: str, **fields: Any) -> dict[str, Any]:
        return self.emit(event, level="warning", **fields)

    def error(self, event: str, **fields: Any) -> dict[str, Any]:
        return self.emit(event, level="error", **fields)


def null_logger() -> RunLogger:
    """A logger that discards events - useful in unit tests."""
    return RunLogger([])


def read_events(path: Path) -> Iterator[dict[str, Any]]:
    """Read back a JSONL event log, skipping malformed lines rather than raising."""
    if not path.exists():
        return
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue
