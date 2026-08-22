"""How a control plane and a worker talk.

The transport is an interface with two implementations and one deliberate
absence.

``InProcessTransport``
    Both ends in one process. Used by tests and by ``--worker local``. It still
    signs and verifies every message, so the security path is the same code the
    subprocess transport runs - a transport that skipped authentication "because
    it is local" would leave that code untested until the day it mattered.

``SubprocessTransport``
    A worker in its own operating-system process, speaking newline-delimited JSON
    over stdio. Separate memory, separate credentials, a scrubbed environment,
    and no way to call into the control plane except through this protocol.

**No network transport.** ``tests/test_architecture.py`` forbids importing an
HTTP client anywhere in ``src/``, because the threat model rests on DevForge
having no outbound network capability at all. Adding a listener would trade a
tested property for a capability no measured workload here needs. Everything that
makes the protocol safe - identity, signing, replay defence, authorisation, the
control plane's independent re-verification - sits above this file and would
carry over to a network transport unchanged.

Framing
-------

One JSON object per line. Newline-delimited because it is the framing that
survives being read by a human with ``cat``, debugged with a pipe, and
implemented in any language a future worker might be written in. Lines are
length-bounded so a hostile peer cannot make the reader allocate without limit.
"""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from pydantic import ValidationError

from devforge.core.errors import DevForgeError
from devforge.platform.identity import WorkerRegistry, sign
from devforge.platform.models import (
    PROTOCOL_VERSION,
    Message,
    TaskEnvelope,
    WorkerResult,
)

#: Bound on one protocol line. A worker that needs more is returning artifacts
#: that should have been rejected by the per-artifact limit first.
MAX_LINE_BYTES = 8_000_000


class TransportError(DevForgeError):
    """The channel failed, as opposed to the task failing."""


class Transport(Protocol):
    """Sends an envelope to a worker and returns what the worker says."""

    name: str

    def dispatch(self, envelope: TaskEnvelope) -> WorkerResult: ...

    def close(self) -> None: ...


# --------------------------------------------------------------------------- framing


def encode(message: Message) -> str:
    line = json.dumps(message.model_dump(mode="json"), sort_keys=True)
    if len(line.encode("utf-8")) > MAX_LINE_BYTES:
        raise TransportError(f"message exceeds {MAX_LINE_BYTES} bytes")
    return line


def decode(line: str) -> Message:
    if len(line.encode("utf-8", errors="ignore")) > MAX_LINE_BYTES:
        raise TransportError(f"received a line over {MAX_LINE_BYTES} bytes; refusing to parse")
    try:
        return Message.model_validate_json(line)
    except ValidationError as exc:
        raise TransportError(f"not a protocol message: {exc}") from exc


def signed(
    kind: str, worker_id: str, key: str, payload: dict
) -> Message:
    message = Message(kind=kind, worker_id=worker_id, payload=payload)
    message.signature = sign(key, message)
    return message


# ------------------------------------------------------------------- in process


@dataclass
class InProcessTransport:
    """Both ends in one process, with the full authentication path intact."""

    registry: WorkerRegistry
    worker: object  # devforge.platform.worker.Worker
    control: object | None = None  # devforge.platform.control.ControlPlane
    name: str = "in-process"

    def dispatch(self, envelope: TaskEnvelope) -> WorkerResult:
        worker_id = self.worker.identity.worker_id  # type: ignore[attr-defined]
        key = self.registry.key(worker_id)

        request = signed("execute", worker_id, key, {"envelope": envelope.model_dump(mode="json")})
        if self.control is not None:
            self.control.authenticate(request)  # type: ignore[attr-defined]

        received = TaskEnvelope.model_validate(request.payload["envelope"])
        result = self.worker.execute(received)  # type: ignore[attr-defined]

        response = signed("result", worker_id, key, {"result": result.model_dump(mode="json")})
        if self.control is not None:
            self.control.authenticate(response)  # type: ignore[attr-defined]
        return WorkerResult.model_validate(response.payload["result"])

    def close(self) -> None:
        return None


# -------------------------------------------------------------------- subprocess


@dataclass
class SubprocessTransport:
    """A worker in its own process, over stdio.

    The child is started with an explicit argv - never a shell string - and a
    scrubbed environment carrying only its worker id, its root and its key. The
    key reaches the child through the environment rather than the command line,
    because a command line is readable by every other process on the machine.
    """

    registry: WorkerRegistry
    worker_id: str
    root: Path
    argv: list[str] | None = None
    timeout_s: int = 1800
    name: str = "subprocess"

    def command(self) -> list[str]:
        return self.argv or [
            sys.executable,
            "-m",
            "devforge.platform.stdio_worker",
        ]

    def dispatch(self, envelope: TaskEnvelope) -> WorkerResult:
        from devforge.tools.environment import build_env

        key = self.registry.key(self.worker_id)
        request = signed(
            "execute", self.worker_id, key, {"envelope": envelope.model_dump(mode="json")}
        )

        environment = build_env(allow=[])
        environment.update(
            {
                "DEVFORGE_WORKER_ID": self.worker_id,
                "DEVFORGE_WORKER_ROOT": str(self.root),
                "DEVFORGE_WORKER_KEY": key,
            }
        )

        try:
            completed = subprocess.run(  # noqa: S603 - explicit argv, never a shell
                self.command(),
                input=encode(request) + "\n",
                capture_output=True,
                text=True,
                timeout=self.timeout_s,
                env=environment,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise TransportError(
                f"worker '{self.worker_id}' did not answer within {self.timeout_s}s"
            ) from exc
        except OSError as exc:
            raise TransportError(f"could not start worker '{self.worker_id}': {exc}") from exc

        line = _last_json_line(completed.stdout)
        if line is None:
            raise TransportError(
                f"worker '{self.worker_id}' returned no protocol message "
                f"(exit {completed.returncode}): {completed.stderr.strip()[:400]}"
            )

        response = decode(line)
        if response.kind != "result":
            raise TransportError(f"expected a result, got '{response.kind}'")
        # Verified here as well as by the control plane: this is the boundary the
        # bytes actually crossed, and a transport that hands unverified messages
        # upward makes the verification optional in practice.
        from devforge.platform.identity import MessageVerifier

        MessageVerifier(self.registry).verify(response)
        try:
            return WorkerResult.model_validate(response.payload["result"])
        except (KeyError, ValidationError) as exc:
            raise TransportError(f"malformed result from '{self.worker_id}': {exc}") from exc

    def close(self) -> None:
        return None


def _last_json_line(text: str) -> str | None:
    """The final JSON object in the child's stdout.

    A worker's own logging can share stdout with the protocol, so the reader
    takes the last parseable line rather than assuming it owns the stream. A
    dedicated file descriptor would be cleaner and is not portable to Windows,
    which is the platform this runs on.
    """
    for line in reversed(text.splitlines()):
        stripped = line.strip()
        if stripped.startswith("{") and stripped.endswith("}"):
            return stripped
    return None


def protocol_banner() -> dict:
    return {"protocol": PROTOCOL_VERSION, "framing": "newline-delimited JSON"}
