"""The worker process entry point: read one signed envelope, execute, answer.

``python -m devforge.platform.stdio_worker``

It takes its identity, its root and its key from the environment, because a key
on a command line is readable by every other process on the machine.

The worker verifies the control plane's message before acting on it. A worker
that executed whatever arrived on its stdin would be a remote code execution
endpoint for anything that could write to that pipe.

One envelope per process. Not because a long-lived worker is wrong, but because
a process that exits after each task cannot carry state from one task into the
next - which is the cheapest possible task isolation, and it costs an interpreter
start.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from devforge.core.errors import DevForgeError
from devforge.platform.identity import MessageVerifier, WorkerRegistry, sign
from devforge.platform.models import Message, TaskEnvelope, WorkerResult
from devforge.platform.transport import decode, encode
from devforge.platform.worker import Worker


def main(argv: list[str] | None = None) -> int:
    worker_id = os.environ.get("DEVFORGE_WORKER_ID", "")
    root = os.environ.get("DEVFORGE_WORKER_ROOT", "")
    key = os.environ.get("DEVFORGE_WORKER_KEY", "")

    if not (worker_id and root and key):
        print(
            "DEVFORGE_WORKER_ID, DEVFORGE_WORKER_ROOT and DEVFORGE_WORKER_KEY "
            "must all be set",
            file=sys.stderr,
        )
        return 2

    line = sys.stdin.readline()
    if not line.strip():
        print("no envelope on stdin", file=sys.stderr)
        return 2

    try:
        request = decode(line)
    except DevForgeError as exc:
        print(f"unreadable request: {exc}", file=sys.stderr)
        return 2

    registry = WorkerRegistry(Path(root))
    try:
        # The control plane signs with this worker's key, so verifying proves the
        # request came from something holding it. It is not proof of *which* side
        # sent it - a shared secret cannot distinguish two holders - and that
        # limitation is recorded in docs/platform.md.
        MessageVerifier(registry).verify(request)
    except DevForgeError as exc:
        print(f"refusing an unauthenticated request: {exc}", file=sys.stderr)
        return 3

    if request.kind != "execute":
        print(f"unexpected message kind '{request.kind}'", file=sys.stderr)
        return 2

    try:
        envelope = TaskEnvelope.model_validate(request.payload["envelope"])
    except (KeyError, ValueError) as exc:
        print(f"malformed envelope: {exc}", file=sys.stderr)
        return 2

    identity = registry.require(worker_id)
    result = Worker(identity, root=Path(root)).execute(envelope)
    _answer(result, worker_id=worker_id, key=key)
    return 0 if result.ok else 1


def _answer(result: WorkerResult, *, worker_id: str, key: str) -> None:
    """Write the one line the control plane reads.

    Written last and alone: anything else this process printed went to stderr, so
    the protocol line is unambiguous even when the task itself was noisy.
    """
    message = Message(
        kind="result", worker_id=worker_id, payload={"result": result.model_dump(mode="json")}
    )
    message.signature = sign(key, message)
    sys.stdout.write(encode(message) + "\n")
    sys.stdout.flush()


if __name__ == "__main__":  # pragma: no cover - process entry point
    raise SystemExit(main())
