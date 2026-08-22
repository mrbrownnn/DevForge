"""The audit trail: append-only, hash-chained, and checkable.

Each entry carries the digest of the one before it. Editing an entry changes its
digest, which breaks the link the next entry holds, and every link after that.
Removing an entry does the same. So the trail does not prevent tampering - it
makes tampering *detectable*, which is the property an audit log can actually
provide on a filesystem the operator controls.

What this is and is not
-----------------------

It is a local file owned by the same user the control plane runs as. Somebody
with that user's privileges can delete it, and can rewrite the whole chain from
scratch. What they cannot do is quietly change one entry, which is the realistic
failure: a mistake being tidied away, not a determined attacker rebuilding
history.

An off-host log or a signature over the head would raise that bar. Both are
extension points; neither is implemented, because both need infrastructure this
project's measured workload does not justify.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from devforge.core.errors import DevForgeError
from devforge.observability.redaction import redact_value
from devforge.platform.identity import canonical
from devforge.platform.models import AuditEvent

AUDIT_FILENAME = "audit.jsonl"
#: The first entry's `previous`. A fixed, recognisable root so an empty chain and
#: a truncated one are distinguishable.
GENESIS = "0" * 64


def audit_path(root: Path) -> Path:
    return Path(root) / ".devforge" / "platform" / AUDIT_FILENAME


def digest_of(event: AuditEvent) -> str:
    """The hash an entry commits to: everything except the digest field itself."""
    material = canonical(
        {
            "sequence": event.sequence,
            "at": event.at.isoformat(),
            "event": event.event,
            "actor": event.actor,
            "task_id": event.task_id,
            "worker_id": event.worker_id,
            "detail": event.detail,
            "previous": event.previous,
        }
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class AuditTrail:
    """Appends events and can prove the chain is intact."""

    def __init__(self, root: Path) -> None:
        self.path = audit_path(root)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(
        self,
        event: str,
        *,
        actor: str = "control-plane",
        task_id: str = "",
        worker_id: str = "",
        **detail: Any,
    ) -> AuditEvent:
        """Append one event.

        ``detail`` is redacted before it is written. An audit trail is a durable,
        widely-read file, which makes it one of the worst places for a credential
        to land - so it goes through the same redaction boundary as every other
        persisted record rather than trusting callers.
        """
        entries = self.read()
        previous = entries[-1].digest if entries else GENESIS
        record = AuditEvent(
            sequence=len(entries),
            event=event,
            actor=actor,
            task_id=task_id,
            worker_id=worker_id,
            detail=redact_value(detail),
            previous=previous,
        )
        record.digest = digest_of(record)
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record.model_dump(mode="json"), sort_keys=True) + "\n")
        return record

    def read(self) -> list[AuditEvent]:
        if not self.path.is_file():
            return []
        entries: list[AuditEvent] = []
        for number, line in enumerate(self.path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                entries.append(AuditEvent.model_validate_json(line))
            except ValidationError as exc:
                raise DevForgeError(
                    f"{self.path}:{number} is not a valid audit entry: {exc}"
                ) from exc
        return entries

    def verify(self) -> list[str]:
        """Every broken link in the chain, in order. Empty means intact."""
        problems: list[str] = []
        previous = GENESIS
        for index, event in enumerate(self.read()):
            if event.sequence != index:
                problems.append(
                    f"entry {index}: sequence is {event.sequence}; an entry is missing "
                    "or was reordered"
                )
            if event.previous != previous:
                problems.append(
                    f"entry {index} ({event.event}): does not follow the entry before it"
                )
            recomputed = digest_of(event)
            if recomputed != event.digest:
                problems.append(
                    f"entry {index} ({event.event}): content does not match its digest"
                )
            previous = event.digest
        return problems

    def for_task(self, task_id: str) -> list[AuditEvent]:
        return [event for event in self.read() if event.task_id == task_id]
