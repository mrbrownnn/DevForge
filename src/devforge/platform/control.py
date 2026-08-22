"""The control plane.

It owns the queue, the identities, the audit trail and the artifacts of record.
It does not execute anything.

The load-bearing decision in this file is what happens when a worker says it
succeeded. The answer is: nothing yet. ``accept`` records the claim, stores the
artifacts it was given, and then **re-runs verification itself** over those
artifacts. A task reaches ``VERIFIED`` because the control plane checked, never
because a worker reported it.

That is what "assume workers can be compromised" has to mean in code. A worker
that lies about its tests is the cheapest possible attack - it costs nothing and
it is invisible if the control plane takes results at face value. Here it fails,
loudly, with the mismatch recorded in the audit trail.
"""

from __future__ import annotations

from pathlib import Path

from devforge.core.errors import DevForgeError
from devforge.core.state.store import ProjectStore
from devforge.observability.logging import RunLogger, null_logger
from devforge.platform.audit import AuditTrail
from devforge.platform.identity import (
    AuthzError,
    MessageVerifier,
    WorkerRegistry,
    authorize,
)
from devforge.platform.isolation import store_artifacts
from devforge.platform.models import (
    Lease,
    Message,
    TaskEnvelope,
    TaskRecord,
    TaskState,
    VerificationClaim,
    WorkerIdentity,
    WorkerResult,
)
from devforge.platform.queue import DEFAULT_LEASE_S, TaskQueue


class ControlPlane:
    """Scheduling, state, policy, approvals, observability and artifacts."""

    def __init__(
        self,
        root: Path,
        *,
        logger: RunLogger | None = None,
        store: ProjectStore | None = None,
    ) -> None:
        self.root = Path(root).resolve()
        self.queue = TaskQueue(self.root)
        self.registry = WorkerRegistry(self.root)
        self.audit = AuditTrail(self.root)
        self.verifier = MessageVerifier(self.registry)
        self.logger = logger or null_logger()
        self._store = store

    @property
    def store(self) -> ProjectStore:
        if self._store is None:
            self._store = ProjectStore.discover(self.root)
        return self._store

    # -- workers ----------------------------------------------------------------

    def register_worker(self, **kwargs) -> tuple[WorkerIdentity, str]:
        """Register a worker and audit it here, not at whichever caller asked.

        Registration creates a credential, which is exactly the kind of event an
        operator reads a trail to find. Leaving the record to the CLI would mean
        a second caller could create one silently.
        """
        identity, key = self.registry.register(**kwargs)
        self.audit.record(
            "worker.registered",
            worker_id=identity.worker_id,
            capabilities=[capability.value for capability in identity.capabilities],
            tools=identity.tools,
            fingerprint=identity.key_fingerprint,
        )
        return identity, key

    def revoke_worker(self, worker_id: str) -> WorkerIdentity:
        identity = self.registry.revoke(worker_id)
        self.audit.record("worker.revoked", worker_id=identity.worker_id)
        return identity

    # -- submit -----------------------------------------------------------------

    def submit(self, envelope: TaskEnvelope) -> TaskRecord:
        record = self.queue.submit(envelope)
        self.audit.record(
            "task.submitted",
            task_id=record.task_id,
            workflow=envelope.workflow,
            requires=[capability.value for capability in envelope.requires],
            tools=envelope.tools,
        )
        self.logger.info("platform.submit", task_id=record.task_id)
        return record

    # -- schedule ---------------------------------------------------------------

    def schedulable(self, identity: WorkerIdentity) -> list[TaskRecord]:
        """Ready tasks this worker is actually allowed to run.

        Authorisation is part of scheduling rather than a check after it. A task a
        worker may not run is not a task that worker is waiting for, and treating
        it as one produces a queue that looks busy and never drains.
        """
        allowed: list[TaskRecord] = []
        for record in self.queue.ready():
            try:
                authorize(identity, record.envelope)
            except AuthzError:
                continue
            allowed.append(record)
        return allowed

    def lease_next(
        self, worker_id: str, *, seconds: int = DEFAULT_LEASE_S
    ) -> tuple[TaskRecord, Lease] | None:
        """Hand the oldest permitted task to a worker, or nothing."""
        identity = self.registry.require(worker_id)
        candidates = self.schedulable(identity)
        if not candidates:
            return None

        record = candidates[0]
        # Checked again immediately before granting: `schedulable` filtered a
        # snapshot, and the registry could have changed since it was taken.
        authorize(identity, record.envelope)
        lease = self.queue.lease(identity, record, seconds=seconds)
        self.audit.record(
            "task.leased",
            task_id=record.task_id,
            worker_id=worker_id,
            attempt=record.attempts,
            expires_at=lease.expires_at.isoformat(),
        )
        self.logger.info("platform.lease", task_id=record.task_id, worker=worker_id)
        return record, lease

    # -- accept -----------------------------------------------------------------

    def accept(self, result: WorkerResult, *, verify: bool = True) -> TaskRecord:
        """Take a result, store its artifacts, then check it independently."""
        record = self.queue.load(result.task_id)
        self.queue.check_lease(record, result.worker_id)

        record.result = result
        record.state = TaskState.EXECUTED
        record.touch()
        self.queue.save(record)

        pending = _pending_gates(result)
        if pending and not result.ok:
            # Not a failure: a question. The run stopped where a human has to
            # decide, and the control plane is where that decision is made.
            record.state = TaskState.AWAITING_APPROVAL
            record.reason = f"waiting on approval for {', '.join(pending)}"
            record.lease = None
            self.queue.save(record)
            self.audit.record(
                "task.awaiting_approval",
                task_id=record.task_id,
                worker_id=result.worker_id,
                gates=pending,
            )
            return record
        self.audit.record(
            "task.result_received",
            task_id=record.task_id,
            worker_id=result.worker_id,
            claimed_ok=result.ok,
            artifacts=len(result.artifacts),
            claims=[claim.verifier for claim in result.claims],
        )

        try:
            destination = self.store.artifacts_dir(record.task_id)
        except DevForgeError:
            destination = self.root / ".devforge" / "platform" / "artifacts" / record.task_id
        try:
            record.artifact_paths = store_artifacts(destination, result.artifacts)
        except DevForgeError as exc:
            record.state = TaskState.REJECTED
            record.reason = f"artifacts were refused: {exc}"
            self.queue.save(record)
            self.audit.record(
                "task.rejected",
                task_id=record.task_id,
                worker_id=result.worker_id,
                reason=record.reason,
            )
            return record

        if not verify:
            self.queue.save(record)
            return record
        return self.verify(record, destination)

    # -- approvals --------------------------------------------------------------

    def approve(self, task_id: str, gate: str, *, by: str = "", reason: str = "") -> TaskRecord:
        """Record a human's decision and put the task back on the queue.

        The grant is per gate and travels in the envelope, so a worker that runs
        the task next answers exactly this gate and declines any other. Approval
        authority never leaves the control plane; what crosses is a decision
        somebody already made.
        """
        record = self.queue.load(task_id)
        if record.state is not TaskState.AWAITING_APPROVAL:
            raise DevForgeError(
                f"task '{task_id}' is {record.state.value}; nothing is waiting for approval"
            )
        if gate not in record.envelope.approved_gates:
            record.envelope.approved_gates.append(gate)
        record.state = TaskState.QUEUED
        record.reason = f"gate '{gate}' approved by {by or 'an operator'}"
        self.queue.save(record)
        self.audit.record(
            "approval.granted",
            task_id=task_id,
            actor=by or "operator",
            gate=gate,
            reason=reason,
        )
        return record

    def reject(self, task_id: str, gate: str, *, by: str = "", reason: str = "") -> TaskRecord:
        record = self.queue.load(task_id)
        record.state = TaskState.REJECTED
        record.reason = f"gate '{gate}' rejected by {by or 'an operator'}: {reason}".strip(": ")
        self.queue.save(record)
        self.audit.record(
            "approval.refused",
            task_id=task_id,
            actor=by or "operator",
            gate=gate,
            reason=reason,
        )
        return record

    # -- verify -----------------------------------------------------------------

    def verify(self, record: TaskRecord, artifacts: Path) -> TaskRecord:
        """Re-run the task's verifiers here, over the artifacts that arrived.

        The worker's claims are kept beside the result and are never read as
        evidence. A worker that reported green tests and shipped artifacts that
        fail them is rejected, and the mismatch is what the audit trail records.
        """
        confirmed: list[VerificationClaim] = []
        for verifier in record.envelope.verify:
            confirmed.append(self._run_verifier(verifier, artifacts))

        record.verified = confirmed
        failed = [claim.verifier for claim in confirmed if claim.status != "passed"]

        claimed_ok = bool(record.result and record.result.ok)
        if failed:
            record.state = TaskState.REJECTED
            record.reason = (
                f"verification failed here for {', '.join(failed)}"
                + (
                    "; the worker reported success, so its report and this result disagree"
                    if claimed_ok
                    else ""
                )
            )
        elif not claimed_ok:
            record.state = TaskState.FAILED
            record.reason = record.result.error if record.result else "the worker reported failure"
        elif not record.envelope.verify:
            # Nothing was declared, so nothing was checked. Calling that
            # "verified" would put the strongest word in the vocabulary on the
            # weakest evidence there is - a worker's opinion of itself.
            record.state = TaskState.EXECUTED
            record.reason = (
                "the worker reported success and no verifier was declared, so the "
                "control plane confirmed nothing independently"
            )
        else:
            record.state = TaskState.VERIFIED
            record.reason = "verified by the control plane against the artifacts it received"

        record.lease = None
        self.queue.save(record)
        self.audit.record(
            f"task.{record.state.value}",
            task_id=record.task_id,
            worker_id=record.result.worker_id if record.result else "",
            state=record.state.value,
            reason=record.reason,
            confirmed=[claim.verifier for claim in confirmed],
            disagreed=bool(failed and claimed_ok),
        )
        self.logger.info(
            "platform.verify", task_id=record.task_id, state=record.state.value
        )
        return record

    def _run_verifier(self, verifier: str, artifacts: Path) -> VerificationClaim:
        """Run one verifier over the returned artifacts.

        An artifact verifier is the only kind that means anything here: the
        control plane holds files, not the worker's workspace, so a command
        verifier would be running against a tree that no longer exists. That
        limit is stated in the claim's summary rather than hidden by returning
        `passed`.
        """
        expected = verifier.strip()
        if not expected:
            return VerificationClaim(
                verifier=verifier, status="skipped", summary="empty verifier id"
            )
        target = artifacts / expected
        if target.exists():
            return VerificationClaim(
                verifier=verifier,
                status="passed",
                summary=f"'{expected}' is present among the returned artifacts",
            )
        return VerificationClaim(
            verifier=verifier,
            status="failed",
            summary=f"'{expected}' was declared but is not among the returned artifacts",
        )

    # -- messages ---------------------------------------------------------------

    def authenticate(self, message: Message) -> WorkerIdentity:
        try:
            identity = self.verifier.verify(message)
        except DevForgeError as exc:
            # Recorded before it is raised: a rejected message is exactly the
            # thing an operator wants in the trail, and an exception on its way
            # up the stack is not evidence of anything.
            self.audit.record(
                "auth.rejected",
                worker_id=message.worker_id,
                kind=message.kind,
                reason=str(exc),
            )
            raise
        return identity

    # -- observability ----------------------------------------------------------

    def awaiting_approval(self) -> list[TaskRecord]:
        return [
            record
            for record in self.queue.all()
            if record.state is TaskState.AWAITING_APPROVAL
        ]

    def status(self) -> dict:
        return {
            "root": str(self.root),
            "counts": self.queue.counts(),
            "workers": [
                {
                    "worker_id": identity.worker_id,
                    "enabled": identity.enabled,
                    "capabilities": [c.value for c in identity.capabilities],
                }
                for identity in self.registry.all()
            ],
            "audit_entries": len(self.audit.read()),
            "audit_intact": not self.audit.verify(),
            "unreadable_queue_files": self.queue.unreadable(),
        }


def _pending_gates(result: WorkerResult) -> list[str]:
    """Gates the worker reported it could not pass.

    Read from metadata rather than trusted as a control signal: the worst a
    lying worker achieves here is asking for an approval nobody was going to
    give, which a human then declines.
    """
    gates = result.metadata.get("pending_gates")
    return [str(gate) for gate in gates] if isinstance(gates, list) else []
