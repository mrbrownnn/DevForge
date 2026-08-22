"""The worker: executes tasks, and is not trusted while it does.

A worker holds an identity, declares capabilities, and refuses envelopes that ask
for more than it was given - *again*, after the control plane has already checked.
That duplication is deliberate. The control plane's check protects the operator
from work going to the wrong machine. The worker's check protects the machine
from a control plane that has been persuaded, compromised, or misconfigured into
asking for something the operator never permitted here.

Execution runs through the ordinary machinery: an isolated workspace, a policy
engine bound to it, a scrubbed environment, and the same orchestrator the local
CLI uses. Nothing about being remote weakens what runs - which is the property
the phase exists to preserve.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

from devforge.core.errors import DevForgeError
from devforge.core.models import Approval, ApprovalStatus, Task, utcnow
from devforge.core.state.store import ProjectStore
from devforge.observability.logging import RunLogger, null_logger
from devforge.platform.identity import authorize
from devforge.platform.isolation import (
    collect_artifacts,
    discard_workspace,
    prepare_workspace,
)
from devforge.platform.models import (
    Capability,
    TaskEnvelope,
    VerificationClaim,
    WorkerIdentity,
    WorkerResult,
)
from devforge.policy.engine import PolicyEngine


class Worker:
    """Executes one envelope at a time, inside its own root."""

    def __init__(
        self,
        identity: WorkerIdentity,
        *,
        root: Path,
        logger: RunLogger | None = None,
        runtime_factory: object | None = None,
    ) -> None:
        self.identity = identity
        self.root = Path(root).resolve()
        self.logger = logger or null_logger()
        #: Test and extension seam: a callable returning an AgentRuntime, for a
        #: runtime the registry cannot name.
        self.runtime_factory = runtime_factory

    # -- execution --------------------------------------------------------------

    def execute(self, envelope: TaskEnvelope) -> WorkerResult:
        """Run a task and report what happened. Every field of the result is a claim."""
        started = time.monotonic()
        result = WorkerResult(task_id=envelope.task_id, worker_id=self.identity.worker_id)

        try:
            # Re-authorised here, not only at the control plane. See the module
            # docstring: the two checks defend against different failures.
            authorize(self.identity, envelope)
        except DevForgeError as exc:
            result.error = f"refused: {exc}"
            result.duration_ms = int((time.monotonic() - started) * 1000)
            self.logger.info(
                "worker.refused", task_id=envelope.task_id, reason=str(exc)
            )
            return result

        workspace = prepare_workspace(self.root, envelope)
        try:
            result = self._run(envelope, workspace, result)
        except DevForgeError as exc:
            result.ok = False
            result.error = str(exc)
        except Exception as exc:  # a broken task must not take the worker down
            result.ok = False
            result.error = f"{type(exc).__name__}: {exc}"
        finally:
            result.duration_ms = int((time.monotonic() - started) * 1000)
            if result.ok:
                # Kept on failure so a person can look at what went wrong; a
                # successful task's workspace has nothing left to say.
                discard_workspace(self.root, envelope.task_id)

        self.logger.info(
            "worker.executed",
            task_id=envelope.task_id,
            ok=result.ok,
            artifacts=len(result.artifacts),
        )
        return result

    def _run(
        self, envelope: TaskEnvelope, workspace: Path, result: WorkerResult
    ) -> WorkerResult:
        from devforge.core.orchestrator.context import AppContext

        ProjectStore.initialize(
            workspace,
            name=f"task-{envelope.task_id}",
            default_runtime=envelope.runtime,
            force=True,
        )
        ctx = AppContext.load(workspace)
        spec = ctx.workflows.load(envelope.workflow)

        policy = PolicyEngine.load(workspace, workspace=workspace)
        runtime = (
            self.runtime_factory()  # type: ignore[operator]
            if self.runtime_factory is not None
            else ctx.runtimes.create(envelope.runtime)
        )
        availability = runtime.availability()
        if not availability.available:
            result.error = f"runtime '{envelope.runtime}' is unavailable: {availability.detail}"
            return result

        task = Task(
            project_id=envelope.project_id or ctx.config.project_id,
            description=envelope.description,
            workflow=spec.name,
            runtime=envelope.runtime,
        )
        # A decision the control plane already made is recorded on the task as a
        # decision, not re-asked here. There is no prompter: a worker has nobody
        # to ask, and a prompter that answered would be the worker deciding.
        # Gates nobody approved stay pending, which pauses the run instead of
        # rejecting it - the difference between "not yet" and "no".
        _seed_approvals(task, spec, envelope.approved_gates)

        orchestrator = ctx.orchestrator(
            runtime=runtime,
            logger=self.logger,
            prompter=None,
        )
        orchestrator.policy = policy
        orchestrator.workspace = workspace

        outcome = asyncio.run(orchestrator.run(task, spec))

        result.ok = outcome.completed
        result.summary = outcome.reason or outcome.status.value
        result.output = "\n".join(
            f"{step.step_id}: {step.status.value}" for step in task.steps
        )
        result.claims = [
            VerificationClaim(
                verifier=verification.verifier,
                status=verification.status.value,
                summary=verification.summary,
                exit_code=verification.exit_code,
            )
            for verification in task.verification_results
        ]
        result.artifacts = collect_artifacts(workspace, envelope.verify)
        result.metadata = {
            "steps": len(task.steps),
            "attempts": sum(step.attempt_count for step in task.steps),
            "pending_gates": outcome.pending_gates,
        }
        if not result.ok and not result.error:
            result.error = outcome.reason or "the run did not complete"
        return result

    # -- description ------------------------------------------------------------

    def describe(self) -> dict:
        return {
            "worker_id": self.identity.worker_id,
            "root": str(self.root),
            "capabilities": [capability.value for capability in self.identity.capabilities],
            "tools": list(self.identity.tools),
            "runtimes": list(self.identity.runtimes),
        }


def _seed_approvals(task: Task, spec: object, gates: list[str]) -> None:
    """Write the control plane's decisions onto the task before the run starts.

    The approval gate reads an existing non-pending decision and moves on, so
    seeding is how a granted gate becomes granted without anybody at this end
    being asked. The record names the control plane as the decider, because that
    is where the human actually decided.
    """
    for step in getattr(spec, "steps", []):
        gate = getattr(step, "gate", None)
        if not gate or gate not in gates:
            continue
        task.approvals.append(
            Approval(
                gate=gate,
                step_id=step.id,
                status=ApprovalStatus.APPROVED,
                decided_at=utcnow(),
                decided_by="control-plane",
                reason="approved through the control plane before dispatch",
            )
        )


def default_capabilities() -> list[Capability]:
    """What a worker gets when nobody says otherwise.

    Agents, tools and verification - not the browser, not the shell, not the
    network. An operator who wants those grants them explicitly, because each is
    a capability whose absence is a real reduction in what a compromised worker
    can reach.
    """
    return [Capability.AGENT, Capability.TOOLS, Capability.VERIFY]
