"""The orchestrator.

One loop drives every workflow::

    for step in workflow:
        agent step   -> invoke -> verify -> (repair -> verify)* up to max_attempts
        verify step  -> verify only
        approval step-> request a human decision, pause if it is not yet given

Design constraints this file deliberately respects:

* It knows nothing about any specific runtime, tool or verifier - only their
  interfaces, all injected through :class:`Orchestrator` construction.
* It never trusts an agent's own report of success. ``AgentResult.ok`` only means
  the runtime worked; passing a step requires the verifiers to agree.
* It persists after every attempt, so a crashed or interrupted process resumes
  rather than restarts.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from devforge.agents.prompt import build_invocation
from devforge.agents.spec import AgentRegistry
from devforge.approval.gate import ApprovalGate
from devforge.core.models import (
    ApprovalStatus,
    StepAttempt,
    StepRecord,
    StepStatus,
    Task,
    TaskStatus,
    utcnow,
)
from devforge.core.registry.skills import SkillRegistry
from devforge.core.state.store import ProjectStore
from devforge.core.workflow.spec import OnFailure, StepKind, WorkflowSpec, WorkflowStep
from devforge.observability.logging import RunLogger
from devforge.policy.engine import PolicyEngine
from devforge.runtime.base import AgentRuntime, RuntimeContext
from devforge.tools.base import ToolRegistry
from devforge.verification.base import VerificationContext
from devforge.verification.engine import VerificationEngine, VerificationReport


@dataclass
class RunOutcome:
    """What a call to :meth:`Orchestrator.run` did."""

    task: Task
    stopped_at: str | None = None
    reason: str = ""

    @property
    def awaiting_approval(self) -> bool:
        return self.task.status is TaskStatus.AWAITING_APPROVAL

    @property
    def completed(self) -> bool:
        return self.task.status is TaskStatus.COMPLETED


class Orchestrator:
    """Executes a workflow against a task. All collaborators are injected."""

    def __init__(
        self,
        *,
        store: ProjectStore,
        runtime: AgentRuntime,
        tools: ToolRegistry,
        skills: SkillRegistry,
        agents: AgentRegistry,
        verification: VerificationEngine,
        approvals: ApprovalGate,
        policy: PolicyEngine,
        logger: RunLogger,
        workspace: Path | None = None,
    ) -> None:
        self.store = store
        self.runtime = runtime
        self.tools = tools
        self.skills = skills
        self.agents = agents
        self.verification = verification
        self.approvals = approvals
        self.policy = policy
        self.logger = logger
        self.workspace = Path(workspace or store.root)

    # -- entry point ------------------------------------------------------------

    async def run(self, task: Task, workflow: WorkflowSpec) -> RunOutcome:
        specs = self.verification.collect_specs(workflow, self.store.load_config().verifiers)
        missing = workflow.missing_verifiers(set(specs))
        if missing:
            return self._fail_run(
                task, "configuration", f"workflow references undefined verifiers: {sorted(missing)}"
            )

        task.status = TaskStatus.RUNNING
        self.store.save_task(task)
        self.logger.info(
            "run.start",
            task_id=task.task_id,
            workflow=workflow.name,
            runtime=self.runtime.name,
            steps=len(workflow.steps),
            resumed=bool(task.completed_steps),
        )

        for step in workflow.steps:
            record = task.ensure_step(step.id, kind=step.kind.value, agent=step.agent)
            if record.status in {StepStatus.PASSED, StepStatus.SKIPPED}:
                continue

            task.current_step = step.id
            self.store.save_task(task)

            outcome = await self._run_step(task, workflow, step, record, specs)
            if outcome is not None:
                return outcome

        task.status = TaskStatus.COMPLETED
        task.current_step = None
        self.store.save_task(task)
        self.logger.info("run.finish", task_id=task.task_id, status=task.status.value)
        return RunOutcome(task=task, reason="workflow completed")

    # -- steps ------------------------------------------------------------------

    async def _run_step(
        self,
        task: Task,
        workflow: WorkflowSpec,
        step: WorkflowStep,
        record: StepRecord,
        specs: dict,
    ) -> RunOutcome | None:
        """Run one step. Returns a RunOutcome when the run must stop here."""
        record.status = StepStatus.RUNNING
        record.started_at = record.started_at or utcnow()
        logger = self.logger.bind(task_id=task.task_id, step=step.id, agent=step.agent)
        logger.info("step.start", kind=step.kind.value, workflow=workflow.name)

        if step.kind is StepKind.APPROVAL:
            return self._run_approval_step(task, step, record, logger)

        unavailable = self.tools.unavailable_names(step.tools)
        if unavailable:
            detail = "; ".join(
                f"{name}: {self.tools.get(name).availability().detail}" for name in unavailable
            )
            return self._finish_failed_step(
                task,
                step,
                record,
                f"required tool(s) {unavailable} are unavailable - {detail}",
                logger,
            )

        for attempt_number in range(1, step.max_attempts + 1):
            attempt = StepAttempt(attempt=attempt_number)
            record.attempts.append(attempt)

            if step.kind is StepKind.AGENT:
                previous = record.attempts[-2] if len(record.attempts) > 1 else None
                result = await self._invoke_agent(task, step, attempt_number, previous, logger)
                attempt.agent_result = result
                task.artifacts.extend(result.artifacts)
                if not result.ok:
                    attempt.status = StepStatus.FAILED
                    attempt.finished_at = utcnow()
                    task.add_error("runtime", result.error or "agent failed", step_id=step.id)
                    self.store.save_task(task)
                    logger.error(
                        "step.attempt", attempt=attempt_number, status="failed", error=result.error
                    )
                    if attempt_number == step.max_attempts:
                        return self._finish_failed_step(
                            task, step, record, result.error or "agent execution failed", logger
                        )
                    continue

            report = await self._verify(task, step, specs, attempt_number, logger)
            attempt.verification = report.results
            task.record_verification(report.results)
            attempt.finished_at = utcnow()

            if report.passed:
                attempt.status = StepStatus.PASSED
                record.status = StepStatus.PASSED
                record.finished_at = utcnow()
                self.store.save_task(task)
                logger.info(
                    "step.finish",
                    status="passed",
                    attempts=attempt_number,
                    verification=report.summary or "none",
                )
                return None

            attempt.status = StepStatus.FAILED
            self.store.save_task(task)
            logger.warn(
                "step.attempt",
                attempt=attempt_number,
                status="failed",
                verification=report.summary,
                failures=[result.verifier for result in report.failures],
            )

            if not step.repairable:
                # Nothing would change on a second run: no agent to fix anything.
                break

        failures = ", ".join(
            f"{result.verifier} ({result.status.value})"
            for result in (record.attempts[-1].failed_verifiers if record.attempts else [])
        )
        return self._finish_failed_step(
            task,
            step,
            record,
            f"verification failed after {len(record.attempts)} attempt(s): {failures or 'unknown'}",
            logger,
        )

    def _run_approval_step(
        self, task: Task, step: WorkflowStep, record: StepRecord, logger: RunLogger
    ) -> RunOutcome | None:
        approval = self.approvals.request(
            task,
            gate=step.gate or step.id,
            step_id=step.id,
            prompt=step.description or step.name,
            context={"workflow": task.workflow, "task": task.description},
        )

        if approval.status is ApprovalStatus.APPROVED:
            record.status = StepStatus.PASSED
            record.finished_at = utcnow()
            self.store.save_task(task)
            logger.info("approval.granted", gate=approval.gate, by=approval.decided_by)
            return None

        if approval.status is ApprovalStatus.REJECTED:
            record.status = StepStatus.REJECTED
            record.finished_at = utcnow()
            record.error = approval.reason or "rejected by human"
            task.status = TaskStatus.FAILED
            task.add_error("approval", record.error, step_id=step.id)
            self.store.save_task(task)
            logger.error("approval.rejected", gate=approval.gate, reason=record.error)
            return RunOutcome(
                task=task, stopped_at=step.id, reason=f"gate '{approval.gate}' rejected"
            )

        record.status = StepStatus.AWAITING_APPROVAL
        task.status = TaskStatus.AWAITING_APPROVAL
        self.store.save_task(task)
        logger.info("approval.pending", gate=approval.gate, status="awaiting_approval")
        return RunOutcome(
            task=task,
            stopped_at=step.id,
            reason=(
                f"waiting for approval at gate '{approval.gate}'. "
                f"Approve with: devforge approve --gate {approval.gate}"
            ),
        )

    # -- helpers ----------------------------------------------------------------

    async def _invoke_agent(
        self,
        task: Task,
        step: WorkflowStep,
        attempt_number: int,
        previous: StepAttempt | None,
        logger: RunLogger,
    ):
        spec = self.agents.get(step.agent)
        skill_names = step.skills or spec.skills
        skills = self.skills.resolve(skill_names)
        tools = step.tools or spec.tools

        invocation = build_invocation(
            task=task,
            step=step,
            agent=spec,
            skills=skills,
            memory=self.store.read_memory(),
            tools=tools,
            attempt=attempt_number,
            previous_attempt=previous if previous and previous.failed_verifiers else None,
            workspace=str(self.workspace),
        )
        logger.info(
            "agent.invoke",
            runtime=self.runtime.name,
            attempt=attempt_number,
            mode=invocation.mode.value,
            skills=invocation.skills,
            tools=invocation.tools,
        )
        context = RuntimeContext(
            workspace=self.workspace,
            tools=self.tools.subset(tools) if tools else None,
            logger=logger,
        )
        result = await self.runtime.execute(invocation, context)
        logger.info(
            "agent.result",
            runtime=result.runtime,
            status=result.status.value,
            duration_ms=result.duration_ms,
            summary=result.summary,
        )
        return result

    async def _verify(
        self, task: Task, step: WorkflowStep, specs: dict, attempt_number: int, logger: RunLogger
    ) -> VerificationReport:
        if not step.verify:
            return VerificationReport(results=[])
        selected = self.verification.select(specs, step.verify)
        context = VerificationContext(
            workspace=self.workspace,
            policy=self.policy,
            logger=logger,
            step_id=step.id,
            attempt=attempt_number,
            task_id=task.task_id,
        )
        return await self.verification.run(selected, context)

    def _finish_failed_step(
        self, task: Task, step: WorkflowStep, record: StepRecord, reason: str, logger: RunLogger
    ) -> RunOutcome | None:
        record.status = StepStatus.FAILED
        record.finished_at = utcnow()
        record.error = reason
        task.add_error("step", reason, step_id=step.id)

        if step.on_failure is OnFailure.CONTINUE:
            self.store.save_task(task)
            logger.warn("step.finish", status="failed", continued=True, reason=reason)
            return None

        task.status = TaskStatus.FAILED
        self.store.save_task(task)
        logger.error("step.finish", status="failed", reason=reason)
        return RunOutcome(task=task, stopped_at=step.id, reason=reason)

    def _fail_run(self, task: Task, kind: str, reason: str) -> RunOutcome:
        task.status = TaskStatus.FAILED
        task.add_error(kind, reason)
        self.store.save_task(task)
        self.logger.error("run.finish", task_id=task.task_id, status="failed", reason=reason)
        return RunOutcome(task=task, reason=reason)
