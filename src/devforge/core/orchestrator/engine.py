"""The orchestrator.

One loop drives every workflow::

    for step in workflow:
        agent step   -> invoke -> verify -> (repair -> verify)* up to max_attempts
        verify step  -> verify only
        approval step-> request a human decision, pause if it is not yet given
        falsify step -> search adversarially for counterexamples

Design constraints this file deliberately respects:

* It knows nothing about any specific runtime, tool or verifier - only their
  interfaces, all injected through :class:`Orchestrator` construction.
* It never trusts an agent's own report of success. ``AgentResult.ok`` only means
  the runtime worked; passing a step requires the verifiers to agree.
* Verification and falsification are independent evidence sources, not one
  pipeline. Verification gathers evidence *for* a change; falsification searches
  for evidence *against* it. Neither is correctness, and the orchestrator records
  both rather than collapsing them into a single verdict.
* It persists after every attempt, so a crashed or interrupted process resumes
  rather than restarts.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from devforge.agents.prompt import build_invocation
from devforge.agents.spec import AgentRegistry
from devforge.approval.gate import ApprovalGate
from devforge.core.errors import DevForgeError
from devforge.core.execution import ExecutionContext
from devforge.core.models import (
    ApprovalStatus,
    Artifact,
    StepAttempt,
    StepRecord,
    StepStatus,
    Task,
    TaskResult,
    TaskStatus,
    utcnow,
)
from devforge.core.registry.skills import SkillRegistry
from devforge.core.state.store import ProjectStore
from devforge.core.workflow.spec import OnFailure, StepKind, WorkflowSpec, WorkflowStep
from devforge.falsification.models import FalsificationStatus
from devforge.observability.logging import RunLogger
from devforge.policy.engine import PolicyEngine
from devforge.runtime.base import AgentRuntime
from devforge.tools.base import ToolRegistry
from devforge.verification.engine import VerificationEngine, VerificationReport


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
        skill_registry: object | None = None,
        falsification: object | None = None,
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
        # Registry of reviewed third-party sources; only external skills need it.
        self.skill_registry = skill_registry
        # Optional, and defaulted so every existing construction keeps working. A
        # falsify step with no engine fails the step with a stated reason - it must
        # never pass by omission, which would make the check vanish silently.
        self.falsification = falsification

    # -- entry point ------------------------------------------------------------

    async def run(self, task: Task, workflow: WorkflowSpec) -> TaskResult:
        specs = self.verification.collect_specs(workflow, self.store.load_config().verifiers)
        missing = workflow.missing_verifiers(set(specs))
        if missing:
            return self._fail_run(
                task, "configuration", f"workflow references undefined verifiers: {sorted(missing)}"
            )

        # A workflow that declares dependencies is a graph, and graphs are run by the
        # supervisor: parallel levels, conditions, artifact contracts. One executor
        # for the inside of a step, two for the shape of a run.
        if any(step.depends_on for step in workflow.steps):
            from devforge.core.graph.models import graph_from_workflow
            from devforge.core.graph.supervisor import Supervisor

            return await Supervisor(self, logger=self.logger).run(
                task, workflow, graph_from_workflow(workflow)
            )

        task.status = TaskStatus.RUNNING
        self.store.save_task(task)
        execution = ExecutionContext(
            task=task,
            workspace=self.workspace,
            policy=self.policy,
            tools=self.tools,
            approval_gate=self.approvals,
            logger=self.logger,
        )
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

            outcome = await self.run_step(
                task=task,
                step=step,
                record=record,
                specs=specs,
                execution=execution,
                workflow=workflow,
            )
            if outcome is not None:
                return outcome

        task.status = TaskStatus.COMPLETED
        task.current_step = None
        self.store.save_task(task)
        self.logger.info("run.finish", task_id=task.task_id, status=task.status.value)
        return TaskResult.from_task(task, reason="workflow completed")

    # -- steps ------------------------------------------------------------------

    async def run_step(
        self,
        *,
        task: Task,
        step: WorkflowStep,
        record: StepRecord,
        specs: dict,
        execution: ExecutionContext,
        workflow: WorkflowSpec | None = None,
        artifact_manifest: str = "",
    ) -> TaskResult | None:
        """Run one step. Returns a TaskResult when the run must stop here.

        Public because the graph supervisor drives nodes through it: the inside of a
        node - agent, verification, repair, approval - is identical whether the step
        came from a sequential workflow or a graph, and duplicating it would let the
        two diverge.

        ``artifact_manifest`` is how a graph node learns what upstream agents
        produced. It carries references and previews, never a transcript.
        """
        record.status = StepStatus.RUNNING
        record.started_at = record.started_at or utcnow()
        logger = self.logger.bind(task_id=task.task_id, step=step.id, agent=step.agent)
        logger.info(
            "step.start",
            kind=step.kind.value,
            workflow=workflow.name if workflow else task.workflow,
        )

        if step.kind is StepKind.APPROVAL:
            return self._run_approval_step(task, step, record, logger)

        if step.kind is StepKind.FALSIFY:
            return await self._run_falsify_step(task, step, record, logger)

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

        if step.kind is StepKind.AGENT:
            blocked = self._untrusted_skills(step, logger)
            if blocked:
                return self._finish_failed_step(task, step, record, blocked, logger)

        for attempt_number in range(1, step.max_attempts + 1):
            attempt = StepAttempt(attempt=attempt_number)
            record.attempts.append(attempt)

            if step.kind is StepKind.AGENT:
                previous = record.attempts[-2] if len(record.attempts) > 1 else None
                step_context = execution.for_step(step.id, attempt_number)
                result = await self._invoke_agent(
                    task, step, attempt_number, previous, step_context, artifact_manifest
                )
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

            report = await self._verify(step, specs, execution.for_step(step.id, attempt_number))
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
    ) -> TaskResult | None:
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
            return TaskResult.from_task(
                task, stopped_at=step.id, reason=f"gate '{approval.gate}' rejected"
            )

        record.status = StepStatus.AWAITING_APPROVAL
        task.status = TaskStatus.AWAITING_APPROVAL
        self.store.save_task(task)
        logger.info("approval.pending", gate=approval.gate, status="awaiting_approval")
        return TaskResult.from_task(
            task,
            stopped_at=step.id,
            reason=(
                f"waiting for approval at gate '{approval.gate}'. "
                f"Approve with: devforge approve --gate {approval.gate}"
            ),
        )

    async def _run_falsify_step(
        self, task: Task, step: WorkflowStep, record: StepRecord, logger: RunLogger
    ) -> TaskResult | None:
        """Search for counterexamples, and record what the search actually covered.

        The engine returns a report; this decides what the report means for the run.
        The two are separate because "a counterexample exists" and "this step fails"
        are different judgements, and only the second belongs to the workflow.
        """
        from devforge.core.workflow.spec import OnUnsearched

        if self.falsification is None:
            return self._finish_failed_step(
                task,
                step,
                record,
                "this workflow declares a falsify step but no falsification engine "
                "was configured; refusing to pass a check that did not run",
                logger,
            )

        attempt = StepAttempt(attempt=1)
        record.attempts.append(attempt)

        patch = await self._collect_patch(logger)
        report = await self._falsify(task, step, patch, logger)

        record.falsification = report.status.value
        record.falsification_run_id = report.run_id
        attempt.finished_at = utcnow()

        artifact_path = self._persist_falsification(task, report, logger)
        if artifact_path:
            task.artifacts.append(
                Artifact(
                    path=artifact_path,
                    kind="falsification-report",
                    description=report.headline(),
                    step_id=step.id,
                )
            )

        status = report.status
        logger.info(
            "falsification.step",
            status=status.value,
            confidence=report.confidence.value,
            counterexamples=len(report.counterexamples),
            weaknesses=len(report.weaknesses),
            mutation_score=report.mutation_score,
        )

        if status is FalsificationStatus.FAILED:
            attempt.status = StepStatus.FAILED
            reason = (
                f"falsification found {len(report.counterexamples)} counterexample(s) "
                f"and {len(report.weaknesses)} test weakness(es); see {artifact_path}"
            )
            return self._finish_failed_step(task, step, record, reason, logger)

        if status in {FalsificationStatus.INCOMPLETE, FalsificationStatus.ERROR}:
            if step.on_incomplete is OnUnsearched.FAIL:
                attempt.status = StepStatus.FAILED
                return self._finish_failed_step(
                    task,
                    step,
                    record,
                    f"the falsification search did not complete ({status.value}): "
                    f"{'; '.join(report.limitations[:2])}",
                    logger,
                )
            logger.warn("falsification.incomplete", continued=True, status=status.value)

        if status is FalsificationStatus.UNAVAILABLE and step.on_unavailable is OnUnsearched.FAIL:
            attempt.status = StepStatus.FAILED
            return self._finish_failed_step(
                task,
                step,
                record,
                f"falsification could not run: {'; '.join(report.limitations[:2])}",
                logger,
            )

        attempt.status = StepStatus.PASSED
        record.status = StepStatus.PASSED
        record.finished_at = utcnow()
        self.store.save_task(task)
        logger.info(
            "step.finish",
            status="passed",
            falsification=status.value,
            confidence=report.confidence.value,
            note="no counterexample was found within the configured search space",
        )
        return None

    async def _falsify(self, task: Task, step: WorkflowStep, patch, logger: RunLogger):
        from devforge.falsification.models import Budget, MutationScope

        return await self.falsification.run(
            source_root=self.workspace,
            policy=self.policy,
            strategies=step.strategies or None,
            target_names=step.targets or None,
            budget=Budget.model_validate(step.budget) if step.budget else Budget(),
            config={**step.falsify, "lines": patch.lines},
            diff=patch.diff,
            changed_files=patch.files,
            scope=MutationScope(step.scope),
            task_id=task.task_id,
            step_id=step.id,
            logger=logger,
            order=step.order or None,
        )

    async def _collect_patch(self, logger: RunLogger):
        """The change under attack.

        Delegated to the falsification layer: reading a diff means running git, and
        core depends on interfaces rather than on how a subprocess is spawned.
        """
        from devforge.falsification.patch import collect_patch

        return await collect_patch(self.workspace, self.policy, logger=logger)

    def _persist_falsification(self, task: Task, report, logger: RunLogger) -> str:
        from devforge.falsification.store import record_corpus, save_report

        try:
            path = save_report(self.store, report)
            record_corpus(self.store, report)
        except OSError as exc:  # pragma: no cover - disk failure
            logger.warn("falsification.persist_failed", error=str(exc))
            return ""
        try:
            return path.relative_to(self.store.root).as_posix()
        except ValueError:  # pragma: no cover - report outside the project
            return str(path)

    # -- helpers ----------------------------------------------------------------

    def _untrusted_skills(self, step: WorkflowStep, logger: RunLogger) -> str:
        """Refuse to compose an untrusted skill into a prompt.

        Returns a failure reason, or "" when every skill is cleared. A blocked skill
        fails the step rather than being dropped: a prompt missing the instructions it
        was meant to carry is a different prompt, and silently degrading the work would
        hide the problem (docs/security/skill-supply-chain.md).
        """
        from devforge.supplychain.consumption import assess_all

        spec = self.agents.get(step.agent)
        names = step.skills or spec.skills
        if not names:
            return ""

        skills = self.skills.resolve(names)
        assessments = assess_all(skills, project_root=self.store.root, registry=self.skill_registry)
        refused = [assessment for assessment in assessments if not assessment.allowed]
        for assessment in refused:
            logger.error(
                "skill.blocked",
                skill=assessment.skill,
                origin=assessment.origin.value,
                reason=assessment.reason,
                content_hash=assessment.content_hash or None,
            )
        if not refused:
            return ""
        detail = "; ".join(f"{a.skill} ({a.origin.value}): {a.reason}" for a in refused)
        return f"untrusted skill(s) refused - {detail}"

    async def _invoke_agent(
        self,
        task: Task,
        step: WorkflowStep,
        attempt_number: int,
        previous: StepAttempt | None,
        execution: ExecutionContext,
        artifact_manifest: str = "",
    ):
        logger = execution.logger
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
            context_pack=self._compose_context(task, step, logger, artifact_manifest),
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
        # Two narrowings, both explicit. Tools: a step that declared none gets an
        # empty scope, never the whole registry by omission. Policy: the agent's own
        # declared permissions, intersected with the project's - an agent spec can
        # remove access, never add it.
        from devforge.policy.agent_scope import scope_for_agent

        scoped = execution
        agent_policy = scope_for_agent(self.policy, spec.permissions)
        if agent_policy is not self.policy:
            scoped = replace(execution, policy=agent_policy)
            logger.info("agent.scope", agent=spec.name, permissions=spec.permissions.summary())

        result = await self.runtime.execute(
            invocation, scoped.for_runtime(self.tools.subset(tools))
        )
        logger.info(
            "agent.result",
            runtime=result.runtime,
            status=result.status.value,
            duration_ms=result.duration_ms,
            summary=result.summary,
        )
        return result

    def _compose_context(
        self, task: Task, step: WorkflowStep, logger: RunLogger, artifact_manifest: str = ""
    ) -> str:
        """Retrieved context plus whatever upstream agents produced."""
        pack = self._context_pack(task, step, logger)
        if not artifact_manifest:
            return pack
        upstream = f"## Artifacts from earlier agents\n\n{artifact_manifest}"
        return f"{pack}\n\n{upstream}" if pack else upstream

    def _context_pack(self, task: Task, step: WorkflowStep, logger: RunLogger) -> str:
        """Retrieved context for this step, or nothing if the project has no index.

        A missing index is not an error: the agent falls back to the full project
        memory, exactly as before Phase 4. An index that exists but fails to load is
        reported, because silently degrading to a worse prompt is how a regression
        hides.
        """
        from devforge.context.pack import build_pack

        query = f"{task.description} {step.description or step.name}".strip()
        try:
            pack = build_pack(query, store=self.store, max_files=10, count_tokens=False)
        except DevForgeError as exc:
            logger.info("context.unavailable", reason=str(exc))
            return ""

        rendered = pack.render()
        logger.info(
            "context.pack",
            files=len(pack.relevant_files),
            symbols=len(pack.relevant_symbols),
            characters=len(rendered),
            confident=not pack.retrieval_note,
        )
        return rendered

    async def _verify(
        self, step: WorkflowStep, specs: dict, execution: ExecutionContext
    ) -> VerificationReport:
        if not step.verify:
            return VerificationReport(results=[])
        selected = self.verification.select(specs, step.verify)
        return await self.verification.run(selected, execution.for_verification())

    def _finish_failed_step(
        self, task: Task, step: WorkflowStep, record: StepRecord, reason: str, logger: RunLogger
    ) -> TaskResult | None:
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
        return TaskResult.from_task(task, stopped_at=step.id, reason=reason)

    def _fail_run(self, task: Task, kind: str, reason: str) -> TaskResult:
        task.status = TaskStatus.FAILED
        task.add_error(kind, reason)
        self.store.save_task(task)
        self.logger.error("run.finish", task_id=task.task_id, status="failed", reason=reason)
        return TaskResult.from_task(task, reason=reason)
