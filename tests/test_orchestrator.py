from __future__ import annotations

import sys
from pathlib import Path

import pytest

from devforge.agents.spec import AgentRegistry
from devforge.approval.gate import ApprovalGate
from devforge.core.models import ApprovalStatus, StepStatus, Task, TaskStatus, VerificationStatus
from devforge.core.orchestrator.engine import Orchestrator
from devforge.core.registry.skills import SkillRegistry
from devforge.core.state.store import ProjectStore
from devforge.core.workflow.loader import WorkflowLoader
from devforge.core.workflow.spec import (
    OnFailure,
    StepKind,
    VerifierSpec,
    WorkflowSpec,
    WorkflowStep,
)
from devforge.observability.logging import RunLogger, jsonl_sink, read_events
from devforge.policy.engine import PolicyEngine
from devforge.policy.models import ApprovalPolicy, GatePolicy, PermissionPolicy
from devforge.runtime.mock import MockAgentRuntime, MockStep
from devforge.tools.base import Tool, ToolAvailability, ToolRegistry
from devforge.verification.engine import VerificationEngine

# The permission policy is exercised in tests/test_policy.py. Here it must permit the
# helper scripts below, so these tests use an explicitly permissive shell policy.
PERMISSIVE_SHELL = {"default": "deny", "allow": ["*"]}

FLAKY_SCRIPT = """
import pathlib, sys
marker = pathlib.Path("attempts.txt")
count = int(marker.read_text()) if marker.exists() else 0
count += 1
marker.write_text(str(count))
if count < {passes_on}:
    print("failing on attempt", count)
    sys.exit(1)
print("passing on attempt", count)
"""


class _UnavailableTool(Tool):
    """A tool that is never usable, so availability handling can be tested regardless
    of what happens to be installed on the machine running the suite."""

    name = "offline"
    actions = ("noop",)

    def availability(self) -> ToolAvailability:
        return ToolAvailability(False, "deliberately unavailable test double")

    async def invoke(self, action, params, ctx):  # pragma: no cover - never reached
        raise AssertionError("an unavailable tool must never be invoked")


def make_policy(root: Path, *, gates: dict[str, GatePolicy] | None = None) -> PolicyEngine:
    permissions = PermissionPolicy.model_validate({"shell": PERMISSIVE_SHELL})
    approvals = ApprovalPolicy(
        gates=gates
        or {
            "architecture": GatePolicy(description="approve design"),
            "final_review": GatePolicy(description="sign off"),
        }
    )
    return PolicyEngine(permissions, approvals, workspace=root)


def flaky_verifier(root: Path, *, passes_on: int) -> VerifierSpec:
    script = root / "flaky_check.py"
    script.write_text(FLAKY_SCRIPT.format(passes_on=passes_on), encoding="utf-8")
    return VerifierSpec(id="tests", kind="tests", argv=[sys.executable, str(script)], timeout_s=60)


def build(
    project: ProjectStore,
    *,
    runtime: MockAgentRuntime | None = None,
    policy: PolicyEngine | None = None,
    prompter=None,
    logger: RunLogger | None = None,
) -> tuple[Orchestrator, MockAgentRuntime]:
    runtime = runtime or MockAgentRuntime()
    policy = policy or make_policy(project.root)
    orchestrator = Orchestrator(
        store=project,
        runtime=runtime,
        tools=ToolRegistry.default(),
        skills=SkillRegistry.discover(project.root),
        agents=AgentRegistry.discover(project.root),
        verification=VerificationEngine(),
        approvals=ApprovalGate(policy, prompter=prompter),
        policy=policy,
        logger=logger or RunLogger([]),
        workspace=project.root,
    )
    return orchestrator, runtime


def new_task(project: ProjectStore, workflow: str = "feature") -> Task:
    return Task(
        project_id=project.load_config().project_id,
        description="Add JWT authentication",
        workflow=workflow,
        runtime="mock",
    )


def simple_workflow(
    steps: list[WorkflowStep], verifiers: list[VerifierSpec] | None = None
) -> WorkflowSpec:
    return WorkflowSpec(name="test", steps=steps, verifiers=verifiers or [])


# --------------------------------------------------------------------------- basics


async def test_runs_steps_in_order_and_completes(project: ProjectStore) -> None:
    workflow = simple_workflow(
        [
            WorkflowStep(id="requirements", agent="planner"),
            WorkflowStep(id="implementation", agent="coder"),
        ]
    )
    orchestrator, runtime = build(project)
    task = new_task(project)

    outcome = await orchestrator.run(task, workflow)

    assert outcome.completed
    assert task.status is TaskStatus.COMPLETED
    assert task.current_step is None
    assert [i.step_id for i in runtime.invocations] == ["requirements", "implementation"]
    assert [s.status for s in task.steps] == [StepStatus.PASSED, StepStatus.PASSED]


async def test_state_is_persisted_after_each_step(project: ProjectStore) -> None:
    workflow = simple_workflow([WorkflowStep(id="requirements", agent="planner")])
    orchestrator, _ = build(project)
    task = new_task(project)

    await orchestrator.run(task, workflow)

    reloaded = project.load_task(task.task_id)
    assert reloaded.status is TaskStatus.COMPLETED
    assert reloaded.step("requirements").attempts[0].agent_result.runtime == "mock"


async def test_agent_artifacts_are_recorded(project: ProjectStore) -> None:
    runtime = MockAgentRuntime(
        script={"implementation": MockStep(writes={"src/auth.py": "# jwt\n"})}
    )
    workflow = simple_workflow([WorkflowStep(id="implementation", agent="coder")])
    orchestrator, _ = build(project, runtime=runtime)
    task = new_task(project)

    await orchestrator.run(task, workflow)

    assert [a.path for a in task.artifacts] == ["src/auth.py"]
    assert (project.root / "src" / "auth.py").exists()


# ---------------------------------------------------------------------- verification


async def test_verification_failure_triggers_repair_then_passes(project: ProjectStore) -> None:
    verifier = flaky_verifier(project.root, passes_on=2)
    workflow = simple_workflow(
        [WorkflowStep(id="implementation", agent="coder", verify=["tests"], max_attempts=3)],
        [verifier],
    )
    orchestrator, runtime = build(project)
    task = new_task(project)

    outcome = await orchestrator.run(task, workflow)

    assert outcome.completed
    record = task.step("implementation")
    assert record.attempt_count == 2
    assert record.attempts[0].status is StepStatus.FAILED
    assert record.attempts[1].status is StepStatus.PASSED
    assert record.status is StepStatus.PASSED

    # The second invocation must be a repair carrying the failure diagnostics.
    assert runtime.invocations[1].mode.value == "repair"
    assert "failing on attempt 1" in runtime.invocations[1].prompt


async def test_retries_stop_at_max_attempts(project: ProjectStore) -> None:
    verifier = flaky_verifier(project.root, passes_on=99)
    workflow = simple_workflow(
        [WorkflowStep(id="implementation", agent="coder", verify=["tests"], max_attempts=3)],
        [verifier],
    )
    orchestrator, runtime = build(project)
    task = new_task(project)

    outcome = await orchestrator.run(task, workflow)

    assert not outcome.completed
    assert task.status is TaskStatus.FAILED
    assert outcome.stopped_at == "implementation"
    assert task.step("implementation").attempt_count == 3
    assert len(runtime.invocations) == 3
    assert "verification failed after 3 attempt(s)" in task.step("implementation").error
    assert (project.root / "attempts.txt").read_text() == "3"


async def test_verification_results_are_persisted(project: ProjectStore) -> None:
    verifier = flaky_verifier(project.root, passes_on=2)
    workflow = simple_workflow(
        [WorkflowStep(id="implementation", agent="coder", verify=["tests"], max_attempts=2)],
        [verifier],
    )
    orchestrator, _ = build(project)
    task = new_task(project)

    await orchestrator.run(task, workflow)
    reloaded = project.load_task(task.task_id)

    statuses = [r.status for r in reloaded.verification_results]
    assert statuses == [VerificationStatus.FAILED, VerificationStatus.PASSED]
    assert reloaded.verification_results[0].attempt == 1
    assert reloaded.verification_results[0].exit_code == 1
    assert "failing on attempt 1" in reloaded.verification_results[0].output_excerpt


async def test_verify_only_step_is_not_retried(project: ProjectStore) -> None:
    verifier = flaky_verifier(project.root, passes_on=99)
    workflow = simple_workflow(
        [WorkflowStep(id="checkpoint", kind=StepKind.VERIFY, verify=["tests"], max_attempts=3)],
        [verifier],
    )
    orchestrator, _ = build(project)
    task = new_task(project)

    await orchestrator.run(task, workflow)

    # No agent can repair anything, so retrying identical commands is pointless.
    assert task.step("checkpoint").attempt_count == 1
    assert task.status is TaskStatus.FAILED


async def test_optional_verifier_failure_does_not_block(project: ProjectStore) -> None:
    failing = flaky_verifier(project.root, passes_on=99)
    optional = VerifierSpec(id="lint", kind="lint", argv=failing.argv, required=False)
    workflow = simple_workflow(
        [WorkflowStep(id="implementation", agent="coder", verify=["lint"])], [optional]
    )
    orchestrator, _ = build(project)
    task = new_task(project)

    outcome = await orchestrator.run(task, workflow)

    assert outcome.completed
    assert task.verification_results[0].status is VerificationStatus.FAILED


async def test_undefined_verifier_fails_the_run_before_any_agent_runs(
    project: ProjectStore,
) -> None:
    workflow = simple_workflow([WorkflowStep(id="implementation", agent="coder", verify=["ghost"])])
    orchestrator, runtime = build(project)
    task = new_task(project)

    outcome = await orchestrator.run(task, workflow)

    assert task.status is TaskStatus.FAILED
    assert "undefined verifiers" in outcome.reason
    assert runtime.invocations == []


async def test_unavailable_verifier_backend_is_not_a_pass(project: ProjectStore) -> None:
    workflow = simple_workflow(
        [WorkflowStep(id="visual-check", kind=StepKind.VERIFY, verify=["visual"])],
        [VerifierSpec(id="visual", kind="visual", required=True)],
    )
    orchestrator, _ = build(project)
    task = new_task(project)

    await orchestrator.run(task, workflow)

    assert task.status is TaskStatus.FAILED
    assert task.verification_results[0].status is VerificationStatus.UNAVAILABLE


# -------------------------------------------------------------------------- agents


async def test_agent_runtime_error_is_retried_then_fails(project: ProjectStore) -> None:
    runtime = MockAgentRuntime(
        script={"implementation": MockStep(fail_attempts=99, error="runtime down")}
    )
    workflow = simple_workflow([WorkflowStep(id="implementation", agent="coder", max_attempts=2)])
    orchestrator, _ = build(project, runtime=runtime)
    task = new_task(project)

    outcome = await orchestrator.run(task, workflow)

    assert task.status is TaskStatus.FAILED
    assert len(runtime.invocations) == 2
    assert outcome.reason == "runtime down"
    assert task.errors[0].kind == "runtime"


async def test_agent_recovers_on_second_attempt(project: ProjectStore) -> None:
    runtime = MockAgentRuntime(script={"implementation": MockStep(fail_attempts=1)})
    workflow = simple_workflow([WorkflowStep(id="implementation", agent="coder", max_attempts=3)])
    orchestrator, _ = build(project, runtime=runtime)
    task = new_task(project)

    outcome = await orchestrator.run(task, workflow)

    assert outcome.completed
    assert task.step("implementation").attempt_count == 2


async def test_step_with_unavailable_tool_fails_clearly(project: ProjectStore) -> None:
    tools = ToolRegistry.default()
    tools.register("offline", _UnavailableTool(), replace=True)
    workflow = simple_workflow([WorkflowStep(id="recon", agent="architect", tools=["offline"])])
    orchestrator, runtime = build(project)
    orchestrator.tools = tools
    task = new_task(project)

    outcome = await orchestrator.run(task, workflow)

    assert task.status is TaskStatus.FAILED
    assert "offline" in outcome.reason and "unavailable" in outcome.reason
    assert runtime.invocations == [], "an agent must not be invoked without its required tools"


async def test_on_failure_continue_keeps_going(project: ProjectStore) -> None:
    tools = ToolRegistry.default()
    tools.register("offline", _UnavailableTool(), replace=True)
    workflow = simple_workflow(
        [
            WorkflowStep(
                id="recon", agent="architect", tools=["offline"], on_failure=OnFailure.CONTINUE
            ),
            WorkflowStep(id="implementation", agent="coder"),
        ]
    )
    orchestrator, runtime = build(project)
    orchestrator.tools = tools
    task = new_task(project)

    outcome = await orchestrator.run(task, workflow)

    assert outcome.completed
    assert task.step("recon").status is StepStatus.FAILED
    assert task.step("implementation").status is StepStatus.PASSED
    assert [i.step_id for i in runtime.invocations] == ["implementation"]


# ------------------------------------------------------------------------ approvals


async def test_run_pauses_at_approval_gate(project: ProjectStore) -> None:
    workflow = simple_workflow(
        [
            WorkflowStep(id="planning", agent="architect"),
            WorkflowStep(id="approve", kind=StepKind.APPROVAL, gate="architecture"),
            WorkflowStep(id="implementation", agent="coder"),
        ]
    )
    orchestrator, runtime = build(project)
    task = new_task(project)

    outcome = await orchestrator.run(task, workflow)

    assert outcome.awaiting_approval
    assert outcome.stopped_at == "approve"
    assert "devforge approve --gate architecture" in outcome.reason
    assert task.step("implementation") is None, "steps after the gate must not have started"
    assert [i.step_id for i in runtime.invocations] == ["planning"]

    persisted = project.load_task(task.task_id)
    assert persisted.status is TaskStatus.AWAITING_APPROVAL
    assert persisted.approvals[0].status is ApprovalStatus.PENDING


async def test_resume_after_approval_completes_without_redoing_work(project: ProjectStore) -> None:
    workflow = simple_workflow(
        [
            WorkflowStep(id="planning", agent="architect"),
            WorkflowStep(id="approve", kind=StepKind.APPROVAL, gate="architecture"),
            WorkflowStep(id="implementation", agent="coder"),
        ]
    )
    policy = make_policy(project.root)
    orchestrator, runtime = build(project, policy=policy)
    task = new_task(project)
    await orchestrator.run(task, workflow)

    # A separate process approves the gate and resumes.
    reloaded = project.load_task(task.task_id)
    ApprovalGate(policy).resolve(reloaded, gate="architecture", approved=True, by="alice")
    project.save_task(reloaded)

    orchestrator2, runtime2 = build(project, policy=policy)
    outcome = await orchestrator2.run(reloaded, workflow)

    assert outcome.completed
    assert [i.step_id for i in runtime2.invocations] == ["implementation"]
    assert reloaded.step("planning").attempt_count == 1, "completed steps must not run twice"


async def test_rejected_approval_fails_the_run(project: ProjectStore) -> None:
    workflow = simple_workflow(
        [
            WorkflowStep(id="approve", kind=StepKind.APPROVAL, gate="architecture"),
            WorkflowStep(id="implementation", agent="coder"),
        ]
    )
    orchestrator, runtime = build(project, prompter=lambda _: False)
    task = new_task(project)

    outcome = await orchestrator.run(task, workflow)

    assert task.status is TaskStatus.FAILED
    assert task.step("approve").status is StepStatus.REJECTED
    assert "rejected" in outcome.reason
    assert runtime.invocations == []


async def test_interactive_approval_runs_straight_through(project: ProjectStore) -> None:
    workflow = simple_workflow(
        [
            WorkflowStep(id="approve", kind=StepKind.APPROVAL, gate="architecture"),
            WorkflowStep(id="implementation", agent="coder"),
        ]
    )
    orchestrator, runtime = build(project, prompter=lambda _: True)
    task = new_task(project)

    outcome = await orchestrator.run(task, workflow)

    assert outcome.completed
    assert task.approvals[0].decided_by == "interactive"
    assert [i.step_id for i in runtime.invocations] == ["implementation"]


async def test_auto_approve_gate_does_not_pause(project: ProjectStore) -> None:
    policy = make_policy(project.root, gates={"architecture": GatePolicy(auto_approve=True)})
    workflow = simple_workflow(
        [WorkflowStep(id="approve", kind=StepKind.APPROVAL, gate="architecture")]
    )
    orchestrator, _ = build(project, policy=policy)
    task = new_task(project)

    outcome = await orchestrator.run(task, workflow)

    assert outcome.completed
    assert task.approvals[0].decided_by == "policy:auto_approve"


# --------------------------------------------------------------------- observability


async def test_run_emits_structured_events(project: ProjectStore) -> None:
    task = new_task(project)
    logger = RunLogger([jsonl_sink(project.events_path(task.task_id))], task_id=task.task_id)
    workflow = simple_workflow(
        [WorkflowStep(id="implementation", agent="coder", verify=["tests"])],
        [flaky_verifier(project.root, passes_on=1)],
    )
    orchestrator, _ = build(project, logger=logger)

    await orchestrator.run(task, workflow)

    events = list(read_events(project.events_path(task.task_id)))
    names = [event["event"] for event in events]

    assert "run.start" in names and "run.finish" in names
    assert "agent.invoke" in names and "verification.finish" in names
    for event in events:
        assert "timestamp" in event and "task_id" in event
    finish = next(e for e in events if e["event"] == "verification.finish")
    assert finish["status"] == "passed" and finish["verifier"] == "tests"
    assert isinstance(finish["duration_ms"], int)


# ---------------------------------------------------------------- built-in workflows


async def test_builtin_feature_workflow_reaches_first_gate(project: ProjectStore) -> None:
    workflow = WorkflowLoader.for_project(project.root).load("feature")
    orchestrator, _ = build(project)
    task = new_task(project)

    outcome = await orchestrator.run(task, workflow)

    assert outcome.awaiting_approval
    assert outcome.stopped_at == "approve-architecture"
    assert task.step("requirements").status is StepStatus.PASSED
    assert task.step("planning").status is StepStatus.PASSED


async def test_builtin_clone_workflow_stops_before_doing_unverifiable_work(
    project: ProjectStore,
) -> None:
    """clone still cannot complete: visual verification has no backend. With a browser
    driver present it now gets as far as the design approval gate instead of failing at
    step one - progress, but it must never reach completion on an unchecked assumption."""
    workflow = WorkflowLoader.for_project(project.root).load("clone")
    orchestrator, _ = build(project)
    task = new_task(project, workflow="clone")

    outcome = await orchestrator.run(task, workflow)

    assert not outcome.completed
    assert outcome.stopped_at in {"recon", "approve-design"}
    if outcome.stopped_at == "recon":
        assert "unavailable" in outcome.reason


@pytest.mark.parametrize("name", ["feature", "bugfix", "refactor", "clone"])
async def test_every_builtin_workflow_references_known_agents_and_skills(
    project: ProjectStore, name: str
) -> None:
    workflow = WorkflowLoader.for_project(project.root).load(name)
    agents = AgentRegistry.discover(project.root)
    skills = SkillRegistry.discover(project.root)

    for step in workflow.steps:
        if step.agent:
            assert step.agent in agents, f"{name}.{step.id} uses unknown agent '{step.agent}'"
        for skill in step.skills:
            assert skill in skills, f"{name}.{step.id} uses unknown skill '{skill}'"
        for tool in step.tools:
            assert tool in ToolRegistry.default(), f"{name}.{step.id} uses unknown tool '{tool}'"
