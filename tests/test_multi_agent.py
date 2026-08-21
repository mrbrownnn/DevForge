"""Phase 5: controlled multi-agent orchestration.

Everything here runs on the deterministic mock runtime, so the whole graph -
fan-out, fan-in, conditions, retries, failure handling - is reproducible without a
model call.

What is being asserted is *control*: that the topology is what the workflow
declared, that agents communicate only through artifacts, that each one gets only
the permissions its role needs, and that a failure preserves work rather than
discarding it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from devforge.agents.spec import AgentPermissions, AgentRegistry
from devforge.approval.gate import ApprovalGate
from devforge.core.graph.artifacts import ArtifactStore
from devforge.core.graph.models import (
    ArtifactSpec,
    Condition,
    NodeStatus,
    TaskGraph,
    TaskNode,
    graph_from_workflow,
)
from devforge.core.models import Task
from devforge.core.orchestrator.engine import Orchestrator
from devforge.core.registry.skills import SkillRegistry
from devforge.core.state.store import ProjectStore
from devforge.core.workflow.loader import WorkflowLoader
from devforge.core.workflow.spec import StepKind, VerifierSpec, WorkflowSpec, WorkflowStep
from devforge.observability.logging import RunLogger, jsonl_sink
from devforge.policy.agent_scope import scope_for_agent
from devforge.policy.engine import PolicyEngine
from devforge.policy.models import ApprovalPolicy, GatePolicy, PermissionPolicy
from devforge.runtime.mock import MockAgentRuntime, MockStep
from devforge.tools.base import ToolRegistry
from devforge.verification.engine import VerificationEngine


def make_policy(root: Path) -> PolicyEngine:
    return PolicyEngine(
        PermissionPolicy.model_validate(
            {
                "shell": {"default": "deny", "allow": ["*"]},
                "filesystem": {"read": ["**"], "write": ["**"], "delete": "require_approval"},
            }
        ),
        ApprovalPolicy(gates={"final_review": GatePolicy(auto_approve=True)}),
        workspace=root,
    )


def build(project: ProjectStore, runtime: MockAgentRuntime, logger: RunLogger | None = None):
    policy = make_policy(project.root)
    return Orchestrator(
        store=project,
        runtime=runtime,
        tools=ToolRegistry.default(),
        skills=SkillRegistry.discover(project.root),
        agents=AgentRegistry.discover(project.root),
        verification=VerificationEngine(),
        approvals=ApprovalGate(policy),
        policy=policy,
        logger=logger or RunLogger([]),
        workspace=project.root,
    )


def new_task(project: ProjectStore, workflow: str) -> Task:
    return Task(
        project_id=project.load_config().project_id,
        description="Add rate limiting to the public API",
        workflow=workflow,
        runtime="mock",
    )


def producing_runtime(**extra: MockStep) -> MockAgentRuntime:
    """A mock that writes each node's declared artifacts, as a real agent would."""
    script = {
        "architect": MockStep(
            writes={"docs/architecture-proposal.md": "# Design\n\nRate limit.\n"}
        ),
        "coder": MockStep(writes={"docs/implementation.patch": "--- a/x\n+++ b/x\n"}),
        "tester": MockStep(writes={"docs/test-results.json": json.dumps({"passed": 12})}),
        "security": MockStep(writes={"docs/security-report.json": json.dumps({"findings": []})}),
        "docs": MockStep(writes={"docs/api-docs.md": "# API\n\nRate limits apply.\n"}),
        "reviewer": MockStep(writes={"docs/review.json": json.dumps({"verdict": "approve"})}),
    }
    script.update(extra)
    return MockAgentRuntime(script=script)


# ------------------------------------------------------------------ graph structure


def test_graph_shape_matches_the_declared_topology() -> None:
    graph = graph_from_workflow(WorkflowLoader.for_project(None).load("multi-agent-feature"))
    levels = graph.levels()

    assert [node.id for node in levels[0]] == ["architect"]
    assert [node.id for node in levels[1]] == ["coder"]
    # The fan-out: three independent agents in one level.
    assert {node.id for node in levels[2]} == {"tester", "security", "docs"}
    # The join: review waits for all three.
    assert [node.id for node in levels[3]] == ["reviewer"]
    assert graph.parallel_width == 3


def test_sequential_workflows_still_form_a_chain() -> None:
    """Existing workflows declare no dependencies and must keep working unchanged."""
    graph = graph_from_workflow(WorkflowLoader.for_project(None).load("demo"))

    assert graph.parallel_width == 1
    assert all(len(level) == 1 for level in graph.levels())


def test_cycles_are_refused() -> None:
    nodes = [
        TaskNode(step=WorkflowStep(id="a", agent="coder"), depends_on=["b"]),
        TaskNode(step=WorkflowStep(id="b", agent="coder"), depends_on=["a"]),
    ]

    with pytest.raises(ValueError, match="cycle"):
        TaskGraph(name="loop", nodes=nodes)


def test_unknown_dependency_is_refused() -> None:
    with pytest.raises(ValueError, match="unknown node"):
        TaskGraph(
            name="g",
            nodes=[TaskNode(step=WorkflowStep(id="a", agent="coder"), depends_on=["ghost"])],
        )


def test_consuming_an_unproduced_artifact_is_refused() -> None:
    """A graph must not promise a channel it cannot deliver."""
    with pytest.raises(ValueError, match="which no node produces"):
        TaskGraph(
            name="g",
            nodes=[TaskNode(step=WorkflowStep(id="a", agent="coder"), consumes=["ghost.json"])],
        )


def test_two_nodes_cannot_produce_the_same_artifact() -> None:
    with pytest.raises(ValueError, match="produced by both"):
        TaskGraph(
            name="g",
            nodes=[
                TaskNode(
                    step=WorkflowStep(id="a", agent="coder"),
                    produces=[ArtifactSpec(name="x.json")],
                ),
                TaskNode(
                    step=WorkflowStep(id="b", agent="coder"),
                    produces=[ArtifactSpec(name="x.json")],
                ),
            ],
        )


# -------------------------------------------------------------------- conditions


def test_conditions_are_a_closed_vocabulary_not_eval() -> None:
    """A workflow file is data. Evaluating expressions from one would make it code."""
    for expression in ("always", "success(coder)", "failed(tester)", "artifact_exists(x.json)"):
        assert Condition(expression=expression)

    for hostile in ("__import__('os').system('id')", "1 == 1", "success(a) and failed(b)"):
        with pytest.raises(ValueError, match="unsupported condition"):
            Condition(expression=hostile)


def test_condition_evaluation() -> None:
    statuses = {"coder": NodeStatus.PASSED, "tester": NodeStatus.FAILED}
    artifacts = {"review.json"}

    assert Condition(expression="always").evaluate(statuses, artifacts)
    assert Condition(expression="success(coder)").evaluate(statuses, artifacts)
    assert not Condition(expression="success(tester)").evaluate(statuses, artifacts)
    assert Condition(expression="failed(tester)").evaluate(statuses, artifacts)
    assert Condition(expression="artifact_exists(review.json)").evaluate(statuses, artifacts)
    assert not Condition(expression="artifact_exists(missing.json)").evaluate(statuses, artifacts)


# --------------------------------------------------------------- least privilege


def test_each_agent_declares_a_narrow_scope() -> None:
    agents = {agent.name: agent for agent in AgentRegistry.discover(None).all()}

    # The documentation agent cannot run commands and cannot touch source.
    docs = agents["docs"].permissions
    assert docs.allow_shell is False
    assert "docs/**" in docs.write and not any(glob.startswith("src/") for glob in docs.write)

    # The security auditor reads everything and writes only reports.
    security = agents["security"].permissions
    assert "**" in security.read
    assert not any(glob.startswith("src/") for glob in security.write)

    # The coder is the only agent that may write source.
    coder = agents["coder"].permissions
    assert "src/**" in coder.write and coder.allow_shell is True


def test_agent_scope_narrows_and_never_widens(tmp_path: Path) -> None:
    project_policy = PolicyEngine(
        PermissionPolicy.model_validate(
            {
                "shell": {"default": "deny", "allow": ["python -m pytest*"]},
                "filesystem": {"read": ["**"], "write": ["src/**", "docs/**"]},
            }
        ),
        ApprovalPolicy(),
        workspace=tmp_path,
    )

    docs_scope = scope_for_agent(
        project_policy, AgentPermissions(read=["**"], write=["docs/**"], allow_shell=False)
    )
    assert docs_scope.check_path("docs/api.md", mode="write").allowed
    assert not docs_scope.check_path("src/app.py", mode="write").allowed
    assert not docs_scope.check_command(["python", "-m", "pytest"]).allowed

    # An agent asking for more than the project allows still gets only the overlap.
    greedy = scope_for_agent(
        project_policy,
        AgentPermissions(write=["/etc/**", "docs/**"], allow_shell=True, shell=["rm -rf *"]),
    )
    assert not greedy.check_path("/etc/passwd", mode="write").allowed
    assert not greedy.check_command(["rm", "-rf", "/"]).allowed


def test_an_agent_without_declared_permissions_is_unchanged(tmp_path: Path) -> None:
    policy = make_policy(tmp_path)

    assert scope_for_agent(policy, AgentPermissions()) is policy


# ------------------------------------------------------------------- artifacts


def test_artifact_manifest_carries_references_not_transcripts(tmp_path: Path) -> None:
    store = ArtifactStore(root=tmp_path, run_dir=tmp_path / "run")
    (tmp_path / "docs").mkdir()
    target = tmp_path / "docs" / "review.json"
    target.write_text(json.dumps({"verdict": "approve", "notes": "looks fine"}), encoding="utf-8")

    store.capture("docs/review.json", target, producer="reviewer", fmt="json")
    manifest = store.manifest(["docs/review.json"])

    assert "docs/review.json" in manifest
    assert "from `reviewer`" in manifest
    assert "sha256:" in manifest
    assert "Read the" in manifest, "the consumer is told to read the file, not given it"


def test_missing_artifact_is_reported_to_the_consumer(tmp_path: Path) -> None:
    store = ArtifactStore(root=tmp_path, run_dir=tmp_path / "run")
    store.capture("docs/x.json", tmp_path / "docs" / "x.json", producer="coder")

    assert store.missing(["docs/x.json"]) == ["docs/x.json"]
    assert "NOT PRODUCED" in store.manifest(["docs/x.json"])


# ------------------------------------------------------------- the whole workflow


async def test_multi_agent_feature_workflow_runs_end_to_end(project: ProjectStore) -> None:
    """The DONE criterion: one complete multi-agent feature workflow, deterministic."""
    workflow = WorkflowLoader.for_project(project.root).load("multi-agent-feature")
    task = new_task(project, "multi-agent-feature")
    events_path = project.events_path(task.task_id)
    logger = RunLogger([jsonl_sink(events_path)], task_id=task.task_id)
    runtime = producing_runtime()

    result = await build(project, runtime, logger).run(task, workflow)

    assert result.completed, result.reason

    # Every specialist ran, in the declared order.
    order = [invocation.step_id for invocation in runtime.invocations]
    assert order[0] == "architect"
    assert order[1] == "coder"
    assert set(order[2:5]) == {"tester", "security", "docs"}
    assert order[5] == "reviewer"

    # Every declared artifact exists on disk.
    for relative in (
        "docs/architecture-proposal.md",
        "docs/implementation.patch",
        "docs/test-results.json",
        "docs/security-report.json",
        "docs/api-docs.md",
        "docs/review.json",
    ):
        assert (project.root / relative).is_file(), f"{relative} was never written"

    recorded = task.context["graph"]
    assert recorded["nodes"]["reviewer"] == "passed"
    assert {entry["name"] for entry in recorded["artifacts"]} >= {"docs/review.json"}

    events = [json.loads(line) for line in events_path.read_text(encoding="utf-8").splitlines()]
    kinds = {event["event"] for event in events}
    assert {"graph.start", "graph.level", "graph.node_start", "graph.finish"} <= kinds
    parallel = [
        event for event in events if event["event"] == "graph.level" and event.get("parallel")
    ]
    assert parallel, "the fan-out level should be recorded as parallel"


async def test_downstream_agents_receive_upstream_artifacts(project: ProjectStore) -> None:
    """The communication channel: references to files, never a conversation."""
    workflow = WorkflowLoader.for_project(project.root).load("multi-agent-feature")
    runtime = producing_runtime()

    await build(project, runtime).run(new_task(project, "multi-agent-feature"), workflow)

    coder_prompt = next(i for i in runtime.invocations if i.step_id == "coder").prompt
    assert "docs/architecture-proposal.md" in coder_prompt
    assert "produced by earlier agents" in coder_prompt

    reviewer_prompt = next(i for i in runtime.invocations if i.step_id == "reviewer").prompt
    for artifact in ("docs/test-results.json", "docs/security-report.json", "docs/api-docs.md"):
        assert artifact in reviewer_prompt, f"reviewer was not told about {artifact}"


async def test_claiming_an_artifact_is_not_producing_it(project: ProjectStore) -> None:
    """An agent that reports success without writing what it promised fails.

    Two independent checks catch this, and either is a pass: the artifacts verifier
    on the node (which retries first, so the agent gets a chance to fix it) and the
    supervisor's output capture. What matters is that a claim never substitutes for
    a file.
    """
    workflow = WorkflowLoader.for_project(project.root).load("multi-agent-feature")
    runtime = producing_runtime(
        coder=MockStep(summary="implemented it, honestly", write_declared_outputs=False)
    )
    task = new_task(project, "multi-agent-feature")

    result = await build(project, runtime).run(task, workflow)

    assert result.failed
    assert result.stopped_at == "coder"
    assert "implementation-written" in result.reason or "were not written" in result.reason
    assert not (project.root / "docs" / "implementation.patch").exists()
    # Downstream specialists never ran on the missing artifact.
    nodes = task.context["graph"]["nodes"]
    assert nodes["tester"] == "blocked" and nodes["reviewer"] == "blocked"


async def test_failure_blocks_downstream_and_preserves_work(project: ProjectStore) -> None:
    """Failure must not discard what already reached disk."""
    workflow = WorkflowLoader.for_project(project.root).load("multi-agent-feature")
    runtime = producing_runtime(
        coder=MockStep(fail_attempts=99, error="the coder could not build it")
    )
    task = new_task(project, "multi-agent-feature")

    result = await build(project, runtime).run(task, workflow)

    assert result.failed and result.stopped_at == "coder"

    nodes = task.context["graph"]["nodes"]
    for downstream in ("tester", "security", "docs", "reviewer"):
        assert nodes[downstream] == "blocked", f"{downstream} ran on a failed dependency"

    # The architect's work survives the coder's failure.
    assert (project.root / "docs" / "architecture-proposal.md").is_file()
    preserved = project.run_dir(task.task_id) / "preserved"
    assert preserved.is_dir()
    assert (preserved / "architecture-proposal.md").is_file()
    assert "docs/architecture-proposal.md" in task.context["graph"]["preserved"]


async def test_a_failing_specialist_does_not_discard_its_siblings(project: ProjectStore) -> None:
    """One parallel agent failing must not erase what the others produced."""
    workflow = WorkflowLoader.for_project(project.root).load("multi-agent-feature")
    runtime = producing_runtime(security=MockStep(fail_attempts=99, error="auditor crashed"))
    task = new_task(project, "multi-agent-feature")

    result = await build(project, runtime).run(task, workflow)

    assert result.failed
    nodes = task.context["graph"]["nodes"]
    assert nodes["security"] == "failed"
    # Its siblings ran and their work is intact.
    assert nodes["tester"] == "passed" and nodes["docs"] == "passed"
    assert (project.root / "docs" / "test-results.json").is_file()
    assert (project.root / "docs" / "api-docs.md").is_file()
    # The join is blocked rather than run on a missing report.
    assert nodes["reviewer"] == "blocked"


async def test_retry_is_bounded_and_recorded(project: ProjectStore) -> None:
    workflow = WorkflowLoader.for_project(project.root).load("multi-agent-feature")
    # Fails once, then succeeds - the coder node allows three attempts.
    runtime = producing_runtime(
        coder=MockStep(fail_attempts=1, writes={"docs/implementation.patch": "--- a/x\n+++ b/x\n"})
    )
    task = new_task(project, "multi-agent-feature")

    result = await build(project, runtime).run(task, workflow)

    assert result.completed
    assert task.step("coder").attempt_count == 2


async def test_parallel_nodes_share_no_state(project: ProjectStore) -> None:
    """Concurrency is safe because the level is independent by construction."""
    workflow = WorkflowLoader.for_project(project.root).load("multi-agent-feature")
    runtime = producing_runtime()

    await build(project, runtime).run(new_task(project, "multi-agent-feature"), workflow)

    for step_id in ("tester", "security", "docs"):
        invocation = next(i for i in runtime.invocations if i.step_id == step_id)
        assert invocation.attempt == 1
        # Each sibling sees only what it declared, not the others' outputs.
        assert "docs/review.json" not in invocation.prompt


async def test_conditional_node_is_skipped_not_failed(project: ProjectStore) -> None:
    """A guard that does not hold means "did not apply", not "went wrong"."""
    workflow = WorkflowSpec(
        name="conditional",
        verifiers=[VerifierSpec(id="made", kind="artifacts", expect=["docs/a.md"])],
        steps=[
            WorkflowStep(id="first", agent="architect", produces=["docs/a.md"], verify=["made"]),
            WorkflowStep(
                id="repair",
                agent="coder",
                depends_on=["first"],
                when="failed(first)",
                description="Only runs when the first step failed.",
            ),
            WorkflowStep(
                id="finish", agent="reviewer", depends_on=["first"], when="success(first)"
            ),
        ],
    )
    runtime = MockAgentRuntime(script={"first": MockStep(writes={"docs/a.md": "# a\n"})})
    task = new_task(project, "conditional")

    result = await build(project, runtime).run(task, workflow)

    assert result.completed
    nodes = task.context["graph"]["nodes"]
    assert nodes["first"] == "passed"
    assert nodes["repair"] == "skipped", "an unmet condition is a skip, not a failure"
    assert nodes["finish"] == "passed"
    assert "repair" not in [invocation.step_id for invocation in runtime.invocations]


async def test_approval_gate_pauses_the_graph(project: ProjectStore) -> None:
    workflow = WorkflowSpec(
        name="gated",
        steps=[
            WorkflowStep(id="design", agent="architect"),
            WorkflowStep(
                id="gate", kind=StepKind.APPROVAL, gate="architecture", depends_on=["design"]
            ),
            WorkflowStep(id="build", agent="coder", depends_on=["gate"]),
        ],
    )
    runtime = MockAgentRuntime()
    task = new_task(project, "gated")

    result = await build(project, runtime).run(task, workflow)

    assert result.awaiting_approval
    assert result.stopped_at == "gate"
    assert [i.step_id for i in runtime.invocations] == ["design"]


def test_supervisor_reports_are_serialisable(project: ProjectStore) -> None:
    """The graph record is persisted with the task, so a run is reviewable later."""
    from devforge.core.graph.supervisor import GraphRunReport, NodeOutcome

    report = GraphRunReport(graph="g")
    report.outcomes["a"] = NodeOutcome(node_id="a", status=NodeStatus.PASSED, produced=["x.json"])

    assert report.statuses == {"a": NodeStatus.PASSED}
    assert report.failed == [] and report.blocked == []
