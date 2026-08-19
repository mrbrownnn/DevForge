"""The Phase 2 completion criterion, executed.

    agent -> workflow -> tool -> result -> verification -> audit log

with no step bypassing the policy engine. The mock runtime issues real tool calls
through the executor, so this exercises the same path a delegating runtime would:
a granted call succeeds, an ungranted one is refused, a hostile one is denied, and
every outcome lands in the run journal.
"""

from __future__ import annotations

import json
from pathlib import Path

from devforge.agents.spec import AgentRegistry
from devforge.approval.gate import ApprovalGate
from devforge.core.models import StepStatus, Task, ToolStatus, VerificationStatus
from devforge.core.orchestrator.engine import Orchestrator
from devforge.core.registry.skills import SkillRegistry
from devforge.core.state.store import ProjectStore
from devforge.core.workflow.spec import StepKind, VerifierSpec, WorkflowSpec, WorkflowStep
from devforge.observability.logging import RunLogger, jsonl_sink
from devforge.policy.engine import PolicyEngine
from devforge.runtime.capabilities import Capability
from devforge.runtime.mock import MockAgentRuntime, MockStep, MockToolCall
from devforge.tools.base import ToolRegistry
from devforge.verification.engine import VerificationEngine


def build(project: ProjectStore, runtime: MockAgentRuntime, logger: RunLogger) -> Orchestrator:
    policy = PolicyEngine.load(None, workspace=project.root)
    return Orchestrator(
        store=project,
        runtime=runtime,
        tools=ToolRegistry.default(),
        skills=SkillRegistry.discover(project.root),
        agents=AgentRegistry.discover(project.root),
        verification=VerificationEngine(),
        approvals=ApprovalGate(policy),
        policy=policy,
        logger=logger,
        workspace=project.root,
    )


def task_for(project: ProjectStore, workflow: str = "toolchain") -> Task:
    return Task(
        project_id=project.load_config().project_id,
        description="Write the module and prove it exists",
        workflow=workflow,
        runtime="mock",
    )


async def test_agent_tool_result_verification_audit_chain(project: ProjectStore) -> None:
    task = task_for(project)
    events_path = project.events_path(task.task_id)
    logger = RunLogger([jsonl_sink(events_path)], task_id=task.task_id)

    runtime = MockAgentRuntime(
        script={
            "implementation": MockStep(
                tool_calls=[
                    # granted, allowed by policy -> writes a real file
                    MockToolCall(
                        "filesystem", "write", {"path": "src/auth.py", "content": "x = 1\n"}
                    ),
                    # granted tool, refused by policy: outside the write allowlist
                    MockToolCall(
                        "filesystem", "write", {"path": "node_modules/p/i.js", "content": "bad"}
                    ),
                    # granted tool, refused by policy: traversal
                    MockToolCall("filesystem", "read", {"path": "../../etc/passwd"}),
                    # not granted to this step at all
                    MockToolCall("shell", "run", {"argv": ["git", "status"]}),
                ]
            )
        }
    )

    workflow = WorkflowSpec(
        name="toolchain",
        verifiers=[
            VerifierSpec(
                id="module-written",
                kind="artifacts",
                expect=["src/auth.py"],
                required=True,
            )
        ],
        steps=[
            WorkflowStep(
                id="implementation",
                agent="coder",
                tools=["filesystem"],
                verify=["module-written"],
                max_attempts=1,
            ),
            WorkflowStep(
                id="verification",
                kind=StepKind.VERIFY,
                verify=["module-written"],
            ),
        ],
    )

    result = await build(project, runtime, logger).run(task, workflow)

    # -- the workflow completed on the strength of real verification
    assert result.completed, result.reason
    assert task.step("implementation").status is StepStatus.PASSED
    assert [r.status for r in task.verification_results] == [
        VerificationStatus.PASSED,
        VerificationStatus.PASSED,
    ]

    # -- the tool actually did the work
    assert (project.root / "src" / "auth.py").read_text(encoding="utf-8") == "x = 1\n"

    # -- and policy refused everything it should have, mid-run
    calls = {
        (call.tool, call.action, call.status)
        for call in task.step("implementation").attempts[0].agent_result.tool_calls
    }
    assert ("filesystem", "write", ToolStatus.OK) in calls
    assert ("filesystem", "write", ToolStatus.DENIED) in calls
    assert ("filesystem", "read", ToolStatus.DENIED) in calls
    assert ("shell", "run", ToolStatus.DENIED) in calls
    assert not (project.root / "node_modules").exists(), "a denied write must leave no trace"

    # -- the audit log records the whole chain
    events = [json.loads(line) for line in events_path.read_text(encoding="utf-8").splitlines()]
    kinds = [event["event"] for event in events]
    for expected in (
        "run.start",
        "agent.invoke",
        "tool.call",
        "tool.denied",
        "verification.start",
        "verification.finish",
        "run.finish",
    ):
        assert expected in kinds, f"the audit log is missing '{expected}'"

    tool_events = [event for event in events if event["event"] == "tool.call"]
    assert {event["status"] for event in tool_events} == {"ok", "denied"}
    assert all(event["task_id"] == task.task_id for event in events)
    assert all("timestamp" in event for event in events)


async def test_tool_scope_comes_from_the_step_or_the_agent_default(project: ProjectStore) -> None:
    """Least privilege: the scope is what the step declared, or the agent default when
    the step declared nothing. Anything outside it is refused, whatever the agent asks
    for. The architect agent defaults to `filesystem`, so `shell` is out of scope."""
    task = task_for(project, "scope")
    runtime = MockAgentRuntime(
        script={
            "plan": MockStep(
                tool_calls=[
                    MockToolCall("filesystem", "write", {"path": "docs/n.md", "content": "n"}),
                    MockToolCall("shell", "run", {"argv": ["git", "status"]}),
                    MockToolCall("git", "status", {}),
                ]
            )
        }
    )
    workflow = WorkflowSpec(name="scope", steps=[WorkflowStep(id="plan", agent="architect")])

    await build(project, runtime, RunLogger([])).run(task, workflow)

    calls = {
        call.tool: call.status for call in task.step("plan").attempts[0].agent_result.tool_calls
    }
    assert calls["filesystem"] is ToolStatus.OK, "the agent default grants filesystem"
    assert calls["shell"] is ToolStatus.DENIED
    assert calls["git"] is ToolStatus.DENIED


async def test_runtime_capabilities_are_declared_not_assumed(project: ProjectStore) -> None:
    capabilities = MockAgentRuntime().capabilities()

    assert capabilities.has(Capability.TOOLS)
    assert not capabilities.has(Capability.BROWSER), "absent means no, never unknown"
    assert capabilities.missing({Capability.TOOLS, Capability.STREAMING}) == {Capability.STREAMING}
    assert capabilities.describe()["name"] == "mock"


async def test_tool_denials_do_not_fail_the_step_by_themselves(project: ProjectStore) -> None:
    """A refused tool call is information for the agent, not an automatic step failure -
    the verifiers still decide. Here the agent recovers by writing the file it was
    allowed to write, and verification passes on that evidence."""
    task = task_for(project, "recover")
    runtime = MockAgentRuntime(
        script={
            "implementation": MockStep(
                tool_calls=[
                    MockToolCall("filesystem", "write", {"path": "/etc/passwd", "content": "bad"}),
                    MockToolCall("filesystem", "write", {"path": "src/ok.py", "content": "ok\n"}),
                ]
            )
        }
    )
    workflow = WorkflowSpec(
        name="recover",
        verifiers=[VerifierSpec(id="written", kind="artifacts", expect=["src/ok.py"])],
        steps=[
            WorkflowStep(
                id="implementation", agent="coder", tools=["filesystem"], verify=["written"]
            )
        ],
    )

    result = await build(project, runtime, RunLogger([])).run(task, workflow)

    assert result.completed
    assert (project.root / "src" / "ok.py").is_file()


async def test_state_records_tool_calls_for_review(project: ProjectStore) -> None:
    task = task_for(project, "audit")
    runtime = MockAgentRuntime(
        script={
            "implementation": MockStep(
                tool_calls=[
                    MockToolCall("filesystem", "write", {"path": "src/a.py", "content": "a"})
                ]
            )
        }
    )
    workflow = WorkflowSpec(
        name="audit",
        steps=[WorkflowStep(id="implementation", agent="coder", tools=["filesystem"])],
    )

    await build(project, runtime, RunLogger([])).run(task, workflow)
    reloaded = project.load_task(task.task_id)

    recorded = reloaded.step("implementation").attempts[0].agent_result.tool_calls
    assert any(call.tool == "filesystem" and call.status is ToolStatus.OK for call in recorded)


async def test_mcp_tool_is_reachable_through_the_executor(project: ProjectStore) -> None:
    """The MCP bridge is a tool like any other: same scope check, same audit trail."""
    task = task_for(project, "mcp")
    runtime = MockAgentRuntime(
        script={"discover": MockStep(tool_calls=[MockToolCall("mcp", "list_servers", {})])}
    )
    workflow = WorkflowSpec(
        name="mcp", steps=[WorkflowStep(id="discover", agent="architect", tools=["mcp"])]
    )

    await build(project, runtime, RunLogger([])).run(task, workflow)

    call = task.step("discover").attempts[0].agent_result.tool_calls[0]
    assert call.tool == "mcp"
    assert call.status is ToolStatus.OK, "an empty server list is a valid answer"


def test_init_scaffolds_a_denied_by_default_mcp_config(tmp_path: Path) -> None:
    store = ProjectStore.initialize(tmp_path, name="p")

    from devforge.mcp.registry import load_config

    config_file = store.devforge_dir / "mcp.yaml"
    assert config_file.is_file()
    assert load_config(store.root).servers == []
    assert "Nothing here is trusted by being listed" in config_file.read_text(encoding="utf-8")
