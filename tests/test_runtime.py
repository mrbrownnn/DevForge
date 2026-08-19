from __future__ import annotations

import json
from pathlib import Path

import pytest

from devforge.agents.prompt import build_invocation
from devforge.agents.spec import AgentRegistry
from devforge.core.errors import RegistryError, RuntimeExecutionError
from devforge.core.models import (
    AgentInvocation,
    AgentResultStatus,
    InvocationMode,
    StepAttempt,
    Task,
    VerificationResult,
    VerificationStatus,
)
from devforge.core.registry.skills import SkillRegistry
from devforge.core.workflow.spec import WorkflowStep
from devforge.runtime.base import AgentRuntime, RuntimeContext
from devforge.runtime.claude_code import ClaudeCodeRuntime
from devforge.runtime.mock import MockAgentRuntime, MockStep
from devforge.runtime.registry import RuntimeRegistry


def make_invocation(**overrides) -> AgentInvocation:
    defaults = dict(task_id="task_1", step_id="implementation", agent="coder", prompt="do it")
    return AgentInvocation(**{**defaults, **overrides})


def context(tmp_path: Path) -> RuntimeContext:
    return RuntimeContext(workspace=tmp_path)


# --------------------------------------------------------------------------- mock


async def test_mock_runtime_is_deterministic(tmp_path: Path) -> None:
    runtime = MockAgentRuntime()
    invocation = make_invocation()

    first = await runtime.execute(invocation, context(tmp_path))
    second = await runtime.execute(invocation, context(tmp_path))

    assert first.output == second.output
    assert first.summary == second.summary
    assert first.ok and first.runtime == "mock"


async def test_mock_runtime_records_invocations(tmp_path: Path) -> None:
    runtime = MockAgentRuntime()
    await runtime.execute(make_invocation(step_id="a"), context(tmp_path))
    await runtime.execute(make_invocation(step_id="b"), context(tmp_path))

    assert [i.step_id for i in runtime.invocations] == ["a", "b"]


async def test_mock_runtime_writes_scripted_files(tmp_path: Path) -> None:
    runtime = MockAgentRuntime(script={"implementation": MockStep(writes={"src/app.py": "x = 1\n"})})

    result = await runtime.execute(make_invocation(), context(tmp_path))

    assert (tmp_path / "src" / "app.py").read_text(encoding="utf-8") == "x = 1\n"
    assert [a.path for a in result.artifacts] == ["src/app.py"]
    assert result.tool_calls[0].tool == "filesystem"


async def test_mock_runtime_scripted_error(tmp_path: Path) -> None:
    runtime = MockAgentRuntime(
        script={"implementation": MockStep(status=AgentResultStatus.ERROR, error="boom")}
    )

    result = await runtime.execute(make_invocation(), context(tmp_path))

    assert not result.ok and result.error == "boom"


async def test_mock_runtime_fails_first_n_attempts(tmp_path: Path) -> None:
    runtime = MockAgentRuntime(script={"implementation": MockStep(fail_attempts=1)})

    first = await runtime.execute(make_invocation(attempt=1), context(tmp_path))
    second = await runtime.execute(make_invocation(attempt=2), context(tmp_path))

    assert not first.ok
    assert second.ok


async def test_repair_prompt_differs_from_initial_prompt(tmp_path: Path) -> None:
    task = Task(project_id="p", description="Add JWT auth", workflow="feature")
    step = WorkflowStep(id="implementation", agent="coder", verify=["tests"])
    agent = AgentRegistry.discover(None).get("coder")
    skills = SkillRegistry.discover(None).resolve(["backend"])
    failed = StepAttempt(
        attempt=1,
        verification=[
            VerificationResult(
                verifier="tests",
                kind="tests",
                status=VerificationStatus.FAILED,
                exit_code=1,
                output_excerpt="AssertionError: expected 401",
            )
        ],
    )

    initial = build_invocation(
        task=task, step=step, agent=agent, skills=skills, memory={}, tools=["filesystem"]
    )
    repair = build_invocation(
        task=task,
        step=step,
        agent=agent,
        skills=skills,
        memory={},
        tools=["filesystem"],
        attempt=2,
        previous_attempt=failed,
    )

    assert initial.mode is InvocationMode.INITIAL
    assert repair.mode is InvocationMode.REPAIR
    assert "AssertionError: expected 401" in repair.prompt
    assert MockAgentRuntime.prompt_digest(initial) != MockAgentRuntime.prompt_digest(repair)
    assert "{{" not in repair.prompt, "all placeholders should be substituted"


# --------------------------------------------------------------------- claude-code


def test_claude_runtime_builds_argv_without_secrets() -> None:
    runtime = ClaudeCodeRuntime(model="opus", permission_mode="acceptEdits")
    invocation = make_invocation(
        system_prompt="you are a coder", tools=["filesystem", "git"], prompt="implement X"
    )

    argv = runtime.build_argv(invocation, "claude")

    assert argv[:2] == ["claude", "-p"]
    assert "implement X" in argv
    assert "--output-format" in argv and "json" in argv
    assert argv[argv.index("--append-system-prompt") + 1] == "you are a coder"
    assert argv[argv.index("--model") + 1] == "opus"
    assert argv[argv.index("--permission-mode") + 1] == "acceptEdits"


def test_claude_runtime_tool_mapping_is_least_privilege() -> None:
    assert ClaudeCodeRuntime.allowed_tools(["filesystem"]) == ["Edit", "Glob", "Grep", "Read", "Write"]
    assert ClaudeCodeRuntime.allowed_tools(["git"]) == ["Bash(git *)"]
    assert "Bash" not in ClaudeCodeRuntime.allowed_tools(["filesystem"])
    assert ClaudeCodeRuntime.allowed_tools(["browser"]) == []


def test_claude_runtime_parses_json_envelope() -> None:
    runtime = ClaudeCodeRuntime()
    payload = json.dumps(
        {
            "type": "result",
            "is_error": False,
            "result": "Implemented the endpoint.\nAdded tests.",
            "session_id": "sess_1",
            "num_turns": 4,
            "duration_ms": 1234,
            "total_cost_usd": 0.02,
        }
    )

    result = runtime.parse_result(
        make_invocation(), stdout=payload, stderr="", returncode=0, duration_ms=99
    )

    assert result.ok
    assert result.summary == "Implemented the endpoint."
    assert result.output.startswith("Implemented")
    assert result.duration_ms == 1234
    assert result.metadata["session_id"] == "sess_1"


def test_claude_runtime_reports_error_envelope() -> None:
    runtime = ClaudeCodeRuntime()
    payload = json.dumps({"is_error": True, "result": "rate limited", "subtype": "error"})

    result = runtime.parse_result(
        make_invocation(), stdout=payload, stderr="", returncode=1, duration_ms=10
    )

    assert result.status is AgentResultStatus.ERROR
    assert "rate limited" in result.error


def test_claude_runtime_handles_non_json_output() -> None:
    runtime = ClaudeCodeRuntime()

    ok = runtime.parse_result(
        make_invocation(), stdout="plain text", stderr="", returncode=0, duration_ms=5
    )
    failed = runtime.parse_result(
        make_invocation(), stdout="", stderr="binary exploded", returncode=2, duration_ms=5
    )

    assert ok.ok and ok.output == "plain text" and ok.metadata["parsed"] is False
    assert not failed.ok and failed.error == "binary exploded"


def test_claude_runtime_availability_when_binary_missing() -> None:
    runtime = ClaudeCodeRuntime(binary="definitely-not-a-real-binary-xyz")
    status = runtime.availability()

    assert not status.available
    assert "not found on PATH" in status.detail


async def test_claude_runtime_execute_refuses_without_binary(tmp_path: Path) -> None:
    runtime = ClaudeCodeRuntime(binary="definitely-not-a-real-binary-xyz")

    with pytest.raises(RuntimeExecutionError, match="unavailable"):
        await runtime.execute(make_invocation(), context(tmp_path))


# ----------------------------------------------------------------------- registry


def test_runtime_registry_defaults_and_construction() -> None:
    registry = RuntimeRegistry.default()

    assert registry.names() == ["claude-code", "mock"]
    assert isinstance(registry.create("mock"), MockAgentRuntime)
    assert isinstance(registry.create("mock"), AgentRuntime)
    with pytest.raises(RegistryError, match="Available: claude-code, mock"):
        registry.create("gpt-whatever")


def test_runtime_registry_availability_report() -> None:
    report = RuntimeRegistry.default().availability()

    assert report["mock"][0] is True
    assert isinstance(report["claude-code"][0], bool)


def test_registry_survives_a_broken_adapter() -> None:
    registry = RuntimeRegistry.default()

    def broken() -> AgentRuntime:
        raise OSError("no")

    registry.register("broken", broken)
    report = registry.availability()

    assert report["broken"] == (False, "failed to construct: no")
    assert report["mock"][0] is True
