from __future__ import annotations

import pytest
from pydantic import ValidationError

from devforge.core.models import (
    AgentInvocation,
    AgentResult,
    AgentResultStatus,
    InvocationMode,
    StepAttempt,
    StepStatus,
    Task,
    TaskStatus,
    VerificationResult,
    VerificationStatus,
)


def test_task_defaults_and_ids() -> None:
    task = Task(project_id="p", description="d", workflow="feature")

    assert task.task_id.startswith("task_")
    assert task.status is TaskStatus.PENDING
    assert task.current_step is None
    assert task.steps == [] and task.errors == [] and task.verification_results == []


def test_terminal_status_property() -> None:
    assert TaskStatus.COMPLETED.terminal and TaskStatus.FAILED.terminal
    assert not TaskStatus.RUNNING.terminal
    assert not TaskStatus.AWAITING_APPROVAL.terminal


def test_ensure_step_is_idempotent() -> None:
    task = Task(project_id="p", description="d", workflow="feature")
    first = task.ensure_step("impl", agent="coder")
    second = task.ensure_step("impl", agent="coder")

    assert first is second
    assert len(task.steps) == 1


def test_add_error_touches_task() -> None:
    task = Task(project_id="p", description="d", workflow="feature")
    before = task.updated_at
    error = task.add_error("verification", "tests failed", step_id="impl")

    assert task.errors == [error]
    assert task.updated_at >= before


def test_verification_blocking_failure_respects_required_flag() -> None:
    required = VerificationResult(
        verifier="tests", kind="command", status=VerificationStatus.FAILED
    )
    optional = VerificationResult(
        verifier="lint", kind="command", status=VerificationStatus.FAILED, required=False
    )
    unavailable = VerificationResult(
        verifier="visual", kind="visual", status=VerificationStatus.UNAVAILABLE
    )

    assert required.blocking_failure
    assert not optional.blocking_failure
    assert unavailable.blocking_failure, "an unavailable required verifier must not silently pass"
    assert VerificationStatus.SKIPPED.ok


def test_step_attempt_collects_failed_verifiers() -> None:
    attempt = StepAttempt(
        attempt=1,
        status=StepStatus.FAILED,
        verification=[
            VerificationResult(verifier="tests", kind="command", status=VerificationStatus.FAILED),
            VerificationResult(verifier="lint", kind="command", status=VerificationStatus.PASSED),
        ],
    )
    assert [v.verifier for v in attempt.failed_verifiers] == ["tests"]


def test_agent_result_ok_property() -> None:
    ok = AgentResult(invocation_id="i", runtime="mock")
    failed = AgentResult(invocation_id="i", runtime="mock", status=AgentResultStatus.ERROR)

    assert ok.ok and not failed.ok


def test_invocation_defaults_to_initial_mode() -> None:
    invocation = AgentInvocation(task_id="t", step_id="s", agent="coder")

    assert invocation.mode is InvocationMode.INITIAL
    assert invocation.attempt == 1
    assert invocation.invocation_id.startswith("inv_")


def test_models_reject_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        Task(project_id="p", description="d", workflow="feature", bogus=True)
