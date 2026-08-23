"""Core domain models.

These are the only data structures shared across layers. They are deliberately
runtime-agnostic: nothing here knows about a specific agent runtime, tool
implementation or verifier binary.

A *task* is one execution of a workflow. DevForge does not model "run" as a
separate entity: the task id is the run id, and the run directory on disk is
``.devforge/runs/<task_id>/``. One concept, one identifier.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


def utcnow() -> datetime:
    """Timezone-aware UTC timestamp (used everywhere instead of ``datetime.now``)."""
    return datetime.now(UTC)


def new_id(prefix: str) -> str:
    """Short, sortable-enough identifier, e.g. ``task_9f2c1a4b``."""
    return f"{prefix}_{uuid4().hex[:8]}"


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=False)


# --------------------------------------------------------------------------- enums


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    AWAITING_APPROVAL = "awaiting_approval"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

    @property
    def terminal(self) -> bool:
        return self in {TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED}


class StepStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    AWAITING_APPROVAL = "awaiting_approval"
    REJECTED = "rejected"


class VerificationStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"
    SKIPPED = "skipped"
    UNAVAILABLE = "unavailable"

    @property
    def ok(self) -> bool:
        return self in {VerificationStatus.PASSED, VerificationStatus.SKIPPED}


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class ToolStatus(str, Enum):
    OK = "ok"
    ERROR = "error"
    DENIED = "denied"
    UNAVAILABLE = "unavailable"


class AgentResultStatus(str, Enum):
    OK = "ok"
    ERROR = "error"


class InvocationMode(str, Enum):
    """Why an agent is being called: first attempt, or repairing a verification failure."""

    INITIAL = "initial"
    REPAIR = "repair"


# --------------------------------------------------------------------------- records


class Artifact(_Model):
    """Something an agent produced that outlives the step (file, report, patch)."""

    path: str
    kind: str = "file"
    description: str = ""
    step_id: str | None = None
    created_at: datetime = Field(default_factory=utcnow)


class TaskError(_Model):
    """A structured failure attached to the task, not a Python exception."""

    kind: str
    message: str
    step_id: str | None = None
    detail: str = ""
    occurred_at: datetime = Field(default_factory=utcnow)


class ToolCall(_Model):
    """Record of one tool invocation, for observability and review."""

    tool: str
    action: str
    status: ToolStatus
    summary: str = ""
    duration_ms: int = 0
    called_at: datetime = Field(default_factory=utcnow)


class ToolResult(_Model):
    """Uniform return value of every tool action."""

    tool: str
    action: str
    status: ToolStatus
    output: str = ""
    error: str = ""
    data: dict[str, Any] = Field(default_factory=dict)
    duration_ms: int = 0

    @property
    def ok(self) -> bool:
        return self.status is ToolStatus.OK


class VerificationResult(_Model):
    """Outcome of a single verifier. Persisted verbatim - never summarised away."""

    verifier: str
    kind: str
    status: VerificationStatus
    required: bool = True
    exit_code: int | None = None
    duration_ms: int = 0
    summary: str = ""
    output_excerpt: str = ""
    step_id: str | None = None
    attempt: int = 1
    started_at: datetime = Field(default_factory=utcnow)

    @property
    def blocking_failure(self) -> bool:
        """True when this result must stop the step from passing."""
        return self.required and not self.status.ok


class AgentInvocation(_Model):
    """Everything a runtime needs to execute an agent. Runtime-agnostic by design."""

    invocation_id: str = Field(default_factory=lambda: new_id("inv"))
    task_id: str
    step_id: str
    agent: str
    role: str = ""
    mode: InvocationMode = InvocationMode.INITIAL
    attempt: int = 1
    system_prompt: str = ""
    prompt: str = ""
    context: dict[str, Any] = Field(default_factory=dict)
    skills: list[str] = Field(default_factory=list)
    tools: list[str] = Field(default_factory=list)
    workspace: str = "."
    timeout_s: int = 900


class AgentResult(_Model):
    """Structured result of an agent execution.

    ``status`` reports whether the *runtime* succeeded, never whether the work is
    correct - that judgement belongs exclusively to the verification layer.
    """

    invocation_id: str
    runtime: str
    status: AgentResultStatus = AgentResultStatus.OK
    summary: str = ""
    output: str = ""
    artifacts: list[Artifact] = Field(default_factory=list)
    tool_calls: list[ToolCall] = Field(default_factory=list)
    duration_ms: int = 0
    error: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status is AgentResultStatus.OK


class Approval(_Model):
    """A human decision gate, persisted so a run can pause and resume across processes."""

    gate: str
    step_id: str
    status: ApprovalStatus = ApprovalStatus.PENDING
    prompt: str = ""
    requested_at: datetime = Field(default_factory=utcnow)
    decided_at: datetime | None = None
    decided_by: str = ""
    reason: str = ""
    context: dict[str, Any] = Field(default_factory=dict)


class StepAttempt(_Model):
    """One pass through a step: agent execution plus the verification that followed."""

    attempt: int
    status: StepStatus = StepStatus.RUNNING
    agent_result: AgentResult | None = None
    verification: list[VerificationResult] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=utcnow)
    finished_at: datetime | None = None

    @property
    def failed_verifiers(self) -> list[VerificationResult]:
        return [v for v in self.verification if v.blocking_failure]


class StepRecord(_Model):
    """Execution history of a workflow step across all its attempts."""

    step_id: str
    kind: str = "agent"
    agent: str | None = None
    status: StepStatus = StepStatus.PENDING
    attempts: list[StepAttempt] = Field(default_factory=list)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error: str = ""
    #: Verdict of a falsify step: failed, survived, incomplete, unavailable, error.
    #: Recorded rather than derived from ``status`` because the two differ - a
    #: falsify step that finds a counterexample worked correctly and failed the step.
    falsification: str = ""
    #: Where the full report was persisted, so a finding stays explainable later.
    falsification_run_id: str = ""

    @property
    def attempt_count(self) -> int:
        return len(self.attempts)


class Task(_Model):
    """The unit of execution: one workflow run against one project."""

    task_id: str = Field(default_factory=lambda: new_id("task"))
    project_id: str
    description: str
    workflow: str
    runtime: str = "mock"
    status: TaskStatus = TaskStatus.PENDING
    current_step: str | None = None
    context: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
    steps: list[StepRecord] = Field(default_factory=list)
    artifacts: list[Artifact] = Field(default_factory=list)
    errors: list[TaskError] = Field(default_factory=list)
    verification_results: list[VerificationResult] = Field(default_factory=list)
    approvals: list[Approval] = Field(default_factory=list)

    # -- mutation helpers (timestamp discipline lives in one place) --------------

    def touch(self) -> None:
        self.updated_at = utcnow()

    def step(self, step_id: str) -> StepRecord | None:
        return next((s for s in self.steps if s.step_id == step_id), None)

    def ensure_step(
        self, step_id: str, kind: str = "agent", agent: str | None = None
    ) -> StepRecord:
        record = self.step(step_id)
        if record is None:
            record = StepRecord(step_id=step_id, kind=kind, agent=agent)
            self.steps.append(record)
        return record

    def approval(self, gate: str, step_id: str | None = None) -> Approval | None:
        for approval in self.approvals:
            if approval.gate == gate and (step_id is None or approval.step_id == step_id):
                return approval
        return None

    def add_error(
        self, kind: str, message: str, *, step_id: str | None = None, detail: str = ""
    ) -> TaskError:
        error = TaskError(kind=kind, message=message, step_id=step_id, detail=detail)
        self.errors.append(error)
        self.touch()
        return error

    def record_verification(self, results: list[VerificationResult]) -> None:
        self.verification_results.extend(results)
        self.touch()

    @property
    def completed_steps(self) -> list[str]:
        return [s.step_id for s in self.steps if s.status is StepStatus.PASSED]


class TaskResult(_Model):
    """The outcome of executing a workflow against a task.

    A summary view over :class:`Task`, returned by the orchestrator and rendered by
    the CLI. The task record remains the full history; this is what a caller needs
    in order to decide what happened and what to do next.
    """

    task_id: str
    workflow: str
    status: TaskStatus
    stopped_at: str | None = None
    reason: str = ""
    steps_passed: list[str] = Field(default_factory=list)
    steps_failed: list[str] = Field(default_factory=list)
    pending_gates: list[str] = Field(default_factory=list)
    verification_counts: dict[str, int] = Field(default_factory=dict)
    attempts_used: int = 0
    finished_at: datetime = Field(default_factory=utcnow)

    @classmethod
    def from_task(
        cls, task: Task, *, stopped_at: str | None = None, reason: str = ""
    ) -> TaskResult:
        counts: dict[str, int] = {}
        for result in task.verification_results:
            counts[result.status.value] = counts.get(result.status.value, 0) + 1
        return cls(
            task_id=task.task_id,
            workflow=task.workflow,
            status=task.status,
            stopped_at=stopped_at,
            reason=reason,
            steps_passed=[s.step_id for s in task.steps if s.status is StepStatus.PASSED],
            steps_failed=[
                s.step_id
                for s in task.steps
                if s.status in {StepStatus.FAILED, StepStatus.REJECTED}
            ],
            pending_gates=[a.gate for a in task.approvals if a.status is ApprovalStatus.PENDING],
            verification_counts=counts,
            attempts_used=sum(step.attempt_count for step in task.steps),
        )

    @property
    def completed(self) -> bool:
        return self.status is TaskStatus.COMPLETED

    @property
    def awaiting_approval(self) -> bool:
        return self.status is TaskStatus.AWAITING_APPROVAL

    @property
    def failed(self) -> bool:
        return self.status is TaskStatus.FAILED
