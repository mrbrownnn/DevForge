"""Execution context.

One object carries the run-scoped environment - task, workspace, policy, tools,
logger - and derives the narrower contexts that runtimes, tools and verifiers
actually receive. Before this existed the orchestrator built three similar
context objects inline at three call sites, which is how they drift apart.

Each derived context is deliberately narrow: a verifier has no reason to hold the
tool registry, and a runtime has no reason to hold the approval gate. The
execution context is the composition root for a run; the derived contexts are
capability slices of it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from devforge.core.models import Task
from devforge.observability.logging import RunLogger, null_logger
from devforge.policy.engine import PolicyEngine

if TYPE_CHECKING:  # pragma: no cover - typing only
    from devforge.runtime.base import RuntimeContext
    from devforge.tools.base import ToolContext, ToolRegistry
    from devforge.tools.executor import ToolExecutor
    from devforge.verification.base import VerificationContext


@dataclass
class ExecutionContext:
    """Everything one workflow run needs while it executes."""

    task: Task
    workspace: Path
    policy: PolicyEngine
    tools: ToolRegistry | None = None
    approval_gate: Any | None = None  # devforge.approval.gate.ApprovalGate
    logger: RunLogger = field(default_factory=null_logger)
    step_id: str = ""
    attempt: int = 1

    def for_step(self, step_id: str, attempt: int = 1) -> ExecutionContext:
        """A copy bound to one step and attempt, with a logger bound to match."""
        return ExecutionContext(
            task=self.task,
            workspace=self.workspace,
            policy=self.policy,
            tools=self.tools,
            approval_gate=self.approval_gate,
            logger=self.logger.bind(step=step_id, attempt=attempt),
            step_id=step_id,
            attempt=attempt,
        )

    # -- capability slices ------------------------------------------------------

    def for_runtime(self, tools: ToolRegistry | None = None) -> RuntimeContext:
        from devforge.runtime.base import RuntimeContext

        scoped = tools if tools is not None else self.tools
        return RuntimeContext(
            workspace=self.workspace,
            tools=scoped,
            executor=self.executor(scoped),
            logger=self.logger,
        )

    def executor(self, tools: ToolRegistry | None = None) -> ToolExecutor | None:
        """The policy-enforcing door for tool calls, scoped to this step.

        A step that declared no tools gets an executor with an empty scope rather
        than none: the agent can still attempt a call, and the refusal is recorded.
        Silence would hide the attempt.
        """
        from devforge.tools.executor import ToolExecutor

        if tools is None and self.tools is None:
            return None
        scoped = tools if tools is not None else self.tools
        return ToolExecutor(
            registry=scoped if scoped is not None else self.tools,
            context=self.for_tool(),
            allowed=tuple(scoped.names()) if scoped is not None else (),
        )

    def for_tool(self) -> ToolContext:
        from devforge.tools.base import ToolContext

        return ToolContext(
            workspace=self.workspace,
            policy=self.policy,
            logger=self.logger,
            task=self.task,
            approval_gate=self.approval_gate,
            step_id=self.step_id,
        )

    def for_verification(self) -> VerificationContext:
        from devforge.verification.base import VerificationContext

        return VerificationContext(
            workspace=self.workspace,
            policy=self.policy,
            logger=self.logger,
            step_id=self.step_id,
            attempt=self.attempt,
            task_id=self.task.task_id,
        )
