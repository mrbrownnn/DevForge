"""Deterministic runtime for tests, demos and dry runs.

The mock runtime never calls a model and never costs anything. Given the same
inputs it produces byte-identical output, which is what makes the end-to-end test
meaningful rather than flaky.

It can be scripted per step::

    MockAgentRuntime(script={"implementation": MockStep(status="error", error="boom")})

and it records every invocation it received, so tests can assert on what the
orchestrator actually asked for - including whether a repair attempt carried the
verification diagnostics.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path

from devforge.core.models import (
    AgentInvocation,
    AgentResult,
    AgentResultStatus,
    Artifact,
    InvocationMode,
    ToolCall,
    ToolStatus,
)
from devforge.runtime.base import AgentRuntime, RuntimeAvailability, RuntimeContext


@dataclass
class MockStep:
    """Scripted behaviour for one step id."""

    status: AgentResultStatus = AgentResultStatus.OK
    summary: str = ""
    output: str = ""
    error: str = ""
    #: Files (relative to the workspace) the mock agent should create.
    writes: dict[str, str] = field(default_factory=dict)
    #: Number of leading attempts that fail before this step starts succeeding.
    fail_attempts: int = 0


class MockAgentRuntime(AgentRuntime):
    """Deterministic in-process runtime that fabricates no external calls."""

    name = "mock"

    def __init__(self, script: dict[str, MockStep] | None = None) -> None:
        self.script = script or {}
        self.invocations: list[AgentInvocation] = []

    def availability(self) -> RuntimeAvailability:
        return RuntimeAvailability(available=True, detail="in-process deterministic runtime")

    async def execute(self, invocation: AgentInvocation, context: RuntimeContext) -> AgentResult:
        self.invocations.append(invocation)
        step = self.script.get(invocation.step_id, MockStep())

        if step.fail_attempts >= invocation.attempt:
            return AgentResult(
                invocation_id=invocation.invocation_id,
                runtime=self.name,
                status=AgentResultStatus.ERROR,
                summary=f"mock failure on attempt {invocation.attempt}",
                error=step.error or f"scripted failure for step '{invocation.step_id}'",
                duration_ms=0,
            )
        if step.status is AgentResultStatus.ERROR:
            return AgentResult(
                invocation_id=invocation.invocation_id,
                runtime=self.name,
                status=AgentResultStatus.ERROR,
                summary=step.summary or "mock error",
                error=step.error or "scripted error",
                duration_ms=0,
            )

        artifacts: list[Artifact] = []
        tool_calls: list[ToolCall] = []
        workspace = Path(context.workspace)
        for relative, content in step.writes.items():
            target = workspace / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
            artifacts.append(
                Artifact(path=relative, kind="file", description="written by mock runtime", step_id=invocation.step_id)
            )
            tool_calls.append(
                ToolCall(tool="filesystem", action="write", status=ToolStatus.OK, summary=relative)
            )

        summary = step.summary or self._default_summary(invocation)
        output = step.output or self._default_output(invocation)
        return AgentResult(
            invocation_id=invocation.invocation_id,
            runtime=self.name,
            status=AgentResultStatus.OK,
            summary=summary,
            output=output,
            artifacts=artifacts,
            tool_calls=tool_calls,
            duration_ms=0,
            metadata={"prompt_digest": self.prompt_digest(invocation), "mode": invocation.mode.value},
        )

    @staticmethod
    def prompt_digest(invocation: AgentInvocation) -> str:
        """Stable digest of the composed prompt - lets tests assert prompts changed."""
        payload = f"{invocation.system_prompt}\n{invocation.prompt}".encode()
        return hashlib.sha256(payload).hexdigest()[:16]

    @staticmethod
    def _default_summary(invocation: AgentInvocation) -> str:
        verb = "repaired" if invocation.mode is InvocationMode.REPAIR else "completed"
        return f"mock {invocation.agent} {verb} step '{invocation.step_id}' (attempt {invocation.attempt})"

    @staticmethod
    def _default_output(invocation: AgentInvocation) -> str:
        return (
            f"[mock:{invocation.agent}] step={invocation.step_id} "
            f"mode={invocation.mode.value} attempt={invocation.attempt} "
            f"skills={','.join(invocation.skills) or '-'} tools={','.join(invocation.tools) or '-'}"
        )
