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
from devforge.runtime.capabilities import Capability, RuntimeCapabilities


@dataclass
class MockToolCall:
    """A tool call the mock agent should make through the executor."""

    tool: str
    action: str
    params: dict = field(default_factory=dict)


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
    #: Tool calls to make through the executor, in order.
    tool_calls: list[MockToolCall] = field(default_factory=list)


class MockAgentRuntime(AgentRuntime):
    """Deterministic in-process runtime that fabricates no external calls."""

    name = "mock"

    def __init__(self, script: dict[str, MockStep] | None = None) -> None:
        self.script = script or {}
        self.invocations: list[AgentInvocation] = []

    def availability(self) -> RuntimeAvailability:
        return RuntimeAvailability(available=True, detail="in-process deterministic runtime")

    def capabilities(self) -> RuntimeCapabilities:
        return RuntimeCapabilities(
            name=self.name,
            version="1.0.0",
            capabilities={Capability.TOOLS, Capability.STRUCTURED_OUTPUT},
            notes=(
                "Deterministic and offline. Calls tools through the DevForge executor, "
                "so its tool use is fully policy-checked - which is what makes the "
                "end-to-end security tests meaningful."
            ),
        )

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

        # Produce whatever the workflow step declared as an output. A real agent writes
        # these files; the mock writes a placeholder with the same name, so the artifact
        # verifier has something genuine to check. The verification is real either way -
        # only the file content is a stand-in.
        writes = dict(step.writes)
        for declared in invocation.context.get("outputs", []):
            writes.setdefault(declared, self._placeholder(invocation, declared))

        for relative, content in writes.items():
            target = workspace / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
            artifacts.append(
                Artifact(
                    path=relative,
                    kind="file",
                    description="written by mock runtime",
                    step_id=invocation.step_id,
                )
            )
            tool_calls.append(
                ToolCall(tool="filesystem", action="write", status=ToolStatus.OK, summary=relative)
            )

        # Tool calls go through the executor, so the mock exercises the same policy
        # path a real runtime would - denials included.
        for planned in step.tool_calls:
            if context.executor is None:
                tool_calls.append(
                    ToolCall(
                        tool=planned.tool,
                        action=planned.action,
                        status=ToolStatus.DENIED,
                        summary="no tool executor was provided to this runtime",
                    )
                )
                continue
            outcome = await context.executor.call(planned.tool, planned.action, planned.params)
            tool_calls.append(
                ToolCall(
                    tool=outcome.tool,
                    action=outcome.action,
                    status=outcome.status,
                    summary=(outcome.error or outcome.output or "")[:200],
                    duration_ms=outcome.duration_ms,
                )
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
            metadata={
                "prompt_digest": self.prompt_digest(invocation),
                "mode": invocation.mode.value,
            },
        )

    @staticmethod
    def _placeholder(invocation: AgentInvocation, relative: str) -> str:
        """Deterministic stand-in content for a declared output."""
        return (
            f"# {relative}\n\n"
            f"Placeholder written by the mock runtime for step '{invocation.step_id}' "
            f"(agent {invocation.agent}, attempt {invocation.attempt}).\n\n"
            f"Task: {invocation.task_id}\n"
        )

    @staticmethod
    def prompt_digest(invocation: AgentInvocation) -> str:
        """Stable digest of the composed prompt - lets tests assert prompts changed."""
        payload = f"{invocation.system_prompt}\n{invocation.prompt}".encode()
        return hashlib.sha256(payload).hexdigest()[:16]

    @staticmethod
    def _default_summary(invocation: AgentInvocation) -> str:
        verb = "repaired" if invocation.mode is InvocationMode.REPAIR else "completed"
        return (
            f"mock {invocation.agent} {verb} step '{invocation.step_id}' "
            f"(attempt {invocation.attempt})"
        )

    @staticmethod
    def _default_output(invocation: AgentInvocation) -> str:
        return (
            f"[mock:{invocation.agent}] step={invocation.step_id} "
            f"mode={invocation.mode.value} attempt={invocation.attempt} "
            f"skills={','.join(invocation.skills) or '-'} tools={','.join(invocation.tools) or '-'}"
        )
