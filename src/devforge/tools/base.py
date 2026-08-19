"""Tool interface and registry.

A tool is an executable capability with a stable name, a set of actions, and a
uniform :class:`~devforge.core.models.ToolResult`. The orchestrator never
branches on tool type, so a new tool is added by registering it - no core change.

Every tool receives a :class:`ToolContext` carrying the policy engine, and must
consult it before touching the filesystem, spawning a process or reaching the
network. Helper methods on this class implement that consultation once so tools
cannot forget it in a new code path.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from devforge.core.models import Task, ToolResult, ToolStatus
from devforge.core.registry.base import Registry
from devforge.observability.logging import RunLogger, null_logger
from devforge.policy.engine import PolicyDecision, PolicyEngine


@dataclass(frozen=True)
class ToolAvailability:
    available: bool
    detail: str = ""


@dataclass
class ToolContext:
    workspace: Path
    policy: PolicyEngine
    logger: RunLogger = field(default_factory=null_logger)
    task: Task | None = None
    approval_gate: Any | None = None  # devforge.approval.gate.ApprovalGate
    step_id: str = ""


class Tool(ABC):
    name: str = "tool"
    description: str = ""
    actions: tuple[str, ...] = ()

    @abstractmethod
    async def invoke(self, action: str, params: dict[str, Any], ctx: ToolContext) -> ToolResult:
        """Perform ``action`` and return a structured result.

        Tools report failure through ``ToolResult.status``; they raise only for
        programming errors.
        """

    def availability(self) -> ToolAvailability:
        return ToolAvailability(available=True)

    # -- helpers shared by every tool -------------------------------------------

    def ok(self, action: str, output: str = "", **data: Any) -> ToolResult:
        return ToolResult(tool=self.name, action=action, status=ToolStatus.OK, output=output, data=data)

    def fail(self, action: str, error: str, **data: Any) -> ToolResult:
        return ToolResult(tool=self.name, action=action, status=ToolStatus.ERROR, error=error, data=data)

    def denied(self, action: str, decision: PolicyDecision) -> ToolResult:
        return ToolResult(
            tool=self.name,
            action=action,
            status=ToolStatus.DENIED,
            error=decision.reason,
            data={"effect": decision.effect.value, "rule": decision.rule, "gate": decision.gate},
        )

    def unavailable(self, action: str, detail: str) -> ToolResult:
        return ToolResult(
            tool=self.name, action=action, status=ToolStatus.UNAVAILABLE, error=detail
        )

    def unknown_action(self, action: str) -> ToolResult:
        return self.fail(
            action, f"unknown action '{action}' for tool '{self.name}'; expected one of {list(self.actions)}"
        )

    def authorize(self, action: str, decision: PolicyDecision, ctx: ToolContext, *, gate_prompt: str = "") -> ToolResult | None:
        """Return a blocking ToolResult, or ``None`` when the operation may proceed.

        When policy demands approval, an approval is requested on the task. If it
        has already been granted the operation proceeds; otherwise the caller is
        told it is waiting on a human.
        """
        if decision.allowed:
            return None
        if not decision.needs_approval:
            return self.denied(action, decision)

        gate = decision.gate or "destructive_command"
        if ctx.approval_gate is None or ctx.task is None:
            return self.denied(action, decision)

        approval = ctx.approval_gate.request(
            ctx.task,
            gate=gate,
            step_id=ctx.step_id or "tool",
            prompt=gate_prompt or decision.reason,
            context={"tool": self.name, "action": action, "rule": decision.rule},
        )
        from devforge.core.models import ApprovalStatus

        if approval.status is ApprovalStatus.APPROVED:
            return None
        if approval.status is ApprovalStatus.REJECTED:
            return self.denied(action, decision)
        return ToolResult(
            tool=self.name,
            action=action,
            status=ToolStatus.DENIED,
            error=f"awaiting approval at gate '{gate}': {decision.reason}",
            data={"gate": gate, "awaiting_approval": True},
        )


class ToolRegistry(Registry[Tool]):
    def __init__(self) -> None:
        super().__init__("tool")

    @classmethod
    def default(cls) -> ToolRegistry:
        from devforge.tools.browser import BrowserTool
        from devforge.tools.filesystem import FilesystemTool
        from devforge.tools.git import GitTool
        from devforge.tools.mcp import McpTool
        from devforge.tools.shell import ShellTool

        registry = cls()
        for tool in (FilesystemTool(), ShellTool(), GitTool(), BrowserTool(), McpTool()):
            registry.register(tool.name, tool)
        return registry

    def subset(self, names: list[str]) -> ToolRegistry:
        """A registry containing only the named tools - what a step is allowed to use."""
        scoped = ToolRegistry()
        for name in names:
            scoped.register(name, self.get(name))
        return scoped

    def availability(self) -> dict[str, ToolAvailability]:
        return {tool.name: tool.availability() for tool in self.all()}

    def unavailable_names(self, names: list[str]) -> list[str]:
        return [name for name in names if not self.get(name).availability().available]
