"""The single door through which every tool call passes.

Phase 0 shipped a tool layer that the orchestrator used but agents did not: a
runtime executing its own file edits bypassed `permissions.yaml` entirely, and
that was recorded as the first roadmap item. The executor closes it for any
runtime that accepts one.

Everything a tool call needs to be safe happens here, in order, once:

1. the tool exists and is available;
2. the tool is in the scope granted to this step (least privilege);
3. the action exists on that tool;
4. parameters validate against the declared input schema;
5. a destructive-risk tool routes through an approval gate;
6. the call executes with a timeout;
7. the outcome is audited - allowed or refused, both are events.

A runtime that cannot delegate its tool calls - an external CLI that runs its own -
is unaffected, and that limitation stays documented. What the executor guarantees
is that when a call *does* come through DevForge, no path around the policy engine
exists.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any

from devforge.core.models import ToolCall, ToolResult, ToolStatus
from devforge.tools.base import ToolContext, ToolRegistry
from devforge.tools.descriptor import RiskLevel

DEFAULT_CALL_TIMEOUT_S = 300.0


@dataclass
class ToolExecutor:
    """Executes tool calls on behalf of an agent, under policy.

    ``allowed`` is the tool scope for the current step. An empty scope means the
    agent may call nothing, which is the correct default for a step that declared
    no tools.
    """

    registry: ToolRegistry
    context: ToolContext
    allowed: tuple[str, ...] = ()
    timeout_s: float = DEFAULT_CALL_TIMEOUT_S
    calls: list[ToolCall] = field(default_factory=list)

    def names(self) -> list[str]:
        return sorted(self.allowed)

    def descriptors(self) -> list[dict[str, Any]]:
        """What the agent is allowed to use, in a form safe to put in a prompt."""
        described = []
        for name in self.names():
            tool = self.registry.try_get(name)
            if tool is None:
                continue
            descriptor = tool.descriptor
            described.append(
                {
                    "name": descriptor.name,
                    "version": descriptor.version,
                    "description": descriptor.description,
                    "actions": list(descriptor.actions),
                    "risk": descriptor.risk.value,
                    "permissions": descriptor.permissions.summary(),
                }
            )
        return described

    async def call(
        self, tool_name: str, action: str, params: dict[str, Any] | None = None
    ) -> ToolResult:
        params = params or {}
        started = time.monotonic()
        result = await self._call(tool_name, action, params)
        result.duration_ms = result.duration_ms or int((time.monotonic() - started) * 1000)

        self.calls.append(
            ToolCall(
                tool=tool_name,
                action=action,
                status=result.status,
                summary=(result.error or result.output or "")[:200],
                duration_ms=result.duration_ms,
            )
        )
        self.context.logger.info(
            "tool.call",
            tool=tool_name,
            action=action,
            status=result.status.value,
            duration_ms=result.duration_ms,
            step=self.context.step_id or None,
            error=result.error or None,
        )
        return result

    async def _call(self, tool_name: str, action: str, params: dict[str, Any]) -> ToolResult:
        if tool_name not in self.allowed:
            self.context.logger.warn(
                "tool.denied",
                tool=tool_name,
                action=action,
                reason="tool is not in the scope granted to this step",
            )
            return ToolResult(
                tool=tool_name,
                action=action,
                status=ToolStatus.DENIED,
                error=(
                    f"tool '{tool_name}' is not available to this step "
                    f"(granted: {self.names() or 'none'})"
                ),
            )

        tool = self.registry.try_get(tool_name)
        if tool is None:
            return ToolResult(
                tool=tool_name,
                action=action,
                status=ToolStatus.DENIED,
                error=f"unknown tool '{tool_name}'",
            )

        availability = tool.availability()
        if not availability.available:
            return ToolResult(
                tool=tool_name,
                action=action,
                status=ToolStatus.UNAVAILABLE,
                error=availability.detail,
            )

        if action not in tool.actions:
            return tool.unknown_action(action)

        invalid = tool.validate(action, params)
        if invalid is not None:
            return invalid

        # A destructive tool needs a human even when policy would allow the call.
        if tool.descriptor.risk is RiskLevel.DESTRUCTIVE:
            refusal = self._require_approval(tool, action)
            if refusal is not None:
                return refusal

        try:
            return await asyncio.wait_for(
                tool.invoke(action, params, self.context), timeout=self.timeout_s
            )
        except TimeoutError:
            return ToolResult(
                tool=tool_name,
                action=action,
                status=ToolStatus.ERROR,
                error=f"tool call exceeded the {self.timeout_s}s limit and was abandoned",
            )
        except Exception as exc:  # a broken tool must not take the run down
            self.context.logger.error(
                "tool.error", tool=tool_name, action=action, error=f"{type(exc).__name__}: {exc}"
            )
            return ToolResult(
                tool=tool_name,
                action=action,
                status=ToolStatus.ERROR,
                error=f"{type(exc).__name__}: {exc}",
            )

    def _require_approval(self, tool, action: str) -> ToolResult | None:
        from devforge.core.models import ApprovalStatus

        gate = (tool.descriptor.permissions.gates or ["destructive_operation"])[0]
        if self.context.approval_gate is None or self.context.task is None:
            return ToolResult(
                tool=tool.name,
                action=action,
                status=ToolStatus.DENIED,
                error=f"'{tool.name}.{action}' is destructive and no approval gate is available",
            )
        approval = self.context.approval_gate.request(
            self.context.task,
            gate=gate,
            step_id=self.context.step_id or "tool",
            prompt=f"{tool.name}.{action} is classified destructive",
            context={"tool": tool.name, "action": action, "risk": tool.descriptor.risk.value},
        )
        if approval.status is ApprovalStatus.APPROVED:
            return None
        return ToolResult(
            tool=tool.name,
            action=action,
            status=ToolStatus.DENIED,
            error=f"awaiting approval at gate '{gate}' for a destructive tool call",
            data={"gate": gate, "awaiting_approval": True},
        )
