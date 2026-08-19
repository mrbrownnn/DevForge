"""Shell tool.

Runs an allowlisted command as an argument vector. No shell is spawned: a
``command`` string is split with :func:`shlex.split` and executed with ``exec``,
so ``&&``, ``|`` and ``$(...)`` are arguments, not operators. Commands that
policy marks destructive route to a human approval gate instead of running.
"""

from __future__ import annotations

import shlex
from typing import Any

from devforge.core.models import ToolResult
from devforge.tools.base import Tool, ToolContext
from devforge.tools.descriptor import (
    TOOL_OUTPUT_SCHEMA,
    RiskLevel,
    ToolDescriptor,
    ToolPermissions,
)
from devforge.tools.process import run_process


class ShellTool(Tool):
    name = "shell"
    description = "Run an allowlisted command (no shell interpretation)."
    actions = ("run",)

    descriptor = ToolDescriptor(
        name="shell",
        version="1.0.0",
        description="Run an allowlisted command as an argv. No shell is spawned.",
        capabilities=["process-execution"],
        permissions=ToolPermissions(process_execution=True, gates=["destructive_command"]),
        risk=RiskLevel.EXECUTE,
        input_schema={
            "run": {
                "type": "object",
                "properties": {
                    "argv": {"type": "array", "items": {"type": "string"}},
                    "command": {"type": "string"},
                    "cwd": {"type": "string"},
                    "timeout_s": {"type": "integer"},
                },
                "additionalProperties": False,
            }
        },
        output_schema=TOOL_OUTPUT_SCHEMA,
    )

    async def invoke(self, action: str, params: dict[str, Any], ctx: ToolContext) -> ToolResult:
        if action != "run":
            return self.unknown_action(action)

        invalid = self.validate(action, params)
        if invalid is not None:
            return invalid

        argv = params.get("argv")
        if argv is None:
            command = params.get("command")
            if not command:
                return self.fail(action, "provide either 'argv' (preferred) or 'command'")
            try:
                argv = shlex.split(command)
            except ValueError as exc:
                return self.fail(action, f"could not parse command: {exc}")
        if not isinstance(argv, list) or not all(isinstance(item, str) for item in argv):
            return self.fail(action, "'argv' must be a list of strings")
        if not argv:
            return self.fail(action, "empty command")

        decision = ctx.policy.check_command(argv)
        blocked = self.authorize(action, decision, ctx, gate_prompt=f"run: {shlex.join(argv)}")
        if blocked is not None:
            ctx.logger.warn(
                "tool.denied",
                tool=self.name,
                command=shlex.join(argv),
                reason=decision.reason,
                effect=decision.effect.value,
            )
            return blocked

        timeout = int(params.get("timeout_s") or ctx.policy.permissions.shell.timeout_s)
        cwd = ctx.policy.resolve_path(params["cwd"]) if params.get("cwd") else ctx.workspace
        process_policy = ctx.policy.permissions.process
        result = await run_process(
            argv,
            cwd=cwd,
            timeout_s=timeout,
            allow_env=process_policy.allow_env,
            max_output_chars=process_policy.max_output_chars,
        )

        ctx.logger.info(
            "tool.shell",
            tool=self.name,
            command=shlex.join(argv),
            exit_code=result.exit_code,
            duration_ms=result.duration_ms,
            status="ok" if result.exit_code == 0 else "error",
        )

        payload = {
            "argv": argv,
            "exit_code": result.exit_code,
            "duration_ms": result.duration_ms,
            "timed_out": result.timed_out,
            "truncated": result.truncated,
        }
        if result.exit_code == 0:
            outcome = self.ok(action, result.combined, **payload)
        else:
            outcome = self.fail(action, result.error or f"exit code {result.exit_code}", **payload)
            outcome.output = result.combined
        outcome.duration_ms = result.duration_ms
        return outcome
