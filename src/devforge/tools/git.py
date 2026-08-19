"""Git tool.

A thin, explicit wrapper over the ``git`` binary. Each action builds its own argv
and goes through the same policy check as any other command, so ``git push`` is
gated by ``permissions.yaml`` exactly like a raw shell call - there is no
side door.
"""

from __future__ import annotations

import shutil
from typing import Any

from devforge.core.models import ToolResult
from devforge.tools.base import Tool, ToolAvailability, ToolContext
from devforge.tools.process import run_process

BINARY = "git"


class GitTool(Tool):
    name = "git"
    description = "Inspect and record changes with git."
    actions = ("status", "diff", "log", "show", "branch", "add", "commit", "current_branch")

    def availability(self) -> ToolAvailability:
        path = shutil.which(BINARY)
        if path is None:
            return ToolAvailability(False, "'git' not found on PATH")
        return ToolAvailability(True, path)

    def _argv(self, action: str, params: dict[str, Any]) -> list[str] | str:
        if action == "status":
            return [BINARY, "status", "--short", "--branch"]
        if action == "diff":
            argv = [BINARY, "diff"]
            if params.get("staged"):
                argv.append("--staged")
            paths = params.get("paths") or []
            return [*argv, "--", *paths] if paths else argv
        if action == "log":
            return [BINARY, "log", f"-{int(params.get('limit', 10))}", "--oneline"]
        if action == "show":
            ref = params.get("ref", "HEAD")
            return [BINARY, "show", "--stat", str(ref)]
        if action == "branch":
            return [BINARY, "branch", "--list"]
        if action == "current_branch":
            return [BINARY, "rev-parse", "--abbrev-ref", "HEAD"]
        if action == "add":
            paths = params.get("paths")
            if not paths:
                return "action 'add' requires 'paths'"
            return [BINARY, "add", "--", *[str(p) for p in paths]]
        if action == "commit":
            message = params.get("message")
            if not message:
                return "action 'commit' requires 'message'"
            return [BINARY, "commit", "-m", str(message)]
        return f"unknown action '{action}'"

    async def invoke(self, action: str, params: dict[str, Any], ctx: ToolContext) -> ToolResult:
        if action not in self.actions:
            return self.unknown_action(action)

        availability = self.availability()
        if not availability.available:
            return self.unavailable(action, availability.detail)

        argv = self._argv(action, params)
        if isinstance(argv, str):
            return self.fail(action, argv)

        decision = ctx.policy.check_command(argv)
        blocked = self.authorize(action, decision, ctx, gate_prompt=" ".join(argv))
        if blocked is not None:
            return blocked

        result = await run_process(
            argv, cwd=ctx.workspace, timeout_s=int(params.get("timeout_s", 120))
        )
        ctx.logger.info(
            "tool.git",
            tool=self.name,
            action=action,
            exit_code=result.exit_code,
            duration_ms=result.duration_ms,
            status="ok" if result.exit_code == 0 else "error",
        )
        if result.exit_code == 0:
            outcome = self.ok(action, result.combined, exit_code=0)
        else:
            outcome = self.fail(
                action,
                result.error or result.combined or f"exit {result.exit_code}",
                exit_code=result.exit_code,
            )
            outcome.output = result.combined
        outcome.duration_ms = result.duration_ms
        return outcome
