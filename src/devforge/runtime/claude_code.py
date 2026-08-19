"""Claude Code runtime adapter.

The only vendor-specific module in DevForge. It shells out to the `claude` CLI in
non-interactive mode and translates its JSON envelope into an
:class:`~devforge.core.models.AgentResult`. Nothing else in the codebase imports
it directly - the orchestrator resolves runtimes through the registry.

Cost and safety notes:

* Every execution is a real, billed model call. The CLI default runtime is
  ``mock``; this adapter runs only when explicitly selected.
* DevForge maps its own tool names onto Claude Code tool permissions, so a step
  that declares ``tools: [filesystem]`` cannot run shell commands.
* Permission mode defaults to the CLI default (no bypass). Setting
  ``permission_mode: bypassPermissions`` is possible but is never DevForge's
  default, and is documented as unsafe in docs/security.md.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
import time
from typing import Any

from devforge.core.errors import RuntimeExecutionError
from devforge.core.models import AgentInvocation, AgentResult, AgentResultStatus
from devforge.runtime.base import AgentRuntime, RuntimeAvailability, RuntimeContext

BINARY = "claude"

#: DevForge tool name -> Claude Code tool permission patterns.
TOOL_PERMISSION_MAP: dict[str, list[str]] = {
    "filesystem": ["Read", "Write", "Edit", "Glob", "Grep"],
    "shell": ["Bash"],
    "git": ["Bash(git *)"],
    "browser": [],  # no Claude Code equivalent is wired up; see docs/tools.md
    "mcp": [],
}

MAX_OUTPUT_CHARS = 200_000


class ClaudeCodeRuntime(AgentRuntime):
    """Runs agents through the local `claude` CLI in print mode."""

    name = "claude-code"

    def __init__(
        self,
        *,
        binary: str = BINARY,
        model: str | None = None,
        permission_mode: str | None = None,
        extra_args: list[str] | None = None,
    ) -> None:
        self.binary = binary
        self.model = model
        self.permission_mode = permission_mode
        self.extra_args = list(extra_args or [])

    # -- availability -----------------------------------------------------------

    def _resolve_binary(self) -> str | None:
        return shutil.which(self.binary)

    def availability(self) -> RuntimeAvailability:
        path = self._resolve_binary()
        if path is None:
            return RuntimeAvailability(
                available=False,
                detail=f"'{self.binary}' not found on PATH - install the Claude Code CLI",
            )
        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
                [path, "--version"], capture_output=True, text=True, timeout=20
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return RuntimeAvailability(available=False, detail=f"could not run '{path}': {exc}")
        if proc.returncode != 0:
            return RuntimeAvailability(
                available=False, detail=f"'{path} --version' exited {proc.returncode}"
            )
        return RuntimeAvailability(available=True, detail=path, version=proc.stdout.strip())

    # -- execution --------------------------------------------------------------

    def build_argv(self, invocation: AgentInvocation, binary: str) -> list[str]:
        argv = [binary, "-p", invocation.prompt, "--output-format", "json"]
        if invocation.system_prompt:
            argv += ["--append-system-prompt", invocation.system_prompt]
        allowed = self.allowed_tools(invocation.tools)
        if allowed:
            argv += ["--allowedTools", *allowed]
        if self.model:
            argv += ["--model", self.model]
        if self.permission_mode:
            argv += ["--permission-mode", self.permission_mode]
        argv += self.extra_args
        return argv

    @staticmethod
    def allowed_tools(tools: list[str]) -> list[str]:
        allowed: list[str] = []
        for tool in tools:
            allowed.extend(TOOL_PERMISSION_MAP.get(tool, []))
        return sorted(set(allowed))

    async def execute(self, invocation: AgentInvocation, context: RuntimeContext) -> AgentResult:
        binary = self._resolve_binary()
        if binary is None:
            raise RuntimeExecutionError(
                f"runtime '{self.name}' is unavailable: {self.availability().detail}"
            )

        argv = self.build_argv(invocation, binary)
        context.logger.info(
            "runtime.invoke",
            runtime=self.name,
            agent=invocation.agent,
            step=invocation.step_id,
            attempt=invocation.attempt,
            mode=invocation.mode.value,
        )

        started = time.monotonic()
        try:
            process = await asyncio.create_subprocess_exec(
                *argv,
                cwd=str(context.workspace),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError as exc:  # binary vanished between the check and the spawn
            raise RuntimeExecutionError(f"failed to start '{binary}': {exc}") from exc

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                process.communicate(), timeout=invocation.timeout_s
            )
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            duration_ms = int((time.monotonic() - started) * 1000)
            return AgentResult(
                invocation_id=invocation.invocation_id,
                runtime=self.name,
                status=AgentResultStatus.ERROR,
                summary="runtime timed out",
                error=f"'{self.binary}' exceeded the {invocation.timeout_s}s timeout",
                duration_ms=duration_ms,
            )

        duration_ms = int((time.monotonic() - started) * 1000)
        stdout = stdout_bytes.decode("utf-8", errors="replace")[:MAX_OUTPUT_CHARS]
        stderr = stderr_bytes.decode("utf-8", errors="replace")[:MAX_OUTPUT_CHARS]
        return self.parse_result(
            invocation, stdout=stdout, stderr=stderr, returncode=process.returncode or 0,
            duration_ms=duration_ms,
        )

    def parse_result(
        self,
        invocation: AgentInvocation,
        *,
        stdout: str,
        stderr: str,
        returncode: int,
        duration_ms: int,
    ) -> AgentResult:
        """Translate the CLI envelope into an AgentResult.

        Kept separate from the subprocess plumbing so it can be tested without
        spawning anything or spending money.
        """
        payload: dict[str, Any] | None = None
        if stdout.strip():
            try:
                decoded = json.loads(stdout)
                payload = decoded if isinstance(decoded, dict) else None
            except json.JSONDecodeError:
                payload = None

        if payload is None:
            failed = returncode != 0
            return AgentResult(
                invocation_id=invocation.invocation_id,
                runtime=self.name,
                status=AgentResultStatus.ERROR if failed else AgentResultStatus.OK,
                summary="unparsable runtime output" if failed else "plain text output",
                output=stdout.strip(),
                error=(stderr.strip() or f"exit code {returncode}") if failed else "",
                duration_ms=duration_ms,
                metadata={"parsed": False, "exit_code": returncode},
            )

        text = str(payload.get("result", "") or "")
        is_error = bool(payload.get("is_error")) or returncode != 0
        metadata = {
            "parsed": True,
            "exit_code": returncode,
            "session_id": payload.get("session_id"),
            "num_turns": payload.get("num_turns"),
            "total_cost_usd": payload.get("total_cost_usd"),
            "subtype": payload.get("subtype"),
        }
        return AgentResult(
            invocation_id=invocation.invocation_id,
            runtime=self.name,
            status=AgentResultStatus.ERROR if is_error else AgentResultStatus.OK,
            summary=text.strip().splitlines()[0][:200] if text.strip() else "no textual result",
            output=text,
            error=(stderr.strip() or text.strip()) if is_error else "",
            duration_ms=int(payload.get("duration_ms") or duration_ms),
            metadata={k: v for k, v in metadata.items() if v is not None},
        )
