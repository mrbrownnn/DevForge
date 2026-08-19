"""Subprocess execution shared by the shell tool, the git tool and verifiers.

Two rules, enforced here rather than at every call site:

* Commands are argument vectors executed with ``exec``. DevForge never spawns a
  shell, so there is no shell metacharacter interpretation and no quoting bug
  that can turn into command injection.
* Every process has a timeout and is killed when it expires.
* Every process gets a constructed environment, never the host one. Passing the
  invoking shell's environment would hand every ambient credential to any allowed
  command - see devforge.tools.environment.
* Captured output is bounded and truncation is visible in the result rather than
  silent, so a tool cannot flood the context by printing forever.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from pathlib import Path

from devforge.tools.environment import build_env

MAX_CAPTURE_CHARS = 200_000


@dataclass(frozen=True)
class ProcessResult:
    argv: list[str]
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool = False
    started: bool = True
    error: str = ""
    truncated: bool = False

    @property
    def combined(self) -> str:
        parts = [part for part in (self.stdout.strip(), self.stderr.strip()) if part]
        return "\n".join(parts)

    def excerpt(self, limit: int = 4000) -> str:
        """Tail of the output - the end of a failing build is the informative part."""
        text = self.combined
        if len(text) <= limit:
            return text
        return "...\n" + text[-limit:]


async def run_process(
    argv: list[str],
    *,
    cwd: Path,
    timeout_s: int = 600,
    env: dict[str, str] | None = None,
    allow_env: list[str] | None = None,
    max_output_chars: int = MAX_CAPTURE_CHARS,
) -> ProcessResult:
    """Run an argv with a timeout, a sanitised environment and bounded output.

    ``env`` replaces the constructed environment entirely (tests use this).
    ``allow_env`` names extra parent variables to carry through the allowlist.
    """
    child_env = env if env is not None else build_env(allow=allow_env or [])
    started_at = time.monotonic()
    try:
        process = await asyncio.create_subprocess_exec(
            *argv,
            cwd=str(cwd),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=child_env,
        )
    except (OSError, ValueError) as exc:
        return ProcessResult(
            argv=argv,
            exit_code=127,
            stdout="",
            stderr=str(exc),
            duration_ms=int((time.monotonic() - started_at) * 1000),
            started=False,
            error=f"could not start '{argv[0]}': {exc}",
        )

    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            process.communicate(), timeout=timeout_s
        )
    except TimeoutError:
        process.kill()
        await process.wait()
        return ProcessResult(
            argv=argv,
            exit_code=124,
            stdout="",
            stderr=f"timed out after {timeout_s}s",
            duration_ms=int((time.monotonic() - started_at) * 1000),
            timed_out=True,
            error=f"'{argv[0]}' timed out after {timeout_s}s",
        )

    stdout = stdout_bytes.decode("utf-8", errors="replace")
    stderr = stderr_bytes.decode("utf-8", errors="replace")
    truncated = len(stdout) > max_output_chars or len(stderr) > max_output_chars
    return ProcessResult(
        argv=argv,
        exit_code=process.returncode or 0,
        stdout=stdout[:max_output_chars],
        stderr=stderr[:max_output_chars],
        duration_ms=int((time.monotonic() - started_at) * 1000),
        truncated=truncated,
    )
