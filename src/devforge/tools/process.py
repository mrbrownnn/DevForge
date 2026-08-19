"""Subprocess execution shared by the shell tool, the git tool and verifiers.

Two rules, enforced here rather than at every call site:

* Commands are argument vectors executed with ``exec``. DevForge never spawns a
  shell, so there is no shell metacharacter interpretation and no quoting bug
  that can turn into command injection.
* Every process has a timeout and is killed when it expires.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from pathlib import Path

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
    argv: list[str], *, cwd: Path, timeout_s: int = 600, env: dict[str, str] | None = None
) -> ProcessResult:
    started_at = time.monotonic()
    try:
        process = await asyncio.create_subprocess_exec(
            *argv,
            cwd=str(cwd),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
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

    return ProcessResult(
        argv=argv,
        exit_code=process.returncode or 0,
        stdout=stdout_bytes.decode("utf-8", errors="replace")[:MAX_CAPTURE_CHARS],
        stderr=stderr_bytes.decode("utf-8", errors="replace")[:MAX_CAPTURE_CHARS],
        duration_ms=int((time.monotonic() - started_at) * 1000),
    )
