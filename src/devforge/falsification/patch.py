"""Reading the change under attack.

Falsification is evidence about a *patch*, so it has to know what the patch is. That
means asking git, which means running a process - and ``devforge.core`` may not
import a concrete tool (``tests/test_architecture.py`` enforces it, and rightly: the
orchestrator depends on interfaces, not on how a subprocess is spawned).

So the reading lives here, in the falsification layer, and the orchestrator calls it.
The same reasoning already put diff collection for the patch guard in
``devforge.verification.repair`` rather than in the core loop.

A repository that cannot answer yields an empty patch. That is not an error: the
strategies then report that they had nothing to attack, which is the honest outcome
and is visible in the report.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from devforge.observability.logging import RunLogger, null_logger
from devforge.policy.engine import PolicyEngine
from devforge.tools.process import run_process

MAX_DIFF_CHARS = 400_000
GIT_TIMEOUT_S = 120


@dataclass(frozen=True)
class Patch:
    """The change under attack."""

    diff: str = ""
    files: list[str] = field(default_factory=list)
    #: Line numbers the patch touches, per file. This is what makes ``scope: diff``
    #: a real boundary rather than a whole-file approximation.
    lines: dict[str, set[int]] = field(default_factory=dict)
    unavailable_reason: str = ""

    @property
    def empty(self) -> bool:
        return not self.diff


async def collect_patch(
    workspace: Path,
    policy: PolicyEngine,
    *,
    base: str = "HEAD",
    logger: RunLogger | None = None,
) -> Patch:
    """The worktree diff, the files it touches, and the lines it touches in them."""
    logger = logger or null_logger()

    argv = ["git", "diff", "--no-color", base] if base else ["git", "diff", "--no-color"]
    decision = policy.check_command(argv)
    if not decision.allowed:
        logger.info("falsification.patch_unavailable", reason=decision.reason)
        return Patch(unavailable_reason=decision.reason)

    result = await run_process(
        argv,
        cwd=workspace,
        timeout_s=GIT_TIMEOUT_S,
        allow_env=policy.permissions.process.allow_env,
        max_output_chars=MAX_DIFF_CHARS,
    )
    if result.exit_code != 0 and base:
        # A repository with no commits has no HEAD to diff against. The worktree
        # diff is still the patch, so fall back rather than reporting nothing.
        fallback = ["git", "diff", "--no-color"]
        if policy.check_command(fallback).allowed:
            result = await run_process(
                fallback,
                cwd=workspace,
                timeout_s=GIT_TIMEOUT_S,
                allow_env=policy.permissions.process.allow_env,
                max_output_chars=MAX_DIFF_CHARS,
            )

    if result.exit_code != 0:
        reason = result.error or (result.combined or "git could not read the patch")[:200]
        logger.info("falsification.patch_unavailable", reason=reason)
        return Patch(unavailable_reason=reason)

    return parse_patch(result.stdout)


def parse_patch(diff: str) -> Patch:
    """Split a unified diff into the files and the added lines it touches.

    Only *added* lines are recorded. A deleted line no longer exists to be mutated,
    and a context line is not part of the change, so mutating either would attack
    code the patch did not write - which is the boundary ``scope: diff`` draws.
    """
    files: list[str] = []
    lines: dict[str, set[int]] = {}
    current = ""
    new_lineno = 0

    for line in diff.splitlines():
        if line.startswith("diff --git "):
            current = line.split(" b/", 1)[-1].strip()
            if current and current not in files:
                files.append(current)
            lines.setdefault(current, set())
            continue

        if line.startswith("+++ b/"):
            current = line[6:].strip()
            if current and current not in files:
                files.append(current)
            lines.setdefault(current, set())
            continue

        if line.startswith("@@"):
            new_lineno = _hunk_start(line)
            continue

        if not current:
            continue

        if line.startswith("+") and not line.startswith("+++"):
            lines[current].add(new_lineno)
            new_lineno += 1
        elif line.startswith("-") and not line.startswith("---"):
            continue  # a removed line has no position in the new file
        elif line.startswith(("\\", "index ", "similarity ", "rename ")):
            continue
        else:
            new_lineno += 1

    return Patch(diff=diff, files=files, lines={k: v for k, v in lines.items() if v})


def _hunk_start(header: str) -> int:
    """The first line number of a hunk in the new file, from ``@@ -a,b +c,d @@``."""
    try:
        after = header.split("+", 1)[1]
        number = after.split(",", 1)[0].split(" ", 1)[0]
        return int(number)
    except (IndexError, ValueError):
        return 1
