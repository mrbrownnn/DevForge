"""Running the project's tests inside a sandbox, and reading the result.

Every strategy that needs a verdict from the test suite goes through here, for two
reasons. The command passes the permission policy exactly once, in one place, so a
strategy cannot smuggle an argv past it. And the parsing of which tests failed lives
in one function rather than three, so the mutation strategy and the reliability
probe cannot disagree about what "this test failed" means.

Nothing here decides anything. It runs an argv and reports what happened; the
judgement about what a failure implies belongs to the caller.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from devforge.policy.engine import PolicyEngine
from devforge.tools.process import run_process

#: pytest prints one of these per failing test in its short summary and in the
#: default output. Both spellings are matched because ``-q`` changes the shape.
_FAILURE_PATTERNS = (
    re.compile(r"^(?:FAILED|ERROR)\s+(\S+?)(?:\s|$)", re.MULTILINE),
    re.compile(r"^(\S+::\S+)\s+(?:FAILED|ERROR)", re.MULTILINE),
)

#: Exit codes that mean "the runner worked, the tests disagreed" versus "the runner
#: itself could not run". Telling them apart is what stops a broken command being
#: recorded as a killed mutant.
PYTEST_TESTS_FAILED = 1
PYTEST_NO_TESTS = 5


@dataclass
class TestOutcome:
    """One execution of the test suite."""

    #: True when the suite ran and every test passed.
    passed: bool
    exit_code: int
    duration_ms: int
    #: Node ids of tests that failed, where the runner reported them.
    failures: list[str] = field(default_factory=list)
    output: str = ""
    #: Set when the suite could not be run at all, as opposed to failing.
    error: str = ""
    timed_out: bool = False

    @property
    def ran(self) -> bool:
        return not self.error

    @property
    def signature(self) -> tuple[bool, tuple[str, ...]]:
        """What must be identical across probes for a suite to be called reliable.

        Deliberately not the full output: timestamps and durations differ between
        identical runs, and comparing them would quarantine every test in the tree.
        """
        return (self.passed, tuple(sorted(self.failures)))


async def run_tests(
    argv: list[str],
    *,
    workspace: Path,
    policy: PolicyEngine,
    timeout_s: int = 300,
    extra_args: list[str] | None = None,
) -> TestOutcome:
    """Run the suite in ``workspace``, subject to the permission policy.

    A command the policy refuses is an ``error``, never a failure and never a pass.
    "We were not allowed to check" and "the check failed" are different facts, and
    the whole subsystem depends on not confusing them.
    """
    command = [*argv, *(extra_args or [])]
    if not command:
        return TestOutcome(
            passed=False, exit_code=-1, duration_ms=0, error="no test command was configured"
        )

    decision = policy.check_command(command)
    if not decision.allowed:
        return TestOutcome(
            passed=False,
            exit_code=-1,
            duration_ms=0,
            error=f"the test command is refused by policy: {decision.reason}",
        )

    result = await run_process(
        command,
        cwd=workspace,
        timeout_s=timeout_s,
        allow_env=policy.permissions.process.allow_env,
        max_output_chars=policy.permissions.process.max_output_chars,
    )

    if not result.started:
        return TestOutcome(
            passed=False,
            exit_code=result.exit_code,
            duration_ms=result.duration_ms,
            output=result.combined,
            error=result.error or f"could not start {command[0]!r}",
        )

    if result.timed_out:
        return TestOutcome(
            passed=False,
            exit_code=result.exit_code,
            duration_ms=result.duration_ms,
            output=result.combined,
            timed_out=True,
            error=f"the test suite timed out after {timeout_s}s",
        )

    if result.exit_code == PYTEST_NO_TESTS:
        return TestOutcome(
            passed=False,
            exit_code=result.exit_code,
            duration_ms=result.duration_ms,
            output=result.combined,
            error="no tests were collected, so nothing could judge this run",
        )

    return TestOutcome(
        passed=result.exit_code == 0,
        exit_code=result.exit_code,
        duration_ms=result.duration_ms,
        failures=parse_failures(result.combined),
        output=result.combined,
    )


def parse_failures(output: str) -> list[str]:
    """Node ids of failing tests, as far as the runner made them visible.

    Best-effort by nature: a runner that does not name its failures leaves this
    empty, and callers must treat an empty list as "unknown", never as "none".
    """
    found: list[str] = []
    for pattern in _FAILURE_PATTERNS:
        for match in pattern.finditer(output or ""):
            node = match.group(1).strip()
            if node and node not in found:
                found.append(node)
    return found
