"""Reproducing a defect on demand.

Everything downstream depends on this step. A diagnosis of a bug nobody can
trigger is a guess, and a "fix" for it cannot be verified - the suite was going to
pass either way. So reproduction is a first-class product with its own verdict,
and "I could not make it happen" is a legitimate, reported outcome rather than
something to work around.

Determinism is checked, not assumed
-----------------------------------

The command runs more than once. Three outcomes matter and they are different
kinds of information:

* failed every time - deterministic, and a later pass is real evidence of repair;
* failed sometimes - flaky, and a green run proves nothing at all;
* never failed - either it is already fixed, or the command does not exercise it.

Averaging the second case into "mostly fails" is how a repair loop convinces
itself it succeeded. It is reported as FLAKY and the repair verifier refuses to
treat it as a baseline.

Safety
------

The command is an argv, checked against the permission policy, executed with
:func:`devforge.tools.process.run_process` - no shell, a sanitised environment,
bounded output. A bug report is untrusted input; "run this to reproduce" is not
a licence to run anything.
"""

from __future__ import annotations

from pathlib import Path

from devforge.debug.models import Reproduction, ReproductionAttempt, ReproductionOutcome
from devforge.observability.logging import RunLogger, null_logger
from devforge.observability.redaction import redact_text
from devforge.policy.engine import PolicyEngine
from devforge.tools.process import run_process

DEFAULT_RUNS = 2
MAX_RUNS = 5
MAX_EXCERPT_CHARS = 8_000


async def reproduce(
    argv: list[str],
    *,
    workspace: Path,
    policy: PolicyEngine,
    runs: int = DEFAULT_RUNS,
    timeout_s: int = 600,
    logger: RunLogger | None = None,
    expect_failure: bool = True,
) -> Reproduction:
    """Run the reproduction command and classify what happened.

    ``expect_failure`` says which exit status counts as "the defect appeared".
    It is true for the usual case - a failing test - and false for the rarer one
    where the bug is a command that wrongly succeeds.
    """
    log = logger or null_logger()
    reproduction = Reproduction(argv=list(argv))

    if not argv:
        reproduction.summary = "no reproduction command was given"
        return reproduction

    decision = policy.check_command(argv)
    if not decision.allowed:
        reproduction.outcome = ReproductionOutcome.UNAVAILABLE
        reproduction.summary = f"refused by policy: {decision.reason}"
        log.warn("debug.reproduce_denied", command=" ".join(argv)[:200], reason=decision.reason)
        return reproduction

    attempts = max(1, min(int(runs), MAX_RUNS))
    for index in range(attempts):
        result = await run_process(
            argv,
            cwd=workspace,
            timeout_s=timeout_s,
            allow_env=policy.permissions.process.allow_env,
            max_output_chars=policy.permissions.process.max_output_chars,
        )
        nonzero = result.exit_code != 0
        failed = nonzero if expect_failure else not nonzero
        reproduction.attempts.append(
            ReproductionAttempt(
                exit_code=result.exit_code,
                duration_ms=result.duration_ms,
                failed=failed,
                output_excerpt=redact_text(result.combined)[:MAX_EXCERPT_CHARS],
            )
        )
        log.info(
            "debug.reproduce_attempt",
            attempt=index + 1,
            exit_code=result.exit_code,
            reproduced=failed,
            duration_ms=result.duration_ms,
        )

    reproduction.outcome, reproduction.summary = _classify(reproduction, expect_failure)
    log.info(
        "debug.reproduce",
        outcome=reproduction.outcome.value,
        attempts=len(reproduction.attempts),
    )
    return reproduction


def _classify(reproduction: Reproduction, expect_failure: bool) -> tuple[ReproductionOutcome, str]:
    total = len(reproduction.attempts)
    failures = sum(1 for attempt in reproduction.attempts if attempt.failed)
    wording = "failed" if expect_failure else "unexpectedly succeeded"

    if failures == total:
        return (
            ReproductionOutcome.DETERMINISTIC,
            f"the command {wording} on all {total} attempt(s); a later pass is real evidence",
        )
    if failures == 0:
        return (
            ReproductionOutcome.NOT_REPRODUCED,
            f"the command never {wording} in {total} attempt(s) - the defect is not "
            "exercised by this command, or it is already fixed",
        )
    return (
        ReproductionOutcome.FLAKY,
        f"the command {wording} on {failures} of {total} attempt(s); a green run would "
        "not prove a repair, so the reproduction must be made deterministic first",
    )
