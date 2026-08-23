"""Screening the test suite before trusting it to judge anything.

A mutant can survive for a reason the equivalence layers are structurally unable to
see: the test that should have killed it is flaky and happened to pass. That is not
behavioural equivalence. It is a property of the suite, not of the code, and routing
it through :mod:`devforge.falsification.equivalence` would produce a confident wrong
answer.

It corrupts the mutation score in both directions::

    flaky test passes on the mutant  -> SURVIVED  -> score understated,
                                                     a false TEST_WEAKNESS finding
    flaky test fails on the mutant   -> KILLED    -> score overstated,
                                                     a real weakness hidden

No deterministic fixture can catch either case, which is exactly why this is
screened explicitly rather than left to the benchmark suite.

**How.** Before any mutation, the suite is run ``flakiness_probes`` times against the
*unmutated* sandbox. Any test whose outcome is not identical across probes is
quarantined. A mutant whose verdict then rests on a quarantined test is classified
``UNRELIABLE`` and excluded from both halves of the score.

**Cost.** One extra pass of the suite per run - paid once, not per mutant. Re-running
every mutant *n* times would multiply the most expensive part of the strategy.

**When it is skipped.** ``flakiness_probes: 0`` disables screening for a suite too
slow to run twice. The screening is optional; the resulting uncertainty is not, and
:meth:`ReliabilityReport.limitation` puts it on every survival in the run.
"""

from __future__ import annotations

from pathlib import Path

from devforge.falsification.models import ReliabilityReport
from devforge.falsification.testrun import TestOutcome, run_tests
from devforge.observability.logging import RunLogger, null_logger
from devforge.policy.engine import PolicyEngine


async def screen(
    *,
    workspace: Path,
    policy: PolicyEngine,
    test_command: list[str],
    probes: int,
    timeout_s: int = 300,
    logger: RunLogger | None = None,
) -> tuple[ReliabilityReport, TestOutcome | None]:
    """Probe the suite and report which tests cannot be trusted.

    Returns the report and the first baseline outcome, which the mutation strategy
    reuses as its "before" state rather than running the suite a third time.
    """
    logger = logger or null_logger()

    if probes <= 0:
        return (
            ReliabilityReport(
                probes=0,
                unavailable_reason="screening was disabled (flakiness_probes: 0)",
            ),
            None,
        )

    if probes == 1:
        # One probe cannot detect anything: flakiness is defined by disagreement
        # between runs, and one run agrees with itself. Saying so is better than
        # running the suite once and implying it was screened.
        return (
            ReliabilityReport(
                probes=1,
                unavailable_reason=(
                    "one probe cannot detect flakiness; at least two runs are needed "
                    "for outcomes to disagree"
                ),
            ),
            None,
        )

    outcomes: list[TestOutcome] = []
    for index in range(probes):
        outcome = await run_tests(
            test_command, workspace=workspace, policy=policy, timeout_s=timeout_s
        )
        if not outcome.ran:
            return (
                ReliabilityReport(
                    probes=index,
                    unavailable_reason=f"the baseline suite could not be run: {outcome.error}",
                ),
                None,
            )
        outcomes.append(outcome)
        logger.info(
            "falsification.reliability.probe",
            probe=index + 1,
            passed=outcome.passed,
            failures=len(outcome.failures),
            duration_ms=outcome.duration_ms,
        )

    quarantined = _disagreeing_tests(outcomes)
    observed = len({node for outcome in outcomes for node in outcome.failures})

    report = ReliabilityReport(
        probes=probes,
        tests_observed=observed,
        quarantined=quarantined,
    )
    if quarantined:
        logger.warn(
            "falsification.reliability.quarantine",
            tests=quarantined,
            reason="outcome differed between identical baseline runs",
        )
    return report, outcomes[0]


def _disagreeing_tests(outcomes: list[TestOutcome]) -> list[str]:
    """Tests that failed in some probes and not others.

    The suite-level signature is checked too: probes that disagree on the overall
    verdict while naming no differing test still indicate an unreliable suite, and
    that fact must not be lost just because the runner did not name names.
    """
    failure_sets = [set(outcome.failures) for outcome in outcomes]
    always = set.intersection(*failure_sets) if failure_sets else set()
    ever = set().union(*failure_sets) if failure_sets else set()
    disagreeing = sorted(ever - always)

    if disagreeing:
        return disagreeing

    signatures = {outcome.signature for outcome in outcomes}
    if len(signatures) > 1:
        # The runner did not name the difference, but there was one. A synthetic
        # entry keeps the fact in the report instead of discarding it.
        return ["<suite verdict differed between identical runs>"]
    return []


def verdict_is_reliable(failures: list[str], quarantined: list[str]) -> tuple[bool, list[str]]:
    """Whether a mutant's verdict can be trusted, and which tests taint it.

    A kill is unreliable when *every* test that reported the failure is quarantined:
    if a reliable test also failed, the mutant is genuinely killed regardless of what
    the flaky one did. A survival is unreliable whenever any quarantined test exists,
    because a flaky test that happened to pass is exactly what would hide the kill.
    """
    if not quarantined:
        return True, []

    if failures:
        tainted = [node for node in failures if node in quarantined]
        reliable_failures = [node for node in failures if node not in quarantined]
        if reliable_failures:
            return True, []
        return (not tainted), tainted

    # A survival: no failure to attribute, so any quarantined test could have been
    # the one that should have caught this.
    return False, list(quarantined)
