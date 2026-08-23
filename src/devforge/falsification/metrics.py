"""Falsification metrics, in the shape the evaluation framework already uses.

Every metric here is a :class:`~devforge.eval.metrics.MetricValue`, which carries
three things a bare number does not: which direction is better, what the denominator
was, and *why* it is missing when it is missing. All three matter more here than
almost anywhere else in DevForge, because the numbers this subsystem produces are
unusually easy to misread.

Two rules inherited from ``eval/metrics.py`` and enforced again:

**``None`` means not measured.** A mutation score over zero valid mutants is unknown,
not perfect. A post-repair survival rate over zero repairs is unknown, not 100%.
Neither is ever rendered as a number.

**Every rate states its basis.** "80%" of five mutants and of five hundred are
different claims, and a report that prints them identically is misleading whichever
one it means.

One metric is the point of the whole subsystem: **post-repair falsification
survival**. Falsifying a patch once is a finding; falsifying it, repairing it, and
falsifying it again is the only measurement that says whether the repair actually
removed the counterexample or merely moved it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from devforge.eval.metrics import Direction, MetricValue

if TYPE_CHECKING:  # pragma: no cover - typing only
    from devforge.falsification.models import FalsificationReport


def _rate(numerator: int, denominator: int) -> float | None:
    """A rate over nothing is unknown, never 1.0 and never 0.0."""
    return numerator / denominator if denominator else None


def metrics_for(report: FalsificationReport) -> list[MetricValue]:
    """The metrics one falsification run supports."""
    values: list[MetricValue] = []

    # 1. mutation score - about the test suite, never about the code
    values.append(
        MetricValue(
            id="mutation_score",
            label="Mutation score",
            value=report.mutation_score,
            unit="%",
            direction=Direction.UP,
            basis=(
                f"{report.mutants_killed} killed of {report.valid_mutants} valid "
                "non-equivalent mutants detected by the test suite"
            ),
            unknown_reason=(
                ""
                if report.mutation_score is not None
                else "no valid non-equivalent mutants were generated"
            ),
        )
    )

    # 2. counterexamples found - a count, not a rate: more is better here, because
    #    the strategy succeeding means the implementation did not.
    values.append(
        MetricValue(
            id="counterexamples_found",
            label="Counterexamples found",
            value=float(len(report.counterexamples)),
            direction=Direction.NEUTRAL,
            basis=f"across {len(report.strategy_coverage.executed)} executed strategy/strategies",
        )
    )

    # 3. property violation rate
    values.append(
        MetricValue(
            id="property_violation_rate",
            label="Property violation rate",
            value=_rate(report.property_violations, report.properties_tested),
            unit="%",
            direction=Direction.NEUTRAL,
            basis=f"{report.property_violations} of {report.properties_tested} properties",
            unknown_reason="" if report.properties_tested else "no properties were declared",
        )
    )

    # 4. adversarial discovery rate
    adversarial = report.strategy("adversarial")
    discovered = len(adversarial.counterexamples) if adversarial else 0
    attempted = adversarial.adversarial_tests if adversarial else 0
    values.append(
        MetricValue(
            id="adversarial_discovery_rate",
            label="Adversarial discovery rate",
            value=_rate(discovered, attempted),
            unit="%",
            direction=Direction.NEUTRAL,
            basis=f"{discovered} of {attempted} generated adversarial test(s) failed",
            unknown_reason="" if attempted else "no adversarial test was generated",
        )
    )

    # 5. differential mismatch rate
    differential = report.strategy("differential")
    cases = differential.differential_cases if differential else 0
    values.append(
        MetricValue(
            id="differential_mismatch_rate",
            label="Differential mismatch rate",
            value=_rate(report.differential_mismatches, cases),
            unit="%",
            direction=Direction.DOWN,
            basis=f"{report.differential_mismatches} of {cases} compared case(s)",
            unknown_reason="" if cases else "no differential case was compared",
        )
    )

    # 6. attack surface coverage - explored surface, never correctness
    values.append(
        MetricValue(
            id="attack_surface_coverage",
            label="Attack surface coverage",
            value=report.coverage.fraction,
            unit="%",
            direction=Direction.UP,
            basis=(
                f"{len(report.coverage.attacked)} of "
                f"{len([t for t in report.coverage.targets if t.applicable])} in-scope "
                "target(s) attacked; measures explored surface, not correctness"
            ),
            unknown_reason=(
                "" if report.coverage.fraction is not None else "no target was in scope"
            ),
        )
    )

    # 7. strategy coverage
    values.append(
        MetricValue(
            id="strategy_coverage",
            label="Strategy coverage",
            value=report.strategy_coverage.fraction,
            unit="%",
            direction=Direction.UP,
            basis=(
                f"{len(report.strategy_coverage.executed)} of "
                f"{len(report.strategy_coverage.requested)} requested strategy/strategies ran"
            ),
            unknown_reason=(
                ""
                if report.strategy_coverage.fraction is not None
                else "no strategy was requested"
            ),
        )
    )

    # 8. runtime
    values.append(
        MetricValue(
            id="falsification_runtime",
            label="Falsification runtime",
            value=float(report.duration_ms),
            unit="ms",
            direction=Direction.DOWN,
            basis=f"wall clock for {len(report.strategies)} strategy report(s)",
        )
    )

    # 9. cost - tokens, where the runtime reported any. Where it did not, this is
    #    unknown rather than zero, exactly as the budget is unenforceable rather
    #    than satisfied.
    values.append(
        MetricValue(
            id="falsification_cost",
            label="Falsification cost",
            value=float(report.usage.tokens) if report.usage.tokens is not None else None,
            unit="tokens",
            direction=Direction.DOWN,
            basis="reported by the runtime",
            unknown_reason=(
                "" if report.usage.tokens is not None else "the runtime reported no token counts"
            ),
        )
    )

    return values


def post_repair_survival(
    before: FalsificationReport, after: FalsificationReport | None
) -> MetricValue:
    """Did the repair actually remove the counterexample, or only move it?

    The lifecycle measurement this subsystem exists to make possible::

        initial patch -> falsify -> repair -> falsify again

    ``None`` when there was no second run: an unrepeated search says nothing about a
    repair, and reporting it as success would be the same overreach the status
    vocabulary already refuses.
    """
    from devforge.falsification.models import FalsificationStatus

    if after is None:
        return MetricValue(
            id="post_repair_survival",
            label="Post-repair falsification survival",
            value=None,
            unit="%",
            direction=Direction.UP,
            unknown_reason="falsification was not re-run after the repair",
        )

    survived = after.status is FalsificationStatus.SURVIVED
    remaining = len(after.counterexamples)
    fixed = max(0, len(before.counterexamples) - remaining)

    return MetricValue(
        id="post_repair_survival",
        label="Post-repair falsification survival",
        value=1.0 if survived else 0.0,
        unit="%",
        direction=Direction.UP,
        basis=(
            f"{fixed} of {len(before.counterexamples)} counterexample(s) no longer "
            f"reproduce; {remaining} still do"
            + ("" if survived else "; the re-run did not survive")
        ),
    )


def repair_after_falsification(reports: list[FalsificationReport]) -> MetricValue:
    """How often a falsification failure was followed by a repair attempt.

    A falsification run that finds a counterexample and is then ignored has produced
    a report nobody acted on, which is a process measurement rather than a code one -
    and worth having, because that is the failure mode that makes the whole subsystem
    ceremonial.
    """
    from devforge.falsification.models import FalsificationStatus

    failed = [r for r in reports if r.status is FalsificationStatus.FAILED]
    repaired = sum(1 for r in failed if r.step_id and _has_later_run(reports, r))

    return MetricValue(
        id="repair_after_falsification",
        label="Repair after falsification",
        value=_rate(repaired, len(failed)),
        unit="%",
        direction=Direction.UP,
        basis=f"{repaired} of {len(failed)} failed run(s) were followed by another run",
        unknown_reason="" if failed else "no falsification run failed",
    )


def _has_later_run(reports: list[FalsificationReport], report: FalsificationReport) -> bool:
    return any(
        other.task_id == report.task_id and other.started_at > report.started_at
        for other in reports
        if other.run_id != report.run_id
    )
