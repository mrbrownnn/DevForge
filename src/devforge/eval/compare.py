"""Comparing two reports.

This module does arithmetic and refuses to do anything else. It says which axes
differed, which cases changed outcome, and which direction each metric moved. It
does not say which configuration is better, does not compute a composite score,
and does not test significance - because with a benchmark this size there is no
significance to test, and printing a verdict anyway is how a measurement becomes a
marketing claim.

What it *does* assert is regression, which is a different kind of statement: a
case that passed and now fails is a specific, reproducible fact about specific
cases, not an inference about quality. That is the signal ``--fail-on-regression``
acts on.

Comparisons are only meaningful between reports over the same cases, so a
mismatch is reported rather than quietly intersected.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from devforge.eval.metrics import Direction, MetricValue
from devforge.eval.models import CaseOutcome, EvalReport


class Movement(str, Enum):
    IMPROVED = "improved"
    DEGRADED = "degraded"
    UNCHANGED = "unchanged"
    UNKNOWN = "unknown"


class MetricDelta(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    label: str
    unit: str = ""
    baseline: float | None = None
    candidate: float | None = None
    delta: float | None = None
    movement: Movement = Movement.UNKNOWN
    note: str = ""

    def format_delta(self) -> str:
        if self.delta is None:
            return "-"
        if self.unit == "%":
            return f"{self.delta:+.0%}"
        if self.unit == "usd":
            return f"{self.delta:+.4f}"
        if self.unit in {"ms", "tokens"}:
            return f"{self.delta:+,.0f}"
        return f"{self.delta:+.2f}"


class CaseDelta(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: str
    baseline: str = "absent"
    candidate: str = "absent"

    @property
    def changed(self) -> bool:
        return self.baseline != self.candidate

    @property
    def regressed(self) -> bool:
        return self.baseline == CaseOutcome.SUCCESS.value and self.candidate != self.baseline

    @property
    def fixed(self) -> bool:
        return self.candidate == CaseOutcome.SUCCESS.value and self.baseline != self.candidate


class Comparison(BaseModel):
    """Two reports, side by side, with nothing concluded."""

    model_config = ConfigDict(extra="forbid")

    baseline_id: str
    candidate_id: str
    baseline_config: str
    candidate_config: str
    #: axis -> (baseline value, candidate value), for axes that differ.
    axes: dict[str, tuple[str, str]] = Field(default_factory=dict)
    metrics: list[MetricDelta] = Field(default_factory=list)
    cases: list[CaseDelta] = Field(default_factory=list)
    #: Cases present in one report and not the other. A comparison over different
    #: case sets is not a comparison, so this is surfaced rather than absorbed.
    case_mismatch: list[str] = Field(default_factory=list)
    sample_size: int = 0

    @property
    def regressions(self) -> list[CaseDelta]:
        return [case for case in self.cases if case.regressed]

    @property
    def fixes(self) -> list[CaseDelta]:
        return [case for case in self.cases if case.fixed]

    @property
    def has_regression(self) -> bool:
        return bool(self.regressions)

    def render(self) -> str:
        return render_comparison(self)


def compare_reports(baseline: EvalReport, candidate: EvalReport) -> Comparison:
    axes: dict[str, tuple[str, str]] = {}
    base_axes = baseline.config.axes()
    cand_axes = candidate.config.axes()
    for axis, value in cand_axes.items():
        if base_axes.get(axis) != value:
            axes[axis] = (base_axes.get(axis, "(unset)"), value)

    metrics = [
        _delta(metric, candidate.metrics.get(metric.id)) for metric in baseline.metrics.values
    ]

    base_results = {result.case_id: result for result in baseline.results}
    cand_results = {result.case_id: result for result in candidate.results}
    cases = [
        CaseDelta(
            case_id=case_id,
            baseline=base_results[case_id].outcome.value if case_id in base_results else "absent",
            candidate=cand_results[case_id].outcome.value if case_id in cand_results else "absent",
        )
        for case_id in sorted(set(base_results) | set(cand_results))
    ]

    return Comparison(
        baseline_id=baseline.report_id,
        candidate_id=candidate.report_id,
        baseline_config=baseline.config.id,
        candidate_config=candidate.config.id,
        axes=axes,
        metrics=metrics,
        cases=cases,
        case_mismatch=sorted(set(base_results) ^ set(cand_results)),
        sample_size=len(candidate.attempted),
    )


def _delta(baseline: MetricValue, candidate: MetricValue | None) -> MetricDelta:
    """One metric, both sides.

    A metric that is unknown on either side stays unknown. Treating a missing
    measurement as zero would manufacture an improvement out of a runtime that
    simply reports less than the other one - the exact mistake that makes
    cross-runtime cost comparisons meaningless.
    """
    delta = MetricDelta(
        id=baseline.id,
        label=baseline.label,
        unit=baseline.unit,
        baseline=baseline.value,
        candidate=candidate.value if candidate else None,
    )
    if candidate is None:
        delta.note = "the candidate report does not contain this metric"
        return delta
    if baseline.value is None or candidate.value is None:
        missing = "baseline" if baseline.value is None else "candidate"
        source = baseline if baseline.value is None else candidate
        delta.note = f"unknown on the {missing}: {source.unknown_reason}"
        return delta

    delta.delta = candidate.value - baseline.value
    if delta.delta == 0 or baseline.direction is Direction.NEUTRAL:
        delta.movement = Movement.UNCHANGED if delta.delta == 0 else Movement.UNKNOWN
        if baseline.direction is Direction.NEUTRAL and delta.delta != 0:
            delta.note = "no direction is better for this metric; it is context"
        return delta
    improved = (delta.delta > 0) if baseline.direction is Direction.UP else (delta.delta < 0)
    delta.movement = Movement.IMPROVED if improved else Movement.DEGRADED
    return delta


def render_comparison(comparison: Comparison) -> str:
    lines = [
        "# Evaluation comparison",
        "",
        f"baseline `{comparison.baseline_config}` ({comparison.baseline_id}) → "
        f"candidate `{comparison.candidate_config}` ({comparison.candidate_id})",
        "",
    ]

    lines += ["## What differed", ""]
    if comparison.axes:
        lines += ["| axis | baseline | candidate |", "| --- | --- | --- |"]
        lines += [
            f"| {axis} | {before} | {after} |"
            for axis, (before, after) in comparison.axes.items()
        ]
        if len(comparison.axes) > 1:
            lines += [
                "",
                f"**{len(comparison.axes)} axes changed at once.** Any difference below "
                "cannot be attributed to one of them. Vary one axis per comparison if "
                "the answer matters.",
            ]
    else:
        lines.append(
            "Nothing. The two reports ran the same configuration, so any difference "
            "below is run-to-run variation - which is itself worth knowing."
        )

    lines += [
        "",
        "## Metrics",
        "",
        "| metric | baseline | candidate | change | |",
        "| --- | --- | --- | --- | --- |",
    ]
    for metric in comparison.metrics:
        base = _format(metric.baseline, metric.unit)
        cand = _format(metric.candidate, metric.unit)
        marker = {
            Movement.IMPROVED: "better",
            Movement.DEGRADED: "worse",
            Movement.UNCHANGED: "same",
            Movement.UNKNOWN: metric.note or "unknown",
        }[metric.movement]
        lines.append(f"| {metric.label} | {base} | {cand} | {metric.format_delta()} | {marker} |")

    changed = [case for case in comparison.cases if case.changed]
    lines += ["", "## Cases that changed", ""]
    if changed:
        lines += ["| case | baseline | candidate |", "| --- | --- | --- |"]
        lines += [f"| {case.case_id} | {case.baseline} | {case.candidate} |" for case in changed]
    else:
        lines.append("None. Every case ended the same way in both runs.")

    if comparison.case_mismatch:
        lines += [
            "",
            "## Case sets differ",
            "",
            "These cases appear in only one of the two reports: "
            + ", ".join(comparison.case_mismatch)
            + ".",
            "",
            "The metrics above are computed over different sets and are not directly "
            "comparable. Re-run both configurations over the same suites.",
        ]

    if comparison.regressions:
        lines += ["", "## Regressions", ""]
        lines += [
            f"- **{case.case_id}**: passed on the baseline, now `{case.candidate}`"
            for case in comparison.regressions
        ]

    lines += ["", "## How to read this", "", *_caveats(comparison)]
    return "\n".join(lines) + "\n"


def _caveats(comparison: Comparison) -> list[str]:
    n = comparison.sample_size
    granularity = f"{1 / n:.0%}" if n else "n/a"
    return [
        f"**Sample size: {n} attempted case(s).** One case is worth {granularity} of "
        "the success rate, so a change of one case moves it by that much. No "
        "statistical test is performed and none would be informative at this size.",
        "",
        "**No winner is declared.** \"better\" and \"worse\" mark the direction a "
        "number moved, nothing more. Deciding which configuration to adopt needs "
        "the cost, the latency and the failures read together, and that judgement "
        "is the reader's.",
        "",
        "**Regressions are the exception.** A case that passed and now fails is a "
        "reproducible fact about that case, which is why it is the only thing here "
        "that can fail a build.",
    ]


def _format(value: float | None, unit: str) -> str:
    if value is None:
        return "unknown"
    if unit == "%":
        return f"{value:.0%}"
    if unit == "usd":
        return f"${value:.4f}"
    if unit in {"ms", "tokens"}:
        return f"{value:,.0f}"
    if float(value).is_integer():
        return f"{value:.0f}"
    return f"{value:.2f}"
