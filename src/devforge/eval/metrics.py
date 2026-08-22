"""The twelve metrics, and the arithmetic that produces them.

Each metric knows three things a bare number does not: which direction is better,
what its denominator was, and why it is missing when it is missing. All three are
needed to read a comparison honestly.

``value is None`` means *not measured*. It is never rendered as ``0``, never
averaged into anything, and never compared - ``eval compare`` reports it as
"unknown" on whichever side lacks it. The mock runtime reports no token counts, so
a mock report has no token figure; writing ``0 tokens`` there would be a false
measurement rather than a missing one.
"""

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:  # pragma: no cover - typing only
    from devforge.eval.models import CaseResult


class Direction(str, Enum):
    """Which way is an improvement. ``NEUTRAL`` metrics are context, not scores."""

    UP = "up"
    DOWN = "down"
    NEUTRAL = "neutral"


class MetricValue(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    label: str
    value: float | None = None
    unit: str = ""
    direction: Direction = Direction.NEUTRAL
    #: What the number was computed over, in words. Printed next to it, because
    #: "80%" of three cases and of three hundred are different claims.
    basis: str = ""
    #: Why the value is None. Required whenever it is.
    unknown_reason: str = ""

    @property
    def known(self) -> bool:
        return self.value is not None

    def format(self) -> str:
        if self.value is None:
            return "unknown"
        if self.unit == "%":
            return f"{self.value:.0%}"
        if self.unit == "usd":
            return f"${self.value:.4f}"
        if self.unit == "ms":
            return f"{self.value:,.0f} ms"
        if self.unit == "tokens":
            return f"{self.value:,.0f}"
        if float(self.value).is_integer():
            return f"{self.value:.0f}"
        return f"{self.value:.2f}"


class Metrics(BaseModel):
    model_config = ConfigDict(extra="forbid")

    values: list[MetricValue] = Field(default_factory=list)

    def get(self, metric_id: str) -> MetricValue | None:
        return next((value for value in self.values if value.id == metric_id), None)

    def value_of(self, metric_id: str) -> float | None:
        metric = self.get(metric_id)
        return metric.value if metric else None

    def render_table(self) -> list[str]:
        lines = ["| metric | value | basis |", "| --- | --- | --- |"]
        for metric in self.values:
            basis = metric.basis if metric.known else metric.unknown_reason
            lines.append(f"| {metric.label} | {metric.format()} | {basis} |")
        return lines


# --------------------------------------------------------------------------- computation


def _rate(numerator: int, denominator: int) -> float | None:
    """A rate over nothing is unknown, never 1.0 and never 0.0.

    Zero cases attempted is the situation where a vacuous rate does the most
    damage: it looks like a result and is printed alongside real ones.
    """
    return numerator / denominator if denominator else None


def compute_metrics(results: list[CaseResult]) -> Metrics:
    """Derive the twelve tracked metrics from a run's case results."""
    from devforge.eval.models import CaseOutcome

    attempted = [r for r in results if r.outcome.attempted]
    n = len(attempted)
    denominator = f"{n} attempted case(s)"
    skipped = len(results) - n
    if skipped:
        denominator += f"; {skipped} not attempted"

    values: list[MetricValue] = []

    # 1. task success rate
    wins = sum(1 for r in attempted if r.outcome.success)
    values.append(
        MetricValue(
            id="task_success_rate",
            label="Task success rate",
            value=_rate(wins, n),
            unit="%",
            direction=Direction.UP,
            basis=f"{wins}/{n} - {denominator}",
            unknown_reason="no case was attempted",
        )
    )

    # 2. first-pass success
    scored = [r for r in attempted if r.first_pass is not None]
    first = sum(1 for r in scored if r.first_pass)
    values.append(
        MetricValue(
            id="first_pass_success",
            label="First-pass success",
            value=_rate(first, len(scored)),
            unit="%",
            direction=Direction.UP,
            basis=f"{first}/{len(scored)} succeeded with no step retried",
            unknown_reason="this driver does not run steps, so there is no first pass",
        )
    )

    # 3. repair success - of the cases that needed a retry, how many recovered
    retried = [
        r for r in attempted if r.attempts is not None and r.steps_total is not None
        and r.attempts > r.steps_total
    ]
    repaired = sum(1 for r in retried if r.outcome.success)
    values.append(
        MetricValue(
            id="repair_success",
            label="Repair success",
            value=_rate(repaired, len(retried)),
            unit="%",
            direction=Direction.UP,
            basis=f"{repaired}/{len(retried)} cases that needed a retry ended green",
            unknown_reason="no case needed a repair attempt",
        )
    )

    # 4. verification pass rate
    passed = sum(r.verifications_passed or 0 for r in attempted)
    failed = sum(r.verifications_failed or 0 for r in attempted)
    values.append(
        MetricValue(
            id="verification_pass_rate",
            label="Verification pass rate",
            value=_rate(passed, passed + failed),
            unit="%",
            direction=Direction.UP,
            basis=f"{passed}/{passed + failed} verifier results",
            unknown_reason="no verifier ran",
        )
    )

    # 5. regression rate - a guard that passed before the attempt and failed after
    regressed = sum(1 for r in attempted if r.regressed)
    values.append(
        MetricValue(
            id="regression_rate",
            label="Regression rate",
            value=_rate(regressed, n),
            unit="%",
            direction=Direction.DOWN,
            basis=f"{regressed}/{n} broke something that worked before",
            unknown_reason="no case was attempted",
        )
    )

    # 6. average iterations
    counted = [r for r in attempted if r.attempts is not None and r.steps_total]
    iterations = (
        sum(r.attempts / r.steps_total for r in counted if r.steps_total) / len(counted)
        if counted
        else None
    )
    values.append(
        MetricValue(
            id="average_iterations",
            label="Average iterations per step",
            value=iterations,
            direction=Direction.DOWN,
            basis=f"mean over {len(counted)} case(s); 1.0 means nothing was retried",
            unknown_reason="this driver does not run steps",
        )
    )

    # 7/8. tokens and cost - reported by the runtime or not at all
    token_cases = [r for r in attempted if r.tokens is not None]
    values.append(
        MetricValue(
            id="token_usage",
            label="Token usage",
            value=float(sum(r.tokens or 0 for r in token_cases)) if token_cases else None,
            unit="tokens",
            direction=Direction.DOWN,
            basis=f"total over {len(token_cases)} case(s) that reported counts",
            unknown_reason="the runtime reported no token counts",
        )
    )
    cost_cases = [r for r in attempted if r.cost_usd is not None]
    values.append(
        MetricValue(
            id="cost_usd",
            label="Cost",
            value=sum(r.cost_usd or 0.0 for r in cost_cases) if cost_cases else None,
            unit="usd",
            direction=Direction.DOWN,
            basis=f"total over {len(cost_cases)} case(s) that reported cost",
            unknown_reason="the runtime reported no cost",
        )
    )

    # 9. latency
    durations = [r.duration_ms for r in attempted if r.duration_ms > 0]
    values.append(
        MetricValue(
            id="latency_ms",
            label="Latency per case (mean)",
            value=sum(durations) / len(durations) if durations else None,
            unit="ms",
            direction=Direction.DOWN,
            basis=f"wall clock, mean of {len(durations)} case(s), grading included",
            unknown_reason="no case ran long enough to time",
        )
    )

    # 10. human intervention
    intervened = sum(1 for r in attempted if r.interventions)
    values.append(
        MetricValue(
            id="human_intervention_rate",
            label="Human intervention rate",
            value=_rate(intervened, n),
            unit="%",
            direction=Direction.DOWN,
            basis=(
                f"{intervened}/{n} reached an approval gate; an eval answers gates "
                "automatically, so this counts decisions a human would have made"
            ),
            unknown_reason="no case was attempted",
        )
    )

    # 11. security violations
    violations = sum(r.security_violations for r in attempted)
    rejected = sum(1 for r in attempted if r.outcome is CaseOutcome.REJECTED_SUSPICIOUS)
    values.append(
        MetricValue(
            id="security_violations",
            label="Security violations",
            value=float(violations),
            direction=Direction.DOWN,
            basis=(
                f"denied tool calls and suspicious-patch findings; {rejected} case(s) "
                "rejected outright"
            ),
        )
    )

    # 12. tool failures
    failure_cases = [r for r in attempted if r.tool_failures is not None]
    values.append(
        MetricValue(
            id="tool_failures",
            label="Tool failures",
            value=float(sum(r.tool_failures or 0 for r in failure_cases))
            if failure_cases
            else None,
            direction=Direction.DOWN,
            basis=(
                f"tool calls that errored, over {sum(r.tool_calls or 0 for r in failure_cases)} "
                "call(s)"
            ),
            unknown_reason="this driver makes no tool calls",
        )
    )

    return Metrics(values=values)
