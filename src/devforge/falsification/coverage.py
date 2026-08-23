"""Attack surface coverage: what was actually looked at.

A mutation score alone is not enough to read a falsification run. It says how many
injected faults the tests caught; it says nothing about *which surfaces were probed
at all*. A run that scores 100% having attacked only ordinary behaviour has not
examined the authorisation boundary, and a report that shows only the score lets
that go unnoticed.

So coverage is tracked on two axes:

``AttackSurfaceCoverage``
    Per target: how many of the strategies that *could* attack it actually did.
``StrategyCoverage``
    Which strategies were requested, which executed, and why the rest did not.

**Coverage never implies correctness.** A target at 100% means every applicable
strategy ran against it and none found a counterexample within its budget. It does
not mean the target is sound.

**A target nothing can attack still appears, reporting zero.** Six of the ten
registered targets ship with no strategy capable of attacking them. Omitting them
would make the report look complete; showing `security 0%` makes the gap visible and
plannable. That difference is the reason this module exists rather than the numbers
being derived ad hoc wherever they are printed.

The models live here rather than in :mod:`devforge.falsification.models` so that
computation and shape stay together, and because nothing here needs to know what a
report is - which is what keeps the import direction one-way.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:  # pragma: no cover - typing only
    from devforge.falsification.models import StrategyName, StrategyReport


class TargetCoverage(BaseModel):
    """How much of one target's attack surface was actually attacked."""

    model_config = ConfigDict(extra="forbid")

    target: str
    #: Strategies that could attack this target and did run.
    attacked_by: list[str] = Field(default_factory=list)
    #: Strategies that could attack it but did not run.
    unattacked_by: list[str] = Field(default_factory=list)
    attempts: int = 0
    counterexamples: int = 0

    @property
    def applicable(self) -> int:
        return len(self.attacked_by) + len(self.unattacked_by)

    @property
    def fraction(self) -> float | None:
        """Attacked over applicable strategies, or ``None`` when none apply.

        ``None`` rather than ``0.0``: a target no shipped strategy can attack has
        not scored badly, it has not been measured, and the two read very
        differently in a table.
        """
        return len(self.attacked_by) / self.applicable if self.applicable else None

    def format(self) -> str:
        return "n/a" if self.fraction is None else f"{self.fraction:.0%}"


class AttackSurfaceCoverage(BaseModel):
    """Per-target coverage across a run."""

    model_config = ConfigDict(extra="forbid")

    targets: list[TargetCoverage] = Field(default_factory=list)

    def get(self, target: str) -> TargetCoverage | None:
        return next((entry for entry in self.targets if entry.target == target), None)

    @property
    def attacked(self) -> list[TargetCoverage]:
        return [entry for entry in self.targets if entry.attacked_by]

    @property
    def unattacked(self) -> list[TargetCoverage]:
        """Targets in scope that nothing actually attacked."""
        return [entry for entry in self.targets if entry.applicable and not entry.attacked_by]

    @property
    def fraction(self) -> float | None:
        """Mean coverage across measurable targets, or ``None`` when there are none."""
        measurable = [entry.fraction for entry in self.targets if entry.fraction is not None]
        return sum(measurable) / len(measurable) if measurable else None

    def render(self) -> list[str]:
        width = max((len(entry.target) for entry in self.targets), default=0)
        return [f"{entry.target.ljust(width)}  {entry.format()}" for entry in self.targets]


class StrategyCoverage(BaseModel):
    """Which strategies ran, and which were asked for but could not."""

    model_config = ConfigDict(extra="forbid")

    requested: list[str] = Field(default_factory=list)
    executed: list[str] = Field(default_factory=list)
    #: Strategy name -> the reason it did not run. Always populated when a requested
    #: strategy is absent from ``executed``: a silent omission is indistinguishable
    #: from a strategy that ran and found nothing.
    unavailable: dict[str, str] = Field(default_factory=dict)

    @property
    def fraction(self) -> float | None:
        return len(self.executed) / len(self.requested) if self.requested else None

    def render(self) -> list[str]:
        lines = [f"executed: {', '.join(sorted(self.executed)) or '(none)'}"]
        for name, reason in sorted(self.unavailable.items()):
            lines.append(f"not run:  {name} - {reason}")
        return lines


def compute_attack_surface(
    *,
    target_names: list[str],
    selected: list[StrategyName],
    executed: set[StrategyName],
    strategy_reports: list[StrategyReport],
    counterexample_targets: list[str],
) -> AttackSurfaceCoverage:
    """Derive per-target coverage from what the run actually did.

    Every registered target appears, including those in no scope and those no
    strategy can attack. The distinction between them is carried by
    ``applicable``: a target out of scope has no applicable strategies and formats
    as ``n/a``, rather than looking like a failure to cover it.
    """
    from devforge.falsification import targets as registry

    entries: list[TargetCoverage] = []

    for name in registry.known_targets():
        target = registry.get(name)
        if target is None:  # pragma: no cover - the registry is the source of names
            continue

        if name not in target_names:
            entries.append(TargetCoverage(target=name))
            continue

        capable = {strategy for strategy in target.strategies if strategy in set(selected)}
        attacked = sorted(strategy.value for strategy in capable if strategy in executed)
        entries.append(
            TargetCoverage(
                target=name,
                attacked_by=attacked,
                unattacked_by=sorted(
                    strategy.value for strategy in capable if strategy.value not in attacked
                ),
                attempts=sum(
                    report.attempts for report in strategy_reports if name in (report.targets or [])
                ),
                counterexamples=counterexample_targets.count(name),
            )
        )

    return AttackSurfaceCoverage(targets=entries)
