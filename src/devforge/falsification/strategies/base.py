"""The strategy interface: one way to attack an implementation.

A strategy answers a single question - *can I find a counterexample of my kind?* -
and reports what it found and what it could not look at. It never decides whether
the run passes, never writes to the user's tree, and never runs a command the policy
engine has not allowed.

Adding a strategy means implementing :class:`FalsificationStrategy`, registering it,
and adding it to the applicability matrix in :mod:`devforge.falsification.targets`.
The engine does not change. That is the extension point for the strategies named in
the design but deliberately not implemented: fuzzing, fault injection, chaos,
concurrency and race detection, browser adversarial testing, API contract attacks,
security fuzzing.

Two rules every implementation must respect, because the engine cannot enforce them
from outside:

* **Never raise for a failed attack.** A strategy that finds nothing reports
  ``SURVIVED``; a strategy that breaks reports ``ERROR``. The engine converts an
  escaping exception into ``ERROR`` rather than letting it abort the run, but that
  is a safety net, not a contract.
* **Never report ``SURVIVED`` for work you did not do.** A missing tool, an
  unsupported target or a budget that ran out before anything ran is ``UNAVAILABLE``
  or ``INCOMPLETE``. Reporting a survival for an unrun search is the precise failure
  mode this subsystem exists to prevent.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from devforge.core.registry.base import Registry
from devforge.falsification.models import (
    Budget,
    BudgetUsage,
    StrategyName,
    StrategyReport,
    StrategyStatus,
)
from devforge.observability.logging import RunLogger, null_logger
from devforge.policy.engine import PolicyEngine

#: Bound on any excerpt a strategy attaches to a finding. Evidence is meant to be
#: read by a person; a megabyte of pytest output is not evidence, it is a haystack.
MAX_EVIDENCE_CHARS = 4_000


@dataclass(frozen=True)
class Availability:
    """Whether a strategy can run here, and why not when it cannot."""

    available: bool
    detail: str = ""


class BudgetLedger:
    """Tracks spend against a :class:`Budget` and names the limit that stopped it.

    Deliberately a small mutable object rather than a context manager: strategies
    check it inside loops and the engine reads accumulated usage afterwards. The
    wall clock starts when the ledger is constructed, which is when the run starts.

    ``sub`` produces a child ledger bounded by one strategy's share of the wall
    clock, which is how one slow agent call is stopped from spending a budget four
    other strategies were relying on.
    """

    def __init__(self, budget: Budget, *, deadline_s: float | None = None) -> None:
        self.budget = budget
        self.usage = BudgetUsage()
        self._started = time.monotonic()
        self._deadline_s = float(budget.max_duration_s if deadline_s is None else deadline_s)

    # -- clock ------------------------------------------------------------------

    @property
    def elapsed_ms(self) -> int:
        return int((time.monotonic() - self._started) * 1000)

    @property
    def remaining_s(self) -> float:
        return max(0.0, self._deadline_s - (time.monotonic() - self._started))

    def out_of_time(self) -> bool:
        if self.remaining_s > 0:
            return False
        self.exhaust("max_duration_s")
        return True

    def sub(self, strategy: StrategyName) -> BudgetLedger:
        """A child ledger for one strategy, bounded by its declared share."""
        share = self.budget.share_for(strategy, int(self.remaining_s))
        return BudgetLedger(self.budget, deadline_s=share)

    # -- counters ---------------------------------------------------------------

    def spend(self, counter: str, amount: int = 1) -> None:
        setattr(self.usage, counter, getattr(self.usage, counter) + amount)

    def allows(self, counter: str, limit_name: str) -> bool:
        """Whether one more unit of ``counter`` fits inside ``limit_name``.

        Records the exhausted limit as a side effect, so a truncated search shows up
        in the report instead of looking like a completed one.
        """
        if self.out_of_time():
            return False
        if getattr(self.usage, counter) >= getattr(self.budget, limit_name):
            self.exhaust(limit_name)
            return False
        return True

    def exhaust(self, limit_name: str) -> None:
        if limit_name not in self.usage.exhausted:
            self.usage.exhausted.append(limit_name)

    def unenforceable(self, limit_name: str) -> None:
        """Record a limit that could not be measured, so was not enforced.

        Used for ``max_tokens`` against a runtime that reports no token counts. The
        alternative - saying nothing - reads as "the budget was respected", which is
        a claim nobody checked.
        """
        if limit_name not in self.usage.unenforceable:
            self.usage.unenforceable.append(limit_name)

    def count_tokens(self, tokens: int | None) -> None:
        """Fold a runtime's token report into the ledger, or note it is missing."""
        if tokens is None:
            self.unenforceable("max_tokens")
            return
        self.usage.tokens = (self.usage.tokens or 0) + tokens
        if self.budget.max_tokens is not None and self.usage.tokens >= self.budget.max_tokens:
            self.exhaust("max_tokens")

    def snapshot(self) -> BudgetUsage:
        usage = self.usage.model_copy(deep=True)
        usage.duration_ms = self.elapsed_ms
        return usage


@dataclass
class FalsificationContext:
    """Everything a strategy is given, and nothing it is not.

    ``workspace`` is the **isolated** copy: everything a strategy writes lands there
    and nowhere else. ``source_root`` is present only so a strategy can read the
    original for comparison - differential testing needs both - and is never a write
    target for any strategy under any configuration.
    """

    workspace: Path
    source_root: Path
    #: Scratch directory inside the workspace for generated tests and artifacts.
    #: The only place the adversarial agent may write.
    scratch: Path
    policy: PolicyEngine
    ledger: BudgetLedger
    logger: RunLogger = field(default_factory=null_logger)

    task_id: str = ""
    step_id: str = ""
    run_id: str = ""

    #: The patch under attack, and the files it touches.
    diff: str = ""
    changed_files: list[str] = field(default_factory=list)
    #: Targets this run is attacking, already validated against the registry.
    targets: list[str] = field(default_factory=list)

    #: How to run the project's tests. An argv, checked against the policy before it
    #: is ever executed.
    test_command: list[str] = field(default_factory=lambda: ["python", "-m", "pytest", "-q"])
    test_timeout_s: int = 300
    #: Tests the reliability probe quarantined. A verdict resting on one of these is
    #: UNRELIABLE rather than trusted.
    quarantined_tests: list[str] = field(default_factory=list)

    #: Per-strategy configuration straight from the workflow YAML. Opaque to the
    #: engine, exactly as ``VerifierSpec.params`` is opaque to the orchestrator.
    config: dict[str, Any] = field(default_factory=dict)

    #: Invokes the adversarial agent. Absent when no runtime was wired in, which is
    #: why the adversarial strategy reports UNAVAILABLE rather than inventing tests.
    agent_invoker: Callable[..., Any] | None = None

    def options(self, strategy: StrategyName) -> dict[str, Any]:
        """Configuration for one strategy, defaulting to an empty mapping."""
        value = self.config.get(strategy.value)
        return value if isinstance(value, dict) else {}

    def for_strategy(self, strategy: StrategyName) -> FalsificationContext:
        """A copy with a strategy-scoped ledger and a bound logger."""
        scoped = FalsificationContext(**{**self.__dict__})
        scoped.ledger = self.ledger.sub(strategy)
        scoped.logger = self.logger.bind(strategy=strategy.value)
        return scoped

    def relative(self, path: Path) -> str:
        try:
            return path.resolve().relative_to(self.workspace.resolve()).as_posix()
        except ValueError:
            return Path(path).as_posix()


class FalsificationStrategy(ABC):
    """One kind of adversarial search."""

    #: Stable identifier used in workflow YAML, CLI flags and persisted reports.
    name: StrategyName

    def available(self, ctx: FalsificationContext) -> Availability:
        """Cheap local check, made before any budget is spent."""
        return Availability(available=True)

    @abstractmethod
    async def attack(self, ctx: FalsificationContext) -> StrategyReport:
        """Search for counterexamples. Must not raise for a failed search."""

    # -- helpers for implementations --------------------------------------------

    def report(self, **fields: Any) -> StrategyReport:
        return StrategyReport(strategy=self.name, **fields)

    def unavailable(self, detail: str) -> StrategyReport:
        return StrategyReport(
            strategy=self.name,
            status=StrategyStatus.UNAVAILABLE,
            summary=detail,
            limitations=[f"{self.name.value}: did not run - {detail}"],
        )

    def reduce(self, ctx: FalsificationContext, value: object, still_fails=None):
        """Minimise a counterexample and record what happened.

        Shared here rather than repeated per strategy so that every counterexample
        is shrunk by the same algorithm and reports the same status. ``still_fails``
        defaults to accepting every candidate, which is the honest behaviour when a
        strategy cannot cheaply re-run its own reproduction: the reducer then only
        performs the structural shrinking that cannot change the outcome, and says
        so through its status rather than claiming a verified minimum.
        """
        from devforge.falsification.reduction import reduce_value

        budget = ctx.ledger.budget.max_reduction_steps
        reduction = reduce_value(
            value, still_fails or (lambda _candidate: True), max_steps=budget
        )
        ctx.ledger.spend("reduction_steps", reduction.steps)
        ctx.logger.info(
            "counterexample.reduced",
            strategy=self.name.value,
            status=reduction.status.value,
            steps=reduction.steps,
            shrank=reduction.succeeded,
        )
        return reduction

    @staticmethod
    def excerpt(text: str, limit: int = MAX_EVIDENCE_CHARS) -> str:
        """Tail of an output - the end of a failing run is the informative part."""
        text = text or ""
        if len(text) <= limit:
            return text
        return "...\n" + text[-limit:]


class StrategyRegistry(Registry[FalsificationStrategy]):
    """Name to strategy. The extension point for every future attack kind."""

    def __init__(self) -> None:
        super().__init__("falsification strategy")

    @classmethod
    def default(cls) -> StrategyRegistry:
        from devforge.falsification.strategies.adversarial import AdversarialStrategy
        from devforge.falsification.strategies.differential import DifferentialStrategy
        from devforge.falsification.strategies.metamorphic import MetamorphicStrategy
        from devforge.falsification.strategies.mutation import MutationStrategy
        from devforge.falsification.strategies.property import PropertyStrategy

        registry = cls()
        for strategy in (
            MutationStrategy(),
            PropertyStrategy(),
            AdversarialStrategy(),
            DifferentialStrategy(),
            MetamorphicStrategy(),
        ):
            registry.register(strategy.name.value, strategy)
        return registry
