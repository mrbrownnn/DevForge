"""The falsification engine: a peer of the verification engine, not a replacement.

Verification asks *do the declared checks pass?* and produces evidence **for** a
patch. This asks *can I find a counterexample?* and produces evidence **against** it.
Both report to the orchestrator, which decides; neither is correctness.

    patch ──┬──> VerificationEngine ──> evidence FOR ──┐
            └──> FalsificationEngine ─> evidence AGAINST ─┴──> orchestrator

The run, in order::

    resolve targets  -> validated against the target registry
    resolve strategies -> filtered by the target x strategy applicability matrix
    acquire sandbox  -> worktree, else copy, else refuse
    reliability probe -> quarantine flaky tests before anything is judged
    for each strategy, cheapest and most deterministic first:
        available? no -> UNAVAILABLE with a reason  (never a survival)
        attack, under a sub-budget of its own
    coverage -> settle -> persist -> release the sandbox

Two ordering decisions are load-bearing. Strategies run cheapest-first so that
budget exhaustion truncates the *least* reproducible evidence rather than the most -
an expensive agent call should not consume the budget mutation testing needed. And
the reliability probe runs before any mutation, because a verdict from a suite whose
flakiness nobody has measured is not a verdict.

The engine never decides the step's fate. It returns a report; the orchestrator
applies ``on_incomplete`` and ``on_unavailable`` and decides what that means for the
workflow.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from devforge.falsification import targets as target_registry
from devforge.falsification.coverage import compute_attack_surface
from devforge.falsification.models import (
    DEFAULT_STRATEGY_ORDER,
    Budget,
    FalsificationReport,
    FalsificationStatus,
    MutationScope,
    StrategyCoverage,
    StrategyName,
    StrategyReport,
    StrategyStatus,
)
from devforge.falsification.reliability import screen
from devforge.falsification.sandbox import Isolation, Sandbox, create_sandbox
from devforge.falsification.strategies.base import (
    BudgetLedger,
    FalsificationContext,
    StrategyRegistry,
)
from devforge.observability.logging import RunLogger, null_logger
from devforge.policy.engine import PolicyEngine


class FalsificationEngine:
    """Runs the configured strategies against a patch and reports what it found."""

    def __init__(self, registry: StrategyRegistry | None = None) -> None:
        self.registry = registry or StrategyRegistry.default()

    # -- resolution -------------------------------------------------------------

    def select(
        self, requested: list[str] | None, target_names: list[str], order: list[str] | None = None
    ) -> tuple[list[StrategyName], dict[str, str]]:
        """Which strategies to run, and why each rejected one was rejected.

        A strategy that cannot attack any of the chosen targets is dropped with a
        stated reason rather than run pointlessly - and the reason lands in the
        report, so "we did not run property testing" is never silent.
        """
        names = requested or [name.value for name in DEFAULT_STRATEGY_ORDER]
        unknown = [name for name in names if name not in {s.value for s in StrategyName}]
        if unknown:
            raise ValueError(
                f"unknown falsification strategy/strategies {sorted(unknown)}; "
                f"known: {', '.join(s.value for s in StrategyName)}"
            )

        applicable = target_registry.strategies_for(target_names)
        selected: list[StrategyName] = []
        rejected: dict[str, str] = {}

        for name in dict.fromkeys(names):
            strategy = StrategyName(name)
            if strategy not in applicable:
                rejected[name] = (
                    f"none of the selected targets ({', '.join(target_names)}) can be "
                    f"attacked by the {name} strategy"
                )
                continue
            selected.append(strategy)

        sequence = [StrategyName(name) for name in order] if order else list(DEFAULT_STRATEGY_ORDER)
        selected.sort(key=lambda item: sequence.index(item) if item in sequence else len(sequence))
        return selected, rejected

    # -- execution --------------------------------------------------------------

    async def run(
        self,
        *,
        source_root: Path,
        policy: PolicyEngine,
        strategies: list[str] | None = None,
        target_names: list[str] | None = None,
        budget: Budget | None = None,
        config: dict[str, Any] | None = None,
        diff: str = "",
        changed_files: list[str] | None = None,
        test_command: list[str] | None = None,
        test_timeout_s: int = 300,
        scope: MutationScope = MutationScope.DIFF,
        task_id: str = "",
        step_id: str = "",
        commit: str = "",
        logger: RunLogger | None = None,
        agent_invoker: Callable[..., Any] | None = None,
        isolation: Isolation | None = None,
        order: list[str] | None = None,
    ) -> FalsificationReport:
        """Execute a falsification run and return its report.

        Never raises for a failed search. A configuration error raises, because a
        workflow that names a strategy that does not exist is broken and should say
        so loudly rather than quietly attacking less than it claimed.
        """
        logger = logger or null_logger()
        budget = budget or Budget()
        resolved_targets = target_registry.resolve(target_names)
        selected, rejected = self.select(strategies, resolved_targets, order)

        report = FalsificationReport(
            task_id=task_id,
            step_id=step_id,
            commit=commit,
            diff_digest=hashlib.sha256(diff.encode("utf-8")).hexdigest()[:16] if diff else "",
            diff_files=list(changed_files or []),
            targets=resolved_targets,
            scope=scope,
            budget=budget,
            strategy_coverage=StrategyCoverage(
                requested=[s.value for s in selected] + sorted(rejected),
                unavailable=dict(rejected),
            ),
        )
        started = time.monotonic()

        logger = logger.bind(run_id=report.run_id)
        logger.info(
            "falsification.started",
            task_id=task_id,
            step=step_id,
            strategies=[s.value for s in selected],
            targets=resolved_targets,
            scope=scope.value,
        )

        sandbox = create_sandbox(source_root, run_id=report.run_id, prefer=isolation)
        report.isolation = sandbox.isolation.value

        try:
            if not sandbox.available:
                # ISOLATION_UNAVAILABLE. There is no configuration in which this
                # subsystem mutates the user's working tree instead.
                report.limitations.append(f"ISOLATION_UNAVAILABLE: {sandbox.detail}")
                report.strategies = []
                report.status = FalsificationStatus.UNAVAILABLE
                report.duration_ms = int((time.monotonic() - started) * 1000)
                logger.error(
                    "falsification.completed",
                    status=report.status.value,
                    reason="isolation unavailable",
                )
                report.settle()
                report.status = FalsificationStatus.UNAVAILABLE
                return report

            await self._execute(
                report=report,
                sandbox=sandbox,
                selected=selected,
                policy=policy.for_workspace(sandbox.root),
                budget=budget,
                config=config or {},
                diff=diff,
                changed_files=list(changed_files or []),
                test_command=list(test_command or ["python", "-m", "pytest", "-q"]),
                test_timeout_s=test_timeout_s,
                task_id=task_id,
                step_id=step_id,
                logger=logger,
                agent_invoker=agent_invoker,
                targets=resolved_targets,
            )
        finally:
            sandbox.release()

        report.duration_ms = int((time.monotonic() - started) * 1000)
        report.coverage = compute_attack_surface(
            target_names=resolved_targets,
            selected=selected,
            executed=self._executed(report),
            strategy_reports=report.strategies,
            counterexample_targets=[c.target for c in report.counterexamples],
        )
        report.settle()

        logger.info(
            "falsification.completed",
            status=report.status.value,
            confidence=report.confidence.value,
            counterexamples=len(report.counterexamples),
            mutants=report.mutants_total,
            mutation_score=report.mutation_score,
            duration_ms=report.duration_ms,
        )
        return report

    async def _execute(
        self,
        *,
        report: FalsificationReport,
        sandbox: Sandbox,
        selected: list[StrategyName],
        policy: PolicyEngine,
        budget: Budget,
        config: dict[str, Any],
        diff: str,
        changed_files: list[str],
        test_command: list[str],
        test_timeout_s: int,
        task_id: str,
        step_id: str,
        logger: RunLogger,
        agent_invoker: Callable[..., Any] | None,
        targets: list[str],
    ) -> None:
        ledger = BudgetLedger(budget)

        reliability, _ = await screen(
            workspace=sandbox.root,
            policy=policy,
            test_command=test_command,
            probes=budget.flakiness_probes,
            timeout_s=test_timeout_s,
            logger=logger,
        )
        report.reliability = reliability

        base = FalsificationContext(
            workspace=sandbox.root,
            source_root=Path(report.diff_files and sandbox.root or sandbox.root),
            scratch=sandbox.scratch,
            policy=policy,
            ledger=ledger,
            logger=logger,
            task_id=task_id,
            step_id=step_id,
            run_id=report.run_id,
            diff=diff,
            changed_files=changed_files,
            targets=targets,
            test_command=test_command,
            test_timeout_s=test_timeout_s,
            quarantined_tests=list(reliability.quarantined),
            config={**config, "isolation": sandbox.isolation.value},
            agent_invoker=agent_invoker,
        )

        for name in selected:
            strategy = self.registry.try_get(name.value)
            if strategy is None:  # pragma: no cover - registry and enum agree
                continue

            ctx = base.for_strategy(name)
            logger.info("falsification.strategy.started", strategy=name.value)

            try:
                result = await strategy.attack(ctx)
            except Exception as exc:
                # A broken strategy must not abort the run, and must never be
                # recorded as a survival.
                result = StrategyReport(
                    strategy=name,
                    status=StrategyStatus.ERROR,
                    summary=f"the strategy raised {type(exc).__name__}: {exc}",
                    limitations=[f"{name.value}: the strategy itself failed ({exc})"],
                )

            report.strategies.append(result)
            report.usage = report.usage.merge(result.usage)
            if result.status in {StrategyStatus.SURVIVED, StrategyStatus.FAILED}:
                report.strategy_coverage.executed.append(name.value)
            elif result.status is StrategyStatus.UNAVAILABLE:
                report.strategy_coverage.unavailable[name.value] = result.summary

            logger.info(
                "falsification.strategy.completed",
                strategy=name.value,
                status=result.status.value,
                counterexamples=len(result.counterexamples),
                duration_ms=result.duration_ms,
            )

            if ledger.out_of_time():
                logger.warn(
                    "falsification.budget_exhausted",
                    limit="max_duration_s",
                    remaining_strategies=[
                        s.value for s in selected[selected.index(name) + 1 :]
                    ],
                )
                break

        report.usage = report.usage.merge(ledger.snapshot())

    @staticmethod
    def _executed(report: FalsificationReport) -> set[StrategyName]:
        """Strategies that actually ran, as enum members.

        Read back from the coverage record rather than tracked separately: one
        source of truth, so the table and the narrative cannot disagree.
        """
        known = {strategy.value: strategy for strategy in StrategyName}
        return {
            known[name] for name in report.strategy_coverage.executed if name in known
        }
