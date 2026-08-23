"""What falsification produces: mutants, counterexamples, budgets, reports.

Four vocabulary decisions are load-bearing and are enforced by the types rather
than left to convention. Each exists because the obvious alternative would let this
subsystem overstate what it knows.

**There is no ``SUCCESS``.** The best available outcome is
:attr:`FalsificationStatus.SURVIVED`: no counterexample was found inside the
configured search space, with the budget actually spent, using the strategies that
were actually available. A field reading ``status: SUCCESS`` on a report about
correctness gets read as "the code is correct", and no amount of documentation
undoes that. There is no alias.

**A mutation score is never a correctness score.** It is killed over *valid,
non-equivalent, reliably-judged* mutants and nothing else, and it renders through
:meth:`StrategyReport.score_sentence` which states what it measures. A score over
zero mutants is ``None`` - the absence of a measurement - never ``1.0``.

**Uncertain is its own value.** A mutant nobody could classify is ``INVALID`` or
``ERROR``, never quietly ``EQUIVALENT``. A mutant whose verdict depended on a flaky
test is ``UNRELIABLE`` - a property of the suite, not of the code, and not the same
finding as equivalence however similar the two look from outside.

**A budget that could not be measured was not enforced.** ``max_tokens`` against a
runtime that reports no token counts is recorded as unenforceable, never as
satisfied.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from devforge.core.models import new_id, utcnow


class StrategyName(str, Enum):
    """The attack strategies that ship. Extension point, not a closed concept.

    A future strategy (fuzzing, fault injection, concurrency) registers under its
    own name. This enum exists so a workflow naming an unknown strategy fails at
    parse time rather than silently attacking nothing.
    """

    MUTATION = "mutation"
    PROPERTY = "property"
    ADVERSARIAL = "adversarial"
    DIFFERENTIAL = "differential"
    METAMORPHIC = "metamorphic"


#: Cheapest and most deterministic first. Budget exhaustion truncates whatever is
#: running, so this order means a truncated run loses the least reproducible
#: evidence rather than the most. Overridable per step with ``order:``.
DEFAULT_STRATEGY_ORDER: tuple[StrategyName, ...] = (
    StrategyName.MUTATION,
    StrategyName.PROPERTY,
    StrategyName.DIFFERENTIAL,
    StrategyName.METAMORPHIC,
    StrategyName.ADVERSARIAL,
)


class MutantStatus(str, Enum):
    """What happened to one mutant."""

    #: A reliable test failed on the mutant.
    KILLED = "killed"
    #: Every reliable test passed. Evidence about the *test suite*, not a verdict
    #: on the code.
    SURVIVED = "survived"
    #: Behaviourally identical to the original, per a named layer.
    EQUIVALENT = "equivalent"
    #: The verdict depended on a test the reliability probe quarantined. Excluded
    #: from the score entirely, and never folded into EQUIVALENT: one is a property
    #: of the code, the other of the suite.
    UNRELIABLE = "unreliable"
    #: Does not compile, or is not a realistic fault.
    INVALID = "invalid"
    #: Could not be evaluated at all.
    ERROR = "error"

    @property
    def counts_toward_score(self) -> bool:
        """Only valid, non-equivalent, reliably-judged mutants belong in a score."""
        return self in {MutantStatus.KILLED, MutantStatus.SURVIVED}


class StrategyStatus(str, Enum):
    """How one strategy ended. ``UNAVAILABLE`` and ``INCOMPLETE`` are not survivals."""

    #: At least one valid counterexample was found. The strategy did its job.
    FAILED = "failed"
    #: Ran to completion in the configured space and found nothing.
    SURVIVED = "survived"
    #: Started but could not fully explore: budget, timeout, partial run.
    INCOMPLETE = "incomplete"
    #: Cannot execute here: dependency missing, language unsupported, no isolation.
    UNAVAILABLE = "unavailable"
    #: The strategy itself broke. Never evidence about the code under test.
    ERROR = "error"


class FalsificationStatus(str, Enum):
    """The verdict of a whole run. Deliberately without a ``SUCCESS``."""

    FAILED = "failed"
    SURVIVED = "survived"
    INCOMPLETE = "incomplete"
    UNAVAILABLE = "unavailable"
    ERROR = "error"

    @property
    def falsified(self) -> bool:
        """Whether a counterexample exists and repair has something to act on."""
        return self is FalsificationStatus.FAILED


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"low": 0, "medium": 1, "high": 2, "critical": 3}[self.value]


class Confidence(str, Enum):
    """How much searching stands behind a ``SURVIVED``.

    Never a probability that the code is correct. It answers a narrower question:
    how hard did we look, and how much of what we tried actually ran?
    """

    NONE = "none"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"


class EquivalenceLayer(str, Enum):
    """Which layer judged a mutant equivalent, so the judgement can be reviewed."""

    STATIC = "static"
    BEHAVIORAL = "behavioral"
    ASSISTED = "assisted"
    #: Nothing could decide. The mutant stays unclassified rather than assumed safe.
    UNDETERMINED = "undetermined"


class ReductionStatus(str, Enum):
    """What the counterexample reducer managed to do."""

    REDUCED = "reduced"
    IRREDUCIBLE = "irreducible"
    UNAVAILABLE = "unavailable"
    BUDGET_EXHAUSTED = "budget_exhausted"
    ERROR = "error"


class MutationScope(str, Enum):
    """How much of the tree mutation is allowed to touch.

    ``DIFF`` is the default and is a scope boundary, not only a cost control:
    falsification is an evidence system for a *change*, so a pre-existing defect in
    untouched code will not be found, and the report says so.
    """

    DIFF = "diff"
    FILES = "files"
    MODULE = "module"


# --------------------------------------------------------------------------- budget


class Budget(BaseModel):
    """Bounds on a falsification run. Every one of them is enforced, not advisory."""

    model_config = ConfigDict(extra="forbid")

    max_duration_s: int = 600
    #: 50 rather than 100: mutation cost is mutants x suite duration, and a
    #: 60-second suite against 100 mutants is 100 minutes.
    max_mutants: int = 50
    max_property_examples: int = 1000
    max_adversarial_tests: int = 20
    #: Calls, which is a different number from produced tests: one call can yield
    #: several tests or none, so capping only outputs bounds nothing.
    max_agent_invocations: int = 5
    max_differential_cases: int = 200
    max_metamorphic_cases: int = 200
    max_reduction_steps: int = 50
    max_retries: int = 2
    #: Unenforceable, and reported so, against a runtime that reports no tokens.
    max_tokens: int | None = None
    max_parallel_jobs: int = 4
    #: Baseline test repetitions used to quarantine flaky tests before mutation.
    #: 0 disables screening and puts the resulting uncertainty in the report.
    flakiness_probes: int = 2
    #: Per-strategy fractions of ``max_duration_s``. Unlisted strategies share what
    #: remains. Stops one slow agent call spending a budget four strategies needed.
    strategy_share: dict[str, float] = Field(
        default_factory=lambda: {StrategyName.ADVERSARIAL.value: 0.4}
    )

    @model_validator(mode="after")
    def _check(self) -> Budget:
        positive = (
            "max_duration_s",
            "max_mutants",
            "max_property_examples",
            "max_adversarial_tests",
            "max_agent_invocations",
            "max_differential_cases",
            "max_metamorphic_cases",
            "max_reduction_steps",
            "max_parallel_jobs",
        )
        for field in positive:
            if getattr(self, field) < 1:
                raise ValueError(f"budget.{field} must be >= 1")
        if self.max_retries < 0:
            raise ValueError("budget.max_retries must be >= 0")
        if self.flakiness_probes < 0:
            raise ValueError("budget.flakiness_probes must be >= 0")
        if self.max_tokens is not None and self.max_tokens < 1:
            raise ValueError("budget.max_tokens must be >= 1 when set")
        for name, share in self.strategy_share.items():
            if name not in {s.value for s in StrategyName}:
                raise ValueError(f"budget.strategy_share names unknown strategy '{name}'")
            if not 0 < share <= 1:
                raise ValueError(f"budget.strategy_share['{name}'] must be in (0, 1]")
        return self

    def share_for(self, strategy: StrategyName, remaining: int) -> float:
        """Seconds this strategy may spend, from its declared share or what is left."""
        share = self.strategy_share.get(strategy.value)
        if share is None:
            return float(max(0, remaining))
        return min(float(max(0, remaining)), self.max_duration_s * share)


class BudgetUsage(BaseModel):
    """What a run actually spent.

    A number produced under an exhausted budget means something different from the
    same number produced with budget to spare, and a report that cannot tell them
    apart overstates its own coverage.
    """

    model_config = ConfigDict(extra="forbid")

    duration_ms: int = 0
    mutants_generated: int = 0
    property_examples: int = 0
    adversarial_tests: int = 0
    agent_invocations: int = 0
    differential_cases: int = 0
    metamorphic_cases: int = 0
    reduction_steps: int = 0
    #: ``None`` means the runtime reported nothing, not that nothing was spent.
    tokens: int | None = None
    #: Which limits stopped the search, by name. Empty means nothing was truncated.
    exhausted: list[str] = Field(default_factory=list)
    #: Limits that could not be measured, so could not be enforced.
    unenforceable: list[str] = Field(default_factory=list)

    @property
    def truncated(self) -> bool:
        return bool(self.exhausted)

    def merge(self, other: BudgetUsage) -> BudgetUsage:
        """Combine two usages. Used to roll strategy spend up into the run."""
        tokens: int | None
        if self.tokens is None and other.tokens is None:
            tokens = None
        else:
            tokens = (self.tokens or 0) + (other.tokens or 0)
        return BudgetUsage(
            duration_ms=max(self.duration_ms, other.duration_ms),
            mutants_generated=self.mutants_generated + other.mutants_generated,
            property_examples=self.property_examples + other.property_examples,
            adversarial_tests=self.adversarial_tests + other.adversarial_tests,
            agent_invocations=self.agent_invocations + other.agent_invocations,
            differential_cases=self.differential_cases + other.differential_cases,
            metamorphic_cases=self.metamorphic_cases + other.metamorphic_cases,
            reduction_steps=self.reduction_steps + other.reduction_steps,
            tokens=tokens,
            exhausted=sorted(set(self.exhausted) | set(other.exhausted)),
            unenforceable=sorted(set(self.unenforceable) | set(other.unenforceable)),
        )


# --------------------------------------------------------------------------- findings


class Reduction(BaseModel):
    """The result of trying to shrink a counterexample.

    A reducer that loses a counterexample is worse than no reducer, so the original
    is carried here whatever happens.
    """

    model_config = ConfigDict(extra="forbid")

    status: ReductionStatus = ReductionStatus.UNAVAILABLE
    original: str = ""
    minimized: str = ""
    steps: int = 0
    detail: str = ""

    @property
    def succeeded(self) -> bool:
        return self.status is ReductionStatus.REDUCED and bool(self.minimized)


class Counterexample(BaseModel):
    """One concrete demonstration that something is wrong.

    ``reproduction`` is an argv, never a shell string, for the same reason nothing
    else in DevForge accepts one: a counterexample is data, and data that reaches a
    shell is an injection surface. It is what a person runs to see the failure again.
    """

    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(default_factory=lambda: new_id("fx"))
    strategy: StrategyName
    #: What was under attack, from the target registry.
    target: str = "behavior"
    input: str = ""
    expected: str = ""
    actual: str = ""
    reproduction: list[str] = Field(default_factory=list)
    file: str = ""
    symbol: str = ""
    severity: Severity = Severity.MEDIUM
    #: Output, traceback or diff supporting the claim. Bounded by the caller.
    evidence: str = ""
    reduction: Reduction | None = None
    #: Detail a strategy needs to carry (relation name, mutant id, transformation).
    detail: dict[str, Any] = Field(default_factory=dict)
    discovered_at: datetime = Field(default_factory=utcnow)

    @property
    def minimal_input(self) -> str:
        """The smallest known form, falling back to the original."""
        if self.reduction and self.reduction.succeeded:
            return self.reduction.minimized
        return self.input

    def summary(self) -> str:
        if self.expected or self.actual:
            return f"expected {self.expected or '?'}, got {self.actual or '?'}"
        return self.minimal_input or "counterexample recorded"

    def describe(self) -> str:
        where = self.symbol or self.file or "unknown location"
        return (
            f"[{self.strategy.value}/{self.target}/{self.severity.value}] "
            f"{where}: {self.summary()}"
        )


class Mutant(BaseModel):
    """One realistic fault injected into the patch, and what the suite did about it."""

    model_config = ConfigDict(extra="forbid")

    mutant_id: str = Field(default_factory=lambda: new_id("mut"))
    file: str
    line: int
    operator: str
    original: str
    mutated: str
    target: str = "behavior"
    status: MutantStatus = MutantStatus.ERROR
    killed_by: str = ""
    #: Why it is classified the way it is. Required for the dismissive statuses.
    reason: str = ""
    equivalence_layer: EquivalenceLayer | None = None
    equivalence_confidence: Confidence = Confidence.NONE
    #: Tests the reliability probe quarantined that bear on this mutant's verdict.
    unreliable_tests: list[str] = Field(default_factory=list)
    duration_ms: int = 0

    @model_validator(mode="after")
    def _check(self) -> Mutant:
        dismissive = {MutantStatus.EQUIVALENT, MutantStatus.INVALID, MutantStatus.UNRELIABLE}
        if self.status in dismissive and not self.reason:
            raise ValueError(
                f"mutant {self.mutant_id}: '{self.status.value}' must record why. "
                "An unexplained dismissal is how a weak test hides."
            )
        if self.status is MutantStatus.EQUIVALENT and self.equivalence_layer is None:
            raise ValueError(
                f"mutant {self.mutant_id}: an equivalent mutant must name the layer "
                "that judged it equivalent"
            )
        if self.status is MutantStatus.UNRELIABLE and not self.unreliable_tests:
            raise ValueError(
                f"mutant {self.mutant_id}: an unreliable verdict must name the "
                "quarantined test(s) it depended on"
            )
        return self

    def describe(self) -> str:
        return (
            f"{self.file}:{self.line} [{self.operator}] "
            f"{self.original.strip()!r} -> {self.mutated.strip()!r} = {self.status.value}"
        )


class TestWeakness(BaseModel):
    """A surviving mutant, expressed as something a person can act on.

    This is the finding the mutation strategy exists to produce. A mutation score is
    a summary of these; it is not a substitute for them.
    """

    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(default_factory=lambda: new_id("tw"))
    mutant_id: str
    file: str
    line: int
    operator: str
    #: What the code does that nothing checks.
    unchecked_behavior: str
    relevant_tests: list[str] = Field(default_factory=list)
    #: A test the falsifier proposes. Never written into the permanent suite here -
    #: the workflow decides whether to accept it.
    proposed_test: str = ""
    reproduction: list[str] = Field(default_factory=list)
    severity: Severity = Severity.MEDIUM


class ReliabilityReport(BaseModel):
    """What the baseline probe learned about the test suite before any mutation.

    Screening is skippable; the resulting uncertainty is not. When ``probes`` is 0
    this report still exists and still says so, and every survival in the run
    inherits the stated limitation.
    """

    model_config = ConfigDict(extra="forbid")

    probes: int = 0
    tests_observed: int = 0
    #: Tests whose outcome was not identical across probes.
    quarantined: list[str] = Field(default_factory=list)
    #: Set when the probe itself could not run (no test command, budget, error).
    unavailable_reason: str = ""

    @property
    def screened(self) -> bool:
        return self.probes >= 2 and not self.unavailable_reason

    def limitation(self) -> str:
        if self.screened:
            if not self.quarantined:
                return ""
            return (
                f"{len(self.quarantined)} test(s) were quarantined as unreliable; "
                "mutants depending on them were excluded from the mutation score"
            )
        reason = self.unavailable_reason or "screening was disabled (flakiness_probes: 0)"
        return (
            f"test reliability was not screened ({reason}); a surviving mutant may "
            "indicate a flaky test rather than a weak one"
        )


# --------------------------------------------------------------------------- coverage


class TargetCoverage(BaseModel):
    """How much of one target's attack surface was actually attacked.

    Coverage measures explored attack surface. It never implies correctness, and a
    target with no strategy attacking it reports 0 rather than being omitted - a
    visible gap is worth more than a silent one.
    """

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
        """Attacked over applicable strategies, or ``None`` when none apply."""
        return len(self.attacked_by) / self.applicable if self.applicable else None

    def format(self) -> str:
        return "n/a" if self.fraction is None else f"{self.fraction:.0%}"


class AttackSurfaceCoverage(BaseModel):
    """Per-target coverage across a run: a summary of what was looked at."""

    model_config = ConfigDict(extra="forbid")

    targets: list[TargetCoverage] = Field(default_factory=list)

    def get(self, target: str) -> TargetCoverage | None:
        return next((entry for entry in self.targets if entry.target == target), None)

    @property
    def attacked(self) -> list[TargetCoverage]:
        return [entry for entry in self.targets if entry.attacked_by]

    def render(self) -> list[str]:
        width = max((len(entry.target) for entry in self.targets), default=0)
        return [f"{entry.target.ljust(width)}  {entry.format()}" for entry in self.targets]


class StrategyCoverage(BaseModel):
    """Which strategies ran, and which were asked for but could not."""

    model_config = ConfigDict(extra="forbid")

    requested: list[str] = Field(default_factory=list)
    executed: list[str] = Field(default_factory=list)
    unavailable: dict[str, str] = Field(default_factory=dict)

    @property
    def fraction(self) -> float | None:
        return len(self.executed) / len(self.requested) if self.requested else None


# --------------------------------------------------------------------------- reports


class StrategyReport(BaseModel):
    """What one strategy found, and what it could not look at."""

    model_config = ConfigDict(extra="forbid")

    strategy: StrategyName
    status: StrategyStatus = StrategyStatus.UNAVAILABLE
    attempts: int = 0
    duration_ms: int = 0
    summary: str = ""
    targets: list[str] = Field(default_factory=list)

    mutants: list[Mutant] = Field(default_factory=list)
    counterexamples: list[Counterexample] = Field(default_factory=list)
    weaknesses: list[TestWeakness] = Field(default_factory=list)

    properties_tested: int = 0
    property_violations: int = 0
    adversarial_tests: int = 0
    differential_cases: int = 0
    metamorphic_cases: int = 0

    usage: BudgetUsage = Field(default_factory=BudgetUsage)
    #: What this strategy did not or could not search. Never empty for a survival.
    limitations: list[str] = Field(default_factory=list)

    # -- mutation arithmetic ----------------------------------------------------

    @property
    def mutants_total(self) -> int:
        return len(self.mutants)

    def _count(self, status: MutantStatus) -> int:
        return sum(1 for mutant in self.mutants if mutant.status is status)

    @property
    def mutants_killed(self) -> int:
        return self._count(MutantStatus.KILLED)

    @property
    def mutants_survived(self) -> int:
        return self._count(MutantStatus.SURVIVED)

    @property
    def mutants_equivalent(self) -> int:
        return self._count(MutantStatus.EQUIVALENT)

    @property
    def mutants_unreliable(self) -> int:
        return self._count(MutantStatus.UNRELIABLE)

    @property
    def mutants_invalid(self) -> int:
        return self._count(MutantStatus.INVALID)

    @property
    def mutants_errored(self) -> int:
        return self._count(MutantStatus.ERROR)

    @property
    def valid_mutants(self) -> int:
        """The denominator: valid, non-equivalent, reliably-judged mutants only."""
        return sum(1 for mutant in self.mutants if mutant.status.counts_toward_score)

    @property
    def mutation_score(self) -> float | None:
        """Killed over valid non-equivalent mutants, or ``None`` when there are none.

        ``None`` rather than ``1.0``: a score over zero mutants is not a perfect
        score, it is the absence of a measurement, and printing 100% there would be
        the most misleading number this subsystem could produce.
        """
        denominator = self.valid_mutants
        return self.mutants_killed / denominator if denominator else None

    def score_sentence(self) -> str:
        """The mutation score as a claim that states what it measures."""
        if self.mutation_score is None:
            return "no valid non-equivalent mutants were generated, so there is no score"
        return (
            f"{self.mutation_score:.0%} of {self.valid_mutants} valid generated mutants "
            "were detected by the test suite"
        )


class FalsificationReport(BaseModel):
    """The persisted record of one falsification run."""

    model_config = ConfigDict(extra="forbid")

    run_id: str = Field(default_factory=lambda: new_id("fals"))
    task_id: str = ""
    step_id: str = ""
    commit: str = ""
    #: A digest and a file list, never the patch itself: a diff can carry secrets
    #: and is already on disk.
    diff_digest: str = ""
    diff_files: list[str] = Field(default_factory=list)
    targets: list[str] = Field(default_factory=list)
    scope: MutationScope = MutationScope.DIFF

    strategies: list[StrategyReport] = Field(default_factory=list)
    status: FalsificationStatus = FalsificationStatus.UNAVAILABLE
    confidence: Confidence = Confidence.NONE

    coverage: AttackSurfaceCoverage = Field(default_factory=AttackSurfaceCoverage)
    strategy_coverage: StrategyCoverage = Field(default_factory=StrategyCoverage)
    reliability: ReliabilityReport = Field(default_factory=ReliabilityReport)

    budget: Budget = Field(default_factory=Budget)
    usage: BudgetUsage = Field(default_factory=BudgetUsage)

    #: How the run was isolated. Never claimed stronger than it was.
    isolation: str = "none"
    limitations: list[str] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=utcnow)
    finished_at: datetime | None = None
    duration_ms: int = 0

    # -- aggregates -------------------------------------------------------------

    @property
    def counterexamples(self) -> list[Counterexample]:
        found = [c for report in self.strategies for c in report.counterexamples]
        return sorted(found, key=lambda c: c.severity.rank, reverse=True)

    @property
    def weaknesses(self) -> list[TestWeakness]:
        return [w for report in self.strategies for w in report.weaknesses]

    @property
    def mutants(self) -> list[Mutant]:
        return [m for report in self.strategies for m in report.mutants]

    @property
    def mutants_total(self) -> int:
        return len(self.mutants)

    @property
    def mutants_killed(self) -> int:
        return sum(r.mutants_killed for r in self.strategies)

    @property
    def mutants_survived(self) -> int:
        return sum(r.mutants_survived for r in self.strategies)

    @property
    def mutants_equivalent(self) -> int:
        return sum(r.mutants_equivalent for r in self.strategies)

    @property
    def mutants_unreliable(self) -> int:
        return sum(r.mutants_unreliable for r in self.strategies)

    @property
    def valid_mutants(self) -> int:
        return sum(r.valid_mutants for r in self.strategies)

    @property
    def mutation_score(self) -> float | None:
        return self.mutants_killed / self.valid_mutants if self.valid_mutants else None

    @property
    def properties_tested(self) -> int:
        return sum(r.properties_tested for r in self.strategies)

    @property
    def property_violations(self) -> int:
        return sum(r.property_violations for r in self.strategies)

    @property
    def adversarial_tests(self) -> int:
        return sum(r.adversarial_tests for r in self.strategies)

    @property
    def differential_mismatches(self) -> int:
        return sum(1 for c in self.counterexamples if c.strategy is StrategyName.DIFFERENTIAL)

    @property
    def metamorphic_violations(self) -> int:
        return sum(1 for c in self.counterexamples if c.strategy is StrategyName.METAMORPHIC)

    def strategy(self, name: StrategyName | str) -> StrategyReport | None:
        wanted = StrategyName(name) if isinstance(name, str) else name
        return next((r for r in self.strategies if r.strategy is wanted), None)

    def finding(self, finding_id: str) -> Counterexample | TestWeakness | None:
        for example in self.counterexamples:
            if example.finding_id == finding_id:
                return example
        return next((w for w in self.weaknesses if w.finding_id == finding_id), None)

    # -- verdict ----------------------------------------------------------------

    def derive_status(self) -> FalsificationStatus:
        """The verdict, derived from the strategies rather than asserted.

        The order is the point. Any counterexample fails the run, whatever else
        survived. A strategy that errored or was truncated never averages away into
        a survival - that collapse is the failure mode this whole subsystem exists
        to prevent.
        """
        if not self.strategies:
            return FalsificationStatus.UNAVAILABLE
        statuses = {report.status for report in self.strategies}
        if StrategyStatus.FAILED in statuses:
            return FalsificationStatus.FAILED
        if StrategyStatus.ERROR in statuses:
            return FalsificationStatus.INCOMPLETE
        if StrategyStatus.INCOMPLETE in statuses or self.usage.truncated:
            return FalsificationStatus.INCOMPLETE
        if statuses == {StrategyStatus.UNAVAILABLE}:
            return FalsificationStatus.UNAVAILABLE
        return FalsificationStatus.SURVIVED

    def derive_confidence(self) -> Confidence:
        """How much searching stands behind the verdict.

        A failed run has no confidence in the implementation: a counterexample
        exists. Otherwise confidence rises with the number of strategies that ran to
        completion, and is capped when the budget was exhausted, when mutants
        survived, or when the suite's reliability was never screened.
        """
        if self.derive_status() is FalsificationStatus.FAILED:
            return Confidence.NONE
        completed = [
            r
            for r in self.strategies
            if r.status in {StrategyStatus.SURVIVED, StrategyStatus.FAILED}
        ]
        if not completed:
            return Confidence.NONE
        capped = self.usage.truncated or self.mutants_survived or not self.reliability.screened
        if capped:
            return Confidence.LOW
        if len(completed) >= 3:
            return Confidence.HIGH
        if len(completed) == 2:
            return Confidence.MODERATE
        return Confidence.LOW

    def settle(self) -> FalsificationReport:
        """Fill in the derived fields and the limitations. Called once, at the end."""
        self.status = self.derive_status()
        self.confidence = self.derive_confidence()
        self.finished_at = self.finished_at or utcnow()
        for report in self.strategies:
            if report.status is StrategyStatus.SURVIVED and not report.limitations:
                report.limitations = [
                    f"{report.strategy.value}: searched only the configured space"
                ]
        self._settle_limitations()
        return self

    def _settle_limitations(self) -> None:
        """Every limitation the run is obliged to state, whether or not it was set.

        A report with no limitations recorded gets one written for it. There is no
        configuration in which this subsystem reports a clean survival with nothing
        qualifying it.
        """
        stated = list(self.limitations)

        reliability = self.reliability.limitation()
        if reliability:
            stated.append(reliability)

        if self.scope is MutationScope.DIFF:
            stated.append(
                "only code the patch touched was attacked; a pre-existing defect in "
                "unchanged code would not be found"
            )
        if self.usage.truncated:
            stated.append(
                f"the search was truncated by {', '.join(self.usage.exhausted)}; "
                "the space beyond those limits was not explored"
            )
        for limit in self.usage.unenforceable:
            stated.append(f"'{limit}' could not be measured in this run, so it was not enforced")
        unattacked = [entry.target for entry in self.coverage.targets if not entry.attacked_by]
        if unattacked:
            stated.append(
                f"no strategy attacked: {', '.join(sorted(unattacked))} - "
                "0% coverage is not the same claim as absence of defects"
            )
        if self.isolation == "copy":
            stated.append(
                "the sandbox was a filtered copy without version-control history; "
                "strategies needing history were limited accordingly"
            )
        if self.status is FalsificationStatus.SURVIVED:
            stated.append(
                "no counterexample was found within the configured search space; "
                "that is not evidence of correctness"
            )

        # Deduplicate while preserving the order they were stated in.
        self.limitations = list(dict.fromkeys(stated))

    # -- rendering --------------------------------------------------------------

    def headline(self) -> str:
        score = (
            f"{self.mutation_score:.0%} of {self.valid_mutants} valid generated mutants "
            "were detected by the test suite"
            if self.mutation_score is not None
            else "no mutation score (no valid non-equivalent mutants)"
        )
        return f"{self.status.value.upper()}; confidence {self.confidence.value}; {score}"

    def render(self) -> str:
        """The human-readable report. Every number arrives with its basis."""
        lines = ["FALSIFICATION REPORT", ""]
        lines.append(f"run:        {self.run_id}")
        if self.task_id:
            lines.append(f"task:       {self.task_id}")
        if self.commit:
            lines.append(f"commit:     {self.commit}")
        lines.append(f"isolation:  {self.isolation}")
        lines.append(f"scope:      {self.scope.value}")
        lines.append(f"targets:    {', '.join(self.targets) or '(none)'}")
        lines.append("")

        for report in self.strategies:
            lines.append(f"{report.strategy.value.title()}:")
            lines.append(f"  status: {report.status.value}")
            if report.mutants:
                lines.append(f"  {report.valid_mutants} valid mutants")
                lines.append(f"  {report.mutants_killed} killed")
                lines.append(f"  {report.mutants_survived} survived")
                lines.append(f"  {report.mutants_equivalent} equivalent")
                if report.mutants_unreliable:
                    lines.append(f"  {report.mutants_unreliable} unreliable (flaky tests)")
                if report.mutants_invalid or report.mutants_errored:
                    lines.append(
                        f"  {report.mutants_invalid} invalid, {report.mutants_errored} errored"
                    )
                lines.append(f"  {report.score_sentence()}")
            if report.properties_tested:
                lines.append(f"  {report.properties_tested} properties")
                lines.append(f"  {report.property_violations} violations")
            if report.adversarial_tests:
                lines.append(f"  {report.adversarial_tests} adversarial tests")
            if report.differential_cases:
                lines.append(f"  {report.differential_cases} differential cases")
            if report.metamorphic_cases:
                lines.append(f"  {report.metamorphic_cases} metamorphic cases")
            if report.counterexamples:
                lines.append(f"  {len(report.counterexamples)} counterexample(s)")
            if report.summary:
                lines.append(f"  {report.summary}")
            lines.append("")

        if self.coverage.targets:
            lines.append("Attack surface coverage:")
            lines.extend(f"  {line}" for line in self.coverage.render())
            lines.append("  (coverage measures explored attack surface, never correctness)")
            lines.append("")

        lines.append("Status:")
        lines.append(f"  {self.status.value.upper()}")
        lines.append("")
        lines.append("Confidence:")
        lines.append(f"  {self.confidence.value.upper()}")
        lines.append("")

        if self.counterexamples:
            lines.append("Counterexamples:")
            for example in self.counterexamples:
                lines.append(f"  - {example.finding_id} {example.describe()}")
            lines.append("")

        if self.weaknesses:
            lines.append("Test weaknesses:")
            for weakness in self.weaknesses:
                lines.append(
                    f"  - {weakness.finding_id} {weakness.file}:{weakness.line} "
                    f"{weakness.unchecked_behavior}"
                )
            lines.append("")

        lines.append("Limitations:")
        for limitation in self.limitations:
            lines.append(f"  - {limitation}")
        for report in self.strategies:
            for limitation in report.limitations:
                lines.append(f"  - {limitation}")
        lines.append("")
        lines.append(
            "Surviving falsification does not mean the implementation is correct. "
            "It means no counterexample was found within the configured search space."
        )
        return "\n".join(lines)
