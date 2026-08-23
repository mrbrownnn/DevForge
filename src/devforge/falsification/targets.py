"""What is under attack, as opposed to how it is attacked.

A strategy describes *how*: mutate the code, generate inputs, ask an adversarial
agent. A target describes *what*: the behaviour, the error paths, the authorisation
boundary. They compose - ``mutation x behavior`` and ``mutation x security`` are
different searches driven by the same machinery - and separating them is what makes
:class:`AttackSurfaceCoverage` mean anything. Without targets, "we ran four
strategies" is the only coverage statement available, and it says nothing about
which parts of the surface were looked at.

Ten targets are registered. Four ship attacked; six ship with no strategy attacking
them and report 0% coverage. That is deliberate. A declared target reporting zero is
a visible gap; an undeclared target is an invisible one, and only one of those can
be planned against. Adding a strategy for ``concurrency`` later means registering it
in the applicability matrix below - the engine does not change.

**Coverage never implies correctness.** A target at 100% means every strategy that
could attack it did. It does not mean the target is sound; it means nobody found a
counterexample there with the strategies available and the budget spent.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from devforge.falsification.models import StrategyName

#: The default target set for a step that names none. Deliberately the three a
#: patch is most likely to break, not everything - attacking ten targets by default
#: would spend a budget across surfaces most changes never touch.
DEFAULT_TARGETS: tuple[str, ...] = ("behavior", "boundary_conditions", "error_handling")


@dataclass(frozen=True)
class FalsificationTarget:
    """One surface a falsification run can attack."""

    name: str
    description: str
    #: Strategies capable of attacking this target. Empty means nothing ships that
    #: can, and the target reports 0% rather than being hidden.
    strategies: frozenset[StrategyName] = field(default_factory=frozenset)

    @property
    def attackable(self) -> bool:
        return bool(self.strategies)

    def accepts(self, strategy: StrategyName) -> bool:
        return strategy in self.strategies


#: The applicability matrix. Read a row as "this target can be attacked by these
#: strategies"; read a column as "this strategy is useful against these targets".
TARGETS: tuple[FalsificationTarget, ...] = (
    FalsificationTarget(
        name="behavior",
        description="What the code computes for ordinary inputs.",
        strategies=frozenset(
            {
                StrategyName.MUTATION,
                StrategyName.PROPERTY,
                StrategyName.ADVERSARIAL,
                StrategyName.DIFFERENTIAL,
                StrategyName.METAMORPHIC,
            }
        ),
    ),
    FalsificationTarget(
        name="boundary_conditions",
        description="Empty, zero, maximum, off-by-one and the edges of every range.",
        strategies=frozenset(
            {
                StrategyName.MUTATION,
                StrategyName.PROPERTY,
                StrategyName.ADVERSARIAL,
                StrategyName.METAMORPHIC,
            }
        ),
    ),
    FalsificationTarget(
        name="error_handling",
        description="What happens on the paths that are supposed to fail.",
        strategies=frozenset(
            {StrategyName.MUTATION, StrategyName.PROPERTY, StrategyName.ADVERSARIAL}
        ),
    ),
    FalsificationTarget(
        name="regression",
        description="Behaviour that used to hold and must still hold.",
        strategies=frozenset({StrategyName.DIFFERENTIAL, StrategyName.METAMORPHIC}),
    ),
    # -- declared, not yet attacked -------------------------------------------
    #
    # Each of these needs a strategy that does not ship yet. They are registered so
    # that a report says "security: 0%" instead of saying nothing at all.
    FalsificationTarget(
        name="security",
        description="Injection, unsafe deserialisation, secret handling. Needs a "
        "security-fuzzing strategy.",
    ),
    FalsificationTarget(
        name="authorization",
        description="Who may do what. Needs an authorisation-boundary strategy.",
    ),
    FalsificationTarget(
        name="input_validation",
        description="What the code accepts that it should refuse. Needs a fuzzing "
        "strategy.",
    ),
    FalsificationTarget(
        name="state_transitions",
        description="Legal and illegal moves through a state machine. Needs a "
        "model-based strategy.",
    ),
    FalsificationTarget(
        name="api_contract",
        description="Promises made to callers. Needs a contract-fuzzing strategy.",
    ),
    FalsificationTarget(
        name="concurrency",
        description="Interleavings and races. Needs a concurrency or race-detection "
        "strategy.",
    ),
)

_BY_NAME = {target.name: target for target in TARGETS}


def known_targets() -> list[str]:
    return [target.name for target in TARGETS]


def attackable_targets() -> list[str]:
    return [target.name for target in TARGETS if target.attackable]


def get(name: str) -> FalsificationTarget | None:
    return _BY_NAME.get(name)


def resolve(names: list[str] | None) -> list[str]:
    """Validate requested target names, defaulting when none were requested.

    Raises on an unknown name rather than ignoring it: a workflow that asks for
    ``authorisation`` (misspelled) and silently gets nothing has a security gap it
    believes is covered.
    """
    if not names:
        return list(DEFAULT_TARGETS)
    unknown = [name for name in names if name not in _BY_NAME]
    if unknown:
        raise ValueError(
            f"unknown falsification target(s) {sorted(unknown)}; "
            f"known targets: {', '.join(known_targets())}"
        )
    # Preserve the caller's order, drop duplicates.
    return list(dict.fromkeys(names))


def strategies_for(target_names: list[str]) -> set[StrategyName]:
    """Every strategy capable of attacking any of these targets."""
    selected: set[StrategyName] = set()
    for name in target_names:
        target = _BY_NAME.get(name)
        if target is not None:
            selected |= set(target.strategies)
    return selected


def targets_for(strategy: StrategyName, among: list[str]) -> list[str]:
    """The subset of ``among`` this strategy can actually attack."""
    return [name for name in among if (t := _BY_NAME.get(name)) is not None and t.accepts(strategy)]
