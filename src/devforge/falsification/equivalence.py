"""Deciding whether a surviving mutant is actually equivalent to the original.

A surviving mutant is not automatically a weak test. Some mutants cannot change
behaviour at all - ``x * 1`` becoming ``x // 1`` for integers, a constant that is
never read, a branch whose two arms are identical - and reporting those as test
weaknesses trains people to ignore the report, which is worse than not producing it.

Three layers, tried in order, each recording *which* layer decided and how sure it
was::

    static      cheap AST reasoning; high confidence when it fires at all
    behavioral  the mutated code produced identical observable output
    assisted    an opinion, gated behind an explicit opt-in, capped at LOW

**Uncertainty stays uncertain.** A mutant no layer can classify keeps its
``SURVIVED`` status. It is never quietly promoted to ``EQUIVALENT`` - that promotion
is exactly how a real weakness disappears from a report, and it is the single most
dangerous shortcut available in this subsystem.

The assisted layer is off by default. It is the only part of the design where a
model's opinion could downgrade a genuine finding, so it requires
``equivalence.assisted: true``, records ``EquivalenceLayer.ASSISTED`` on every
judgement it makes, and is hard-capped at :attr:`Confidence.LOW` however confident
the model sounds.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

from devforge.falsification.models import Confidence, EquivalenceLayer
from devforge.falsification.mutation_operators import (
    ARITHMETIC,
    BOUNDARY,
    COMPARISON,
    CONSTANT,
    MutationCandidate,
)


@dataclass(frozen=True)
class Judgement:
    """One layer's verdict on one mutant."""

    equivalent: bool
    layer: EquivalenceLayer
    confidence: Confidence
    reason: str

    @property
    def decided(self) -> bool:
        """Whether this is an answer, as opposed to a shrug."""
        return self.layer is not EquivalenceLayer.UNDETERMINED


UNDETERMINED = Judgement(
    equivalent=False,
    layer=EquivalenceLayer.UNDETERMINED,
    confidence=Confidence.NONE,
    reason="no layer could determine equivalence",
)


def classify(
    candidate: MutationCandidate,
    *,
    original_source: str,
    behavioral_output: tuple[str, str] | None = None,
    assisted: bool = False,
    assistant: object | None = None,
) -> Judgement:
    """Judge one surviving mutant. Returns :data:`UNDETERMINED` rather than guessing.

    ``behavioral_output`` is ``(original, mutated)`` observable output when the
    caller was able to capture both. Absent, the behavioural layer is skipped rather
    than assumed to agree.
    """
    static = judge_static(candidate, original_source)
    if static.decided:
        return static

    if behavioral_output is not None:
        behavioral = judge_behavioral(*behavioral_output)
        if behavioral.decided:
            return behavioral

    if assisted and assistant is not None:
        return judge_assisted(candidate, assistant)

    return UNDETERMINED


# --------------------------------------------------------------------------- static


def judge_static(candidate: MutationCandidate, original_source: str) -> Judgement:
    """AST-level reasoning about whether the mutation can change anything.

    Only fires on patterns that are provably inert. Everything else is left to a
    later layer, because a static analysis that guesses is worse than one that
    abstains.
    """
    if candidate.source == original_source:
        return Judgement(
            equivalent=True,
            layer=EquivalenceLayer.STATIC,
            confidence=Confidence.HIGH,
            reason="the mutation produced textually identical source",
        )

    try:
        original_tree = ast.parse(original_source)
        mutated_tree = ast.parse(candidate.source)
    except SyntaxError:
        return UNDETERMINED

    if ast.dump(original_tree) == ast.dump(mutated_tree):
        return Judgement(
            equivalent=True,
            layer=EquivalenceLayer.STATIC,
            confidence=Confidence.HIGH,
            reason="the mutated source parses to an identical syntax tree",
        )

    identity = _identity_arithmetic(candidate)
    if identity:
        return Judgement(
            equivalent=True,
            layer=EquivalenceLayer.STATIC,
            confidence=Confidence.MODERATE,
            reason=identity,
        )

    dead = _unreachable_mutation(candidate, mutated_tree)
    if dead:
        return Judgement(
            equivalent=True,
            layer=EquivalenceLayer.STATIC,
            confidence=Confidence.MODERATE,
            reason=dead,
        )

    return UNDETERMINED


def _identity_arithmetic(candidate: MutationCandidate) -> str:
    """Operator swaps that cannot change the value because an operand is an identity.

    ``x * 1`` and ``x // 1`` agree for every integer; ``x + 0`` and ``x - 0`` agree
    for every number. These are the textbook equivalent mutants, and they are worth
    detecting precisely because they are the ones that recur.
    """
    if candidate.operator not in {ARITHMETIC, COMPARISON, BOUNDARY}:
        return ""
    try:
        tree = ast.parse(candidate.source)
    except SyntaxError:
        return ""

    for node in ast.walk(tree):
        if not isinstance(node, ast.BinOp) or getattr(node, "lineno", None) != candidate.line:
            continue
        right = node.right
        if not isinstance(right, ast.Constant) or isinstance(right.value, bool):
            continue
        value = right.value
        if isinstance(value, int | float):
            multiplicative = {"*", "//", "/"}
            additive = {"+", "-"}
            if (
                value == 1
                and candidate.original in multiplicative
                and candidate.mutated in multiplicative
            ):
                return (
                    f"'{candidate.original}' and '{candidate.mutated}' by 1 agree for "
                    "every integer value at this site"
                )
            if value == 0 and candidate.original in additive and candidate.mutated in additive:
                return (
                    f"'{candidate.original}' and '{candidate.mutated}' by 0 agree for "
                    "every numeric value at this site"
                )
    return ""


def _unreachable_mutation(candidate: MutationCandidate, mutated_tree: ast.AST) -> str:
    """A mutation inside a body that cannot execute changes nothing observable."""
    for node in ast.walk(mutated_tree):
        if not isinstance(node, ast.If):
            continue
        test = node.test
        if not isinstance(test, ast.Constant) or test.value is not False:
            continue
        body_lines = {
            getattr(child, "lineno", -1) for child in ast.walk(node) if hasattr(child, "lineno")
        }
        if candidate.line in body_lines and candidate.line != test.lineno:
            return "the mutated statement is inside a branch that can never be taken"
    return ""


# --------------------------------------------------------------------------- behavioral


def judge_behavioral(original_output: str, mutated_output: str) -> Judgement:
    """Compare observable behaviour of the two versions.

    Identical output across the same executions is evidence of equivalence, but only
    over the inputs that were actually run - which is why this is ``MODERATE`` and
    never ``HIGH``. A mutant that agrees on every test the suite happens to contain
    may still differ on an input nobody tried, and claiming otherwise would be the
    same overreach this subsystem exists to avoid.
    """
    if original_output == mutated_output:
        return Judgement(
            equivalent=True,
            layer=EquivalenceLayer.BEHAVIORAL,
            confidence=Confidence.MODERATE,
            reason=(
                "the mutated code produced output identical to the original over "
                "every execution that was observed"
            ),
        )
    return Judgement(
        equivalent=False,
        layer=EquivalenceLayer.BEHAVIORAL,
        confidence=Confidence.MODERATE,
        reason="the mutated code produced different observable output",
    )


# --------------------------------------------------------------------------- assisted


def judge_assisted(candidate: MutationCandidate, assistant: object) -> Judgement:
    """An opinion from a model, deliberately the weakest layer available.

    Hard-capped at ``LOW`` confidence and always recorded as ``ASSISTED``, so a
    reviewer can find every judgement this layer made and disbelieve it. Any failure
    or unclear answer returns :data:`UNDETERMINED` rather than a guess: the whole
    risk of this layer is that it turns a real finding into a dismissed one.
    """
    ask = getattr(assistant, "judge_equivalence", None)
    if ask is None:
        return UNDETERMINED
    try:
        verdict = ask(candidate)
    except Exception:  # an unreliable assistant must not decide anything
        return UNDETERMINED

    if not isinstance(verdict, tuple) or len(verdict) != 2:
        return UNDETERMINED
    equivalent, reason = verdict
    if equivalent is not True:
        return UNDETERMINED

    return Judgement(
        equivalent=True,
        layer=EquivalenceLayer.ASSISTED,
        confidence=Confidence.LOW,
        reason=f"assisted judgement (low confidence, review this): {reason}",
    )


def describes_constant_noise(candidate: MutationCandidate) -> bool:
    """Whether a constant mutation targets something with no behavioural role.

    Used to mark a mutant INVALID rather than EQUIVALENT: a docstring change is not
    an equivalent implementation, it is not an implementation change at all.
    """
    return candidate.operator == CONSTANT and candidate.original.strip().startswith(('"""', "'''"))
