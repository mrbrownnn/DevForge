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
    """Operator swaps that provably cannot change the value at this exact site.

    Two things make this sound, and both were missing before.

    **It must be the mutated operator.** A line can hold several ``BinOp`` nodes.
    Matching on the line alone let ``price * qty + 1`` - mutated at the ``*`` - be
    dismissed because the *other* operator on the line happened to have ``1`` on its
    right. The mutated column now has to fall between the end of ``left`` and the
    start of ``right``, which identifies one operator token and no other.

    **The left operand must provably be an integer.** ``x * 1`` and ``x // 1`` agree
    for integers and for nothing else: ``2.5 * 1`` is ``2.5`` while ``2.5 // 1`` is
    ``2.0``, and ``"ab" // 1`` is a ``TypeError``. A literal ``1`` on the right says
    nothing about the type on the left, so the left is checked too, statically, and
    the rule abstains whenever the type cannot be established.

    ``/`` is not an identity under either rule. ``x / 1`` returns a float where
    ``x * 1`` returns an int, and ``(10**400) / 1`` raises ``OverflowError`` where
    ``x * 1`` does not.
    """
    if candidate.operator not in {ARITHMETIC, COMPARISON, BOUNDARY}:
        return ""
    if candidate.col < 0:
        return ""
    try:
        tree = ast.parse(candidate.source)
    except SyntaxError:
        return ""

    for node in ast.walk(tree):
        if not isinstance(node, ast.BinOp):
            continue
        if not _mutated_here(node, candidate):
            continue
        right = node.right
        if not isinstance(right, ast.Constant) or isinstance(right.value, bool):
            continue
        if type(right.value) is not int:
            # A float ``1.0`` compares equal to 1 but is not the same identity:
            # ``2.5 * 1.0`` and ``2.5 // 1.0`` differ.
            continue
        if not _definitely_int(node.left):
            continue
        value = right.value
        if value == 1 and {candidate.original, candidate.mutated} <= {"*", "//"}:
            return (
                f"'{candidate.original}' and '{candidate.mutated}' by 1 agree for "
                "every integer, and the left operand is statically an integer here"
            )
        if value == 0 and {candidate.original, candidate.mutated} <= {"+", "-"}:
            return (
                f"'{candidate.original}' and '{candidate.mutated}' by 0 agree for "
                "every integer, and the left operand is statically an integer here"
            )
    return ""


def _mutated_here(node: ast.BinOp, candidate: MutationCandidate) -> bool:
    """Whether ``node``'s operator token is the one the candidate rewrote.

    Operator nodes carry no column of their own, so the token is located by the gap
    between the operands. Anything spanning more than the mutated line is refused
    rather than guessed at.
    """
    left, right = node.left, node.right
    if getattr(left, "end_lineno", None) != candidate.line:
        return False
    if getattr(right, "lineno", None) != candidate.line:
        return False
    left_end = getattr(left, "end_col_offset", None)
    right_start = getattr(right, "col_offset", None)
    if left_end is None or right_start is None:
        return False
    return left_end <= candidate.col < right_start


#: Calls whose result is an ``int`` for every argument they accept.
_INT_CALLS = frozenset({"len", "ord", "int", "hash", "id"})

#: Binary operators that map two ints to an int. ``/`` gives a float and ``**`` can
#: (``2 ** -1``), so neither is here.
_INT_BINOPS = (ast.Add, ast.Sub, ast.Mult, ast.FloorDiv, ast.Mod)


def _definitely_int(node: ast.AST) -> bool:
    """Whether ``node`` evaluates to an ``int`` for every possible execution.

    Deliberately a small, conservative recogniser. It returns ``False`` for anything
    it cannot establish - including every plain name, because a parameter called
    ``count`` can still be handed a float - and the caller then abstains instead of
    claiming an equivalence it has not shown.
    """
    if isinstance(node, ast.Constant):
        return type(node.value) is int
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.UAdd | ast.USub):
        return _definitely_int(node.operand)
    if isinstance(node, ast.BinOp) and isinstance(node.op, _INT_BINOPS):
        return _definitely_int(node.left) and _definitely_int(node.right)
    if isinstance(node, ast.Call):
        func = node.func
        return isinstance(func, ast.Name) and func.id in _INT_CALLS and not node.keywords
    return False


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
