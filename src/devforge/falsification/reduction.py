"""Shrinking a counterexample to the smallest form that still fails.

A counterexample of 200 elements and one of 2 prove the same thing, and only one of
them can be read. Minimisation is therefore not a nicety; it is what turns a
falsification finding into something a person can act on in the time they have.

This is a subsystem rather than a detail inside each strategy because property,
adversarial, differential and future fuzzing counterexamples all need the same
algorithm - delta debugging over a reproduction the strategy knows how to re-run -
and four copies of it would drift into four different behaviours.

**The reducer never loses a counterexample.** Every failure mode returns the
original: an unshrinkable input, an exhausted budget, a predicate that raises. A
reducer that discards evidence because it could not simplify it is worse than no
reducer, so :class:`~devforge.falsification.models.Reduction` always carries the
original text and states what happened.
"""

from __future__ import annotations

import json
from collections.abc import Callable

from devforge.falsification.models import Reduction, ReductionStatus

#: A predicate returns True when the candidate still reproduces the failure.
Predicate = Callable[[object], bool]


def reduce_sequence(
    value: list | tuple | str,
    still_fails: Predicate,
    *,
    max_steps: int = 50,
) -> tuple[object, ReductionStatus, int]:
    """Delta-debug a sequence down to a minimal still-failing subsequence.

    Classic ddmin: halve, then quarter, then finer, removing chunks that are not
    needed to reproduce. Bounded by ``max_steps`` because each step re-runs the
    predicate, which is usually the expensive part.
    """
    steps = 0
    current: list = list(value)
    granularity = 2

    while len(current) >= 2:
        if steps >= max_steps:
            return _restore(value, current), ReductionStatus.BUDGET_EXHAUSTED, steps

        chunk = max(1, len(current) // granularity)
        reduced = False

        for start in range(0, len(current), chunk):
            if steps >= max_steps:
                return _restore(value, current), ReductionStatus.BUDGET_EXHAUSTED, steps
            candidate = current[:start] + current[start + chunk :]
            if not candidate:
                continue
            steps += 1
            try:
                if still_fails(_restore(value, candidate)):
                    current = candidate
                    granularity = max(granularity - 1, 2)
                    reduced = True
                    break
            except Exception:
                # A predicate that raises tells us nothing about this candidate.
                # Keep the larger input rather than shrinking on a broken signal.
                continue

        if not reduced:
            if granularity >= len(current):
                break
            granularity = min(granularity * 2, len(current))

    status = (
        ReductionStatus.REDUCED if len(current) < len(value) else ReductionStatus.IRREDUCIBLE
    )
    return _restore(value, current), status, steps


def reduce_number(
    value: int | float,
    still_fails: Predicate,
    *,
    max_steps: int = 50,
) -> tuple[object, ReductionStatus, int]:
    """Walk a number toward zero, keeping the smallest value that still fails.

    Binary search toward zero rather than decrementing: a counterexample at 10^9
    would otherwise never finish shrinking.
    """
    steps = 0
    best = value
    low: float = 0
    high: float = abs(value)
    sign = -1 if value < 0 else 1

    while steps < max_steps and high - low > (1 if isinstance(value, int) else 1e-9):
        middle = low + (high - low) / 2
        candidate: int | float = int(middle) if isinstance(value, int) else middle
        candidate *= sign
        steps += 1
        try:
            if still_fails(candidate):
                best = candidate
                high = abs(candidate)
            else:
                low = abs(candidate)
        except Exception:
            break

    status = ReductionStatus.REDUCED if abs(best) < abs(value) else ReductionStatus.IRREDUCIBLE
    return best, status, steps


def reduce_value(
    value: object,
    still_fails: Predicate,
    *,
    max_steps: int = 50,
) -> Reduction:
    """Shrink whatever kind of counterexample this is, or say why it could not.

    The dispatch is intentionally narrow. An unrecognised type returns
    ``UNAVAILABLE`` with the original preserved, which is honest; trying to be clever
    about arbitrary objects is how a reducer starts producing candidates that fail
    for a different reason than the original did.
    """
    original = _render(value)

    try:
        if isinstance(value, list | tuple | str):
            if len(value) < 2:
                return Reduction(
                    status=ReductionStatus.IRREDUCIBLE,
                    original=original,
                    minimized=original,
                    detail="the counterexample is already minimal",
                )
            minimized, status, steps = reduce_sequence(value, still_fails, max_steps=max_steps)
        elif isinstance(value, bool):
            return Reduction(
                status=ReductionStatus.IRREDUCIBLE,
                original=original,
                minimized=original,
                detail="a boolean has no smaller form",
            )
        elif isinstance(value, int | float):
            minimized, status, steps = reduce_number(value, still_fails, max_steps=max_steps)
        elif isinstance(value, dict):
            minimized, status, steps = _reduce_mapping(value, still_fails, max_steps)
        else:
            return Reduction(
                status=ReductionStatus.UNAVAILABLE,
                original=original,
                minimized=original,
                detail=f"no reduction strategy for {type(value).__name__}",
            )
    except Exception as exc:  # never lose the counterexample to a reducer bug
        return Reduction(
            status=ReductionStatus.ERROR,
            original=original,
            minimized=original,
            detail=f"reduction failed ({type(exc).__name__}); the original is preserved",
        )

    return Reduction(
        status=status,
        original=original,
        minimized=_render(minimized),
        steps=steps,
        detail=_detail_for(status, steps),
    )


def _reduce_mapping(
    value: dict, still_fails: Predicate, max_steps: int
) -> tuple[object, ReductionStatus, int]:
    """Drop keys that are not needed to reproduce the failure."""
    steps = 0
    current = dict(value)
    for key in list(current):
        if steps >= max_steps:
            return current, ReductionStatus.BUDGET_EXHAUSTED, steps
        candidate = {k: v for k, v in current.items() if k != key}
        steps += 1
        try:
            if still_fails(candidate):
                current = candidate
        except Exception:
            continue
    status = ReductionStatus.REDUCED if len(current) < len(value) else ReductionStatus.IRREDUCIBLE
    return current, status, steps


def _restore(original: object, items: list) -> object:
    """Rebuild the reduced sequence in the shape it started as."""
    if isinstance(original, str):
        return "".join(items)
    if isinstance(original, tuple):
        return tuple(items)
    return list(items)


def _render(value: object) -> str:
    try:
        return json.dumps(value, default=str)
    except (TypeError, ValueError):
        return repr(value)


def _detail_for(status: ReductionStatus, steps: int) -> str:
    if status is ReductionStatus.REDUCED:
        return f"minimised in {steps} step(s)"
    if status is ReductionStatus.BUDGET_EXHAUSTED:
        return (
            f"the reduction budget ran out after {steps} step(s); the smallest form "
            "found so far is reported and the original is preserved"
        )
    if status is ReductionStatus.IRREDUCIBLE:
        return f"no smaller failing form was found in {steps} step(s)"
    return ""
