"""Differential testing: does the new implementation still agree with the old one?

The strategy for refactors, rewrites, migrations and optimisations, where the
specification is *whatever the previous version did*. Both versions run against
identical inputs and the outputs are compared::

    input ──┬── old ──> A
            └── new ──> B     A != B  ->  DIFFERENTIAL_MISMATCH

**Not every difference is a defect**, and treating them as such is what makes naive
differential testing useless on real systems. Timestamps differ. Generated
identifiers differ. Dictionary ordering differs. Floating-point arithmetic differs in
the last place. So equivalence is configurable, and every rule that fires is recorded
on the comparison - a suppressed difference is reported as suppressed, never silently
dropped, because a rule that is quietly hiding a real regression is worse than no
rule at all.

Configuration::

    falsify:
      differential:
        command: [python, scripts/run.py]
        baseline_ref: HEAD~1
        cases: [ {args: ["--input", "a.json"]}, ... ]
        equivalence:
          float_tolerance: 1e-9
          ignore_ordering: true
          ignore_timestamps: true
          ignore_generated_ids: true
          ignore_fields: [request_id, duration_ms]
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from devforge.falsification.models import (
    Counterexample,
    Severity,
    StrategyName,
    StrategyReport,
    StrategyStatus,
)
from devforge.falsification.strategies.base import (
    Availability,
    FalsificationContext,
    FalsificationStrategy,
)
from devforge.tools.process import run_process

#: Shapes that differ between two identical runs for reasons that are never defects.
TIMESTAMP_PATTERN = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
)
UUID_PATTERN = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
HEX_ID_PATTERN = re.compile(r"\b[0-9a-f]{16,}\b")


@dataclass
class EquivalenceRules:
    """What counts as "the same output" for this comparison."""

    float_tolerance: float = 0.0
    ignore_ordering: bool = False
    ignore_timestamps: bool = False
    ignore_generated_ids: bool = False
    ignore_fields: list[str] = field(default_factory=list)

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> EquivalenceRules:
        return cls(
            float_tolerance=float(config.get("float_tolerance", 0.0)),
            ignore_ordering=bool(config.get("ignore_ordering", False)),
            ignore_timestamps=bool(config.get("ignore_timestamps", False)),
            ignore_generated_ids=bool(config.get("ignore_generated_ids", False)),
            ignore_fields=[str(name) for name in config.get("ignore_fields", [])],
        )

    def describe(self) -> str:
        active = []
        if self.float_tolerance:
            active.append(f"float tolerance {self.float_tolerance}")
        if self.ignore_ordering:
            active.append("ordering ignored")
        if self.ignore_timestamps:
            active.append("timestamps ignored")
        if self.ignore_generated_ids:
            active.append("generated ids ignored")
        if self.ignore_fields:
            active.append(f"fields ignored: {', '.join(self.ignore_fields)}")
        return "; ".join(active) or "exact comparison"


@dataclass
class Comparison:
    """The result of comparing one pair of outputs."""

    equivalent: bool
    detail: str = ""
    #: Rules that fired to make two different outputs count as equivalent.
    suppressed_by: list[str] = field(default_factory=list)


class DifferentialStrategy(FalsificationStrategy):
    """Run two implementations against the same inputs and compare."""

    name = StrategyName.DIFFERENTIAL

    def available(self, ctx: FalsificationContext) -> Availability:
        options = ctx.options(StrategyName.DIFFERENTIAL)
        if not options.get("command"):
            return Availability(
                False,
                "no differential command is configured; this strategy needs to know "
                "how to execute both versions",
            )
        if not options.get("cases"):
            return Availability(False, "no differential cases are configured")
        if not options.get("baseline_dir") and not options.get("baseline_ref"):
            return Availability(
                False,
                "no baseline is configured; a differential run needs an old "
                "implementation to compare against",
            )
        if options.get("baseline_ref") and ctx.config.get("isolation") == "copy":
            return Availability(
                False,
                "a baseline ref needs version-control history, which the copy "
                "sandbox does not carry; configure baseline_dir instead",
            )
        return Availability(True)

    async def attack(self, ctx: FalsificationContext) -> StrategyReport:
        availability = self.available(ctx)
        if not availability.available:
            return self.unavailable(availability.detail)

        options = ctx.options(StrategyName.DIFFERENTIAL)
        rules = EquivalenceRules.from_config(options.get("equivalence", {}))
        command = [str(part) for part in options["command"]]
        cases = [case for case in options["cases"] if isinstance(case, dict)]

        baseline = await self._prepare_baseline(ctx, options)
        if baseline is None:
            return self.unavailable(
                "the baseline implementation could not be prepared for comparison"
            )

        decision = ctx.policy.check_command(command)
        if not decision.allowed:
            return self.unavailable(
                f"the differential command is refused by policy: {decision.reason}"
            )

        counterexamples: list[Counterexample] = []
        suppressed = 0
        executed = 0

        for case in cases:
            if not ctx.ledger.allows("differential_cases", "max_differential_cases"):
                break
            ctx.ledger.spend("differential_cases")
            executed += 1

            args = [str(part) for part in case.get("args", [])]
            old = await self._execute(ctx, command + args, baseline)
            new = await self._execute(ctx, command + args, ctx.workspace)

            comparison = compare_outputs(old, new, rules)
            if comparison.equivalent:
                if comparison.suppressed_by:
                    suppressed += 1
                continue

            ctx.logger.warn(
                "differential.mismatch",
                case=case.get("id", f"case_{executed}"),
                detail=comparison.detail,
            )
            counterexamples.append(
                Counterexample(
                    strategy=self.name,
                    target=str(case.get("target", "regression")),
                    input=" ".join(args) or "(no arguments)",
                    expected=self.excerpt(old, 800),
                    actual=self.excerpt(new, 800),
                    reproduction=command + args,
                    file=str(case.get("file", "")),
                    symbol=str(case.get("symbol", "")),
                    severity=Severity(str(case.get("severity", "high"))),
                    evidence=comparison.detail,
                    reduction=self.reduce(ctx, args) if args else None,
                    detail={"case": str(case.get("id", f"case_{executed}"))},
                )
            )

        usage = ctx.ledger.snapshot()
        limitations = [
            f"differential: compared {executed} configured case(s) under "
            f"[{rules.describe()}]; behaviour outside those inputs was not compared"
        ]
        if suppressed:
            limitations.append(
                f"differential: {suppressed} difference(s) were suppressed by the "
                "configured equivalence rules and were not reported as mismatches"
            )
        if usage.truncated:
            limitations.append(
                f"differential: stopped by {', '.join(usage.exhausted)} after "
                f"{executed} of {len(cases)} case(s)"
            )

        status = StrategyStatus.FAILED if counterexamples else StrategyStatus.SURVIVED
        if not counterexamples and usage.truncated:
            status = StrategyStatus.INCOMPLETE

        return self.report(
            status=status,
            attempts=executed,
            duration_ms=usage.duration_ms,
            targets=["regression"],
            counterexamples=counterexamples,
            differential_cases=executed,
            usage=usage,
            limitations=limitations,
            summary=f"{executed} case(s), {len(counterexamples)} mismatch(es)",
        )

    # -- execution --------------------------------------------------------------

    async def _prepare_baseline(self, ctx: FalsificationContext, options: dict) -> Any:
        """Where the old implementation lives.

        ``baseline_dir`` is a directory that already holds it. ``baseline_ref`` needs
        git history, which only the worktree sandbox carries - the availability check
        has already refused the combination that cannot work.
        """
        from pathlib import Path

        directory = options.get("baseline_dir")
        if directory:
            path = Path(directory)
            if not path.is_absolute():
                path = ctx.workspace / path
            return path if path.is_dir() else None

        ref = str(options.get("baseline_ref", ""))
        target = ctx.scratch / "baseline"
        argv = ["git", "worktree", "add", "--detach", str(target), ref]
        decision = ctx.policy.check_command(argv)
        if not decision.allowed:
            ctx.logger.info("differential.baseline_denied", reason=decision.reason)
            return None
        result = await run_process(
            argv,
            cwd=ctx.workspace,
            timeout_s=120,
            allow_env=ctx.policy.permissions.process.allow_env,
        )
        return target if result.exit_code == 0 and target.is_dir() else None

    async def _execute(self, ctx: FalsificationContext, argv: list[str], cwd: Any) -> str:
        """Run one case and return everything that distinguishes the two builds.

        The exit status is part of the observable behaviour and is prepended rather
        than discarded. Comparing stdout alone called two builds equivalent whenever
        they printed the same thing and disagreed only about whether they succeeded -
        including the case where both merely failed to start, which compared equal
        because both produced no output at all.
        """
        result = await run_process(
            argv,
            cwd=cwd,
            timeout_s=ctx.test_timeout_s,
            allow_env=ctx.policy.permissions.process.allow_env,
            max_output_chars=ctx.policy.permissions.process.max_output_chars,
        )
        if not result.started:
            return f"[devforge: did not start: {result.error or 'unknown'}]"
        status = "timed out" if result.timed_out else f"exit {result.exit_code}"
        return f"[devforge: {status}]\n" + result.combined


# --------------------------------------------------------------------------- comparison


def compare_outputs(old: str, new: str, rules: EquivalenceRules) -> Comparison:
    """Compare two outputs under the configured equivalence rules.

    Exact equality short-circuits. Otherwise the rules are applied in order and the
    ones that fired are recorded, so a suppressed difference stays visible in the
    report as something that was suppressed rather than something that did not exist.
    """
    if old == new:
        return Comparison(equivalent=True)

    fired: list[str] = []
    left, right = old, new

    if rules.ignore_timestamps:
        normalised_left = TIMESTAMP_PATTERN.sub("<TIMESTAMP>", left)
        normalised_right = TIMESTAMP_PATTERN.sub("<TIMESTAMP>", right)
        if (normalised_left, normalised_right) != (left, right):
            fired.append("ignore_timestamps")
        left, right = normalised_left, normalised_right

    if rules.ignore_generated_ids:
        for pattern, label in ((UUID_PATTERN, "<UUID>"), (HEX_ID_PATTERN, "<ID>")):
            normalised_left = pattern.sub(label, left)
            normalised_right = pattern.sub(label, right)
            if (normalised_left, normalised_right) != (left, right):
                fired.append("ignore_generated_ids")
            left, right = normalised_left, normalised_right

    if left == right:
        return Comparison(equivalent=True, suppressed_by=sorted(set(fired)))

    structured = _compare_structured(left, right, rules)
    if structured is not None:
        if structured.equivalent:
            return Comparison(
                equivalent=True,
                suppressed_by=sorted(set(fired + structured.suppressed_by)),
            )
        return Comparison(equivalent=False, detail=structured.detail, suppressed_by=fired)

    return Comparison(equivalent=False, detail=_text_difference(left, right), suppressed_by=fired)


def _compare_structured(left: str, right: str, rules: EquivalenceRules) -> Comparison | None:
    """Compare as JSON when both sides parse; ``None`` when they do not."""
    try:
        old_value = json.loads(left)
        new_value = json.loads(right)
    except (json.JSONDecodeError, ValueError):
        return None

    fired: list[str] = []
    equivalent = _values_equal(old_value, new_value, rules, fired, path="$")
    if equivalent:
        return Comparison(equivalent=True, suppressed_by=sorted(set(fired)))
    return Comparison(
        equivalent=False,
        detail=_first_difference(old_value, new_value, rules, path="$"),
        suppressed_by=sorted(set(fired)),
    )


def _values_equal(old: Any, new: Any, rules: EquivalenceRules, fired: list[str], path: str) -> bool:
    if isinstance(old, dict) and isinstance(new, dict):
        keys = (set(old) | set(new)) - set(rules.ignore_fields)
        if set(rules.ignore_fields) & (set(old) | set(new)):
            fired.append("ignore_fields")
        return all(
            _values_equal(old.get(key), new.get(key), rules, fired, f"{path}.{key}")
            for key in keys
        )

    if isinstance(old, list) and isinstance(new, list):
        if len(old) != len(new):
            return False
        if rules.ignore_ordering:
            remaining = list(new)
            for item in old:
                match = next(
                    (
                        candidate
                        for candidate in remaining
                        if _values_equal(item, candidate, rules, [], path)
                    ),
                    None,
                )
                if match is None:
                    return False
                remaining.remove(match)
            if old != new:
                fired.append("ignore_ordering")
            return True
        return all(
            _values_equal(a, b, rules, fired, f"{path}[{i}]")
            for i, (a, b) in enumerate(zip(old, new, strict=False))
        )

    if isinstance(old, float | int) and isinstance(new, float | int):
        if isinstance(old, bool) or isinstance(new, bool):
            return old == new
        if old == new:
            return True
        if rules.float_tolerance and abs(float(old) - float(new)) <= rules.float_tolerance:
            fired.append("float_tolerance")
            return True
        return False

    return old == new


def _first_difference(old: Any, new: Any, rules: EquivalenceRules, path: str) -> str:
    """A path to the first real disagreement, so a person can find it."""
    if isinstance(old, dict) and isinstance(new, dict):
        for key in sorted((set(old) | set(new)) - set(rules.ignore_fields)):
            if not _values_equal(old.get(key), new.get(key), rules, [], path):
                return _first_difference(old.get(key), new.get(key), rules, f"{path}.{key}")
    if isinstance(old, list) and isinstance(new, list):
        if len(old) != len(new):
            return f"{path}: length {len(old)} became {len(new)}"
        for index, (a, b) in enumerate(zip(old, new, strict=False)):
            if not _values_equal(a, b, rules, [], path):
                return _first_difference(a, b, rules, f"{path}[{index}]")
    return f"{path}: {old!r} became {new!r}"


def _text_difference(old: str, new: str) -> str:
    old_lines, new_lines = old.splitlines(), new.splitlines()
    for index, (a, b) in enumerate(zip(old_lines, new_lines, strict=False), start=1):
        if a != b:
            return f"line {index}: {a!r} became {b!r}"
    if len(old_lines) != len(new_lines):
        return f"output length differs: {len(old_lines)} line(s) became {len(new_lines)}"
    return "outputs differ"
