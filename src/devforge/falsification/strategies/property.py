"""Property-based testing: generate inputs and look for a violated invariant.

Where mutation asks *do the tests notice a fault?*, this asks *does the code hold a
stated property across inputs nobody thought to write down?* The two find different
things, which is why both exist.

Properties come from the workflow, not from guesswork::

    falsify:
      property:
        properties:
          - id: non-negative-total
            module: billing
            call: total
            args: [ints]
            invariant: result >= 0

Inferring invariants from source is deliberately not attempted. A guessed invariant
that does not hold produces a counterexample against a property the author never
claimed, and a report full of those is one nobody reads.

**Hypothesis is optional.** It cannot be a runtime dependency - the dependency list
is pinned by an architecture test - so when it is absent this strategy reports
``UNAVAILABLE`` with the reason and the run records the gap. It never silently
degrades to a weaker search and calls the result a survival.

Generated tests are written into the sandbox scratch directory and executed there.
Nothing is written to the project's permanent test suite.
"""

from __future__ import annotations

import importlib.util
import json
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
from devforge.falsification.testrun import run_tests

#: The generated file's name inside the scratch directory. One file for all
#: properties in a run, so a single pytest invocation covers them.
GENERATED_TEST = "test_falsification_properties.py"

#: Strategy expressions by name, so a workflow names a shape rather than writing
#: code. A workflow file is data; letting it supply a Hypothesis expression would
#: make it executable, which is the same reasoning that keeps `eval` out of
#: conditions.
ARGUMENT_STRATEGIES = {
    "ints": "st.integers()",
    "small_ints": "st.integers(min_value=-1000, max_value=1000)",
    "floats": "st.floats(allow_nan=False, allow_infinity=False)",
    "any_floats": "st.floats()",
    "text": "st.text()",
    "ascii_text": "st.text(alphabet=st.characters(min_codepoint=32, max_codepoint=126))",
    "lists_of_ints": "st.lists(st.integers())",
    "lists_of_text": "st.lists(st.text())",
    "booleans": "st.booleans()",
    "dicts": "st.dictionaries(st.text(), st.integers())",
}


class PropertyStrategy(FalsificationStrategy):
    """Search an input space for a violation of a declared invariant."""

    name = StrategyName.PROPERTY

    def available(self, ctx: FalsificationContext) -> Availability:
        if importlib.util.find_spec("hypothesis") is None:
            return Availability(
                False,
                "hypothesis is not installed; install the 'falsification' extra to "
                "enable property-based search",
            )
        if not self._properties(ctx):
            return Availability(
                False,
                "no properties were declared for this step; invariants are declared, "
                "never inferred",
            )
        return Availability(True)

    async def attack(self, ctx: FalsificationContext) -> StrategyReport:
        availability = self.available(ctx)
        if not availability.available:
            return self.unavailable(availability.detail)

        properties = self._properties(ctx)
        scheduled: list[dict[str, Any]] = []
        for spec in properties:
            if not ctx.ledger.allows("property_examples", "max_property_examples"):
                break
            ctx.ledger.spend("property_examples", self._examples(ctx, spec))
            scheduled.append(spec)

        if not scheduled:
            return self.report(
                status=StrategyStatus.INCOMPLETE,
                summary="the budget was exhausted before any property could run",
                usage=ctx.ledger.snapshot(),
                limitations=["property: no property was executed within the budget"],
            )

        try:
            source = self._render_module(ctx, scheduled)
            path = ctx.scratch / GENERATED_TEST
            path.write_text(source, encoding="utf-8")
        except OSError as exc:
            return self.report(
                status=StrategyStatus.ERROR,
                summary=f"the generated property module could not be written: {exc}",
                limitations=[f"property: {exc}"],
            )

        ctx.logger.info("property.started", properties=len(scheduled), file=str(path.name))

        outcome = await run_tests(
            ctx.test_command,
            workspace=ctx.workspace,
            policy=ctx.policy,
            timeout_s=ctx.test_timeout_s,
            extra_args=[str(path.relative_to(ctx.workspace).as_posix())],
        )

        usage = ctx.ledger.snapshot()
        if not outcome.ran:
            return self.report(
                status=StrategyStatus.ERROR,
                summary=f"the property module could not be executed: {outcome.error}",
                properties_tested=0,
                usage=usage,
                limitations=[f"property: {outcome.error}"],
            )

        counterexamples = self._counterexamples(ctx, outcome.output, scheduled)
        for example in counterexamples:
            ctx.logger.warn(
                "property.counterexample",
                property=example.detail.get("property"),
                input=example.minimal_input,
                severity=example.severity.value,
            )

        status = StrategyStatus.FAILED if counterexamples else StrategyStatus.SURVIVED
        if not counterexamples and usage.truncated:
            status = StrategyStatus.INCOMPLETE

        limitations = [
            f"property: only the {len(scheduled)} declared propert(ies) were checked, "
            "over generated inputs of the declared shapes"
        ]
        if usage.truncated:
            limitations.append(
                f"property: stopped by {', '.join(usage.exhausted)}; "
                f"{len(properties) - len(scheduled)} propert(ies) were not run"
            )

        return self.report(
            status=status,
            attempts=len(scheduled),
            duration_ms=outcome.duration_ms,
            targets=sorted({str(spec.get("target", "behavior")) for spec in scheduled}),
            counterexamples=counterexamples,
            properties_tested=len(scheduled),
            property_violations=len(counterexamples),
            usage=usage,
            limitations=limitations,
            summary=(
                f"{len(scheduled)} propert(ies), {len(counterexamples)} violation(s)"
            ),
        )

    # -- configuration ----------------------------------------------------------

    @staticmethod
    def _properties(ctx: FalsificationContext) -> list[dict[str, Any]]:
        declared = ctx.options(StrategyName.PROPERTY).get("properties")
        if not isinstance(declared, list):
            return []
        return [spec for spec in declared if isinstance(spec, dict) and spec.get("invariant")]

    @staticmethod
    def _examples(ctx: FalsificationContext, spec: dict[str, Any]) -> int:
        requested = int(spec.get("examples", 100))
        return max(1, min(requested, ctx.ledger.budget.max_property_examples))

    # -- code generation --------------------------------------------------------

    def _render_module(self, ctx: FalsificationContext, specs: list[dict[str, Any]]) -> str:
        """Build the property module. Every value interpolated is validated first."""
        lines = [
            '"""Generated by DevForge falsification. Temporary; not part of the suite."""',
            "",
            "import json",
            "import sys",
            "from pathlib import Path",
            "",
            "import pytest",
            "from hypothesis import given, settings, HealthCheck",
            "from hypothesis import strategies as st",
            "",
            "sys.path.insert(0, str(Path(__file__).resolve().parents[1]))",
            "",
        ]

        for index, spec in enumerate(specs):
            lines.extend(self._render_property(ctx, spec, index))

        return "\n".join(lines) + "\n"

    def _render_property(
        self, ctx: FalsificationContext, spec: dict[str, Any], index: int
    ) -> list[str]:
        module = self._identifier(spec.get("module", ""), "module")
        call = self._identifier(spec.get("call", ""), "call")
        invariant = str(spec.get("invariant", "")).strip()
        examples = self._examples(ctx, spec)
        property_id = str(spec.get("id", f"property_{index}"))

        arguments = [str(name) for name in spec.get("args", [])]
        unknown = [name for name in arguments if name not in ARGUMENT_STRATEGIES]
        if unknown:
            raise ValueError(
                f"property '{property_id}': unknown argument shape(s) {unknown}; "
                f"known shapes: {', '.join(sorted(ARGUMENT_STRATEGIES))}"
            )

        parameters = ", ".join(f"a{i}" for i in range(len(arguments)))
        strategies = ", ".join(ARGUMENT_STRATEGIES[name] for name in arguments)
        marker = f"DEVFORGE_PROPERTY::{property_id}"

        return [
            f"@given({strategies})" if strategies else "@given(st.none())",
            f"@settings(max_examples={examples}, deadline=None, "
            "suppress_health_check=[HealthCheck.too_slow])",
            f"def test_{self._slug(property_id)}({parameters or '_unused'}):",
            f"    import {module} as target",
            f"    args = [{parameters}]" if parameters else "    args = []",
            f"    result = target.{call}(*args)",
            "    try:",
            f"        holds = bool({invariant})",
            "    except Exception as exc:",
            f"        print({marker!r} + json.dumps("
            "{'input': repr(args), 'error': repr(exc)}))",
            "        raise",
            "    if not holds:",
            f"        print({marker!r} + json.dumps("
            "{'input': repr(args), 'result': repr(result)}))",
            f"    assert holds, {property_id!r} + ' violated: ' + repr(args)",
            "",
        ]

    @staticmethod
    def _identifier(value: str, field: str) -> str:
        """Refuse anything that is not a plain dotted identifier.

        The generated file is source code, and a workflow file is data that may have
        come from anywhere. Interpolating an unvalidated string here would let a
        workflow write arbitrary Python into a file DevForge then executes.
        """
        text = str(value).strip()
        if not text:
            raise ValueError(f"property: '{field}' is required")
        parts = text.split(".")
        if not all(part.isidentifier() for part in parts):
            raise ValueError(
                f"property: '{field}' must be a dotted identifier, got {text!r}"
            )
        return text

    @staticmethod
    def _slug(text: str) -> str:
        return "".join(char if char.isalnum() else "_" for char in text).strip("_") or "property"

    # -- results ----------------------------------------------------------------

    def _counterexamples(
        self, ctx: FalsificationContext, output: str, specs: list[dict[str, Any]]
    ) -> list[Counterexample]:
        """Read violations back out of the test output.

        Hypothesis has already shrunk what it reports; the reducer runs anyway over
        the recorded input, because a shrink Hypothesis could not perform on a
        composite value is often still available to delta debugging.
        """
        found: list[Counterexample] = []
        by_id = {str(spec.get("id", f"property_{i}")): spec for i, spec in enumerate(specs)}

        for line in (output or "").splitlines():
            marker = "DEVFORGE_PROPERTY::"
            if marker not in line:
                continue
            _, _, rest = line.partition(marker)
            property_id, _, payload = rest.partition("{")
            property_id = property_id.strip()
            try:
                detail = json.loads("{" + payload)
            except json.JSONDecodeError:
                detail = {"input": rest}

            spec = by_id.get(property_id, {})
            raw_input = str(detail.get("input", ""))
            reduction = self.reduce(ctx, raw_input)

            example = Counterexample(
                strategy=self.name,
                target=str(spec.get("target", "behavior")),
                input=raw_input,
                expected=str(spec.get("invariant", "the declared invariant holds")),
                actual=str(detail.get("result", detail.get("error", "invariant did not hold"))),
                reproduction=[*ctx.test_command, f"{ctx.scratch.name}/{GENERATED_TEST}"],
                file=str(spec.get("module", "")),
                symbol=str(spec.get("call", "")),
                severity=Severity(str(spec.get("severity", "high"))),
                evidence=self.excerpt(output),
                reduction=reduction,
                detail={"property": property_id},
            )
            if all(existing.input != example.input for existing in found):
                found.append(example)

        return found
