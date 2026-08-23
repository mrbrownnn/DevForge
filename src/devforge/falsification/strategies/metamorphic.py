"""Metamorphic testing: relationships between executions, when there is no oracle.

Often nobody can say what the right answer *is*, but everybody can say how two
answers must relate. A sort of a shuffled list must equal a sort of the original. A
search over a larger corpus must return at least as many hits. Adding an element must
leave it findable::

    f(x) == f(shuffle(x))
    len(f(x + [e])) >= len(f(x))
    e in f(x + [e])

That relation is the oracle, and it holds without anyone writing down an expected
value. This is the strategy for code whose correct output is expensive or impossible
to state directly.

Relations are declared, never inferred, for the same reason properties are: a guessed
relation that does not actually hold produces counterexamples against a claim the
author never made.

Configuration::

    falsify:
      metamorphic:
        relations:
          - id: order-insensitive
            module: search
            call: rank
            input: [3, 1, 2]
            transformation: shuffle
            relation: equal
"""

from __future__ import annotations

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

GENERATED_TEST = "test_falsification_metamorphic.py"

#: How an input is transformed before the second execution. Each is a named shape
#: rather than an expression, so a workflow file stays data.
TRANSFORMATIONS = {
    "shuffle": "list(reversed(list(value)))",
    "reverse": "list(reversed(list(value)))",
    "duplicate": "list(value) + list(value)",
    "append": "list(value) + [_appended]",
    "negate": "[-item for item in value]",
    "scale": "[item * 2 for item in value]",
    "identity": "list(value)",
}

#: The relation that must hold between the two results.
RELATIONS = {
    "equal": ("original == transformed", "the two results are equal"),
    "not_equal": ("original != transformed", "the two results differ"),
    "same_length": ("len(original) == len(transformed)", "both results are the same length"),
    "subset": (
        "set(map(repr, original)) <= set(map(repr, transformed))",
        "the original result is contained in the transformed one",
    ),
    "monotonic": (
        "len(transformed) >= len(original)",
        "the transformed result is no smaller than the original",
    ),
    "contains_appended": (
        "_appended in transformed",
        "the appended element appears in the transformed result",
    ),
}


class MetamorphicStrategy(FalsificationStrategy):
    """Check declared relations between an execution and a transformed execution."""

    name = StrategyName.METAMORPHIC

    def available(self, ctx: FalsificationContext) -> Availability:
        relations = self._relations(ctx)
        if not relations:
            return Availability(
                False,
                "no metamorphic relations were declared for this step; relations are "
                "declared, never inferred",
            )
        if not ctx.test_command:
            return Availability(False, "no test command is configured to execute relations")
        return Availability(True)

    async def attack(self, ctx: FalsificationContext) -> StrategyReport:
        availability = self.available(ctx)
        if not availability.available:
            return self.unavailable(availability.detail)

        relations = self._relations(ctx)
        scheduled: list[dict[str, Any]] = []
        for relation in relations:
            if not ctx.ledger.allows("metamorphic_cases", "max_metamorphic_cases"):
                break
            ctx.ledger.spend("metamorphic_cases")
            scheduled.append(relation)

        if not scheduled:
            return self.report(
                status=StrategyStatus.INCOMPLETE,
                summary="the budget was exhausted before any relation could be checked",
                usage=ctx.ledger.snapshot(),
                limitations=["metamorphic: no relation was executed within the budget"],
            )

        try:
            path = ctx.scratch / GENERATED_TEST
            path.write_text(self._render(scheduled), encoding="utf-8")
        except (OSError, ValueError) as exc:
            return self.report(
                status=StrategyStatus.ERROR,
                summary=f"the relation module could not be generated: {exc}",
                limitations=[f"metamorphic: {exc}"],
            )

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
                summary=f"the relation module could not be executed: {outcome.error}",
                usage=usage,
                limitations=[f"metamorphic: {outcome.error}"],
            )

        counterexamples = self._counterexamples(ctx, outcome.output, scheduled)
        for example in counterexamples:
            ctx.logger.warn(
                "metamorphic.violation",
                relation=example.detail.get("relation"),
                expected=example.expected,
                actual=example.actual,
            )

        status = StrategyStatus.FAILED if counterexamples else StrategyStatus.SURVIVED
        if not counterexamples and usage.truncated:
            status = StrategyStatus.INCOMPLETE

        limitations = [
            f"metamorphic: only the {len(scheduled)} declared relation(s) were "
            "checked, over the declared inputs"
        ]
        if usage.truncated:
            limitations.append(f"metamorphic: stopped by {', '.join(usage.exhausted)}")

        return self.report(
            status=status,
            attempts=len(scheduled),
            duration_ms=outcome.duration_ms,
            targets=sorted({str(r.get("target", "behavior")) for r in scheduled}),
            counterexamples=counterexamples,
            metamorphic_cases=len(scheduled),
            usage=usage,
            limitations=limitations,
            summary=f"{len(scheduled)} relation(s), {len(counterexamples)} violation(s)",
        )

    # -- configuration ----------------------------------------------------------

    @staticmethod
    def _relations(ctx: FalsificationContext) -> list[dict[str, Any]]:
        declared = ctx.options(StrategyName.METAMORPHIC).get("relations")
        if not isinstance(declared, list):
            return []
        return [item for item in declared if isinstance(item, dict) and item.get("relation")]

    # -- code generation --------------------------------------------------------

    def _render(self, relations: list[dict[str, Any]]) -> str:
        lines = [
            '"""Generated by DevForge falsification. Temporary; not part of the suite."""',
            "",
            "import json",
            "import sys",
            "from pathlib import Path",
            "",
            "sys.path.insert(0, str(Path(__file__).resolve().parents[1]))",
            "",
        ]
        for index, relation in enumerate(relations):
            lines.extend(self._render_relation(relation, index))
        return "\n".join(lines) + "\n"

    def _render_relation(self, spec: dict[str, Any], index: int) -> list[str]:
        module = self._identifier(spec.get("module", ""), "module")
        call = self._identifier(spec.get("call", ""), "call")
        relation_id = str(spec.get("id", f"relation_{index}"))

        transformation = str(spec.get("transformation", "identity"))
        if transformation not in TRANSFORMATIONS:
            raise ValueError(
                f"relation '{relation_id}': unknown transformation {transformation!r}; "
                f"known: {', '.join(sorted(TRANSFORMATIONS))}"
            )
        relation = str(spec.get("relation"))
        if relation not in RELATIONS:
            raise ValueError(
                f"relation '{relation_id}': unknown relation {relation!r}; "
                f"known: {', '.join(sorted(RELATIONS))}"
            )

        expression, description = RELATIONS[relation]
        value = json.dumps(spec.get("input", []))
        appended = json.dumps(spec.get("append", 0))
        marker = f"DEVFORGE_METAMORPHIC::{relation_id}"

        return [
            f"def test_{self._slug(relation_id)}():",
            f"    import {module} as target",
            f"    value = {value}",
            f"    _appended = {appended}",
            f"    original = target.{call}(value)",
            f"    transformed_input = {TRANSFORMATIONS[transformation]}",
            f"    transformed = target.{call}(transformed_input)",
            "    try:",
            f"        holds = bool({expression})",
            "    except Exception as exc:",
            "        holds = False",
            "        transformed = repr(exc)",
            "    if not holds:",
            f"        print({marker!r} + json.dumps({{",
            f"            'transformation': {transformation!r},",
            "            'original_input': value,",
            "            'transformed_input': transformed_input,",
            "            'original_result': repr(original),",
            "            'transformed_result': repr(transformed),",
            f"            'expected_relation': {description!r},",
            "        }))",
            f"    assert holds, {relation_id!r} + ': ' + {description!r}",
            "",
        ]

    @staticmethod
    def _identifier(value: str, field: str) -> str:
        """Refuse anything that is not a plain dotted identifier.

        The generated file is executed, and a workflow file is data that may have
        come from anywhere. See the identical reasoning in the property strategy.
        """
        text = str(value).strip()
        if not text:
            raise ValueError(f"metamorphic: '{field}' is required")
        if not all(part.isidentifier() for part in text.split(".")):
            raise ValueError(f"metamorphic: '{field}' must be a dotted identifier, got {text!r}")
        return text

    @staticmethod
    def _slug(text: str) -> str:
        return "".join(c if c.isalnum() else "_" for c in text).strip("_") or "relation"

    # -- results ----------------------------------------------------------------

    def _counterexamples(
        self, ctx: FalsificationContext, output: str, specs: list[dict[str, Any]]
    ) -> list[Counterexample]:
        by_id = {str(s.get("id", f"relation_{i}")): s for i, s in enumerate(specs)}
        found: list[Counterexample] = []

        for line in (output or "").splitlines():
            marker = "DEVFORGE_METAMORPHIC::"
            if marker not in line:
                continue
            _, _, rest = line.partition(marker)
            relation_id, _, payload = rest.partition("{")
            relation_id = relation_id.strip()
            try:
                detail = json.loads("{" + payload)
            except json.JSONDecodeError:
                continue

            spec = by_id.get(relation_id, {})
            found.append(
                Counterexample(
                    strategy=self.name,
                    target=str(spec.get("target", "behavior")),
                    input=json.dumps(detail.get("original_input")),
                    expected=str(detail.get("expected_relation", "the declared relation holds")),
                    actual=(
                        f"f(original)={detail.get('original_result')} vs "
                        f"f({detail.get('transformation')}(original))="
                        f"{detail.get('transformed_result')}"
                    ),
                    reproduction=[*ctx.test_command, f"{ctx.scratch.name}/{GENERATED_TEST}"],
                    file=str(spec.get("module", "")),
                    symbol=str(spec.get("call", "")),
                    severity=Severity(str(spec.get("severity", "medium"))),
                    evidence=self.excerpt(output),
                    detail={
                        "relation": relation_id,
                        "transformation": str(detail.get("transformation", "")),
                        "transformed_input": json.dumps(detail.get("transformed_input")),
                    },
                )
            )
        return found
