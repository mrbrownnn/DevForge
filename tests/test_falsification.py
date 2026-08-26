"""Falsification: the arithmetic, the status semantics, and the strategies.

The tests that matter most here are the ones asserting what a report is *not*
allowed to say. A mutation score over zero mutants must not be 100%. An unavailable
strategy must not read as a survival. A flaky verdict must not be counted. Each of
those is a one-line change away from being wrong in a way nobody would notice, which
is exactly why they are pinned.
"""

from __future__ import annotations

import ast
import subprocess
from pathlib import Path

import pytest

from devforge.falsification import mutation_operators as operators
from devforge.falsification import targets as target_registry
from devforge.falsification.corpus import record_corpus
from devforge.falsification.engine import FalsificationEngine
from devforge.falsification.equivalence import classify, judge_static
from devforge.falsification.models import (
    Budget,
    Confidence,
    Counterexample,
    EquivalenceLayer,
    FalsificationReport,
    FalsificationStatus,
    Mutant,
    MutantStatus,
    MutationScope,
    ReductionStatus,
    ReliabilityReport,
    StrategyName,
    StrategyReport,
    StrategyStatus,
)
from devforge.falsification.mutation_operators import MutationCandidate
from devforge.falsification.patch import parse_patch
from devforge.falsification.reduction import reduce_value
from devforge.falsification.regression import render_regression_test
from devforge.falsification.reliability import verdict_is_reliable
from devforge.falsification.sandbox import (
    Isolation,
    create_sandbox,
    scope_violations,
    snapshot_tree,
)
from devforge.falsification.store import resolve_report, save_report
from devforge.falsification.strategies.base import BudgetLedger
from devforge.falsification.strategies.differential import EquivalenceRules, compare_outputs
from devforge.policy.engine import PolicyEngine

WEAK_SOURCE = '''def price(amount, discount):
    if discount > 0.5:
        raise ValueError("discount too large")
    return amount * (1 - discount)
'''

WEAK_TEST = '''from billing import price


def test_happy_path():
    assert price(100, 0.0) == 100
'''

STRONG_TEST = '''import pytest

from billing import price


def test_happy_path():
    assert price(100, 0.0) == 100


def test_discount_applied():
    assert price(100, 0.25) == 75


def test_boundary_is_allowed():
    assert price(100, 0.5) == 50


def test_over_boundary_raises():
    with pytest.raises(ValueError):
        price(100, 0.51)
'''


def _mutant(status: MutantStatus, **fields) -> Mutant:
    defaults = {
        "file": "a.py",
        "line": 1,
        "operator": "arithmetic_replacement",
        "original": "+",
        "mutated": "-",
    }
    if status is MutantStatus.EQUIVALENT:
        defaults |= {"reason": "identity", "equivalence_layer": EquivalenceLayer.STATIC}
    if status is MutantStatus.INVALID:
        defaults |= {"reason": "does not compile"}
    if status is MutantStatus.UNRELIABLE:
        defaults |= {"reason": "flaky test", "unreliable_tests": ["tests/test_a.py::test_x"]}
    return Mutant(status=status, **(defaults | fields))


def _project(root: Path, *, test_source: str = WEAK_TEST) -> Path:
    (root / "billing.py").write_text(WEAK_SOURCE, encoding="utf-8")
    (root / "tests").mkdir(exist_ok=True)
    (root / "tests" / "test_billing.py").write_text(test_source, encoding="utf-8")
    (root / "pytest.ini").write_text("[pytest]\npythonpath = .\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init"],
        cwd=root,
        check=True,
    )
    return root


# --------------------------------------------------------------------- score arithmetic


def test_mutation_score_excludes_equivalent_invalid_and_unreliable() -> None:
    report = StrategyReport(
        strategy=StrategyName.MUTATION,
        mutants=[
            _mutant(MutantStatus.KILLED),
            _mutant(MutantStatus.KILLED),
            _mutant(MutantStatus.SURVIVED),
            _mutant(MutantStatus.EQUIVALENT),
            _mutant(MutantStatus.INVALID),
            _mutant(MutantStatus.UNRELIABLE),
            _mutant(MutantStatus.ERROR),
        ],
    )

    assert report.valid_mutants == 3
    assert report.mutation_score == pytest.approx(2 / 3)
    assert report.mutants_unreliable == 1


def test_a_score_over_zero_mutants_is_unknown_not_perfect() -> None:
    """The single most misleading number this subsystem could produce."""
    report = StrategyReport(strategy=StrategyName.MUTATION, mutants=[])

    assert report.mutation_score is None
    assert "no score" in report.score_sentence()
    assert "100%" not in report.score_sentence()


def test_the_score_sentence_states_what_it_measures() -> None:
    report = StrategyReport(
        strategy=StrategyName.MUTATION,
        mutants=[_mutant(MutantStatus.KILLED), _mutant(MutantStatus.SURVIVED)],
    )

    sentence = report.score_sentence()
    assert "detected by the test suite" in sentence
    assert "correct" not in sentence


def test_a_dismissive_classification_must_record_why() -> None:
    for status in (MutantStatus.EQUIVALENT, MutantStatus.INVALID, MutantStatus.UNRELIABLE):
        with pytest.raises(ValueError, match="must"):
            Mutant(
                file="a.py", line=1, operator="op", original="+", mutated="-", status=status
            )


def test_an_equivalent_mutant_must_name_the_layer_that_judged_it() -> None:
    with pytest.raises(ValueError, match="layer"):
        Mutant(
            file="a.py",
            line=1,
            operator="op",
            original="+",
            mutated="-",
            status=MutantStatus.EQUIVALENT,
            reason="looks the same",
        )


# --------------------------------------------------------------------- status semantics


@pytest.mark.parametrize(
    ("statuses", "expected"),
    [
        ([], FalsificationStatus.UNAVAILABLE),
        ([StrategyStatus.SURVIVED], FalsificationStatus.SURVIVED),
        ([StrategyStatus.FAILED], FalsificationStatus.FAILED),
        ([StrategyStatus.SURVIVED, StrategyStatus.FAILED], FalsificationStatus.FAILED),
        ([StrategyStatus.SURVIVED, StrategyStatus.ERROR], FalsificationStatus.INCOMPLETE),
        ([StrategyStatus.SURVIVED, StrategyStatus.INCOMPLETE], FalsificationStatus.INCOMPLETE),
        ([StrategyStatus.UNAVAILABLE], FalsificationStatus.UNAVAILABLE),
        ([StrategyStatus.UNAVAILABLE, StrategyStatus.SURVIVED], FalsificationStatus.SURVIVED),
    ],
)
def test_status_derivation(statuses, expected) -> None:
    report = FalsificationReport(
        strategies=[StrategyReport(strategy=StrategyName.MUTATION, status=s) for s in statuses]
    )

    assert report.derive_status() is expected


def test_unavailable_and_incomplete_never_collapse_into_survived() -> None:
    """The failure mode the whole subsystem exists to prevent."""
    for status in (StrategyStatus.UNAVAILABLE, StrategyStatus.INCOMPLETE, StrategyStatus.ERROR):
        report = FalsificationReport(
            strategies=[StrategyReport(strategy=StrategyName.MUTATION, status=status)]
        )
        assert report.derive_status() is not FalsificationStatus.SURVIVED


def test_there_is_no_success_state_anywhere() -> None:
    """SUCCESS invites being read as 'the code is correct'. There is no alias."""
    values = {status.value for status in FalsificationStatus}

    assert "success" not in values
    assert "survived" in values


def test_a_budget_exhausted_run_is_incomplete_not_survived() -> None:
    report = FalsificationReport(
        strategies=[
            StrategyReport(strategy=StrategyName.MUTATION, status=StrategyStatus.SURVIVED)
        ]
    )
    report.usage.exhausted.append("max_mutants")

    assert report.derive_status() is FalsificationStatus.INCOMPLETE


def test_a_falsified_run_has_no_confidence() -> None:
    report = FalsificationReport(
        strategies=[StrategyReport(strategy=StrategyName.MUTATION, status=StrategyStatus.FAILED)]
    )

    assert report.derive_confidence() is Confidence.NONE


def test_confidence_is_capped_when_reliability_was_never_screened() -> None:
    strategies = [
        StrategyReport(strategy=name, status=StrategyStatus.SURVIVED)
        for name in (StrategyName.MUTATION, StrategyName.PROPERTY, StrategyName.METAMORPHIC)
    ]
    unscreened = FalsificationReport(strategies=strategies)
    screened = FalsificationReport(
        strategies=strategies,
        reliability=ReliabilityReport(probes=2, tests_observed=3),
    )

    assert unscreened.derive_confidence() is Confidence.LOW
    assert screened.derive_confidence() is Confidence.HIGH


def test_every_report_states_its_limitations() -> None:
    """There is no configuration in which a report qualifies nothing."""
    empty = FalsificationReport().settle()
    survived = FalsificationReport(
        strategies=[
            StrategyReport(strategy=StrategyName.MUTATION, status=StrategyStatus.SURVIVED)
        ]
    ).settle()

    assert empty.limitations
    assert any("not evidence of correctness" in item for item in survived.limitations)


def test_diff_scope_is_declared_as_a_boundary() -> None:
    report = FalsificationReport(scope=MutationScope.DIFF).settle()

    assert any("unchanged code" in item for item in report.limitations)


def test_an_unenforceable_budget_is_reported_not_assumed_satisfied() -> None:
    report = FalsificationReport()
    report.usage.unenforceable.append("max_tokens")
    report.settle()

    assert any("not enforced" in item for item in report.limitations)


# --------------------------------------------------------------------- budget ledger


def test_the_ledger_names_the_limit_that_stopped_the_search() -> None:
    ledger = BudgetLedger(Budget(max_mutants=2))

    assert ledger.allows("mutants_generated", "max_mutants")
    ledger.spend("mutants_generated")
    ledger.spend("mutants_generated")

    assert not ledger.allows("mutants_generated", "max_mutants")
    assert "max_mutants" in ledger.usage.exhausted


def test_a_runtime_reporting_no_tokens_makes_the_token_budget_unenforceable() -> None:
    ledger = BudgetLedger(Budget(max_tokens=100))
    ledger.count_tokens(None)

    assert "max_tokens" in ledger.usage.unenforceable
    assert "max_tokens" not in ledger.usage.exhausted
    assert ledger.usage.tokens is None


def test_agent_invocations_are_capped_separately_from_produced_tests() -> None:
    """One call can yield several tests or none, so capping outputs bounds nothing."""
    ledger = BudgetLedger(Budget(max_agent_invocations=1, max_adversarial_tests=20))

    assert ledger.allows("agent_invocations", "max_agent_invocations")
    ledger.spend("agent_invocations")

    assert not ledger.allows("agent_invocations", "max_agent_invocations")
    assert ledger.allows("adversarial_tests", "max_adversarial_tests")


def test_the_adversarial_strategy_gets_a_smaller_share_of_the_clock() -> None:
    budget = Budget(max_duration_s=100)
    ledger = BudgetLedger(budget)

    adversarial = ledger.sub(StrategyName.ADVERSARIAL)
    mutation = ledger.sub(StrategyName.MUTATION)

    assert adversarial.remaining_s <= 40
    assert mutation.remaining_s > 40


# --------------------------------------------------------------------- reliability


def test_a_survival_is_unreliable_when_any_test_is_quarantined() -> None:
    reliable, tainted = verdict_is_reliable([], ["tests/test_a.py::test_flaky"])

    assert reliable is False
    assert tainted == ["tests/test_a.py::test_flaky"]


def test_a_kill_by_a_reliable_test_stands_even_beside_a_flaky_one() -> None:
    reliable, tainted = verdict_is_reliable(
        ["tests/test_a.py::test_solid", "tests/test_a.py::test_flaky"],
        ["tests/test_a.py::test_flaky"],
    )

    assert reliable is True
    assert tainted == []


def test_a_kill_by_only_a_quarantined_test_is_unreliable() -> None:
    reliable, tainted = verdict_is_reliable(
        ["tests/test_a.py::test_flaky"], ["tests/test_a.py::test_flaky"]
    )

    assert reliable is False


def test_unscreened_reliability_states_the_gap_on_every_survival() -> None:
    report = ReliabilityReport(probes=0, unavailable_reason="screening was disabled")

    assert not report.screened
    assert "flaky test rather than a weak one" in report.limitation()


def test_one_probe_cannot_detect_flakiness_and_says_so() -> None:
    report = ReliabilityReport(probes=1, unavailable_reason="one probe cannot detect flakiness")

    assert not report.screened


# --------------------------------------------------------------------- operators


def test_every_operator_class_produces_a_mutant() -> None:
    candidates = operators.generate(WEAK_SOURCE, filename="billing.py")
    candidates += operators.branch_removal(WEAK_SOURCE, filename="billing.py")
    produced = {candidate.operator for candidate in candidates}

    for expected in (
        operators.ARITHMETIC,
        operators.BOUNDARY,
        operators.CONDITIONAL,
        operators.CONSTANT,
        operators.EXCEPTION,
        operators.RETURN_VALUE,
        operators.BRANCH,
    ):
        assert expected in produced, f"{expected} produced no mutant"


def test_every_generated_mutant_is_syntactically_valid() -> None:
    candidates = operators.generate(WEAK_SOURCE, filename="billing.py")
    candidates += operators.branch_removal(WEAK_SOURCE, filename="billing.py")

    for candidate in candidates:
        ast.parse(candidate.source)  # raises if the rewrite corrupted the file


def test_mutation_is_confined_to_the_lines_the_patch_touched() -> None:
    scoped = operators.generate(WEAK_SOURCE, filename="billing.py", lines={4})

    assert scoped
    assert all(candidate.line == 4 for candidate in scoped)


def test_string_concatenation_is_not_mutated_as_arithmetic() -> None:
    """A guaranteed TypeError is an invalid mutant, not a realistic fault."""
    candidates = operators.generate('def f(a):\n    return a + "x"\n', filename="a.py")

    assert not any(candidate.operator == operators.ARITHMETIC for candidate in candidates)


def test_a_file_that_does_not_parse_yields_no_mutants_rather_than_raising() -> None:
    assert operators.generate("def broken(:\n", filename="a.py") == []


# --------------------------------------------------------------------- equivalence


def test_an_identity_arithmetic_mutant_is_judged_equivalent_statically() -> None:
    source = "def f(x):\n    return x * 1\n"
    candidate = MutationCandidate(
        file="a.py",
        line=2,
        operator=operators.ARITHMETIC,
        original="*",
        mutated="//",
        source="def f(x):\n    return x // 1\n",
    )

    judgement = judge_static(candidate, source)

    assert judgement.equivalent
    assert judgement.layer is EquivalenceLayer.STATIC


def test_an_undecidable_survivor_stays_survived_rather_than_equivalent() -> None:
    """Promotion to EQUIVALENT is how a real weakness disappears from a report."""
    source = "def f(x):\n    return x + 2\n"
    candidate = MutationCandidate(
        file="a.py",
        line=2,
        operator=operators.ARITHMETIC,
        original="+",
        mutated="-",
        source="def f(x):\n    return x - 2\n",
    )

    judgement = classify(candidate, original_source=source)

    assert not judgement.equivalent
    assert judgement.layer is EquivalenceLayer.UNDETERMINED


def test_the_assisted_layer_is_off_unless_explicitly_enabled() -> None:
    class Assistant:
        def judge_equivalence(self, candidate):
            return True, "the model says so"

    source = "def f(x):\n    return x + 2\n"
    candidate = MutationCandidate(
        file="a.py",
        line=2,
        operator=operators.ARITHMETIC,
        original="+",
        mutated="-",
        source="def f(x):\n    return x - 2\n",
    )

    off = classify(candidate, original_source=source, assistant=Assistant())
    on = classify(candidate, original_source=source, assisted=True, assistant=Assistant())

    assert not off.equivalent
    assert on.equivalent
    assert on.layer is EquivalenceLayer.ASSISTED
    assert on.confidence is Confidence.LOW, "an assisted judgement is capped at LOW"


# --------------------------------------------------------------------- reduction


def test_a_long_counterexample_shrinks() -> None:
    value = list(range(100))

    result = reduce_value(value, lambda candidate: 42 in candidate)

    assert result.status is ReductionStatus.REDUCED
    assert "42" in result.minimized
    assert len(result.minimized) < len(result.original)


def test_a_failed_reduction_preserves_the_original() -> None:
    def explode(_candidate):
        raise RuntimeError("predicate is broken")

    result = reduce_value([1, 2, 3], explode)

    assert result.original
    assert result.minimized == result.original


def test_reduction_stops_at_its_budget_and_says_so() -> None:
    result = reduce_value(list(range(500)), lambda candidate: True, max_steps=2)

    assert result.status is ReductionStatus.BUDGET_EXHAUSTED
    assert "budget" in result.detail


def test_an_unshrinkable_type_is_unavailable_not_lost() -> None:
    result = reduce_value(object(), lambda _c: True)

    assert result.status is ReductionStatus.UNAVAILABLE
    assert result.original


# --------------------------------------------------------------------- differential


def test_ordering_differences_are_suppressed_when_configured() -> None:
    rules = EquivalenceRules(ignore_ordering=True)

    comparison = compare_outputs('[1, 2, 3]', '[3, 2, 1]', rules)

    assert comparison.equivalent
    assert "ignore_ordering" in comparison.suppressed_by


def test_ordering_differences_are_a_mismatch_by_default() -> None:
    assert not compare_outputs('[1, 2, 3]', '[3, 2, 1]', EquivalenceRules()).equivalent


def test_float_tolerance_suppresses_last_place_noise_but_not_a_real_change() -> None:
    rules = EquivalenceRules(float_tolerance=1e-6)

    assert compare_outputs('{"x": 1.0000001}', '{"x": 1.0}', rules).equivalent
    assert not compare_outputs('{"x": 2.0}', '{"x": 1.0}', rules).equivalent


def test_timestamps_and_generated_ids_can_be_ignored() -> None:
    rules = EquivalenceRules(ignore_timestamps=True, ignore_generated_ids=True)

    comparison = compare_outputs(
        "run at 2024-01-01T00:00:00Z id=550e8400-e29b-41d4-a716-446655440000",
        "run at 2025-06-06T12:30:00Z id=6ba7b810-9dad-11d1-80b4-00c04fd430c8",
        rules,
    )

    assert comparison.equivalent


def test_a_real_difference_reports_where_it_is() -> None:
    comparison = compare_outputs('{"total": 10}', '{"total": 11}', EquivalenceRules())

    assert not comparison.equivalent
    assert "total" in comparison.detail


# --------------------------------------------------------------------- patch parsing


def test_the_patch_parser_records_only_added_lines() -> None:
    diff = (
        "diff --git a/billing.py b/billing.py\n"
        "--- a/billing.py\n"
        "+++ b/billing.py\n"
        "@@ -1,3 +1,4 @@\n"
        " def price(a, d):\n"
        "-    return a\n"
        "+    if d > 0.5:\n"
        "+        raise ValueError()\n"
        "     return a * (1 - d)\n"
    )

    patch = parse_patch(diff)

    assert patch.files == ["billing.py"]
    assert patch.lines["billing.py"] == {2, 3}


# --------------------------------------------------------------------- sandbox


def test_the_copy_sandbox_leaves_secrets_and_history_behind(tmp_path: Path) -> None:
    (tmp_path / "src.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / ".env").write_text("TOKEN=sk-secret\n", encoding="utf-8")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("[core]\n", encoding="utf-8")

    with create_sandbox(tmp_path, prefer=Isolation.COPY) as sandbox:
        assert sandbox.isolation is Isolation.COPY
        assert (sandbox.root / "src.py").is_file()
        assert not (sandbox.root / ".env").exists()
        assert not (sandbox.root / ".git").exists()


def test_the_scope_guard_sees_writes_outside_the_scratch_directory(tmp_path: Path) -> None:
    (tmp_path / "src.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / ".falsification").mkdir()
    before = snapshot_tree(tmp_path)

    (tmp_path / ".falsification" / "test_generated.py").write_text("ok\n", encoding="utf-8")
    (tmp_path / "src.py").write_text("x = 2\n", encoding="utf-8")

    violations = scope_violations(tmp_path, before)

    assert violations == ["modified: src.py"], "the scratch write must be allowed"


def test_a_sandbox_that_cannot_be_created_refuses_rather_than_downgrading() -> None:
    sandbox = create_sandbox(Path("/definitely/not/a/real/path"), prefer=Isolation.WORKTREE)

    assert not sandbox.available
    assert sandbox.isolation is Isolation.NONE


# --------------------------------------------------------------------- targets


def test_every_declared_target_appears_even_when_nothing_attacks_it() -> None:
    known = target_registry.known_targets()

    assert "security" in known
    assert "authorization" in known
    assert not target_registry.get("security").attackable


def test_an_unknown_target_is_refused_rather_than_silently_ignored() -> None:
    with pytest.raises(ValueError, match="unknown falsification target"):
        target_registry.resolve(["authorisation"])  # misspelled


def test_a_strategy_that_cannot_attack_the_targets_is_rejected_with_a_reason() -> None:
    engine = FalsificationEngine()

    selected, rejected = engine.select(["differential"], ["error_handling"])

    assert selected == []
    assert "differential" in rejected


def test_strategies_run_cheapest_and_most_deterministic_first() -> None:
    engine = FalsificationEngine()

    selected, _ = engine.select(["adversarial", "mutation"], ["behavior"])

    assert [name.value for name in selected] == ["mutation", "adversarial"]


def test_an_unknown_strategy_fails_loudly() -> None:
    with pytest.raises(ValueError, match="unknown falsification strategy"):
        FalsificationEngine().select(["fuzzing"], ["behavior"])


# --------------------------------------------------------------------- persistence


def test_a_report_round_trips_through_the_store(project) -> None:
    report = FalsificationReport(task_id="task_1", run_id="fals_test")
    report.strategies.append(
        StrategyReport(strategy=StrategyName.MUTATION, status=StrategyStatus.SURVIVED)
    )
    report.settle()

    save_report(project, report)
    loaded = resolve_report(project, "fals_test")

    assert loaded.run_id == "fals_test"
    assert loaded.status is FalsificationStatus.SURVIVED


def test_the_corpus_outlives_the_run_directory(project) -> None:
    report = FalsificationReport(task_id="task_1")
    report.strategies.append(
        StrategyReport(
            strategy=StrategyName.PROPERTY,
            status=StrategyStatus.FAILED,
            counterexamples=[
                Counterexample(
                    strategy=StrategyName.PROPERTY,
                    input="[-1]",
                    expected="result >= 0",
                    actual="-1",
                    reproduction=["python", "-m", "pytest"],
                )
            ],
        )
    )
    report.settle()

    written = record_corpus(project, report)

    assert written
    assert (project.devforge_dir / "falsification" / "counterexamples").is_dir()


def test_a_counterexample_becomes_a_regression_test() -> None:
    example = Counterexample(
        strategy=StrategyName.PROPERTY,
        input="[-1]",
        expected="result >= 0",
        actual="-1",
        reproduction=["python", "-m", "pytest", "-q"],
        file="billing.py",
        symbol="price",
    )

    source = render_regression_test(example)

    ast.parse(source)  # the generated test must at least be valid Python
    assert "def test_regression" in source
    assert example.finding_id in source
    assert "AssertionError" in source, "an unwritten assertion must fail, not silently pass"


# --------------------------------------------------------------------- end to end


@pytest.mark.slow
def test_a_weak_suite_is_falsified_and_the_working_tree_is_untouched(tmp_path: Path) -> None:
    """The end-to-end proof: real mutants, real pytest runs, real isolation."""
    root = _project(tmp_path)
    policy = PolicyEngine.load(None, workspace=root)

    import asyncio

    report = asyncio.run(
        FalsificationEngine().run(
            source_root=root,
            policy=policy,
            strategies=["mutation"],
            budget=Budget(max_duration_s=300, max_mutants=8, flakiness_probes=0),
            changed_files=["billing.py"],
            diff="diff --git a/billing.py b/billing.py\n",
            test_command=["python", "-m", "pytest", "-q"],
            test_timeout_s=90,
            task_id="task_e2e",
        )
    )

    assert report.status is FalsificationStatus.FAILED
    assert report.mutants_survived > 0
    assert report.weaknesses, "a surviving mutant must produce an actionable finding"
    assert report.confidence is Confidence.NONE

    # The claim the whole sandbox exists to make.
    assert (root / "billing.py").read_text(encoding="utf-8") == WEAK_SOURCE
    dirty = subprocess.run(
        ["git", "status", "--porcelain"], cwd=root, capture_output=True, text=True
    ).stdout.strip()
    assert dirty == "", f"the user's working tree was modified: {dirty}"


@pytest.mark.slow
def test_a_strong_suite_kills_more_mutants_than_a_weak_one(tmp_path: Path) -> None:
    """The score has to actually respond to test quality, or it measures nothing."""
    import asyncio

    def score(directory: Path, tests: str) -> float | None:
        directory.mkdir()
        root = _project(directory, test_source=tests)
        report = asyncio.run(
            FalsificationEngine().run(
                source_root=root,
                policy=PolicyEngine.load(None, workspace=root),
                strategies=["mutation"],
                budget=Budget(max_duration_s=300, max_mutants=8, flakiness_probes=0),
                changed_files=["billing.py"],
                diff="diff --git a/billing.py b/billing.py\n",
                test_command=["python", "-m", "pytest", "-q"],
                test_timeout_s=90,
            )
        )
        return report.mutation_score

    weak = score(tmp_path / "weak", WEAK_TEST)
    strong = score(tmp_path / "strong", STRONG_TEST)

    assert weak is not None and strong is not None
    assert strong > weak, f"a stronger suite scored no better ({strong} vs {weak})"


@pytest.mark.slow
def test_an_exhausted_budget_reports_incomplete_never_survived(tmp_path: Path) -> None:
    import asyncio

    root = _project(tmp_path, test_source=STRONG_TEST)
    report = asyncio.run(
        FalsificationEngine().run(
            source_root=root,
            policy=PolicyEngine.load(None, workspace=root),
            strategies=["mutation"],
            budget=Budget(max_duration_s=300, max_mutants=1, flakiness_probes=0),
            changed_files=["billing.py"],
            diff="diff --git a/billing.py b/billing.py\n",
            test_command=["python", "-m", "pytest", "-q"],
            test_timeout_s=90,
        )
    )

    assert report.status is not FalsificationStatus.SURVIVED
    assert "max_mutants" in report.usage.exhausted
    assert any("truncated" in item for item in report.limitations)


def test_isolation_unavailable_refuses_rather_than_using_the_real_tree(tmp_path: Path) -> None:
    import asyncio

    report = asyncio.run(
        FalsificationEngine().run(
            source_root=tmp_path / "missing",
            policy=PolicyEngine.load(None, workspace=tmp_path),
            strategies=["mutation"],
            isolation=Isolation.WORKTREE,
        )
    )

    assert report.status is FalsificationStatus.UNAVAILABLE
    assert report.isolation == "none"
    assert any("ISOLATION_UNAVAILABLE" in item for item in report.limitations)


# ------------------------------------------------------- regressions: no bypass


def test_lanes_give_each_concurrent_mutant_its_own_tree(tmp_path: Path) -> None:
    """Two lanes must not be the same directory, or they share one test run."""
    from devforge.falsification.sandbox import open_lanes

    root = tmp_path / "src"
    root.mkdir()
    (root / "a.py").write_text("VALUE = 1\n", encoding="utf-8")

    lanes, shortfall = open_lanes(root, 3)
    try:
        assert shortfall == ""
        assert len({lane.root for lane in lanes}) == 3
        assert lanes[0].root == root and lanes[0].primary

        # A write in one lane is invisible in every other.
        (lanes[1].root / "a.py").write_text("VALUE = 2\n", encoding="utf-8")
        assert (lanes[0].root / "a.py").read_text(encoding="utf-8") == "VALUE = 1\n"
        assert (lanes[2].root / "a.py").read_text(encoding="utf-8") == "VALUE = 1\n"
    finally:
        for lane in lanes:
            lane.release()

    assert root.is_dir(), "releasing the pool must not delete the sandbox it borrowed"


@pytest.mark.slow
def test_parallel_mutation_reaches_the_same_verdict_as_serial(tmp_path: Path) -> None:
    """Concurrency must not change a verdict, only how long it takes to reach one.

    Sharing one workspace made mutants judge each other: a mutant in an untested file
    was recorded as killed by a fault injected elsewhere in the same tree, and the
    score came out higher than the suite deserved. A run at four jobs and a run at
    one must agree mutant for mutant.
    """
    import asyncio

    def run(directory: Path, jobs: int):
        directory.mkdir()
        root = _project(directory)
        # A second changed file, untested, so there is something for a concurrent
        # mutant in the tested file to wrongly take credit for killing.
        (root / "untested.py").write_text(
            "def unreached(x):\n    return x + 1\n", encoding="utf-8"
        )
        return asyncio.run(
            FalsificationEngine().run(
                source_root=root,
                policy=PolicyEngine.load(None, workspace=root),
                strategies=["mutation"],
                budget=Budget(
                    max_duration_s=300,
                    max_mutants=12,
                    flakiness_probes=0,
                    max_parallel_jobs=jobs,
                ),
                changed_files=["billing.py", "untested.py"],
                diff="diff --git a/billing.py b/billing.py\n",
                test_command=["python", "-m", "pytest", "-q"],
                test_timeout_s=90,
            )
        )

    serial = run(tmp_path / "serial", 1)
    parallel = run(tmp_path / "parallel", 4)

    def verdicts(report) -> dict[str, str]:
        return {
            f"{m.file}:{m.line}:{m.operator}:{m.mutated}": m.status.value
            for m in report.mutants
        }

    assert verdicts(parallel) == verdicts(serial)
    assert parallel.mutation_score == serial.mutation_score
    assert parallel.status is serial.status


