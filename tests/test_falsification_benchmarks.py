"""The falsification benchmark suite: declared oracles, actually executed.

`builtin/benchmarks/falsification.yaml` states what each case must produce. A
benchmark whose oracles are never run is documentation, so the important cases here
are executed against the real engine rather than asserted about.

The two that matter most are `flaky-survival` and `flaky-kill`. Every other case can
be built from a deterministic fixture; those two cannot, by definition. They use a
test that fails on alternate invocations - reliably flaky, which is the only way to
test flaky-verdict handling at all - and they assert the one thing that must hold:
a verdict resting on such a test never reaches the mutation score.
"""

from __future__ import annotations

import asyncio
import subprocess
from pathlib import Path

import pytest
import yaml

from devforge.falsification.engine import FalsificationEngine
from devforge.falsification.models import (
    Budget,
    FalsificationStatus,
    MutantStatus,
    StrategyName,
)
from devforge.falsification.reliability import screen
from devforge.policy.engine import PolicyEngine

SUITE = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "devforge"
    / "builtin"
    / "benchmarks"
    / "falsification.yaml"
)

TEST_COMMAND = ["python", "-m", "pytest", "-q"]

#: A test that fails on every other invocation. Deterministic in aggregate and
#: reliably flaky per run, which is exactly what the reliability probe must notice.
FLAKY_TEST = '''from pathlib import Path

from billing import price


COUNTER = Path(__file__).parent / "counter.txt"


def _next() -> int:
    value = int(COUNTER.read_text()) if COUNTER.exists() else 0
    COUNTER.write_text(str(value + 1))
    return value


def test_alternating():
    assert price(100, 0.0) == 100
    assert _next() % 2 == 0, "this test fails on alternate runs by design"
'''

STABLE_SOURCE = '''def price(amount, discount):
    if discount > 0.5:
        raise ValueError("discount too large")
    return amount * (1 - discount)
'''


def load_cases() -> list[dict]:
    return yaml.safe_load(SUITE.read_text(encoding="utf-8"))["cases"]


def case(case_id: str) -> dict:
    found = next((c for c in load_cases() if c["id"] == case_id), None)
    assert found is not None, f"benchmark case '{case_id}' is missing from the suite"
    return found


def _project(root: Path, files: dict[str, str]) -> Path:
    for name, body in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    (root / "pytest.ini").write_text("[pytest]\npythonpath = .\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init"],
        cwd=root,
        check=True,
    )
    return root


def _run(root: Path, **overrides):
    budget = overrides.pop("budget", Budget(max_duration_s=300, max_mutants=8, flakiness_probes=0))
    return asyncio.run(
        FalsificationEngine().run(
            source_root=root,
            policy=PolicyEngine.load(None, workspace=root),
            strategies=overrides.pop("strategies", ["mutation"]),
            budget=budget,
            changed_files=overrides.pop("changed_files", ["billing.py"]),
            diff="diff --git a/billing.py b/billing.py\n",
            test_command=TEST_COMMAND,
            test_timeout_s=90,
            **overrides,
        )
    )


# --------------------------------------------------------------------- suite shape


def test_the_suite_declares_everything_a_benchmark_needs() -> None:
    """Expected result, target, strategy, oracle and security expectation, per case."""
    for entry in load_cases():
        for field in (
            "id",
            "title",
            "target",
            "strategy",
            "difficulty",
            "expect",
            "oracle",
            "security_expectation",
        ):
            assert entry.get(field), f"case '{entry.get('id')}' is missing '{field}'"


def test_every_case_names_a_real_target_and_strategy() -> None:
    from devforge.falsification import targets

    known_targets = set(targets.known_targets())
    known_strategies = {name.value for name in StrategyName}

    for entry in load_cases():
        assert entry["target"] in known_targets, entry["id"]
        assert entry["strategy"] in known_strategies, entry["id"]


def test_every_expected_result_is_a_real_status() -> None:
    statuses = {status.value.upper() for status in FalsificationStatus}
    mutant_statuses = {status.value.upper() for status in MutantStatus}

    for entry in load_cases():
        assert entry["expect"] in statuses | mutant_statuses, entry["id"]


def test_the_suite_covers_the_categories_the_design_requires() -> None:
    ids = {entry["id"] for entry in load_cases()}

    required = {
        "obvious-bug",
        "hidden-edge-case",
        "insufficient-tests",
        "surviving-mutant",
        "equivalent-mutant",
        "property-violation",
        "adversarial-discovery",
        "differential-regression",
        "metamorphic-violation",
        "counterexample-reduction",
        "prompt-injection",
        "malicious-test",
        "permission-escalation",
        "secret-leakage",
        "budget-exhaustion",
        "unavailable-strategy",
        "flaky-survival",
        "flaky-kill",
        "adversarial-budget",
    }
    assert required <= ids, f"missing benchmark cases: {sorted(required - ids)}"


def test_the_security_cases_state_a_must_not() -> None:
    """A security expectation that does not forbid anything is not an expectation."""
    for case_id in (
        "malicious-test",
        "permission-escalation",
        "secret-leakage",
        "prompt-injection",
    ):
        expectation = case(case_id)["security_expectation"]
        assert "MUST" in expectation, f"{case_id}: {expectation}"


# --------------------------------------------------------------------- executed oracles


@pytest.mark.slow
def test_insufficient_tests_case_produces_weakness_findings(tmp_path: Path) -> None:
    entry = case("insufficient-tests")
    root = _project(tmp_path, entry["files"])

    report = _run(root)

    assert report.status is FalsificationStatus.FAILED
    assert report.mutants_survived > 0
    assert report.weaknesses, entry["oracle"]


@pytest.mark.slow
def test_budget_exhaustion_case_reports_incomplete(tmp_path: Path) -> None:
    entry = case("budget-exhaustion")
    root = _project(tmp_path, entry["files"])

    report = _run(root, budget=Budget(max_duration_s=300, max_mutants=2, flakiness_probes=0))

    assert report.status is not FalsificationStatus.SURVIVED, entry["oracle"]
    assert "max_mutants" in report.usage.exhausted


def test_unavailable_strategy_case_is_not_a_survival(tmp_path: Path) -> None:
    entry = case("unavailable-strategy")
    root = _project(tmp_path, {"billing.py": STABLE_SOURCE})

    # No properties declared, so the property strategy cannot run whatever is installed.
    report = _run(root, strategies=["property"])

    assert report.status is FalsificationStatus.UNAVAILABLE, entry["oracle"]
    assert report.status is not FalsificationStatus.SURVIVED
    assert report.strategy_coverage.unavailable, "the reason must be recorded"


@pytest.mark.slow
def test_equivalent_mutant_case_is_classified_with_its_layer(tmp_path: Path) -> None:
    entry = case("equivalent-mutant")
    root = _project(tmp_path, entry["files"])

    report = _run(root, changed_files=["scale.py"])

    equivalent = [m for m in report.mutants if m.status is MutantStatus.EQUIVALENT]
    if equivalent:  # the identity mutant is only generated when the operator applies
        assert all(m.equivalence_layer is not None for m in equivalent), entry["oracle"]
        assert all(m.reason for m in equivalent)
        assert all(not m.status.counts_toward_score for m in equivalent)


# --------------------------------------------------------------------- flaky verdicts


@pytest.mark.slow
def test_flaky_survival_case_quarantines_the_test(tmp_path: Path) -> None:
    """The probe must notice a test that disagrees with itself between runs."""
    entry = case("flaky-survival")
    root = _project(
        tmp_path, {"billing.py": STABLE_SOURCE, "tests/test_flaky.py": FLAKY_TEST}
    )

    report, _ = asyncio.run(
        screen(
            workspace=root,
            policy=PolicyEngine.load(None, workspace=root),
            test_command=TEST_COMMAND,
            probes=2,
            timeout_s=90,
        )
    )

    assert report.quarantined, entry["oracle"]
    assert report.screened
    assert "quarantined" in report.limitation()


@pytest.mark.slow
def test_a_flaky_verdict_never_reaches_the_mutation_score(tmp_path: Path) -> None:
    """Both directions at once: an unreliable mutant is in neither half of the score."""
    root = _project(tmp_path, {"billing.py": STABLE_SOURCE, "tests/test_flaky.py": FLAKY_TEST})

    report = _run(
        root, budget=Budget(max_duration_s=300, max_mutants=4, flakiness_probes=2)
    )

    unreliable = [m for m in report.mutants if m.status is MutantStatus.UNRELIABLE]
    for mutant in unreliable:
        assert mutant.unreliable_tests, "an unreliable verdict must name the tests"
        assert mutant.reason
        assert not mutant.status.counts_toward_score

    # Whatever the run decided, the score is computed only over reliable verdicts.
    assert report.valid_mutants == sum(
        1 for m in report.mutants if m.status in {MutantStatus.KILLED, MutantStatus.SURVIVED}
    )
    if unreliable:
        assert report.mutants_unreliable == len(unreliable)


def test_screening_disabled_states_the_uncertainty(tmp_path: Path) -> None:
    entry = case("flaky-kill")
    root = _project(tmp_path, {"billing.py": STABLE_SOURCE})

    report = _run(root, budget=Budget(max_duration_s=60, max_mutants=1, flakiness_probes=0))

    assert not report.reliability.screened
    assert any("flaky test rather than a weak one" in item for item in report.limitations), (
        entry["oracle"]
    )
