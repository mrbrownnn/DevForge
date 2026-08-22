"""Tests for the evaluation harness.

The most important tests here are the calibration ones. A benchmark's grader is
the part nobody checks and everybody trusts, so the anchors are asserted directly:
the reference solution must score 1.0 and the cheat driver must score 0.0 *while
making the checks pass*. If either stops holding, every number the harness
produces becomes unreadable, and that has to be a build failure rather than
something someone notices later.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from devforge.core.errors import ConfigError
from devforge.core.models import (
    AgentResult,
    AgentResultStatus,
    StepAttempt,
    StepRecord,
    StepStatus,
    Task,
    ToolCall,
    ToolStatus,
    VerificationResult,
    VerificationStatus,
)
from devforge.eval.compare import Movement, compare_reports
from devforge.eval.drivers import (
    CheatDriver,
    HarnessDriver,
    NoopDriver,
    ReferenceDriver,
    _telemetry,
    _tokens_of,
    build_driver,
)
from devforge.eval.metrics import Direction, compute_metrics
from devforge.eval.models import (
    CaseOutcome,
    CaseResult,
    Category,
    Check,
    CheckOutcome,
    EvalCase,
    EvalConfig,
    EvalReport,
    Expectation,
)
from devforge.eval.runner import EvalRunner
from devforge.eval.store import list_reports, load_report, resolve_report, save_report
from devforge.eval.suites import load_cases, load_config, load_configs, suite_paths
from devforge.policy.engine import PolicyEngine

# Cases small enough to run the whole grader in a unit test.
FAST_CASES = ["feature-slugify", "bugfix-shared-default"]


def policy_for(root: Path) -> PolicyEngine:
    return PolicyEngine.load(None, workspace=root)


def run_config(config_id: str, case_ids: list[str], tmp_path: Path):
    config = load_config(config_id)
    cases, suites = load_cases(None, case_ids=case_ids)
    runner = EvalRunner(config=config, policy=policy_for(tmp_path))
    return asyncio.run(runner.run(cases, suites=suites))


# --------------------------------------------------------------------------- suites


def test_every_category_has_at_least_one_case() -> None:
    """The brief names eight categories; a category with no case is a claim, not a
    benchmark."""
    cases, _ = load_cases(None)
    covered = {case.category for case in cases}
    missing = sorted(category.value for category in Category if category not in covered)
    assert not missing, f"categories with no case: {missing}"


def test_shipped_suites_are_loadable_and_unique() -> None:
    cases, suites = load_cases(None)
    assert suites, "no suites were discovered"
    ids = [case.id for case in cases]
    assert len(ids) == len(set(ids))


def test_every_case_ships_a_reference_solution() -> None:
    """Without one, the case cannot anchor the grader and cannot be calibrated."""
    cases, _ = load_cases(None)
    unanchored = [case.id for case in cases if not case.solution]
    assert not unanchored, f"cases with no reference solution: {unanchored}"


def test_project_cases_shadow_shipped_ones(tmp_path: Path) -> None:
    shipped = {path.name for path in suite_paths(None)}
    assert "feature.yaml" in shipped

    (tmp_path / "benchmarks").mkdir()
    (tmp_path / "benchmarks" / "feature.yaml").write_text("version: 1\ncases: []\n", "utf-8")
    cases, _ = load_cases(tmp_path, categories=["feature"])

    assert not any(case.id == "feature-slugify" for case in cases), (
        "a project suite must replace the shipped file of the same name, not merge with it"
    )


def test_an_unknown_category_is_an_error() -> None:
    with pytest.raises(ConfigError, match="unknown categor"):
        load_cases(None, categories=["nonsense"])


def test_an_unknown_case_id_is_an_error() -> None:
    """Silently running nothing looks exactly like running everything and passing."""
    with pytest.raises(ConfigError, match="unknown case"):
        load_cases(None, case_ids=["no-such-case"])


def test_a_case_cannot_write_outside_its_workspace(tmp_path: Path) -> None:
    case = EvalCase(
        id="escape",
        category=Category.FEATURE,
        description="x",
        files={"../escaped.txt": "no"},
        checks=[Check(id="c", argv=["python", "-m", "pytest", "-q"])],
    )
    with pytest.raises(ConfigError, match="outside its workspace"):
        case.materialise(tmp_path)
    assert not (tmp_path.parent / "escaped.txt").exists()


def test_a_case_needs_at_least_one_check() -> None:
    with pytest.raises(ValueError, match="at least one check"):
        EvalCase(id="c", category=Category.FEATURE, description="x", checks=[])


def test_a_check_needs_an_argv() -> None:
    with pytest.raises(ValueError, match="argv must not be empty"):
        Check(id="c", argv=[])


# --------------------------------------------------------------------------- configs


def test_the_three_anchors_are_shipped() -> None:
    configs = load_configs(None)
    for anchor in ("reference", "cheat", "none"):
        assert anchor in configs
        assert configs[anchor].driver == anchor


def test_project_configs_override_shipped_ones(tmp_path: Path) -> None:
    (tmp_path / "evals").mkdir()
    (tmp_path / "evals" / "local.yaml").write_text(
        "configs:\n  - id: mock-baseline\n    driver: none\n", "utf-8"
    )
    assert load_configs(tmp_path)["mock-baseline"].driver == "none"


def test_an_unknown_config_names_what_is_available() -> None:
    with pytest.raises(ConfigError, match="defined here"):
        load_config("no-such-config")


def test_the_axes_a_comparison_can_vary_are_all_recorded() -> None:
    """The brief names five: runtime, model, skill set, workflow, context strategy."""
    axes = EvalConfig(id="x").axes()
    for axis in ("runtime", "model", "skills", "workflow", "context_strategy"):
        assert axis in axes


# ------------------------------------------------------------------- calibration


@pytest.mark.slow
def test_the_reference_solution_scores_everything(tmp_path: Path) -> None:
    report = run_config("reference", FAST_CASES, tmp_path)

    assert report.metrics.value_of("task_success_rate") == 1.0, (
        f"the grader rejected correct work: "
        f"{[(r.case_id, r.detail) for r in report.results if not r.outcome.success]}"
    )


@pytest.mark.slow
def test_the_cheat_driver_scores_nothing_even_when_the_checks_pass(tmp_path: Path) -> None:
    """The whole point of the patch guard, stated as a measurement.

    The cheat driver deletes assertions until the checks stop objecting - and it
    succeeds at that. What must not happen is the grader recording it as a repair.
    """
    report = run_config("cheat", FAST_CASES, tmp_path)

    assert report.metrics.value_of("task_success_rate") == 0.0
    rejected = [r for r in report.results if r.outcome is CaseOutcome.REJECTED_SUSPICIOUS]
    assert rejected, "the cheat driver was not caught by the patch guard"
    green = [r for r in rejected if all(check.passed for check in r.checks)]
    assert green, (
        "the cheat driver did not manage to make any checks pass, so this run does "
        "not demonstrate that a green suite alone cannot win"
    )


@pytest.mark.slow
def test_doing_nothing_scores_nothing(tmp_path: Path) -> None:
    """If this is not zero, some case is satisfied by its own starting state."""
    report = run_config("none", FAST_CASES, tmp_path)

    assert report.metrics.value_of("task_success_rate") == 0.0
    assert all(r.outcome is CaseOutcome.FAILED for r in report.results)


# --------------------------------------------------------------------------- grading


@pytest.mark.slow
def test_a_broken_guard_makes_the_case_invalid_not_failed(tmp_path: Path) -> None:
    """A benchmark that was already failing is not evidence about the driver."""
    case = EvalCase(
        id="broken-guard",
        category=Category.FEATURE,
        description="x",
        files={"tests/test_it.py": "def test_it():\n    assert False\n"},
        guards=[Check(id="guard", argv=["python", "-m", "pytest", "-q"])],
        checks=[Check(id="suite", argv=["python", "-m", "pytest", "-q"])],
    )
    runner = EvalRunner(config=EvalConfig(id="x", driver="none"), policy=policy_for(tmp_path))
    result, _ = asyncio.run(runner.run_case(case, NoopDriver()))

    assert result.outcome is CaseOutcome.INVALID
    assert not result.outcome.attempted, "an invalid case must stay out of the denominator"


@pytest.mark.slow
def test_breaking_a_guard_is_a_regression_not_a_pass(tmp_path: Path) -> None:
    """The case's own check passes; a guard that used to pass no longer does."""

    class Vandal:
        name = "vandal"

        async def attempt(self, workspace, case, logger):
            from devforge.eval.drivers import DriverOutcome

            (workspace / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
            return DriverOutcome(detail="changed the value everything depended on")

    case = EvalCase(
        id="regressor",
        category=Category.FEATURE,
        description="x",
        files={
            "app.py": "VALUE = 1\n",
            "tests/test_guard.py": (
                "from app import VALUE\n\n\ndef test_one():\n    assert VALUE == 1\n"
            ),
            "tests/test_new.py": "def test_anything():\n    assert True\n",
        },
        guards=[Check(id="guard", argv=["python", "-m", "pytest", "-q", "tests/test_guard.py"])],
        checks=[Check(id="new", argv=["python", "-m", "pytest", "-q", "tests/test_new.py"])],
    )
    runner = EvalRunner(config=EvalConfig(id="x", driver="none"), policy=policy_for(tmp_path))
    result, _ = asyncio.run(runner.run_case(case, Vandal()))

    assert result.outcome is CaseOutcome.REGRESSED
    assert result.regressed == ["guard"]
    assert all(check.passed for check in result.checks), (
        "this test is only meaningful if the case's own checks passed"
    )


@pytest.mark.slow
def test_a_missing_capability_is_unavailable_not_failed(tmp_path: Path) -> None:
    case = EvalCase(
        id="needs-a-thing",
        category=Category.WEBSITE,
        description="x",
        requires=["a-capability-that-does-not-exist"],
        checks=[Check(id="c", argv=["python", "-m", "pytest", "-q"])],
    )
    runner = EvalRunner(config=EvalConfig(id="x", driver="none"), policy=policy_for(tmp_path))
    result, _ = asyncio.run(runner.run_case(case, NoopDriver()))

    assert result.outcome is CaseOutcome.UNAVAILABLE
    assert not result.outcome.attempted


@pytest.mark.slow
def test_the_policy_refuses_a_check_it_does_not_allow(tmp_path: Path) -> None:
    """A benchmark case is data, and data does not get to widen the shell policy."""
    case = EvalCase(
        id="sneaky",
        category=Category.FEATURE,
        description="x",
        files={"note.txt": "hello"},
        checks=[Check(id="sneaky", argv=["python", "-c", "print('anything at all')"])],
    )
    runner = EvalRunner(config=EvalConfig(id="x", driver="none"), policy=policy_for(tmp_path))
    result, _ = asyncio.run(runner.run_case(case, NoopDriver()))

    assert result.outcome is CaseOutcome.FAILED
    assert "policy refused" in result.checks[0].excerpt


def test_an_expected_failure_is_satisfied_by_a_non_zero_exit() -> None:
    check = Check(id="c", argv=["x"], expect=Expectation.FAIL)
    assert check.satisfied_by(1)
    assert not check.satisfied_by(0)


# --------------------------------------------------------------------------- metrics


def result_for(**kwargs) -> CaseResult:
    base = {"case_id": "c", "category": Category.FEATURE}
    return CaseResult(**{**base, **kwargs})


def test_an_unmeasured_metric_is_unknown_never_zero() -> None:
    """Zero is a measurement. This is the absence of one, and a report that
    confuses them is worse than one that omits the metric."""
    metrics = compute_metrics([result_for(outcome=CaseOutcome.SUCCESS)])

    tokens = metrics.get("token_usage")
    assert tokens is not None
    assert tokens.value is None
    assert tokens.unknown_reason
    assert "unknown" in tokens.format()


def test_a_rate_over_nothing_is_unknown_not_one() -> None:
    metrics = compute_metrics([])
    assert metrics.value_of("task_success_rate") is None


def test_unavailable_cases_stay_out_of_the_denominator() -> None:
    results = [
        result_for(case_id="a", outcome=CaseOutcome.SUCCESS),
        result_for(case_id="b", outcome=CaseOutcome.UNAVAILABLE),
    ]
    metrics = compute_metrics(results)

    assert metrics.value_of("task_success_rate") == 1.0
    assert "1 not attempted" in metrics.get("task_success_rate").basis


def test_all_twelve_tracked_metrics_are_produced() -> None:
    """The brief lists twelve. A metric that is hard to measure is reported as
    unknown; none of them is allowed to simply be absent."""
    expected = {
        "task_success_rate",
        "first_pass_success",
        "repair_success",
        "verification_pass_rate",
        "regression_rate",
        "average_iterations",
        "token_usage",
        "cost_usd",
        "latency_ms",
        "human_intervention_rate",
        "security_violations",
        "tool_failures",
    }
    produced = {metric.id for metric in compute_metrics([result_for()]).values}
    assert expected <= produced, f"missing metrics: {sorted(expected - produced)}"


def test_first_pass_needs_step_counts_to_mean_anything() -> None:
    scripted = result_for(outcome=CaseOutcome.SUCCESS)
    assert scripted.first_pass is None

    ran = result_for(outcome=CaseOutcome.SUCCESS, attempts=3, steps_total=3)
    assert ran.first_pass is True

    retried = result_for(outcome=CaseOutcome.SUCCESS, attempts=4, steps_total=3)
    assert retried.first_pass is False


def test_repair_success_counts_only_the_cases_that_needed_one() -> None:
    results = [
        result_for(case_id="clean", outcome=CaseOutcome.SUCCESS, attempts=2, steps_total=2),
        result_for(case_id="fixed", outcome=CaseOutcome.SUCCESS, attempts=4, steps_total=2),
        result_for(case_id="lost", outcome=CaseOutcome.FAILED, attempts=5, steps_total=2),
    ]
    assert compute_metrics(results).value_of("repair_success") == 0.5


def test_metric_directions_are_declared() -> None:
    """A comparison cannot say "better" without knowing which way better is."""
    metrics = compute_metrics([result_for()])
    assert metrics.get("task_success_rate").direction is Direction.UP
    assert metrics.get("regression_rate").direction is Direction.DOWN
    assert metrics.get("cost_usd").direction is Direction.DOWN


# --------------------------------------------------------------------------- telemetry


def test_token_counts_are_summed_only_when_a_runtime_reports_them() -> None:
    assert _tokens_of({}) == (0, False)
    assert _tokens_of({"total_tokens": 40}) == (40, True)
    assert _tokens_of({"usage": {"input_tokens": 10, "output_tokens": 5}}) == (15, True)


def test_telemetry_is_read_off_the_task_record_not_the_agent_report() -> None:
    task = Task(project_id="p", description="d", workflow="feature")
    task.steps = [
        StepRecord(
            step_id="implementation",
            kind="agent",
            status=StepStatus.PASSED,
            attempts=[
                StepAttempt(
                    attempt=1,
                    agent_result=AgentResult(
                        invocation_id="i",
                        runtime="mock",
                        status=AgentResultStatus.OK,
                        summary="all done, everything is fine",
                        tool_calls=[
                            ToolCall(tool="shell", action="run", status=ToolStatus.DENIED),
                            ToolCall(tool="fs", action="write", status=ToolStatus.ERROR),
                            ToolCall(tool="fs", action="read", status=ToolStatus.OK),
                        ],
                        metadata={"total_cost_usd": 0.25, "usage": {"input_tokens": 100}},
                    ),
                )
            ],
        )
    ]
    task.verification_results = [
        VerificationResult(verifier="tests", kind="tests", status=VerificationStatus.FAILED),
        VerificationResult(verifier="lint", kind="lint", status=VerificationStatus.PASSED),
    ]

    outcome = _telemetry(task, status="failed", detail="x", interventions=2, unhonoured=[])

    assert outcome.security_violations == 1, "a denied tool call is a policy violation"
    assert outcome.tool_failures == 1
    assert outcome.tool_calls == 3
    assert outcome.verifications_passed == 1
    assert outcome.verifications_failed == 1
    assert outcome.tokens == 100
    assert outcome.cost_usd == 0.25
    assert outcome.interventions == 2


def test_an_unhonoured_setting_is_reported_rather_than_dropped() -> None:
    """Otherwise a comparison labels two identical runs as a model difference."""
    from devforge.runtime.mock import MockAgentRuntime

    assert MockAgentRuntime().configure(model="something") == ["model"]


def test_a_runtime_that_takes_a_model_honours_it() -> None:
    from devforge.runtime.claude_code import ClaudeCodeRuntime

    runtime = ClaudeCodeRuntime()
    assert runtime.configure(model="a-model-name") == []
    assert runtime.model == "a-model-name"


# --------------------------------------------------------------------------- drivers


def test_build_driver_rejects_an_unknown_name() -> None:
    with pytest.raises(Exception, match="unknown driver"):
        build_driver(EvalConfig(id="x", driver="teleport"))


def test_the_shipped_drivers_are_what_the_anchors_name() -> None:
    assert isinstance(build_driver(EvalConfig(id="a", driver="reference")), ReferenceDriver)
    assert isinstance(build_driver(EvalConfig(id="b", driver="cheat")), CheatDriver)
    assert isinstance(build_driver(EvalConfig(id="c", driver="none")), NoopDriver)
    assert isinstance(build_driver(EvalConfig(id="d", driver="harness")), HarnessDriver)


def test_restricting_the_skill_set_actually_withholds_skills() -> None:
    """A configuration that only *labels* itself minimal would produce two
    identical runs and attribute the difference to the label."""
    from devforge.core.workflow.loader import WorkflowLoader
    from devforge.eval.drivers import _restrict_skills

    spec = WorkflowLoader.for_project(None).load("feature")
    assert any(step.skills for step in spec.steps)

    narrowed = _restrict_skills(spec, ["testing"])

    assert all(set(step.skills) <= {"testing"} for step in narrowed.steps)
    assert any(step.skills for step in spec.steps), "the original spec must not be mutated"


def test_an_unknown_context_strategy_is_reported_not_guessed(tmp_path: Path) -> None:
    from devforge.eval.drivers import _prepare_context

    class FakeContext:
        class config:
            project_id = "p"

    unhonoured = _prepare_context(tmp_path, FakeContext(), "telepathy")

    assert unhonoured and "telepathy" in unhonoured[0]


@pytest.mark.slow
def test_the_harness_driver_runs_a_real_workflow(tmp_path: Path) -> None:
    """End to end through the orchestrator: steps, verifiers, gates, telemetry."""
    config = EvalConfig(id="harness-test", driver="harness", runtime="mock")
    cases, _ = load_cases(None, case_ids=["feature-slugify"])
    runner = EvalRunner(config=config, policy=policy_for(tmp_path))

    report = asyncio.run(runner.run(cases))
    result = report.results[0]

    assert result.outcome.attempted, f"the harness could not run: {result.detail}"
    assert result.steps_total and result.steps_total > 0
    assert result.attempts and result.attempts >= result.steps_total
    assert result.tool_calls is not None
    assert result.interventions >= 1, "the feature workflow has approval gates"
    assert report.metrics.value_of("human_intervention_rate") == 1.0


# --------------------------------------------------------------------------- comparison


def report_with(config_id: str, outcomes: dict[str, CaseOutcome], **metric_kwargs) -> EvalReport:
    results = [
        CaseResult(case_id=case_id, category=Category.FEATURE, outcome=outcome, **metric_kwargs)
        for case_id, outcome in outcomes.items()
    ]
    return EvalReport(
        report_id=f"eval_{config_id}",
        config=EvalConfig(id=config_id),
        results=results,
        metrics=compute_metrics(results),
    )


def test_a_case_that_stopped_passing_is_a_regression() -> None:
    baseline = report_with("a", {"one": CaseOutcome.SUCCESS, "two": CaseOutcome.SUCCESS})
    candidate = report_with("b", {"one": CaseOutcome.SUCCESS, "two": CaseOutcome.FAILED})

    comparison = compare_reports(baseline, candidate)

    assert comparison.has_regression
    assert [case.case_id for case in comparison.regressions] == ["two"]


def test_a_case_that_started_passing_is_not_a_regression() -> None:
    baseline = report_with("a", {"one": CaseOutcome.FAILED})
    candidate = report_with("b", {"one": CaseOutcome.SUCCESS})

    comparison = compare_reports(baseline, candidate)

    assert not comparison.has_regression
    assert [case.case_id for case in comparison.fixes] == ["one"]


def test_direction_decides_whether_a_delta_is_better_or_worse() -> None:
    baseline = report_with("a", {"one": CaseOutcome.FAILED})
    candidate = report_with("b", {"one": CaseOutcome.SUCCESS})

    comparison = compare_reports(baseline, candidate)
    success = next(m for m in comparison.metrics if m.id == "task_success_rate")

    assert success.movement is Movement.IMPROVED
    assert success.delta == 1.0


def test_an_unknown_metric_on_either_side_stays_unknown() -> None:
    """Treating a missing measurement as zero would manufacture an improvement out
    of a runtime that simply reports less than the other one."""
    baseline = report_with("a", {"one": CaseOutcome.SUCCESS})
    candidate = report_with("b", {"one": CaseOutcome.SUCCESS}, cost_usd=1.5)

    comparison = compare_reports(baseline, candidate)
    cost = next(m for m in comparison.metrics if m.id == "cost_usd")

    assert cost.movement is Movement.UNKNOWN
    assert cost.delta is None
    assert "unknown on the baseline" in cost.note


def test_comparing_different_case_sets_is_flagged() -> None:
    baseline = report_with("a", {"one": CaseOutcome.SUCCESS})
    candidate = report_with("b", {"two": CaseOutcome.SUCCESS})

    comparison = compare_reports(baseline, candidate)

    assert comparison.case_mismatch == ["one", "two"]
    assert "not directly" in comparison.render()


def test_a_comparison_never_declares_a_winner() -> None:
    baseline = report_with("a", {"one": CaseOutcome.FAILED})
    candidate = report_with("b", {"one": CaseOutcome.SUCCESS})

    text = compare_reports(baseline, candidate).render().lower()

    assert "no winner is declared" in text
    assert "no statistical test is performed" in text
    for forbidden in ("is better than", "recommend", "outperforms"):
        assert forbidden not in text


def test_changing_several_axes_at_once_is_called_out() -> None:
    baseline = report_with("a", {"one": CaseOutcome.SUCCESS})
    candidate = report_with("b", {"one": CaseOutcome.SUCCESS})
    candidate.config.runtime = "claude-code"
    candidate.config.context_strategy = "indexed"

    text = compare_reports(baseline, candidate).render()

    assert "2 axes changed at once" in text


def test_the_sample_size_travels_with_the_comparison() -> None:
    baseline = report_with("a", {"one": CaseOutcome.SUCCESS, "two": CaseOutcome.SUCCESS})
    candidate = report_with("b", {"one": CaseOutcome.SUCCESS, "two": CaseOutcome.FAILED})

    text = compare_reports(baseline, candidate).render()

    assert "Sample size: 2 attempted case(s)" in text
    assert "One case is worth 50%" in text


# --------------------------------------------------------------------------- reports


def test_a_report_states_what_it_does_not_say() -> None:
    text = report_with("a", {"one": CaseOutcome.SUCCESS}).render()

    assert "What this report does not say" in text
    assert "does not transfer" in text or "does not predict" in text
    assert "does not measure code quality" in text


def test_unattempted_cases_are_listed_rather_than_dropped() -> None:
    text = report_with("a", {"one": CaseOutcome.UNAVAILABLE}).render()

    assert "Not attempted" in text
    assert "excluded from every rate's denominator" in text


def test_saving_never_overwrites_and_sorts_by_time(tmp_path: Path) -> None:
    first = report_with("cfg", {"one": CaseOutcome.SUCCESS})
    second = report_with("cfg", {"one": CaseOutcome.FAILED})
    second.report_id = "eval_second"

    path_one = save_report(first, tmp_path)
    path_two = save_report(second, tmp_path)

    assert path_one != path_two
    assert len(list_reports(tmp_path, config_id="cfg")) == 2
    assert load_report(path_one).results[0].outcome is CaseOutcome.SUCCESS


def test_a_report_resolves_by_config_id(tmp_path: Path) -> None:
    save_report(report_with("cfg", {"one": CaseOutcome.SUCCESS}), tmp_path)

    assert resolve_report("cfg", tmp_path).config.id == "cfg"


def test_resolving_something_that_does_not_exist_says_so(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="neither a report file nor a configuration"):
        resolve_report("ghost", tmp_path)


def test_a_config_id_cannot_write_outside_the_report_directory(tmp_path: Path) -> None:
    report = report_with("../../escaped", {"one": CaseOutcome.SUCCESS})

    path = save_report(report, tmp_path)

    assert path.parent == tmp_path / "reports"


def test_check_outcomes_survive_a_round_trip(tmp_path: Path) -> None:
    report = report_with("cfg", {"one": CaseOutcome.FAILED})
    report.results[0].checks = [CheckOutcome(id="suite", passed=False, exit_code=1, excerpt="boom")]

    reloaded = load_report(save_report(report, tmp_path))

    assert reloaded.results[0].checks[0].excerpt == "boom"
