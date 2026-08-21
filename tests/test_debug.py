"""Autonomous debugging: reproduction, evidence, the patch guard and the benchmark.

The security-relevant tests here are adversarial by design. A patch guard is only
worth having if it catches a patch that is actively trying to look innocent, so
each detector is exercised with the shape an agent would actually produce when it
decides that deleting the assertion is easier than fixing the code.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from devforge.core.models import ToolStatus, VerificationStatus
from devforge.core.state.store import ProjectStore
from devforge.core.workflow.spec import VerifierSpec
from devforge.debug import evidence as ev
from devforge.debug.benchmark import (
    BUILTIN_SOLVERS,
    BenchmarkRunner,
    cheat_solver,
    load_builtin_suite,
    reference_solver,
)
from devforge.debug.models import (
    Diagnosis,
    EvidenceKind,
    PatchCategory,
    PatchVerdict,
    RepairOutcome,
    RepairReport,
    Reproduction,
    ReproductionOutcome,
    VerificationSummary,
)
from devforge.debug.patch_guard import parse_diff, review_patch
from devforge.debug.reproduce import reproduce
from devforge.policy.engine import PolicyEngine
from devforge.tools.base import ToolContext
from devforge.tools.debug import DebugTool
from devforge.verification.base import VerificationContext
from devforge.verification.repair import PatchGuardVerifier, RepairReportVerifier


def policy_for(root: Path) -> PolicyEngine:
    return PolicyEngine.load(None, workspace=root)


def diff_for(path: str, *, removed: list[str] = (), added: list[str] = ()) -> str:
    body = "".join(f"-{line}\n" for line in removed) + "".join(f"+{line}\n" for line in added)
    return (
        f"diff --git a/{path} b/{path}\n"
        f"--- a/{path}\n"
        f"+++ b/{path}\n"
        f"@@ -1,{max(len(removed), 1)} +1,{max(len(added), 1)} @@\n"
        f"{body}"
    )


# --------------------------------------------------------------------------- patch guard


def test_parse_diff_tracks_files_and_line_numbers() -> None:
    diff = (
        "diff --git a/src/app.py b/src/app.py\n"
        "--- a/src/app.py\n"
        "+++ b/src/app.py\n"
        "@@ -10,3 +10,3 @@\n"
        " context\n"
        "-old line\n"
        "+new line\n"
    )
    changes = parse_diff(diff)

    assert [c.path for c in changes] == ["src/app.py"]
    assert changes[0].removed_lines == [(11, "old line")]
    assert changes[0].added_lines == [(11, "new line")]


def test_a_genuine_fix_is_clean() -> None:
    review = review_patch(
        diff_for("app.py", removed=["    return items[-n + 1:]"], added=["    return items[-n:]"])
    )

    assert review.verdict() is PatchVerdict.CLEAN
    assert review.files_changed == ["app.py"]
    assert not review.major


def test_deleting_assertions_is_major() -> None:
    review = review_patch(
        diff_for(
            "tests/test_app.py",
            removed=["    assert total == 3", "    assert name == 'ada'"],
            added=["    pass"],
        )
    )

    assert review.verdict() is PatchVerdict.SUSPICIOUS
    assert review.major[0].category is PatchCategory.ASSERTION_REMOVED


def test_rewriting_an_assertion_is_not_flagged() -> None:
    """A fix legitimately changes an expected value; only losing checks is suspect."""
    review = review_patch(
        diff_for(
            "tests/test_app.py",
            removed=["    assert average([1, 2]) == 1"],
            added=["    assert average([1, 2]) == 1.5"],
        )
    )

    assert review.verdict() is PatchVerdict.CLEAN


def test_tautological_assertion_is_major() -> None:
    review = review_patch(diff_for("tests/test_app.py", added=["    assert True"]))

    assert any(f.detail == "an assertion that cannot fail was added" for f in review.major)


@pytest.mark.parametrize(
    ("line", "category"),
    [
        ("@pytest.mark.skip(reason='flaky')", PatchCategory.TEST_DISABLED),
        ("@pytest.mark.xfail", PatchCategory.TEST_DISABLED),
        ("    it.skip('renders', () => {})", PatchCategory.TEST_DISABLED),
        ("AUTH_REQUIRED = False", PatchCategory.AUTH_DISABLED),
        ("    permission_classes = []", PatchCategory.AUTH_DISABLED),
        ("    skip_validation = True", PatchCategory.VALIDATION_BYPASSED),
        ("    if False:", PatchCategory.VALIDATION_BYPASSED),
        ("    requests.get(url, verify=False)", PatchCategory.SECURITY_CHECK_OFF),
        ("    ctx.check_hostname = False", PatchCategory.SECURITY_CHECK_OFF),
        ("    try { risky() } catch {}", PatchCategory.EXCEPTION_SWALLOWED),
    ],
)
def test_each_suspicious_pattern_is_detected(line: str, category: PatchCategory) -> None:
    review = review_patch(diff_for("src/app.py", added=[line]))

    assert category in {finding.category for finding in review.major}


def test_removing_an_auth_decorator_is_detected() -> None:
    review = review_patch(diff_for("src/api.py", removed=["@login_required"]))

    assert PatchCategory.AUTH_DISABLED in {f.category for f in review.major}


def test_swallowing_an_exception_needs_both_lines_added() -> None:
    swallowed = review_patch(
        diff_for("src/app.py", added=["    except Exception:", "        pass"])
    )
    handled = review_patch(
        diff_for(
            "src/app.py",
            added=["    except Exception as exc:", "        raise Boom from exc"],
        )
    )

    assert PatchCategory.EXCEPTION_SWALLOWED in {f.category for f in swallowed.major}
    assert not handled.major


def test_editing_the_permission_policy_is_major() -> None:
    review = review_patch(
        diff_for("policies/permissions.yaml", added=["  default: allow"])
    )

    categories = {finding.category for finding in review.major}
    assert PatchCategory.POLICY_WEAKENED in categories


def test_patch_outside_the_workspace_is_major() -> None:
    review = review_patch(diff_for("../other-project/app.py", added=["x = 1"]))

    assert PatchCategory.SCOPE_ESCAPE in {f.category for f in review.major}


def test_a_secret_in_the_patch_is_reported_and_not_echoed() -> None:
    secret = "sk-ant-" + "A" * 32
    review = review_patch(diff_for("src/app.py", added=[f'    KEY = "{secret}"']))

    assert PatchCategory.SECRET_INTRODUCED in {f.category for f in review.major}
    rendered = review.render()
    assert secret not in rendered
    assert all(secret not in finding.evidence for finding in review.findings)


def test_suppression_comment_is_minor_not_blocking() -> None:
    review = review_patch(diff_for("src/app.py", added=["    value = call()  # noqa"]))

    assert review.verdict() is PatchVerdict.CLEAN
    assert review.minor


def test_an_empty_diff_is_not_a_clean_bill_of_health() -> None:
    assert review_patch("").verdict() is PatchVerdict.EMPTY


def test_deleted_test_file_is_detected() -> None:
    diff = (
        "diff --git a/tests/test_app.py b/tests/test_app.py\n"
        "--- a/tests/test_app.py\n"
        "+++ /dev/null\n"
        "@@ -1,2 +0,0 @@\n"
        "-def test_it():\n"
        "-    assert 1 == 1\n"
    )
    review = review_patch(diff)

    assert PatchCategory.TEST_DELETED in {f.category for f in review.major}


# --------------------------------------------------------------------------- reproduction


def test_deterministic_failure_is_usable(tmp_path: Path) -> None:
    (tmp_path / "test_x.py").write_text("def test_fails():\n    assert False\n", encoding="utf-8")

    result = asyncio.run(
        reproduce(
            ["python", "-m", "pytest", "-q"],
            workspace=tmp_path,
            policy=policy_for(tmp_path),
            runs=2,
        )
    )

    assert result.outcome is ReproductionOutcome.DETERMINISTIC
    assert result.outcome.usable
    assert result.failure_output


def test_a_passing_command_is_not_a_reproduction(tmp_path: Path) -> None:
    (tmp_path / "test_x.py").write_text("def test_ok():\n    assert True\n", encoding="utf-8")

    result = asyncio.run(
        reproduce(
            ["python", "-m", "pytest", "-q"],
            workspace=tmp_path,
            policy=policy_for(tmp_path),
            runs=2,
        )
    )

    assert result.outcome is ReproductionOutcome.NOT_REPRODUCED
    assert not result.outcome.usable


def test_flaky_reproduction_is_reported_as_flaky(tmp_path: Path) -> None:
    """A run that fails half the time cannot certify a repair, and says so."""
    (tmp_path / "test_flaky.py").write_text(
        "from pathlib import Path\n"
        "MARK = Path(__file__).parent / 'seen'\n"
        "\n"
        "\n"
        "def test_only_fails_the_first_time():\n"
        "    first = not MARK.exists()\n"
        "    MARK.write_text('x')\n"
        "    assert not first\n",
        encoding="utf-8",
    )

    result = asyncio.run(
        reproduce(
            ["python", "-m", "pytest", "-q"],
            workspace=tmp_path,
            policy=policy_for(tmp_path),
            runs=2,
        )
    )

    assert result.outcome is ReproductionOutcome.FLAKY
    assert not result.outcome.usable
    assert "would not prove a repair" in result.summary


def test_a_command_outside_the_allowlist_is_refused(tmp_path: Path) -> None:
    result = asyncio.run(
        reproduce(
            ["curl", "http://example.com"],
            workspace=tmp_path,
            policy=policy_for(tmp_path),
            runs=1,
        )
    )

    assert result.outcome is ReproductionOutcome.UNAVAILABLE
    assert not result.attempts


# --------------------------------------------------------------------------- evidence


def test_stack_traces_and_frames_are_extracted() -> None:
    text = (
        "Traceback (most recent call last):\n"
        '  File "app.py", line 12, in main\n'
        "    boom()\n"
        "ValueError: nope\n"
        "trailing noise\n"
    )

    traces = ev.extract_stack_traces(text)
    assert len(traces) == 1
    assert "ValueError: nope" in traces[0]
    assert "trailing noise" not in traces[0]
    assert ev.traceback_frames(text) == [("app.py", 12)]


def test_test_failures_keep_their_order() -> None:
    text = "FAILED tests/test_a.py::test_one - AssertionError\nE   assert 1 == 2\nnoise\n"

    assert ev.extract_test_failures(text).splitlines() == [
        "FAILED tests/test_a.py::test_one - AssertionError",
        "E   assert 1 == 2",
    ]


def test_evidence_is_redacted_and_says_so(project: ProjectStore) -> None:
    collector = ev.EvidenceCollector(workspace=project.root, policy=policy_for(project.root))
    secret = "sk-ant-" + "B" * 32
    collector.add(EvidenceKind.LOG, "app log", f"connecting with {secret}")

    item = collector.bundle.items[0]
    assert secret not in item.content
    assert item.redacted


def test_evidence_refuses_denied_paths_and_records_the_refusal(project: ProjectStore) -> None:
    (project.root / ".env").write_text("API_TOKEN=super-secret-value\n", encoding="utf-8")
    collector = ev.EvidenceCollector(workspace=project.root, policy=policy_for(project.root))

    collector.source_files([".env"])

    assert not collector.bundle.items
    assert any(".env" in entry for entry in collector.bundle.refused)
    assert "super-secret-value" not in collector.bundle.render()


def test_runtime_state_reports_env_names_never_values(
    project: ProjectStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("MY_DEPLOY_TOKEN", "hunter2-not-a-shape-we-detect")
    collector = ev.EvidenceCollector(workspace=project.root, policy=policy_for(project.root))

    collector.runtime_state()

    content = collector.bundle.of(EvidenceKind.RUNTIME_STATE)[0].content
    assert "MY_DEPLOY_TOKEN" in content
    assert "hunter2-not-a-shape-we-detect" not in content


def test_source_is_read_only_for_frames_inside_the_workspace(project: ProjectStore) -> None:
    (project.root / "app.py").write_text("\n".join(f"line {i}" for i in range(1, 40)), "utf-8")
    collector = ev.EvidenceCollector(workspace=project.root, policy=policy_for(project.root))
    text = (
        "Traceback (most recent call last):\n"
        '  File "app.py", line 20, in main\n'
        '  File "C:\\\\Python311\\\\lib\\\\json\\\\decoder.py", line 355, in raw_decode\n'
        "ValueError: nope\n"
    )

    collector.source_for_traceback(text)

    sources = collector.bundle.of(EvidenceKind.SOURCE)
    assert [item.source for item in sources] == ["app.py:20"]
    assert "line 20" in sources[0].content


def test_browser_console_and_network_errors_become_evidence(project: ProjectStore) -> None:
    from devforge.browser.models import ConsoleMessage, NetworkEntry, PageSnapshot, Viewport

    snapshot = PageSnapshot(
        url="http://localhost:8000/",
        viewport=Viewport(name="desktop", width=1280, height=800),
        console=[
            ConsoleMessage(level="error", text="TypeError: x is not a function", location="a.js:4"),
            ConsoleMessage(level="log", text="hello"),
        ],
        network=[
            NetworkEntry(url="http://localhost:8000/api", status=500),
            NetworkEntry(url="http://localhost:8000/ok", status=200),
        ],
    )
    collector = ev.EvidenceCollector(workspace=project.root, policy=policy_for(project.root))

    collector.from_page(snapshot)

    console = collector.bundle.of(EvidenceKind.BROWSER_CONSOLE)[0]
    network = collector.bundle.of(EvidenceKind.NETWORK_ERROR)[0]
    assert "TypeError" in console.content
    assert "/api" in network.content
    assert "/ok" not in network.content


# --------------------------------------------------------------------------- report model


def test_a_report_missing_any_required_part_is_incomplete() -> None:
    report = RepairReport(bug="x", diagnosis=Diagnosis(summary="cause found"))

    assert not report.complete
    assert set(report.missing_parts()) == {"changed files", "tests", "verification result"}


def test_a_rendered_report_refuses_to_overclaim() -> None:
    report = RepairReport(
        bug="off-by-one",
        diagnosis=Diagnosis(summary="slice boundary", root_cause="-n + 1"),
        tests=["tests/test_app.py::test_last_two"],
        verification=[VerificationSummary(name="tests", status="passed")],
        reproduction=Reproduction(
            argv=["python", "-m", "pytest"], outcome=ReproductionOutcome.DETERMINISTIC
        ),
    )
    rendered = report.render()

    assert "What this report does not say" in rendered
    assert "does not say the defect class is eliminated" in rendered


# --------------------------------------------------------------------------- verifiers


def verification_context(root: Path) -> VerificationContext:
    return VerificationContext(workspace=root, policy=policy_for(root))


def test_patch_guard_verifier_fails_a_weakening_patch(project: ProjectStore) -> None:
    diff = diff_for("tests/test_app.py", removed=["    assert total == 3"], added=["    pass"])
    (project.root / "patch.diff").write_text(diff, encoding="utf-8")
    spec = VerifierSpec(id="patch-guard", kind="patch-guard", params={"diff_file": "patch.diff"})

    result = asyncio.run(PatchGuardVerifier().run(spec, verification_context(project.root)))

    assert result.status is VerificationStatus.FAILED
    assert "assertion_removed" in result.output_excerpt


def test_patch_guard_verifier_passes_a_real_fix(project: ProjectStore) -> None:
    diff = diff_for("app.py", removed=["return items[-n + 1:]"], added=["return items[-n:]"])
    (project.root / "patch.diff").write_text(diff, encoding="utf-8")
    spec = VerifierSpec(id="patch-guard", kind="patch-guard", params={"diff_file": "patch.diff"})

    result = asyncio.run(PatchGuardVerifier().run(spec, verification_context(project.root)))

    assert result.status is VerificationStatus.PASSED


def test_patch_guard_skips_rather_than_passes_an_empty_diff(project: ProjectStore) -> None:
    (project.root / "patch.diff").write_text("", encoding="utf-8")
    spec = VerifierSpec(id="patch-guard", kind="patch-guard", params={"diff_file": "patch.diff"})

    result = asyncio.run(PatchGuardVerifier().run(spec, verification_context(project.root)))

    assert result.status is VerificationStatus.SKIPPED


def test_missing_repair_report_fails(project: ProjectStore) -> None:
    spec = VerifierSpec(id="repair-report", kind="repair-report", params={})

    result = asyncio.run(RepairReportVerifier().run(spec, verification_context(project.root)))

    assert result.status is VerificationStatus.FAILED
    assert "silent modification" in result.output_excerpt


def test_a_template_shaped_report_does_not_count_as_written(project: ProjectStore) -> None:
    (project.root / "REPAIR-REPORT.md").write_text(
        "# Repair report\n\n## Diagnosis\n\n_No summary given._\n\n"
        "## Changed files\n\n_None recorded._\n\n## Tests\n\n_None recorded._\n\n"
        "## Verification\n\n_No verification was run._\n",
        encoding="utf-8",
    )
    spec = VerifierSpec(id="repair-report", kind="repair-report", params={})

    result = asyncio.run(RepairReportVerifier().run(spec, verification_context(project.root)))

    assert result.status is VerificationStatus.FAILED
    assert "empty" in result.summary


def test_a_complete_report_passes(project: ProjectStore) -> None:
    report = RepairReport(
        bug="off-by-one",
        diagnosis=Diagnosis(summary="slice boundary is wrong"),
        tests=["tests/test_app.py::test_last_two"],
        verification=[VerificationSummary(name="tests", status="passed")],
    )
    report.review.files_changed = ["app.py"]
    (project.root / "REPAIR-REPORT.md").write_text(report.render(), encoding="utf-8")
    spec = VerifierSpec(id="repair-report", kind="repair-report", params={})

    result = asyncio.run(RepairReportVerifier().run(spec, verification_context(project.root)))

    assert result.status is VerificationStatus.PASSED


# --------------------------------------------------------------------------- debug tool


def tool_context(root: Path) -> ToolContext:
    return ToolContext(workspace=root, policy=policy_for(root))


def test_debug_tool_rejects_an_unknown_action(project: ProjectStore) -> None:
    result = asyncio.run(DebugTool().invoke("evaluate", {}, tool_context(project.root)))

    assert result.status is ToolStatus.ERROR
    assert "unknown action" in result.error


def test_debug_tool_validates_parameters(project: ProjectStore) -> None:
    result = asyncio.run(
        DebugTool().invoke("reproduce", {"argv": ["x"], "shell": True}, tool_context(project.root))
    )

    assert result.status is ToolStatus.ERROR
    assert "shell" in result.error


def test_debug_tool_refuses_a_command_policy_denies(project: ProjectStore) -> None:
    result = asyncio.run(
        DebugTool().invoke(
            "reproduce", {"argv": ["curl", "http://x"], "runs": 1}, tool_context(project.root)
        )
    )

    assert result.status is ToolStatus.ERROR
    assert result.data["outcome"] == "unavailable"


def test_debug_tool_writes_a_report_and_derives_the_outcome(project: ProjectStore) -> None:
    result = asyncio.run(
        DebugTool().invoke(
            "report",
            {
                "bug": "off-by-one",
                "diagnosis": {"summary": "slice boundary", "root_cause": "-n + 1"},
                "tests": ["tests/test_app.py::test_last_two"],
                "verification": [{"name": "tests", "status": "passed"}],
            },
            tool_context(project.root),
        )
    )

    assert result.status is ToolStatus.OK
    written = (project.root / "REPAIR-REPORT.md").read_text(encoding="utf-8")
    assert "## Diagnosis" in written
    # No files changed in this workspace, so the tool must not call it repaired.
    assert result.data["outcome"] != RepairOutcome.REPAIRED.value


def test_debug_tool_collects_evidence_without_reading_denied_files(project: ProjectStore) -> None:
    (project.root / ".env").write_text("SECRET_KEY=abcdef123456\n", encoding="utf-8")

    result = asyncio.run(
        DebugTool().invoke(
            "evidence",
            {"output": "E   assert 1 == 2", "source": [".env"], "include_diff": False},
            tool_context(project.root),
        )
    )

    assert result.status is ToolStatus.OK
    assert "abcdef123456" not in result.output
    assert any(".env" in entry for entry in result.data["refused"])


# --------------------------------------------------------------------------- benchmark


def test_the_builtin_suite_is_well_formed() -> None:
    suite = load_builtin_suite()

    assert len(suite.cases) >= 8
    for case in suite.cases:
        assert case.fix, f"{case.id} has no reference fix"
        # A reference fix that edited a test would be the very behaviour the guard
        # exists to reject, and would silently teach the benchmark to accept it.
        assert all("test" not in Path(p).name for p in case.fix), case.id
        assert any("test" in Path(p).name for p in case.files), case.id


def test_solver_names_are_stable() -> None:
    assert set(BUILTIN_SOLVERS) == {"reference", "cheat", "none"}


@pytest.mark.parametrize("case_id", ["off-by-one", "swallowed-exception"])
def test_reference_fix_scores_as_repaired(case_id: str, tmp_path: Path) -> None:
    suite = load_builtin_suite()
    runner = BenchmarkRunner(policy=policy_for(tmp_path))

    result = asyncio.run(runner.run_case(suite.case(case_id), reference_solver))

    assert result.reproduced == ReproductionOutcome.DETERMINISTIC.value
    assert result.outcome is RepairOutcome.REPAIRED
    assert result.tests_pass_after


@pytest.mark.parametrize("case_id", ["off-by-one", "swallowed-exception"])
def test_deleting_the_assertions_makes_tests_pass_and_still_scores_zero(
    case_id: str, tmp_path: Path
) -> None:
    """The adversarial control, and the whole reason the score means anything.

    The suite is genuinely green after the cheat - `tests_pass_after` is True. A
    benchmark that graded on the suite alone would record this as a repair.
    """
    suite = load_builtin_suite()
    runner = BenchmarkRunner(policy=policy_for(tmp_path))

    result = asyncio.run(runner.run_case(suite.case(case_id), cheat_solver))

    assert result.tests_pass_after
    assert result.outcome is RepairOutcome.REJECTED_SUSPICIOUS
    assert not result.success


def test_changing_nothing_is_not_a_repair(tmp_path: Path) -> None:
    suite = load_builtin_suite()
    runner = BenchmarkRunner(policy=policy_for(tmp_path))

    async def noop(workspace: Path, case: object) -> None:
        return None

    result = asyncio.run(runner.run_case(suite.case("off-by-one"), noop))

    assert result.outcome is RepairOutcome.NOT_REPAIRED
    assert result.patch_verdict == PatchVerdict.EMPTY.value


def test_report_states_what_the_rate_does_not_mean(tmp_path: Path) -> None:
    suite = load_builtin_suite()
    runner = BenchmarkRunner(policy=policy_for(tmp_path))

    report = asyncio.run(
        runner.run([suite.case("off-by-one")], reference_solver, solver_name="reference")
    )
    rendered = report.render()

    assert report.success_rate == 1.0
    assert "does not predict performance on real defects" in rendered
