"""Tests for continuous engineering.

Three properties carry the weight here, and each is asserted rather than
described: nothing modifies code, nothing runs without an approval, and security
outranks cosmetic work at equal severity.

The fourth is about noise. A backlog people ignore is worse than no backlog, so
the tests check that low-confidence findings are withheld, that a detector firing
a hundred times collapses into one question, and that no single category can fill
a run's proposals.
"""

from __future__ import annotations

import subprocess
from datetime import date, timedelta
from pathlib import Path

import pytest

from devforge.continuous.backlog import (
    Backlog,
    approve,
    execute,
    load_accepted,
    load_backlog,
    reject,
    save_backlog,
    summarise,
    verify,
)
from devforge.continuous.detectors import DETECTORS
from devforge.continuous.detectors.base import read_sources
from devforge.continuous.detectors.code import (
    DeadCodeDetector,
    DuplicationDetector,
    PerformanceDetector,
    TechDebtDetector,
)
from devforge.continuous.detectors.docs import DocDriftDetector
from devforge.continuous.detectors.quality import (
    ArchitectureDetector,
    FlakyTestDetector,
    MissingTestsDetector,
)
from devforge.continuous.detectors.supply import DependencyDetector, SecurityDetector
from devforge.continuous.engine import FLOOD_LIMIT, detect, prioritize, propose
from devforge.continuous.models import (
    Category,
    DetectorStatus,
    Finding,
    Proposal,
    ProposalState,
    Risk,
    Severity,
    Suppression,
)
from devforge.core.errors import ConfigError, DevForgeError

REPO = Path(__file__).resolve().parents[1]


def write(root: Path, files: dict[str, str]) -> Path:
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return root


def finding(**kwargs) -> Finding:
    base = {
        "finding_id": "CE-TEST-999",
        "category": Category.TECH_DEBT,
        "title": "a thing",
        "severity": Severity.LOW,
        "confidence": 0.9,
        "evidence": "observed here",
        "recommended_action": "do something",
    }
    return Finding(**{**base, **kwargs})


# --------------------------------------------------------------------------- model


def test_a_finding_carries_every_field_the_brief_names() -> None:
    item = finding(affected_files=["a.py:1"], estimated_risk=Risk.HIGH)

    for field in (
        "finding_id",
        "severity",
        "confidence",
        "evidence",
        "affected_files",
        "recommended_action",
        "estimated_risk",
    ):
        assert hasattr(item, field), f"a finding must carry {field}"


def test_a_finding_without_evidence_is_rejected() -> None:
    """Without evidence the claim cannot be checked, which makes it an opinion."""
    with pytest.raises(ValueError, match="an opinion"):
        finding(evidence="   ")


def test_a_finding_must_say_what_to_do() -> None:
    with pytest.raises(ValueError, match="say what to do"):
        finding(recommended_action="")


def test_security_outranks_cosmetic_work_at_equal_severity() -> None:
    """The brief's rule, and the reason category is a term of its own."""
    vulnerability = finding(category=Category.SECURITY, severity=Severity.HIGH)
    cosmetic = finding(category=Category.DUPLICATION, severity=Severity.HIGH)

    assert vulnerability.priority > cosmetic.priority


def test_a_high_security_finding_outranks_a_critical_cosmetic_one() -> None:
    """The stronger claim: the bonus is large enough to cross a severity step."""
    vulnerability = finding(category=Category.SECURITY, severity=Severity.HIGH)
    cosmetic = finding(category=Category.DEAD_CODE, severity=Severity.CRITICAL)

    assert vulnerability.priority > cosmetic.priority


def test_a_riskier_fix_sorts_below_a_cheaper_one() -> None:
    cheap = finding(estimated_risk=Risk.LOW)
    dangerous = finding(estimated_risk=Risk.HIGH)

    assert cheap.priority > dangerous.priority


def test_prioritize_is_stable_between_runs() -> None:
    findings = [finding(finding_id=f"CE-{n}", affected_files=[f"{n}.py"]) for n in range(5)]

    assert [f.finding_id for f in prioritize(findings)] == [
        f.finding_id for f in prioritize(list(reversed(findings)))
    ]


# ------------------------------------------------------------------------ detectors


def test_every_category_the_brief_names_has_a_detector() -> None:
    covered = {detector.category for detector in DETECTORS()}
    missing = sorted(c.value for c in Category if c not in covered)

    assert not missing, f"categories with no detector: {missing}"


def test_a_detector_that_cannot_run_says_so_instead_of_finding_nothing(tmp_path: Path) -> None:
    """"Found nothing" and "could not look" must never render the same."""
    report = FlakyTestDetector().run(read_sources(tmp_path))

    assert report.status is DetectorStatus.UNAVAILABLE
    assert report.detail
    assert not report.findings


def test_a_detector_that_raises_does_not_take_the_scan_with_it(tmp_path: Path) -> None:
    class Exploding:
        name = "exploding"
        category = Category.TECH_DEBT

        def run(self, workspace):
            raise RuntimeError("boom")

    report = detect(tmp_path, detectors=[Exploding()])

    assert report.reports[0].status is DetectorStatus.UNAVAILABLE
    assert "boom" in report.reports[0].detail


def test_credential_files_are_never_read_by_any_detector(tmp_path: Path) -> None:
    write(tmp_path, {".env": "TOKEN=abc123def456\n", "app.py": "x = 1\n"})

    workspace = read_sources(tmp_path)

    assert all(source.path != ".env" for source in workspace.files)
    assert "credential material" in workspace.skipped[".env"]


def test_tech_debt_finds_markers_and_says_where(tmp_path: Path) -> None:
    write(tmp_path, {"app.py": "def f():\n    # TODO: finish this\n    return 1\n"})

    report = TechDebtDetector().run(read_sources(tmp_path))

    assert len(report.findings) == 1
    assert report.findings[0].affected_files == ["app.py:2"]
    assert report.findings[0].confidence >= 0.9


def test_a_cluster_of_markers_is_one_finding_not_six(tmp_path: Path) -> None:
    """Six markers in a file are usually one unfinished decision."""
    body = "".join(f"# TODO: item {n}\n" for n in range(6))
    write(tmp_path, {"app.py": body})

    report = TechDebtDetector().run(read_sources(tmp_path))

    assert len(report.findings) == 1
    assert report.findings[0].finding_id == "CE-DEBT-002"


def test_dead_code_ignores_a_name_used_in_a_string(tmp_path: Path) -> None:
    """Registries, getattr and entry points all reference by string."""
    write(
        tmp_path,
        {
            "app.py": "def handler():\n    return 1\n",
            "registry.py": 'ROUTES = {"go": "handler"}\n',
        },
    )

    report = DeadCodeDetector().run(read_sources(tmp_path))

    assert not report.findings


def test_dead_code_ignores_a_decorated_definition(tmp_path: Path) -> None:
    write(tmp_path, {"app.py": "import x\n\n\n@x.register\ndef handler():\n    return 1\n"})

    assert not DeadCodeDetector().run(read_sources(tmp_path)).findings


def test_dead_code_is_less_sure_about_a_public_name(tmp_path: Path) -> None:
    """A private helper nobody calls is probably dead. A public one may be this
    project's API, so its confidence sits below the default threshold and the
    engine withholds it rather than proposing that someone delete a surface."""
    write(
        tmp_path,
        {"app.py": "def _forgotten():\n    return 1\n\n\ndef exported():\n    return 2\n"},
    )

    report = DeadCodeDetector().run(read_sources(tmp_path))
    by_name = {f.title.split("'")[1]: f for f in report.findings}

    assert by_name["_forgotten"].confidence > by_name["exported"].confidence
    assert by_name["exported"].confidence < 0.6
    assert by_name["exported"].estimated_risk is Risk.HIGH


def test_duplication_needs_two_files_not_two_copies(tmp_path: Path) -> None:
    block = "".join(f"    value_{n} = compute({n})\n" for n in range(10))
    write(tmp_path, {"one.py": f"def a():\n{block}", "two.py": f"def b():\n{block}"})

    report = DuplicationDetector().run(read_sources(tmp_path))

    assert report.findings
    assert len(report.findings[0].affected_files) >= 2


def test_duplication_inside_one_file_is_not_reported(tmp_path: Path) -> None:
    """Repetition in one file is often a deliberate table."""
    block = "".join(f"    value_{n} = compute({n})\n" for n in range(10))
    write(tmp_path, {"one.py": f"def a():\n{block}\n\ndef b():\n{block}"})

    assert not DuplicationDetector().run(read_sources(tmp_path)).findings


def test_architecture_finds_an_import_cycle(tmp_path: Path) -> None:
    write(tmp_path, {"a.py": "import b\n", "b.py": "import a\n"})

    report = ArchitectureDetector().run(read_sources(tmp_path))

    assert any(f.finding_id == "CE-ARCH-001" for f in report.findings)


def test_architecture_ignores_a_cycle_through_a_third_party_package(tmp_path: Path) -> None:
    """A cycle through someone else's code is not this project's cycle."""
    write(tmp_path, {"a.py": "import json\nimport os\n"})

    assert not [
        f for f in ArchitectureDetector().run(read_sources(tmp_path)).findings
        if f.finding_id == "CE-ARCH-001"
    ]


def test_missing_tests_is_unavailable_when_there_are_no_tests(tmp_path: Path) -> None:
    """'Every module is untested' is true here and is not a useful backlog."""
    write(tmp_path, {"app.py": "def go():\n    return 1\n"})

    report = MissingTestsDetector().run(read_sources(tmp_path))

    assert report.status is DetectorStatus.UNAVAILABLE


def test_missing_tests_names_the_untested_module(tmp_path: Path) -> None:
    write(
        tmp_path,
        {
            "app.py": "def go():\n    return 1\n",
            "other.py": "def stay():\n    return 2\n",
            "tests/test_app.py": "from app import go\n\n\ndef test_go():\n    assert go()\n",
        },
    )

    report = MissingTestsDetector().run(read_sources(tmp_path))

    assert [f.affected_files[0] for f in report.findings] == ["other.py"]


def test_performance_finds_a_compile_in_a_loop(tmp_path: Path) -> None:
    write(
        tmp_path,
        {"app.py": "import re\n\n\ndef go(items):\n    for item in items:\n"
                   "        re.compile(item)\n"},
    )

    report = PerformanceDetector().run(read_sources(tmp_path))

    assert [f.finding_id for f in report.findings] == ["CE-PERF-002"]


def test_a_performance_finding_never_claims_to_be_a_measurement(tmp_path: Path) -> None:
    write(
        tmp_path,
        {"app.py": "import re\n\n\ndef go(items):\n    for item in items:\n"
                   "        re.compile(item)\n"},
    )

    report = PerformanceDetector().run(read_sources(tmp_path))

    assert "not a measurement" in report.findings[0].evidence


def test_doc_drift_finds_a_broken_link(tmp_path: Path) -> None:
    write(tmp_path, {"README.md": "See [the guide](docs/gone.md) for details.\n"})

    report = DocDriftDetector().run(read_sources(tmp_path))

    assert [f.finding_id for f in report.findings] == ["CE-DOC-001"]


def test_doc_drift_does_not_flag_a_backticked_path_in_prose(tmp_path: Path) -> None:
    """Ninety-four of these fired on DevForge's own tree and none was real."""
    write(tmp_path, {"README.md": "The adapter lives in `runtime/claude_code.py`.\n"})

    assert not DocDriftDetector().run(read_sources(tmp_path)).findings


def test_doc_drift_does_not_flag_a_documented_function_that_exists(tmp_path: Path) -> None:
    write(
        tmp_path,
        {"app.py": "def process():\n    return 1\n", "README.md": "Call `process()` first.\n"},
    )

    assert not DocDriftDetector().run(read_sources(tmp_path)).findings


def test_dependency_reports_an_unpinned_requirement(tmp_path: Path) -> None:
    write(
        tmp_path,
        {"pyproject.toml": '[project]\nname = "x"\ndependencies = ["requests"]\n'},
    )

    report = DependencyDetector().run(read_sources(tmp_path))

    assert any(f.finding_id == "CE-DEP-001" for f in report.findings)


def test_dependency_states_the_question_it_does_not_answer(tmp_path: Path) -> None:
    """"Outdated" needs a package index, which is a network call and a trust
    decision the operator makes."""
    write(tmp_path, {"pyproject.toml": '[project]\nname = "x"\ndependencies = []\n'})

    report = DependencyDetector().run(read_sources(tmp_path))

    assert "package index" in report.detail
    assert "not measured" in report.detail


def test_dependency_is_unavailable_without_a_manifest(tmp_path: Path) -> None:
    assert DependencyDetector().run(read_sources(tmp_path)).status is DetectorStatus.UNAVAILABLE


def test_the_security_detector_reuses_the_security_scanner(tmp_path: Path) -> None:
    """One rule set, so the two can never disagree about the same file."""
    write(tmp_path, {"app.py": "import os\n\n\ndef go(cmd):\n    os.system(cmd)\n"})

    report = SecurityDetector().run(read_sources(tmp_path))

    assert report.findings
    assert all(f.category is Category.SECURITY for f in report.findings)
    assert all(f.finding_id.startswith("SEC-") for f in report.findings)


# --------------------------------------------------------------------------- noise


def test_a_low_confidence_finding_is_withheld_and_counted(tmp_path: Path) -> None:
    class Unsure:
        name = "unsure"
        category = Category.DEAD_CODE

        def run(self, workspace):
            from devforge.continuous.models import DetectorReport

            return DetectorReport(
                detector=self.name,
                category=self.category,
                findings=[finding(category=Category.DEAD_CODE, confidence=0.3)],
            )

    report = detect(tmp_path, detectors=[Unsure()])

    assert not report.findings
    assert report.withheld == 1


def test_security_is_exempt_from_the_confidence_threshold(tmp_path: Path) -> None:
    """The cost of checking a false positive is a minute; missing a real one is not."""

    class Unsure:
        name = "unsure"
        category = Category.SECURITY

        def run(self, workspace):
            from devforge.continuous.models import DetectorReport

            return DetectorReport(
                detector=self.name,
                category=self.category,
                findings=[finding(category=Category.SECURITY, confidence=0.3)],
            )

    report = detect(tmp_path, detectors=[Unsure()])

    assert len(report.findings) == 1


def test_a_flood_of_findings_becomes_one_question(tmp_path: Path) -> None:
    class Noisy:
        name = "noisy"
        category = Category.TECH_DEBT

        def run(self, workspace):
            from devforge.continuous.models import DetectorReport

            return DetectorReport(
                detector=self.name,
                category=self.category,
                findings=[
                    finding(affected_files=[f"file{n}.py:1"]) for n in range(FLOOD_LIMIT + 10)
                ],
            )

    report = detect(tmp_path, detectors=[Noisy()])

    assert len(report.findings) == 1
    assert "MANY" in report.findings[0].finding_id
    assert "policy" in report.findings[0].recommended_action


def test_no_single_category_can_fill_a_run_of_proposals() -> None:
    findings = [
        finding(category=Category.MISSING_TESTS, affected_files=[f"pkg{n}/mod.py"])
        for n in range(20)
    ]
    findings.append(
        finding(category=Category.SECURITY, severity=Severity.HIGH, affected_files=["a/b.py"])
    )

    proposals = propose(findings, limit=5)
    categories = [proposal.findings[0].category for proposal in proposals]

    assert Category.SECURITY in categories
    assert categories.count(Category.MISSING_TESTS) <= 3


def test_findings_in_one_directory_become_one_proposal() -> None:
    findings = [
        finding(category=Category.MISSING_TESTS, affected_files=[f"pkg/mod{n}.py"])
        for n in range(4)
    ]

    proposals = propose(findings)

    assert len(proposals) == 1
    assert len(proposals[0].findings) == 4


def test_an_accepted_finding_is_suppressed_until_its_acceptance_expires(tmp_path: Path) -> None:
    class One:
        name = "one"
        category = Category.TECH_DEBT

        def run(self, workspace):
            from devforge.continuous.models import DetectorReport

            return DetectorReport(
                detector=self.name,
                category=self.category,
                findings=[finding(affected_files=["app.py:1"])],
            )

    today = date(2026, 1, 1)
    live = Suppression(
        finding_id="CE-TEST-999",
        location="app.py",
        reason="deliberate",
        expires=today + timedelta(days=1),
    )
    stale = Suppression(
        finding_id="CE-TEST-999",
        location="app.py",
        reason="deliberate",
        expires=today - timedelta(days=1),
    )

    suppressed = detect(tmp_path, detectors=[One()], suppressions=[live], today=today)
    expired = detect(tmp_path, detectors=[One()], suppressions=[stale], today=today)

    assert not suppressed.findings and len(suppressed.suppressed) == 1
    assert len(expired.findings) == 1, "an expired acceptance must stop suppressing"


# ---------------------------------------------------------------------- the backlog


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    for argv in (
        ["init", "--quiet", "-b", "main"],
        ["config", "user.email", "t@devforge.invalid"],
        ["config", "user.name", "t"],
    ):
        subprocess.run(["git", *argv], cwd=root, check=True, capture_output=True)
    write(root, {"app.py": "# TODO: finish this\nVALUE = 1\n"})
    subprocess.run(["git", "add", "--all"], cwd=root, check=True, capture_output=True)
    subprocess.run(
        ["git", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "init"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    return root


def backlog_with(repo: Path) -> tuple[Backlog, Proposal]:
    report = detect(repo)
    backlog = Backlog()
    added, _ = backlog.merge(propose(report.findings))
    assert added, "the fixture repository must produce at least one proposal"
    return backlog, added[0]


def test_execute_refuses_a_proposal_nobody_approved(repo: Path) -> None:
    """The brief's rule: no automatic modification, and no unapproved work."""
    backlog, proposal = backlog_with(repo)

    with pytest.raises(ConfigError, match="not approved"):
        execute(backlog, proposal.proposal_id, repo)

    assert not (repo / ".devforge" / "worktrees").exists()


def test_execute_prepares_a_worktree_and_changes_no_source(repo: Path) -> None:
    backlog, proposal = backlog_with(repo)
    before = (repo / "app.py").read_text(encoding="utf-8")
    approve(backlog, proposal.proposal_id, by="tester")

    preparation = execute(backlog, proposal.proposal_id, repo)

    assert Path(preparation.worktree).is_dir()
    assert Path(preparation.issue_path).is_file()
    assert (repo / "app.py").read_text(encoding="utf-8") == before, "source must be untouched"
    assert backlog.require(proposal.proposal_id).state is ProposalState.EXECUTING


def test_the_issue_tells_the_agent_not_to_trust_the_finding(repo: Path) -> None:
    _, proposal = backlog_with(repo)

    body = proposal.issue_body()

    assert "Confirm each one before acting" in body
    assert "Do not weaken a test" in body


def test_verification_re_runs_the_detector_rather_than_believing_a_report(repo: Path) -> None:
    backlog, proposal = backlog_with(repo)
    approve(backlog, proposal.proposal_id)

    still_there = verify(backlog, proposal.proposal_id, repo)
    assert still_there.remaining
    assert not still_there.complete
    assert backlog.require(proposal.proposal_id).state is ProposalState.FAILED

    (repo / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    fixed = verify(backlog, proposal.proposal_id, repo)

    assert fixed.resolved and fixed.complete
    assert backlog.require(proposal.proposal_id).state is ProposalState.VERIFIED


def test_a_rejected_proposal_stays_rejected_when_detection_runs_again(repo: Path) -> None:
    """Otherwise the backlog asks the same question every day."""
    backlog, proposal = backlog_with(repo)
    reject(backlog, proposal.proposal_id, reason="not now")

    added, known = backlog.merge(propose(detect(repo).findings))

    assert not added
    assert known and known[0].state is ProposalState.REJECTED


def test_the_backlog_survives_a_round_trip(repo: Path) -> None:
    backlog, proposal = backlog_with(repo)
    approve(backlog, proposal.proposal_id, by="tester", reason="worth it")
    save_backlog(backlog, repo)

    reloaded = load_backlog(repo)

    assert reloaded.require(proposal.proposal_id).decided_by == "tester"
    assert summarise(reloaded) == {"approved": 1}


def test_an_unreadable_backlog_is_an_error_not_an_empty_one(repo: Path) -> None:
    """Silently emptying it would lose every past decision and re-propose everything."""
    from devforge.continuous.backlog import backlog_path

    path = backlog_path(repo)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{not json", encoding="utf-8")

    with pytest.raises(ConfigError, match="could not read the backlog"):
        load_backlog(repo)


def test_an_unreadable_acceptance_file_is_an_error(repo: Path) -> None:
    from devforge.continuous.backlog import accepted_path

    path = accepted_path(repo)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("accepted: not-a-list\n", encoding="utf-8")

    with pytest.raises(ConfigError, match="expected a list"):
        load_accepted(repo)


def test_a_missing_acceptance_file_is_simply_no_acceptances(repo: Path) -> None:
    assert load_accepted(repo) == []


# -------------------------------------------------------------- against this repo


def test_detection_on_this_repository_stays_readable() -> None:
    """The anti-noise rule, measured on a real tree rather than a fixture.

    The threshold is generous on purpose: this asserts that the output is a list
    a person could read in a sitting, not that DevForge is clean.
    """
    report = detect(REPO)

    assert len(report.findings) < 120, (
        f"{len(report.findings)} findings is a wall of text, not a backlog: "
        f"{[f.finding_id for f in report.findings[:20]]}"
    )
    assert len(propose(report.findings)) <= 10


def test_the_security_detector_finds_what_the_security_centre_finds() -> None:
    from devforge.security.scan import scan_workspace

    scan = scan_workspace(REPO)
    detected = SecurityDetector().run(read_sources(REPO))

    assert len(detected.findings) == len(scan.findings)


def test_devforge_error_is_the_base_of_every_failure_here() -> None:
    assert issubclass(ConfigError, DevForgeError)
