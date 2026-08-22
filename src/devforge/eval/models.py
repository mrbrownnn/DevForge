"""What an evaluation is made of: cases, configurations, results, reports.

A **case** is a workspace with a known-good answer and objective checks. A
**configuration** is what attempts it - a driver, and when that driver is DevForge
itself, the runtime, model, skill set, workflow and context strategy it ran with.
A **report** is one configuration measured against one set of cases, saved so it
can be compared later.

Two design rules run through these models:

*Grading is by command, not by inspection.* A case passes when its checks - argv
vectors run in the finished workspace - exit as the case says they must. Nothing
grades by reading the agent's own account of what it did.

*Unmeasurable is a value.* A configuration whose runtime reports no token counts
gets ``None`` and a reason, never ``0``. Zero is a measurement; this is the
absence of one, and a report that confuses them is worse than one that omits the
metric.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from devforge.core.errors import ConfigError
from devforge.core.models import utcnow
from devforge.eval.metrics import Metrics

#: How long a single check may run before it is failed as a timeout.
DEFAULT_CHECK_TIMEOUT_S = 300
#: Bound on the output kept from a failing check, so one noisy suite cannot
#: dominate a report.
MAX_CHECK_EXCERPT = 1_500


class Category(str, Enum):
    """The benchmark categories. One case belongs to exactly one."""

    FEATURE = "feature"
    BUGFIX = "bugfix"
    REFACTOR = "refactor"
    TESTING = "testing"
    FRONTEND = "frontend"
    WEBSITE = "website"
    SECURITY = "security"
    DOCUMENTATION = "documentation"


class Expectation(str, Enum):
    """What a check's exit status must be for the case to be graded a success."""

    PASS = "pass"
    FAIL = "fail"


class Check(BaseModel):
    """An executable judgement about the finished workspace.

    ``argv`` is an argument vector and never a shell string, for the same reason
    the rest of DevForge refuses one: a case file is data, and data that reaches a
    shell is an injection surface.
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    description: str = ""
    argv: list[str]
    expect: Expectation = Expectation.PASS
    timeout_s: int = DEFAULT_CHECK_TIMEOUT_S

    @model_validator(mode="after")
    def _check(self) -> Check:
        if not self.argv:
            raise ValueError(f"check '{self.id}': argv must not be empty")
        return self

    def satisfied_by(self, exit_code: int) -> bool:
        return (exit_code == 0) if self.expect is Expectation.PASS else (exit_code != 0)


class EvalCase(BaseModel):
    """One task with a known answer.

    ``files`` is the starting workspace. ``description`` is the task an agent is
    given - the same text a human would put in ``devforge run --task``.
    ``solution`` is the known-good answer, used only by the ``reference`` driver
    to prove the grader accepts correct work. An agent never sees it.

    ``checks`` decide success. ``guards`` are the regression contract: they must
    pass *before* the attempt and still pass after. A guard that fails before the
    attempt makes the case invalid rather than failed - the case is broken, not
    the configuration.
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    category: Category
    title: str = ""
    description: str
    workflow: str = "feature"
    files: dict[str, str] = Field(default_factory=dict)
    solution: dict[str, str] = Field(default_factory=dict)
    checks: list[Check] = Field(default_factory=list)
    guards: list[Check] = Field(default_factory=list)
    #: Capabilities the case cannot run without: "browser", "git", "network".
    #: A missing one makes the case unavailable, never failed.
    requires: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    timeout_s: int = 900

    @model_validator(mode="after")
    def _check(self) -> EvalCase:
        if not self.checks:
            raise ValueError(f"case '{self.id}': at least one check is required")
        ids = [check.id for check in self.checks + self.guards]
        duplicates = {cid for cid in ids if ids.count(cid) > 1}
        if duplicates:
            raise ValueError(f"case '{self.id}': duplicate check id(s) {sorted(duplicates)}")
        if not self.title:
            self.title = self.id.replace("-", " ").capitalize()
        return self

    def materialise(self, root: Path) -> None:
        write_files(root, self.files, case_id=self.id)

    def apply_solution(self, root: Path) -> None:
        write_files(root, self.solution, case_id=self.id)


class EvalSuite(BaseModel):
    """A file of cases. Suites are per-category by convention, not by rule."""

    model_config = ConfigDict(extra="forbid")

    version: int = 1
    name: str = ""
    description: str = ""
    cases: list[EvalCase]

    @classmethod
    def load(cls, path: Path) -> EvalSuite:
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except FileNotFoundError as exc:
            raise ConfigError(f"eval suite not found: {path}") from exc
        except (OSError, yaml.YAMLError) as exc:
            raise ConfigError(f"could not read {path}: {exc}") from exc
        try:
            suite = cls.model_validate(raw)
        except ValidationError as exc:
            raise ConfigError(f"{path}: invalid eval suite: {exc}") from exc
        if not suite.name:
            suite.name = path.stem
        return suite


# --------------------------------------------------------------------------- results


class CaseOutcome(str, Enum):
    """Why a case ended the way it did.

    The distinction between ``failed`` and the three that are not failures matters
    for the metrics: an unavailable case has not been attempted, an invalid case
    is a broken benchmark, and a suspicious one is a refusal rather than a miss.
    """

    SUCCESS = "success"
    FAILED = "failed"
    REGRESSED = "regressed"
    REJECTED_SUSPICIOUS = "rejected_suspicious"
    INVALID = "invalid"
    UNAVAILABLE = "unavailable"

    @property
    def success(self) -> bool:
        return self is CaseOutcome.SUCCESS

    @property
    def attempted(self) -> bool:
        """Whether this outcome belongs in a rate's denominator."""
        return self not in {CaseOutcome.UNAVAILABLE, CaseOutcome.INVALID}


class CheckOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    passed: bool
    expect: Expectation = Expectation.PASS
    exit_code: int = 0
    duration_ms: int = 0
    excerpt: str = ""


class CaseResult(BaseModel):
    """Everything one case produced. The report is a list of these plus arithmetic."""

    model_config = ConfigDict(extra="forbid")

    case_id: str
    category: Category
    title: str = ""
    outcome: CaseOutcome = CaseOutcome.FAILED
    detail: str = ""

    checks: list[CheckOutcome] = Field(default_factory=list)
    guards_before: list[CheckOutcome] = Field(default_factory=list)
    guards_after: list[CheckOutcome] = Field(default_factory=list)
    regressed: list[str] = Field(default_factory=list)

    patch_verdict: str = "empty"
    findings: list[str] = Field(default_factory=list)
    files_changed: list[str] = Field(default_factory=list)

    # -- harness telemetry; None means "this driver cannot report it" -----------
    attempts: int | None = None
    steps_total: int | None = None
    verifications_passed: int | None = None
    verifications_failed: int | None = None
    tool_calls: int | None = None
    tool_failures: int | None = None
    security_violations: int = 0
    interventions: int = 0
    tokens: int | None = None
    cost_usd: float | None = None
    duration_ms: int = 0

    @property
    def first_pass(self) -> bool | None:
        """Succeeded with no step needing a second attempt.

        ``None`` when the driver reports no attempt counts - a scripted driver
        makes one pass by construction, but claiming "first-pass success" for it
        would put a number in a column that measures something else.
        """
        if self.attempts is None or self.steps_total is None:
            return None
        return self.outcome.success and self.attempts <= self.steps_total


class EvalConfig(BaseModel):
    """The thing being measured.

    Five of these fields are the comparison axes the brief names. They are recorded
    verbatim in every report so that ``eval compare`` can say precisely what
    differed between two runs rather than inferring it.
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    description: str = ""
    #: reference | cheat | none | harness. The first three are grader anchors.
    driver: str = "harness"
    runtime: str = "mock"
    model: str | None = None
    #: Empty means "whatever each workflow step declares". A non-empty list
    #: restricts every step to that set, which is what makes a skill-set
    #: comparison an actual intervention rather than a label.
    skills: list[str] = Field(default_factory=list)
    #: Overrides the workflow each case names.
    workflow: str | None = None
    #: none | indexed. Whether a retrieval index exists when the agents run.
    context_strategy: str = "none"
    notes: str = ""

    def axes(self) -> dict[str, str]:
        return {
            "driver": self.driver,
            "runtime": self.runtime,
            "model": self.model or "(runtime default)",
            "skills": ", ".join(self.skills) if self.skills else "(per workflow step)",
            "workflow": self.workflow or "(per case)",
            "context_strategy": self.context_strategy,
        }


class EvalReport(BaseModel):
    """One configuration, one set of cases, one moment. Saved as JSON."""

    model_config = ConfigDict(extra="forbid")

    report_id: str
    created_at: datetime = Field(default_factory=utcnow)
    devforge_version: str = ""
    git_commit: str = ""
    config: EvalConfig
    suites: list[str] = Field(default_factory=list)
    results: list[CaseResult] = Field(default_factory=list)
    metrics: Metrics = Field(default_factory=Metrics)
    #: Settings the configuration asked for that nothing honoured, e.g. a model
    #: name given to a runtime that takes none. Recorded, never silently dropped.
    unhonoured: list[str] = Field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def attempted(self) -> list[CaseResult]:
        return [r for r in self.results if r.outcome.attempted]

    @property
    def succeeded(self) -> list[CaseResult]:
        return [r for r in self.results if r.outcome.success]

    def by_category(self) -> dict[Category, list[CaseResult]]:
        grouped: dict[Category, list[CaseResult]] = {}
        for result in self.results:
            grouped.setdefault(result.category, []).append(result)
        return grouped

    def render(self) -> str:
        return render_report(self)


# --------------------------------------------------------------------------- rendering


def render_report(report: EvalReport) -> str:
    """Markdown. The same text `devforge eval report` prints and writes to disk."""
    lines = [
        f"# Evaluation: {report.config.id}",
        "",
        f"`{report.report_id}` - {report.created_at:%Y-%m-%d %H:%M UTC}"
        + (f" - devforge {report.devforge_version}" if report.devforge_version else "")
        + (f" - commit {report.git_commit}" if report.git_commit else ""),
        "",
        "## Configuration",
        "",
        "| axis | value |",
        "| --- | --- |",
    ]
    lines += [f"| {axis} | {value} |" for axis, value in report.config.axes().items()]
    if report.config.notes:
        lines += ["", report.config.notes]
    if report.unhonoured:
        lines += [
            "",
            "Requested but not honoured: " + ", ".join(report.unhonoured) + ".",
            "The measurement is of what actually ran, not of what was asked for.",
        ]

    lines += ["", "## Metrics", "", *report.metrics.render_table()]

    lines += [
        "",
        "## Cases",
        "",
        "| case | category | outcome | checks | detail |",
        "| --- | --- | --- | --- | --- |",
    ]
    for result in report.results:
        passed = sum(1 for c in result.checks if c.passed)
        lines.append(
            f"| {result.case_id} | {result.category.value} | {result.outcome.value} "
            f"| {passed}/{len(result.checks)} | {_one_line(result.detail)} |"
        )

    grouped = report.by_category()
    if len(grouped) > 1:
        lines += [
            "",
            "## By category",
            "",
            "| category | success | attempted |",
            "| --- | --- | --- |",
        ]
        for category in Category:
            results = grouped.get(category)
            if not results:
                continue
            attempted = [r for r in results if r.outcome.attempted]
            wins = sum(1 for r in results if r.outcome.success)
            lines.append(f"| {category.value} | {wins} | {len(attempted)} |")

    unavailable = [r for r in report.results if r.outcome is CaseOutcome.UNAVAILABLE]
    if unavailable:
        lines += ["", "## Not attempted", ""]
        lines += [f"- **{r.case_id}**: {r.detail}" for r in unavailable]
        lines += [
            "",
            "These are excluded from every rate's denominator and counted here "
            "instead. Dropping them silently would raise the success rate by "
            "removing the cases nothing could attempt.",
        ]

    suspicious = [r for r in report.results if r.outcome is CaseOutcome.REJECTED_SUSPICIOUS]
    if suspicious:
        lines += ["", "## Rejected as suspicious", ""]
        for result in suspicious:
            lines.append(f"- **{result.case_id}**")
            lines += [f"  - {finding}" for finding in result.findings]

    lines += ["", "## What this report does not say", "", *_caveats(report)]
    return "\n".join(lines) + "\n"


def _caveats(report: EvalReport) -> list[str]:
    total = len(report.attempted)
    return [
        f"It is one configuration measured once on {total} attempted case(s). "
        "These cases are small, self-contained and have known answers; the "
        "software people actually maintain is none of those things, so the "
        "number does not transfer to it.",
        "",
        "It does not establish that a difference between two configurations is "
        "real. A handful of cases cannot separate a genuine improvement from "
        "run-to-run variation, and `eval compare` says so rather than declaring "
        "a winner.",
        "",
        "It does not measure code quality, maintainability or whether a human "
        "would accept the change. It measures whether the declared checks passed.",
    ]


def _one_line(text: str, limit: int = 90) -> str:
    flat = " ".join(text.split())
    if len(flat) <= limit:
        return flat
    return flat[: limit - 1] + "…"


def write_files(root: Path, files: dict[str, str], *, case_id: str) -> None:
    """Write case files, refusing any path that leaves the workspace.

    Case files are data from a YAML file, and a benchmark suite is exactly the
    kind of thing someone copies from the internet. ``../../.ssh/authorized_keys``
    has to be impossible here, not merely unlikely.
    """
    root = root.resolve()
    for relative, content in files.items():
        target = (root / relative).resolve()
        if target != root and root not in target.parents:
            raise ConfigError(f"case '{case_id}' writes outside its workspace: {relative}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
