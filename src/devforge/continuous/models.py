"""Findings, proposals and the backlog they live in.

A finding carries the seven fields the brief names, and each exists to answer a
question a reader actually has:

``finding_id``       which rule fired, so it can be suppressed by name
``severity``         how bad it is if real
``confidence``       how likely it is to be real - a separate axis, deliberately
``evidence``         what was observed, so the claim can be checked
``affected_files``   where to look
``recommended_action`` what to do, in one sentence
``estimated_risk``   what doing it might break

Severity and confidence are separate because conflating them is what makes an
automated backlog unusable. A possible SQL injection and a certain trailing
whitespace are not comparable on one axis, and a tool that averages them into a
single "priority" number produces an ordering nobody agrees with.
"""

from __future__ import annotations

from datetime import date, datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, model_validator

from devforge.core.models import new_id, utcnow


class Category(str, Enum):
    """The ten kinds of work this package looks for."""

    SECURITY = "security"
    DEPENDENCY = "dependency"
    FLAKY_TEST = "flaky_test"
    DEAD_CODE = "dead_code"
    DUPLICATION = "duplication"
    ARCHITECTURE = "architecture"
    TECH_DEBT = "tech_debt"
    MISSING_TESTS = "missing_tests"
    PERFORMANCE = "performance"
    DOC_DRIFT = "doc_drift"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[self.value]


class Risk(str, Enum):
    """What acting on the finding might cost.

    Not how bad the problem is - how dangerous the *fix* is. Deleting apparently
    dead code is a small change with a large blast radius if the analysis was
    wrong, and a backlog that does not say so invites exactly that mistake.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def weight(self) -> int:
        return {"low": 0, "medium": 1, "high": 2}[self.value]


#: Below this, a finding is withheld rather than filed. A list people ignore is
#: worse than a short list, and the way a list becomes ignorable is guesses.
DEFAULT_MIN_CONFIDENCE = 0.6

#: Categories where a lower-confidence finding is still worth a person's minute,
#: because the cost of missing one is not symmetric with the cost of checking.
CONFIDENCE_EXEMPT: frozenset[Category] = frozenset({Category.SECURITY})


class Finding(BaseModel):
    """One piece of work someone might want to do."""

    model_config = ConfigDict(extra="forbid")

    #: Stable rule id, e.g. ``CE-DEAD-001``. Stable so a backlog can name it.
    finding_id: str
    category: Category
    title: str
    severity: Severity
    #: 0.0-1.0. How likely this is to be real, judged by the detector that found
    #: it, on stated grounds - not a model's impression.
    confidence: float = Field(ge=0.0, le=1.0)
    #: What was observed. Redacted where it could carry a credential.
    evidence: str
    affected_files: list[str] = Field(default_factory=list)
    recommended_action: str
    estimated_risk: Risk = Risk.MEDIUM
    #: Which detector produced it, for triage and for turning one off.
    detector: str = ""
    detected_at: datetime = Field(default_factory=utcnow)

    @model_validator(mode="after")
    def _check(self) -> Finding:
        if not self.evidence.strip():
            raise ValueError(f"{self.finding_id}: a finding without evidence is an opinion")
        if not self.recommended_action.strip():
            raise ValueError(f"{self.finding_id}: a finding must say what to do about it")
        return self

    def key(self) -> str:
        """Identity for suppression and for recognising the same finding again."""
        location = self.affected_files[0] if self.affected_files else ""
        return f"{self.finding_id}:{location}"

    @property
    def priority(self) -> float:
        """Ordering weight. Higher first.

        Security outranks everything at equal severity, by construction rather
        than by tuning: a high-severity security finding must not sort below a
        critical cosmetic one, and the only way to guarantee that is to make the
        category a term of its own.
        """
        base = self.severity.weight * 10
        security_bonus = 15 if self.category is Category.SECURITY else 0
        # A cheap fix at the same severity is worth doing first.
        risk_penalty = self.estimated_risk.weight
        return base + security_bonus + (self.confidence * 5) - risk_penalty

    def summary(self) -> str:
        where = self.affected_files[0] if self.affected_files else "(no file)"
        return f"{self.finding_id} {where}: {self.title}"


class ProposalState(str, Enum):
    """Where a proposal is in ``detect → prioritize → propose → approval →
    execute → verify``."""

    PROPOSED = "proposed"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTING = "executing"
    VERIFIED = "verified"
    FAILED = "failed"

    @property
    def open(self) -> bool:
        return self not in {ProposalState.REJECTED, ProposalState.VERIFIED}


class Proposal(BaseModel):
    """A finding turned into work someone could approve.

    A proposal is not a task. It names the workflow that would do the work and
    the branch it would happen on, and it stays inert until a person approves it.
    """

    model_config = ConfigDict(extra="forbid")

    proposal_id: str = Field(default_factory=lambda: new_id("prop"))
    findings: list[Finding] = Field(default_factory=list)
    title: str
    rationale: str = ""
    workflow: str = "git-feature"
    branch: str = ""
    state: ProposalState = ProposalState.PROPOSED
    decided_by: str = ""
    decided_at: datetime | None = None
    reason: str = ""
    #: Set once the work has run, so verification can find it again.
    task_id: str = ""
    created_at: datetime = Field(default_factory=utcnow)

    @property
    def priority(self) -> float:
        return max((finding.priority for finding in self.findings), default=0.0)

    @property
    def severity(self) -> Severity:
        return max(
            (finding.severity for finding in self.findings),
            key=lambda severity: severity.weight,
            default=Severity.INFO,
        )

    @property
    def files(self) -> list[str]:
        seen: list[str] = []
        for finding in self.findings:
            for path in finding.affected_files:
                if path not in seen:
                    seen.append(path)
        return seen

    def issue_body(self) -> str:
        """The proposal as an issue an agent can be given."""
        lines = [
            f"# {self.title}",
            "",
            self.rationale.strip() or "Proposed by continuous engineering.",
            "",
            "## Findings",
            "",
        ]
        for finding in self.findings:
            lines += [
                f"### {finding.finding_id} - {finding.title}",
                "",
                f"- severity: {finding.severity.value}",
                f"- confidence: {finding.confidence:.0%}",
                f"- risk of acting: {finding.estimated_risk.value}",
                f"- files: {', '.join(finding.affected_files) or '(none)'}",
                "",
                "Evidence:",
                "",
                "```",
                finding.evidence.strip(),
                "```",
                "",
                f"Recommended action: {finding.recommended_action}",
                "",
            ]
        lines += [
            "## Constraints",
            "",
            "- These findings are produced by static analysis. Confirm each one "
            "before acting on it; a detector that was wrong is a normal outcome, "
            "not a reason to change the code anyway.",
            "- Do not weaken a test to make a finding go away.",
            "",
        ]
        return "\n".join(lines)


class Suppression(BaseModel):
    """An accepted finding. Costs a reason and an expiry, like a security baseline."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str
    location: str = ""
    reason: str
    expires: date
    accepted_by: str = ""

    def expired(self, today: date) -> bool:
        return today > self.expires

    def covers(self, finding: Finding, *, today: date) -> bool:
        if self.expired(today) or self.finding_id != finding.finding_id:
            return False
        if not self.location:
            return True
        # An affected file is written `path` or `path:line`; an acceptance names
        # the file or a directory. Line numbers move as a file is edited, so
        # matching on them would make every acceptance expire the next time
        # somebody added an import above it.
        anchor = self.location.rstrip("/")
        return any(
            path.split(":")[0] == anchor or path.startswith(f"{anchor}/")
            for path in finding.affected_files
        )


class DetectorStatus(str, Enum):
    OK = "ok"
    #: The detector could not run - a missing tool, no recorded history, an
    #: unparseable tree. Reported, never silently treated as "nothing found".
    UNAVAILABLE = "unavailable"


class DetectorReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    detector: str
    category: Category
    status: DetectorStatus = DetectorStatus.OK
    detail: str = ""
    files_examined: int = 0
    findings: list[Finding] = Field(default_factory=list)
    #: Findings the detector produced and then withheld for low confidence.
    withheld: int = 0


class ScanReport(BaseModel):
    """Everything one detection pass produced."""

    model_config = ConfigDict(extra="forbid")

    root: str
    scanned_at: datetime = Field(default_factory=utcnow)
    reports: list[DetectorReport] = Field(default_factory=list)
    suppressed: list[Finding] = Field(default_factory=list)

    @property
    def findings(self) -> list[Finding]:
        return [finding for report in self.reports for finding in report.findings]

    @property
    def unavailable(self) -> list[DetectorReport]:
        return [r for r in self.reports if r.status is DetectorStatus.UNAVAILABLE]

    @property
    def withheld(self) -> int:
        return sum(report.withheld for report in self.reports)

    def by_priority(self) -> list[Finding]:
        return sorted(self.findings, key=lambda finding: -finding.priority)

    def by_category(self) -> dict[Category, list[Finding]]:
        grouped: dict[Category, list[Finding]] = {}
        for finding in self.findings:
            grouped.setdefault(finding.category, []).append(finding)
        return grouped
