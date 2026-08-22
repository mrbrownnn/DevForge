"""detect → prioritize → propose.

The three stages before a human sees anything, and the three places where a
continuous-engineering tool usually goes wrong:

*Detection* that treats a crashed detector as a clean result. Every detector
reports its status, and an unavailable one is printed rather than counted as
zero findings.

*Prioritization* that averages severity and confidence into one number and
produces an ordering nobody agrees with. Here security outranks everything at
equal severity by construction, not by weighting.

*Proposal* that files one task per finding. Twenty debt markers in one file are
one decision, not twenty, and a backlog that does not group them is a backlog
people close unread.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

from devforge.continuous.detectors import DETECTORS
from devforge.continuous.detectors.base import Detector, Workspace, read_sources
from devforge.continuous.models import (
    CONFIDENCE_EXEMPT,
    DEFAULT_MIN_CONFIDENCE,
    Category,
    DetectorReport,
    DetectorStatus,
    Finding,
    Proposal,
    ScanReport,
    Severity,
    Suppression,
)
from devforge.observability.logging import RunLogger, null_logger
from devforge.vcs.models import slugify

#: Beyond this many findings from one detector, the individual ones are replaced
#: by a single finding that says how many there are. A detector that fires two
#: hundred times has found a policy question, not two hundred tasks.
FLOOD_LIMIT = 25


def detect(
    root: Path,
    *,
    detectors: list[Detector] | None = None,
    min_confidence: float = DEFAULT_MIN_CONFIDENCE,
    suppressions: list[Suppression] | None = None,
    categories: list[Category] | None = None,
    logger: RunLogger | None = None,
    today: date | None = None,
) -> ScanReport:
    """Run the detectors and return everything worth a person's attention."""
    logger = logger or null_logger()
    today = today or date.today()
    workspace = read_sources(root)
    report = ScanReport(root=str(Path(root).resolve()))

    selected = detectors if detectors is not None else DETECTORS()
    if categories:
        wanted = set(categories)
        selected = [detector for detector in selected if detector.category in wanted]

    for detector in selected:
        result = _run_one(detector, workspace, logger)
        result = _apply_confidence(result, min_confidence)
        result, hidden = _apply_suppressions(result, suppressions or [], today=today)
        result = _collapse_flood(result)
        report.reports.append(result)
        report.suppressed.extend(hidden)
        logger.info(
            "continuous.detector",
            detector=detector.name,
            status=result.status.value,
            findings=len(result.findings),
            withheld=result.withheld,
        )
    return report


def _run_one(detector: Detector, workspace: Workspace, logger: RunLogger) -> DetectorReport:
    """A detector that raises must not take the whole scan with it.

    The failure is reported as unavailable with the exception text, which is the
    one thing that distinguishes "found nothing" from "could not look".
    """
    try:
        return detector.run(workspace)
    except Exception as exc:  # a broken detector is a bug, not a clean repository
        logger.info("continuous.detector_failed", detector=detector.name, error=str(exc))
        return DetectorReport(
            detector=detector.name,
            category=detector.category,
            status=DetectorStatus.UNAVAILABLE,
            detail=f"the detector raised {type(exc).__name__}: {exc}",
        )


def _apply_confidence(report: DetectorReport, minimum: float) -> DetectorReport:
    """Withhold low-confidence findings, and count what was withheld.

    Security is exempt. The cost of checking a false positive there is a minute;
    the cost of missing a real one is not symmetric with it, and pretending
    otherwise is how a threshold becomes a way of not looking.
    """
    if report.category in CONFIDENCE_EXEMPT:
        return report
    kept = [finding for finding in report.findings if finding.confidence >= minimum]
    report.withheld += len(report.findings) - len(kept)
    report.findings = kept
    return report


def _apply_suppressions(
    report: DetectorReport, suppressions: list[Suppression], *, today: date
) -> tuple[DetectorReport, list[Finding]]:
    if not suppressions:
        return report, []
    kept: list[Finding] = []
    hidden: list[Finding] = []
    for finding in report.findings:
        if any(rule.covers(finding, today=today) for rule in suppressions):
            hidden.append(finding)
        else:
            kept.append(finding)
    report.findings = kept
    return report, hidden


def _collapse_flood(report: DetectorReport) -> DetectorReport:
    if len(report.findings) <= FLOOD_LIMIT:
        return report

    findings = report.findings
    worst = max(findings, key=lambda finding: finding.priority)
    files = sorted({path for finding in findings for path in finding.affected_files})
    report.findings = [
        Finding(
            finding_id=f"{worst.finding_id}-MANY",
            category=report.category,
            title=f"{len(findings)} {report.category.value} findings across {len(files)} places",
            severity=worst.severity,
            confidence=min(0.9, worst.confidence),
            evidence=(
                f"The {report.detector} detector produced {len(findings)} findings. "
                "The first ten:\n"
                + "\n".join(f"- {finding.summary()}" for finding in findings[:10])
            ),
            affected_files=files[:50],
            recommended_action=(
                f"Decide a policy for {report.category.value} in this repository before "
                "filing individual tasks. A detector firing this often has found one "
                "question, not "
                f"{len(findings)} of them."
            ),
            estimated_risk=worst.estimated_risk,
            detector=report.detector,
        )
    ]
    return report


# --------------------------------------------------------------------- prioritize


def prioritize(findings: list[Finding]) -> list[Finding]:
    """Highest priority first; ties broken so the order is stable between runs."""
    return sorted(
        findings,
        key=lambda finding: (-finding.priority, finding.finding_id, finding.key()),
    )


# ------------------------------------------------------------------------ propose


#: How many proposals one category may contribute to a single run. Without this
#: the most talkative detector fills the list, and the list stops representing
#: the repository - it represents whichever detector had the most to say.
PER_CATEGORY_LIMIT = 3


def propose(
    findings: list[Finding], *, limit: int = 10, per_category: int = PER_CATEGORY_LIMIT
) -> list[Proposal]:
    """Group findings into work someone could approve.

    Grouping is by category and by the *directory* the findings sit in. The
    directory rather than the file, because that is the granularity at which the
    work is one sitting: five modules in one package that need tests is one
    afternoon, and filing it as five tasks makes it look like five.

    Two caps, both about the reader rather than the analysis. ``limit`` bounds a
    run, because a backlog arriving fifty items at a time gets triaged once and
    then ignored. ``per_category`` bounds any one detector's share, so a category
    with a hundred findings cannot crowd out the one security item.
    """
    grouped: dict[tuple[Category, str], list[Finding]] = {}
    for finding in prioritize(findings):
        grouped.setdefault((finding.category, _anchor(finding)), []).append(finding)

    proposals = [
        _proposal(category, anchor, group) for (category, anchor), group in grouped.items()
    ]
    proposals.sort(key=lambda proposal: (-proposal.priority, proposal.title))

    chosen: list[Proposal] = []
    per_category_count: dict[Category, int] = {}
    for proposal in proposals:
        category = proposal.findings[0].category
        if per_category_count.get(category, 0) >= per_category:
            continue
        per_category_count[category] = per_category_count.get(category, 0) + 1
        chosen.append(proposal)
        if len(chosen) >= limit:
            break
    return chosen


def _anchor(finding: Finding) -> str:
    """The directory a finding is about, which is where its fix lives."""
    if not finding.affected_files:
        return "(project)"
    path = finding.affected_files[0].split(":")[0]
    directory = path.rsplit("/", 1)[0] if "/" in path else ""
    return directory or "(root)"


def _proposal(category: Category, anchor: str, findings: list[Finding]) -> Proposal:
    worst = findings[0]
    where = anchor if anchor != "(project)" else "the project"
    title = (
        worst.title
        if len(findings) == 1
        else f"{len(findings)} {category.value.replace('_', ' ')} findings in {where}"
    )
    return Proposal(
        findings=findings,
        title=title,
        rationale=_rationale(category, findings),
        workflow=_workflow_for(category),
        branch=f"{_branch_prefix(category)}/{slugify(title, limit=40)}",
    )


def _rationale(category: Category, findings: list[Finding]) -> str:
    severity = max(findings, key=lambda finding: finding.severity.weight).severity
    confidence = min(finding.confidence for finding in findings)
    lines = [
        f"{len(findings)} {category.value.replace('_', ' ')} finding(s), worst severity "
        f"{severity.value}, lowest confidence {confidence:.0%}.",
    ]
    if category is Category.SECURITY:
        lines.append(
            "Security work is proposed ahead of other categories at equal severity. "
            "That is an ordering decision, not a claim that these findings are "
            "exploitable - confirm each one before acting."
        )
    if severity is Severity.LOW:
        lines.append(
            "Nothing here is urgent. It is proposed so the choice not to do it is "
            "made deliberately rather than by never noticing."
        )
    return "\n\n".join(lines)


#: Which workflow does this kind of work. Debt and documentation are ordinary
#: feature work; a defect and a security fix want the flows that reproduce and
#: review before they change anything.
_WORKFLOWS = {
    Category.SECURITY: "git-feature",
    Category.FLAKY_TEST: "bugfix",
    Category.DEPENDENCY: "git-feature",
}

_BRANCH_PREFIXES = {
    Category.SECURITY: "fix",
    Category.FLAKY_TEST: "fix",
    Category.DEPENDENCY: "chore",
    Category.DOC_DRIFT: "docs",
    Category.MISSING_TESTS: "test",
    Category.DEAD_CODE: "refactor",
    Category.DUPLICATION: "refactor",
    Category.ARCHITECTURE: "refactor",
    Category.PERFORMANCE: "perf",
    Category.TECH_DEBT: "chore",
}


def _workflow_for(category: Category) -> str:
    return _WORKFLOWS.get(category, "git-feature")


def _branch_prefix(category: Category) -> str:
    return _BRANCH_PREFIXES.get(category, "chore")
