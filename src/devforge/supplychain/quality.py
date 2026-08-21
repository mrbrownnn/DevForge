"""Skill quality scoring from evidence in the tree.

Nine dimensions, ten points each. **Popularity is not one of them.** The Phase 0
survey is the argument: the most-starred source in the ecosystem ships
auto-executing session hooks, and the least-starred one ships CODEOWNERS, a
pre-commit config and a security policy. A score built on stars would rank those
in exactly the wrong order.

Everything here is computed from files that were actually fetched, so a score is
reproducible from a pinned commit rather than from an API that changes hourly.
Repository activity is the one dimension that needs data from outside the tree;
when it is not supplied the dimension scores a neutral 5 and says so, rather than
inventing a number.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from devforge.core.models import utcnow
from devforge.supplychain.catalog import QualityScore
from devforge.supplychain.models import VENDORABLE_LICENSES
from devforge.supplychain.risk import ORDER, RiskAssessment, SkillRisk

DOC_FILES = ("README.md", "README.rst", "README.txt", "SKILL.md", "AGENTS.md")
TEST_MARKERS = ("test", "spec", "__tests__", "conftest.py", "pytest.ini")
CI_MARKERS = (".github/workflows", ".gitlab-ci.yml", "azure-pipelines.yml", "Makefile")
SECURITY_MARKERS = ("SECURITY.md", "CODEOWNERS", ".pre-commit-config.yaml", "renovate.json")
LOCKFILES = ("package-lock.json", "poetry.lock", "uv.lock", "requirements.txt", "Cargo.lock")
VENDOR_MARKERS = (".claude-plugin", ".claude", "claude", "cursor", "codex", "gemini")


@dataclass
class RepoSignals:
    """Facts about the repository that are not visible inside the tree.

    Supplied by a caller that has them (the CLI can read them from the source
    registry); omitted rather than guessed when nobody knows.
    """

    last_commit: datetime | None = None
    open_issues: int | None = None
    archived: bool = False
    maintainer_is_organisation: bool | None = None


def _relative_paths(root: Path, limit: int = 5000) -> list[str]:
    paths: list[str] = []
    for path in root.rglob("*"):
        if path.is_file():
            paths.append(path.relative_to(root).as_posix())
            if len(paths) >= limit:
                break
    return paths


def _score_documentation(root: Path, paths: list[str]) -> tuple[int, str]:
    doc_paths = [p for p in paths if Path(p).name in DOC_FILES]
    if not doc_paths:
        return 0, "no README or SKILL.md"

    longest = 0
    frontmatter = False
    for relative in doc_paths:
        try:
            text = (root / relative).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        longest = max(longest, len(text))
        if text.lstrip().startswith("---"):
            frontmatter = True

    score = 4
    if longest > 800:
        score += 2
    if longest > 3000:
        score += 2
    if frontmatter:
        score += 2  # declares its own metadata rather than relying on a filename
    return min(score, 10), f"{len(doc_paths)} doc file(s), longest {longest} chars"


def _score_tests(paths: list[str]) -> tuple[int, str]:
    test_files = [p for p in paths if any(marker in p.lower() for marker in TEST_MARKERS)]
    ci = [p for p in paths if any(p.startswith(marker) for marker in CI_MARKERS)]
    if not test_files and not ci:
        return 0, "no tests and no CI configuration"
    score = 0
    if test_files:
        score += 5 if len(test_files) > 3 else 3
    if ci:
        score += 4
    return min(score, 10), f"{len(test_files)} test file(s), {len(ci)} CI file(s)"


def _score_license(license_name: str | None, paths: list[str]) -> tuple[int, str]:
    has_file = any(Path(p).name.upper().startswith("LICENSE") for p in paths)
    if not license_name and not has_file:
        return 0, "no license: redistribution terms are undetermined"
    if license_name in VENDORABLE_LICENSES:
        return 10, f"{license_name}: permissive and clear"
    if license_name:
        return 5, f"{license_name}: usable but not permissive (check redistribution terms)"
    return 3, "a LICENSE file exists but the identifier is unknown"


def _score_portability(paths: list[str], supported_runtimes: list[str]) -> tuple[int, str]:
    vendor_dirs = {
        marker for marker in VENDOR_MARKERS if any(p.lower().startswith(marker) for p in paths)
    }
    score = 5
    detail = []
    if "*" in supported_runtimes:
        score += 3
        detail.append("declares runtime-agnostic")
    elif len(supported_runtimes) > 1:
        score += 2
        detail.append(f"{len(supported_runtimes)} runtimes")
    if len(vendor_dirs) > 1:
        score += 2
        detail.append(f"ships adapters for {len(vendor_dirs)} agents")
    elif len(vendor_dirs) == 1:
        score -= 2
        detail.append(f"tied to one agent ({next(iter(vendor_dirs))})")
    return max(0, min(score, 10)), ", ".join(detail) or "no portability signals"


def _score_security_posture(paths: list[str], assessment: RiskAssessment) -> tuple[int, str]:
    markers = [p for p in paths if Path(p).name in SECURITY_MARKERS or p in SECURITY_MARKERS]
    score = 4 + min(len(markers) * 2, 4)
    penalty = {SkillRisk.LOW: 0, SkillRisk.MEDIUM: 2, SkillRisk.HIGH: 5, SkillRisk.CRITICAL: 8}[
        assessment.level
    ]
    score = max(0, min(score, 10) - penalty)
    return score, f"{len(markers)} hygiene marker(s), content risk {assessment.level}"


def _score_dependency_risk(paths: list[str], dependencies: list[str]) -> tuple[int, str]:
    """Fewer moving parts scores higher; an unpinned dependency set scores lowest."""
    manifests = [p for p in paths if Path(p).name in {"package.json", "pyproject.toml"}]
    locks = [p for p in paths if Path(p).name in LOCKFILES]
    if not manifests and not dependencies:
        return 10, "no declared dependencies"
    if locks:
        return 7, f"{len(manifests)} manifest(s) with {len(locks)} lockfile(s)"
    return 3, f"{len(manifests)} manifest(s) and no lockfile: versions float"


def _score_capability_coverage(capabilities: list[str], paths: list[str]) -> tuple[int, str]:
    if not capabilities:
        return 3, "declares no capabilities"
    score = min(4 + len(capabilities), 8)
    if any(Path(p).name == "SKILL.md" for p in paths):
        score += 2
    return min(score, 10), f"{len(capabilities)} declared capability/capabilities"


def _score_maintenance(signals: RepoSignals) -> tuple[int, str]:
    if signals.archived:
        return 0, "repository is archived"
    if signals.last_commit is None:
        return 5, "no commit data supplied; scored neutral rather than guessed"
    age = utcnow() - signals.last_commit
    if age < timedelta(days=30):
        return 10, f"last commit {age.days} days ago"
    if age < timedelta(days=90):
        return 8, f"last commit {age.days} days ago"
    if age < timedelta(days=365):
        return 5, f"last commit {age.days} days ago"
    return 2, f"last commit {age.days} days ago"


def _score_activity(signals: RepoSignals) -> tuple[int, str]:
    if signals.open_issues is None:
        return 5, "no issue data supplied; scored neutral rather than guessed"
    if signals.open_issues == 0:
        return 6, "no open issues (quiet, or unused)"
    if signals.open_issues < 50:
        return 9, f"{signals.open_issues} open issues: active and tractable"
    if signals.open_issues < 500:
        return 7, f"{signals.open_issues} open issues"
    return 4, f"{signals.open_issues} open issues: likely unattended"


def score_skill(
    root: Path,
    *,
    assessment: RiskAssessment,
    license_name: str | None = None,
    capabilities: list[str] | None = None,
    dependencies: list[str] | None = None,
    supported_runtimes: list[str] | None = None,
    signals: RepoSignals | None = None,
) -> QualityScore:
    """Score a fetched skill tree. Every dimension records why it scored what it did."""
    signals = signals or RepoSignals()
    paths = _relative_paths(root)

    maintenance, maintenance_why = _score_maintenance(signals)
    activity, activity_why = _score_activity(signals)
    documentation, documentation_why = _score_documentation(root, paths)
    tests, tests_why = _score_tests(paths)
    license_score, license_why = _score_license(license_name, paths)
    portability, portability_why = _score_portability(paths, supported_runtimes or ["*"])
    posture, posture_why = _score_security_posture(paths, assessment)
    dependency, dependency_why = _score_dependency_risk(paths, dependencies or [])
    coverage, coverage_why = _score_capability_coverage(capabilities or [], paths)

    return QualityScore(
        maintenance=maintenance,
        activity=activity,
        documentation=documentation,
        tests=tests,
        license=license_score,
        portability=portability,
        security_posture=posture,
        dependency_risk=dependency,
        capability_coverage=coverage,
        notes=[
            f"maintenance: {maintenance_why}",
            f"activity: {activity_why}",
            f"documentation: {documentation_why}",
            f"tests: {tests_why}",
            f"license: {license_why}",
            f"portability: {portability_why}",
            f"security_posture: {posture_why}",
            f"dependency_risk: {dependency_why}",
            f"capability_coverage: {coverage_why}",
        ],
    )


def detect_license(root: Path) -> str | None:
    """Identify a license from its file, without guessing.

    Matches the handful of identifiers whose text is unmistakable. Anything else
    returns ``None`` - "unknown" is a useful answer and a wrong SPDX id is not.
    """
    patterns = (
        ("Apache-2.0", re.compile(r"Apache License\s+Version 2\.0", re.I)),
        ("MIT", re.compile(r"\bMIT License\b", re.I)),
        (
            "BSD-3-Clause",
            re.compile(r"Redistributions of source code.*3\.|BSD 3-Clause", re.I | re.S),
        ),
        ("BSD-2-Clause", re.compile(r"BSD 2-Clause", re.I)),
        ("ISC", re.compile(r"\bISC License\b", re.I)),
        ("GPL-3.0", re.compile(r"GNU GENERAL PUBLIC LICENSE\s+Version 3", re.I)),
        ("AGPL-3.0", re.compile(r"GNU AFFERO GENERAL PUBLIC LICENSE", re.I)),
        ("MPL-2.0", re.compile(r"Mozilla Public License Version 2\.0", re.I)),
        ("CC-BY-SA-4.0", re.compile(r"Creative Commons Attribution-ShareAlike 4\.0", re.I)),
        ("CC-BY-4.0", re.compile(r"Creative Commons Attribution 4\.0", re.I)),
    )
    for candidate in sorted(root.rglob("LICENSE*")) + sorted(root.rglob("COPYING*")):
        if not candidate.is_file():
            continue
        try:
            text = candidate.read_text(encoding="utf-8", errors="replace")[:8000]
        except OSError:
            continue
        for name, pattern in patterns:
            if pattern.search(text):
                return name
    return None


def quality_summary(score: QualityScore) -> str:
    weakest = score.weakest
    tail = f"; weakest: {', '.join(weakest)}" if weakest else ""
    return f"{score.grade} ({score.total}/90){tail}"


def exceeds_ceiling(level: str, ceiling: str) -> bool:
    return ORDER[level] > ORDER[ceiling]
