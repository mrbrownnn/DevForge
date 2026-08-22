"""Security findings and dependency findings.

The security detector is a bridge, not a second scanner: it reuses
:mod:`devforge.security.scan`, so a rule improved for the Security Center
improves here too and the two can never disagree about the same file.

The dependency detector is the one with an honest gap. "Outdated" usually means
"behind the latest release", and knowing that needs a package index - a network
call, a new trust relationship and a new egress path, which is the operator's
decision and not a default. So this detector reports what is knowable offline:
declared but not installed, installed below the declared minimum, and declared
with no version constraint at all. It states the gap rather than implying it
covers the whole question.
"""

from __future__ import annotations

import re
import tomllib
from importlib import metadata
from pathlib import Path

from devforge.continuous.detectors.base import Workspace
from devforge.continuous.models import (
    Category,
    DetectorReport,
    DetectorStatus,
    Finding,
    Risk,
    Severity,
)

#: Security severities map to a confidence: the scanner's rules are patterns, and
#: a pattern that fires on a high-severity construct is right more often than one
#: firing on a low-severity hint.
_SECURITY_CONFIDENCE = {"critical": 0.85, "high": 0.8, "medium": 0.7, "low": 0.6, "info": 0.5}
_SECURITY_SEVERITY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


class SecurityDetector:
    """Everything `devforge security scan` finds, as continuous-engineering work."""

    name = "security"
    category = Category.SECURITY

    def run(self, workspace: Workspace) -> DetectorReport:
        from devforge.security.scan import scan_workspace

        report = DetectorReport(detector=self.name, category=self.category)
        scan = scan_workspace(workspace.root)
        report.files_examined = scan.files_scanned

        for finding in scan.findings:
            severity = _SECURITY_SEVERITY.get(finding.severity.value, Severity.MEDIUM)
            report.findings.append(
                Finding(
                    finding_id=finding.id,
                    category=self.category,
                    title=finding.title,
                    severity=severity,
                    confidence=_SECURITY_CONFIDENCE.get(finding.severity.value, 0.7),
                    # Already redacted by the scanner: a report is not the place
                    # to publish the secret it found.
                    evidence=f"{finding.location}: {finding.evidence or finding.title}",
                    affected_files=[finding.location] if finding.location else [],
                    recommended_action=finding.remediation or "Review and remediate.",
                    estimated_risk=Risk.MEDIUM,
                    detector=self.name,
                )
            )
        return report


# --------------------------------------------------------------------------- deps

_REQUIREMENT = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*(?P<extras>\[[^\]]*\])?\s*(?P<spec>.*)$"
)
_MINIMUM = re.compile(r">=\s*(?P<version>[0-9][0-9A-Za-z.\-]*)")


class DependencyDetector:
    """What can be said about dependencies without asking a package index."""

    name = "dependency"
    category = Category.DEPENDENCY

    def run(self, workspace: Workspace) -> DetectorReport:
        report = DetectorReport(detector=self.name, category=self.category)
        manifest = workspace.root / "pyproject.toml"
        if not manifest.is_file():
            report.status = DetectorStatus.UNAVAILABLE
            report.detail = "no pyproject.toml; this detector reads Python declarations only"
            return report

        try:
            data = tomllib.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            report.status = DetectorStatus.UNAVAILABLE
            report.detail = f"could not read pyproject.toml: {exc}"
            return report

        requirements = _requirements(data)
        report.files_examined = 1
        report.detail = (
            "Offline analysis. Whether a dependency is behind its latest release is "
            "not measured: that needs a package index, which is a network call and a "
            "trust decision the operator makes, not a default."
        )

        for group, requirement in requirements:
            match = _REQUIREMENT.match(requirement.strip())
            if match is None:
                continue
            name = match.group("name")
            spec = match.group("spec").strip()
            optional = group != "dependencies"

            if not spec:
                report.findings.append(
                    Finding(
                        finding_id="CE-DEP-001",
                        category=self.category,
                        title=f"'{name}' is declared with no version constraint",
                        severity=Severity.MEDIUM if not optional else Severity.LOW,
                        confidence=0.95,
                        evidence=f"pyproject.toml [{group}]: '{requirement}' has no specifier",
                        affected_files=["pyproject.toml"],
                        recommended_action=(
                            f"Pin a lower bound for '{name}'. Without one, a fresh install "
                            "can resolve to a version this code has never been run against."
                        ),
                        estimated_risk=Risk.LOW,
                        detector=self.name,
                    )
                )

            installed = _installed_version(name)
            if installed is None:
                if optional:
                    # An optional extra that is not installed is the normal state,
                    # and reporting it would file a finding for every extra.
                    continue
                report.findings.append(
                    Finding(
                        finding_id="CE-DEP-002",
                        category=self.category,
                        title=f"'{name}' is required but not installed here",
                        severity=Severity.HIGH,
                        confidence=0.9,
                        evidence=(
                            f"pyproject.toml declares '{requirement}' in [{group}], and "
                            f"importlib.metadata finds no distribution named '{name}' in "
                            "this environment."
                        ),
                        affected_files=["pyproject.toml"],
                        recommended_action=(
                            f"Install '{name}', or remove the declaration. A required "
                            "dependency that is absent makes a feature fail at the moment "
                            "it is used rather than at start-up."
                        ),
                        estimated_risk=Risk.LOW,
                        detector=self.name,
                    )
                )
                continue

            minimum = _MINIMUM.search(spec)
            if minimum and _below(installed, minimum.group("version")):
                report.findings.append(
                    Finding(
                        finding_id="CE-DEP-003",
                        category=self.category,
                        title=f"'{name}' {installed} is below the declared minimum",
                        severity=Severity.HIGH,
                        confidence=0.9,
                        evidence=(
                            f"pyproject.toml requires '{requirement}'; the installed "
                            f"version is {installed}."
                        ),
                        affected_files=["pyproject.toml"],
                        recommended_action=(
                            f"Upgrade '{name}' to at least {minimum.group('version')}. The "
                            "tests are passing against a version the project says it does "
                            "not support."
                        ),
                        estimated_risk=Risk.MEDIUM,
                        detector=self.name,
                    )
                )
        return report


def _requirements(data: dict) -> list[tuple[str, str]]:
    project = data.get("project", {})
    found = [("dependencies", item) for item in project.get("dependencies", []) or []]
    for group, items in (project.get("optional-dependencies", {}) or {}).items():
        found += [(f"optional:{group}", item) for item in items or []]
    return found


def _installed_version(name: str) -> str | None:
    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError:
        return None


def _below(installed: str, minimum: str) -> bool:
    """Compare two versions numerically, and say no when unsure.

    Version comparison has real subtleties - pre-releases, epochs, local
    segments - and this deliberately does not implement them. When either side
    is not a plain dotted number, it answers "not below", because a false
    upgrade demand is worse than a missed one.
    """
    try:
        left = [int(part) for part in installed.split(".")[:3]]
        right = [int(part) for part in minimum.split(".")[:3]]
    except ValueError:
        return False
    left += [0] * (3 - len(left))
    right += [0] * (3 - len(right))
    return left < right


def read_manifest(root: Path) -> dict:
    """Exposed for tests and for callers that want the raw declarations."""
    return tomllib.loads((Path(root) / "pyproject.toml").read_text(encoding="utf-8"))
