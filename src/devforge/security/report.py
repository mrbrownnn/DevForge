"""The security report: scan, audit, inventory, threat model and residual risk.

One document that answers, in order: what is configured, what was found, what is
installed, what we are defending against, and what remains true even when every
check passes.

The last section is not a disclaimer. It is the part a reader most needs, because
the failure mode of a security report is that someone reads a page of green ticks
and concludes the system is safe. Every threat in the catalogue carries a residual
risk and every one of them is printed here, on every run, including the runs where
nothing failed.

There is deliberately no score, no grade and no overall verdict. A number would be
a summary of the checks that exist, which is not the same as a summary of the
risk, and readers do not keep that distinction in mind.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from devforge.security.catalog import LAYERS, THREATS
from devforge.security.models import (
    AuditReport,
    CheckStatus,
    LayerStatus,
    ScanReport,
)
from devforge.security.sbom import summarise

NO_GUARANTEE = (
    "DevForge does not claim to be secure. It claims to make a specific set of "
    "mistakes harder and a specific set of actions visible. Every layer below is a "
    "partial mitigation with a stated limit, and the policy engine is an allowlist "
    "running as the invoking user - not a sandbox."
)


def render_report(
    *,
    root: Path,
    scan: ScanReport,
    audit: AuditReport,
    sbom: dict[str, Any] | None = None,
) -> str:
    lines: list[str] = [
        "# Security report",
        "",
        f"Project: `{root}`",
        f"Generated: {audit.generated_at.isoformat()}",
        "",
        "> " + NO_GUARANTEE,
        "",
    ]

    lines += _summary(scan, audit, sbom)
    lines += _layers()
    lines += _audit_section(audit)
    lines += _scan_section(scan)
    if sbom is not None:
        lines += _inventory(sbom)
    lines += _threat_section()
    lines += _residual_section()
    return "\n".join(lines)


def _summary(scan: ScanReport, audit: AuditReport, sbom: dict[str, Any] | None) -> list[str]:
    counts = scan.by_severity()
    lines = [
        "## At a glance",
        "",
        "| | |",
        "| --- | --- |",
        f"| Files scanned | {scan.files_scanned} (skipped {scan.files_skipped}) |",
        f"| Findings | {len(scan.findings)} "
        f"({', '.join(f'{v} {k}' for k, v in sorted(counts.items())) or 'none'}) |",
        f"| Suppressed by baseline | {len(scan.suppressed)} |",
        f"| Checks failed | {len(audit.failed)} |",
        f"| Checks warned | {len(audit.warned)} |",
        f"| Checks not evaluated | {len(audit.unknown)} |",
    ]
    if sbom is not None:
        inventory = summarise(sbom)
        lines.append(
            f"| Inventory | {', '.join(f'{v} {k}' for k, v in sorted(inventory.items()))} |"
        )
    lines.append("")
    if audit.unknown:
        lines += [
            "Checks that could not be evaluated are listed as `unknown`, never as "
            "passing. An unevaluated control is an unknown control.",
            "",
        ]
    return lines


def _layers() -> list[str]:
    lines = [
        "## Defence in depth",
        "",
        "| # | Layer | Status | Where it lives |",
        "| --- | --- | --- | --- |",
    ]
    for layer in LAYERS:
        lines.append(
            f"| {layer.number} | {layer.name} | {layer.status.value} "
            f"| {', '.join(f'`{m}`' for m in layer.modules)} |"
        )
    lines += ["", "### What each layer does not do", ""]
    for layer in LAYERS:
        marker = " **(not implemented)**" if layer.status is LayerStatus.NOT_IMPLEMENTED else ""
        lines.append(f"- **{layer.number}. {layer.name}**{marker} - {layer.limits}")
    lines.append("")
    return lines


def _audit_section(audit: AuditReport) -> list[str]:
    lines = ["## Configuration audit", ""]
    icons = {
        CheckStatus.PASS: "pass",
        CheckStatus.FAIL: "**FAIL**",
        CheckStatus.WARN: "warn",
        CheckStatus.NOT_APPLICABLE: "n/a",
        CheckStatus.UNKNOWN: "unknown",
    }
    for number, results in audit.by_layer().items():
        name = next((entry.name for entry in LAYERS if entry.number == number), "other")
        lines += [
            f"### Layer {number} - {name}",
            "",
            "| check | status | detail |",
            "| --- | --- | --- |",
        ]
        for result in results:
            lines.append(
                f"| `{result.id}` {result.title} | {icons[result.status]} | {result.detail} |"
            )
        lines.append("")

    actionable = audit.failed + audit.warned
    if actionable:
        lines += ["### What to do about it", ""]
        for result in actionable:
            if result.remediation:
                lines.append(f"- `{result.id}` - {result.remediation}")
        lines.append("")
    return lines


def _scan_section(scan: ScanReport) -> list[str]:
    lines = ["## Workspace scan", ""]
    if not scan.findings:
        lines += [
            "No findings. This means no *pattern in the rule set* matched - it is not "
            "evidence that the code is safe. The scanner does no taint analysis and "
            "has no vulnerability database.",
            "",
        ]
    else:
        lines += ["| severity | rule | location | threat |", "| --- | --- | --- | --- |"]
        for finding in scan.sorted_findings():
            lines.append(
                f"| {finding.severity.value} | `{finding.id}` {finding.title} "
                f"| `{finding.location}` | {finding.threat} |"
            )
        lines += ["", "### Detail", ""]
        for finding in scan.sorted_findings():
            lines += [
                f"**`{finding.id}` at `{finding.location}`** - {finding.title}",
                "",
                f"```\n{finding.evidence}\n```",
                "",
                finding.remediation,
                "",
            ]

    if scan.suppressed:
        lines += [
            "### Accepted by the baseline",
            "",
            "Reported, not hidden. Each was accepted deliberately in "
            "`security/baseline.yaml`, with a reason and an expiry date.",
            "",
        ]
        lines += [f"- `{f.id}` at `{f.location}` - {f.title}" for f in scan.suppressed]
        lines.append("")

    if scan.unreadable:
        lines += ["### Not examined", ""]
        lines += [f"- {entry}" for entry in scan.unreadable]
        lines.append("")
    return lines


def _inventory(sbom: dict[str, Any]) -> list[str]:
    lines = [
        "## Inventory",
        "",
        "| component | version | kind | license |",
        "| --- | --- | --- | --- |",
    ]
    for component in sbom.get("components", []):
        kind = next(
            (p["value"] for p in component.get("properties", []) if p["name"] == "devforge:kind"),
            "python-package",
        )
        licenses = component.get("licenses") or []
        license_name = licenses[0]["license"]["name"] if licenses else "unknown"
        lines.append(
            f"| {component['name']} | {component.get('version', 'unknown')} "
            f"| {kind} | {license_name} |"
        )
    lines += [
        "",
        "This inventory says what is installed and where it came from. It says nothing "
        "about whether any of it is vulnerable: DevForge ships no vulnerability "
        "database and queries no feed.",
        "",
    ]
    return lines


def _threat_section() -> list[str]:
    lines = [
        "## Threat model",
        "",
        "| id | threat | severity | layers | controls |",
        "| --- | --- | --- | --- | --- |",
    ]
    for threat in THREATS:
        lines.append(
            f"| {threat.id} | {threat.name} | {threat.severity.value} "
            f"| {', '.join(str(n) for n in threat.layers)} | {len(threat.controls)} |"
        )
    lines.append("")
    return lines


def _residual_section() -> list[str]:
    lines = [
        "## Residual risk",
        "",
        "What remains after every control above is working as designed. None of these "
        "is hypothetical and none is fixed by passing the checks.",
        "",
    ]
    for threat in THREATS:
        lines.append(f"- **{threat.id} {threat.name}** - {threat.residual}")
    lines += [
        "",
        "### The assumption everything rests on",
        "",
        "DevForge runs as you. Every control here constrains what DevForge's own tools "
        "do on your behalf; none of them constrains a process that has already "
        "obtained your privileges. If you would not open a repository yourself, do not "
        "point an agent at it.",
        "",
    ]
    return lines
