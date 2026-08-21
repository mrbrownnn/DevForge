"""Risk classification and the security report.

The inspector produces findings; this turns them into a decision a policy can act
on. The four levels are the ones the brief names, and each has a concrete rule
rather than a feeling:

``LOW``
    Static instructions only. No executable file, no network reference, no
    installer, no credential reference.
``MEDIUM``
    Ships local scripts, writes files, or *mentions* a credential location -
    capability or context a reviewer must look at, but nothing that by itself
    reaches off the machine.
``HIGH``
    Network access *and* execution, package installation, obfuscated or encoded
    payloads, or an install hook. Any of these means the skill can run code that
    was not in the tree you reviewed.
``CRITICAL``
    An instruction to *access* credentials, or a pipeline into an interpreter. Not a
    risk to weigh - a refusal.

Mention is not access. An early version flagged any occurrence of ``.env`` as
CRITICAL, which rated a CI/CD skill teaching ".env -> NOT committed" as hostile.
Crying wolf on security-conscious content is how a scanner gets switched off, so the
credential rules are split three ways: an instruction to read or send credentials is
CRITICAL, code pulling a secret out of the environment is HIGH, and a bare mention is
MEDIUM.

The mapping is deliberately conservative and deliberately legible: a maintainer
should be able to read a report and reproduce the verdict by hand.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from devforge.core.models import utcnow
from devforge.supplychain.inspect import SCRIPT_SUFFIXES, Finding, InspectionReport
from devforge.supplychain.models import Severity
from devforge.tools.descriptor import RiskLevel


class SkillRisk(str):
    """Namespace for the four report levels (kept as plain strings for YAML/JSON)."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


ORDER = {SkillRisk.LOW: 0, SkillRisk.MEDIUM: 1, SkillRisk.HIGH: 2, SkillRisk.CRITICAL: 3}

#: Inspector rules that force a level, whatever else is present.
CRITICAL_RULES = frozenset({"pipe-to-shell", "credential-access"})
HIGH_RULES = frozenset(
    {
        "install-command",
        "encoded-payload",
        "hook-manifest",
        "credential-env-read",
        "exfiltration",
        "destructive-command",
        "execute-before-read",
        "undeclared-capability",
    }
)
MEDIUM_RULES = frozenset(
    {
        "executable-script",
        "archive-present",
        "network-fetch",
        "instruction-override",
        "approval-bypass",
        "credential-reference",
        "unreadable-file",
        "oversized-file",
    }
)

#: Which capability each rule demonstrates - reported so a reader sees *why*.
CAPABILITY_BY_RULE = {
    "pipe-to-shell": "remote code execution",
    "credential-access": "credential access",
    "credential-env-read": "reads credentials from the environment",
    "credential-reference": "mentions a credential location",
    "install-command": "package installation",
    "encoded-payload": "obfuscated payload",
    "hook-manifest": "install/session hook",
    "exfiltration": "network egress",
    "destructive-command": "destructive operation",
    "execute-before-read": "execute-before-review instruction",
    "undeclared-capability": "capability not declared",
    "executable-script": "local script execution",
    "archive-present": "opaque archive",
    "network-fetch": "network access",
    "instruction-override": "prompt injection",
    "approval-bypass": "safety-control bypass",
}


@dataclass
class RiskAssessment:
    """The verdict, the evidence, and what it means for installation."""

    level: str = SkillRisk.LOW
    reasons: list[str] = field(default_factory=list)
    capabilities: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    content_hash: str = ""
    assessed_at: datetime = field(default_factory=utcnow)

    @property
    def blocked(self) -> bool:
        """CRITICAL is a refusal, not a risk to weigh."""
        return self.level == SkillRisk.CRITICAL

    @property
    def requires_approval(self) -> bool:
        return ORDER[self.level] >= ORDER[SkillRisk.MEDIUM]

    @property
    def tool_risk(self) -> RiskLevel:
        """Map onto the tool-layer risk vocabulary so one policy can cover both."""
        return {
            SkillRisk.LOW: RiskLevel.READ,
            SkillRisk.MEDIUM: RiskLevel.WRITE,
            SkillRisk.HIGH: RiskLevel.EXECUTE,
            SkillRisk.CRITICAL: RiskLevel.DESTRUCTIVE,
        }[self.level]

    def counts(self) -> dict[str, int]:
        counts = {severity.value: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def exceeds(self, ceiling: str) -> bool:
        return ORDER[self.level] > ORDER[ceiling]


def _in_instructions(finding: Finding) -> bool:
    """Whether a finding sits in content an agent will read as instructions."""
    return Path(finding.path).suffix.lower() not in SCRIPT_SUFFIXES


def classify(report: InspectionReport) -> RiskAssessment:
    """Turn inspector findings into a level, with the reasoning attached."""
    rules = {finding.rule for finding in report.findings}
    reasons: list[str] = []
    level = SkillRisk.LOW

    # Credential access in *instructions* steers the agent and is a refusal. The same
    # pattern inside a shipped script is capability, not direction: the script is
    # quarantined and DevForge never runs it, so it is a decision for a human rather
    # than an automatic no. Trail of Bits ships a collector that reads the gh token
    # for rate limits - real credential access, and not a reason to refuse the skill.
    credential_findings = [f for f in report.findings if f.rule == "credential-access"]
    if credential_findings and not any(_in_instructions(f) for f in credential_findings):
        rules.discard("credential-access")
        rules.add("credential-env-read")
        reasons.append(
            "credential access appears only in shipped scripts, which are quarantined "
            "and never executed by DevForge - treated as capability, not direction"
        )

    critical = rules & CRITICAL_RULES
    high = rules & HIGH_RULES
    medium = rules & MEDIUM_RULES

    if critical:
        level = SkillRisk.CRITICAL
        reasons.append(f"credential or remote-execution indicators: {sorted(critical)}")
    elif high:
        level = SkillRisk.HIGH
        reasons.append(f"can execute code that was not in the reviewed tree: {sorted(high)}")
    elif medium:
        level = SkillRisk.MEDIUM
        reasons.append(f"ships capability beyond instructions: {sorted(medium)}")
    else:
        reasons.append("static instructions only: no scripts, network, installers or secrets")

    # Network *and* execution together is worse than either alone: that combination
    # is what turns a local script into a channel off the machine.
    if level == SkillRisk.MEDIUM and {"network-fetch", "executable-script"} <= rules:
        level = SkillRisk.HIGH
        reasons.append("network access combined with local scripts")

    capabilities = sorted(
        {CAPABILITY_BY_RULE[rule] for rule in rules if rule in CAPABILITY_BY_RULE}
    )

    return RiskAssessment(
        level=level,
        reasons=reasons,
        capabilities=capabilities,
        findings=list(report.findings),
        files_scanned=report.files_scanned,
        content_hash=report.content_hash,
    )


def render_report(
    *,
    skill: str,
    repository: str,
    commit: str,
    assessment: RiskAssessment,
    license_name: str | None = None,
    quality_summary: str = "",
) -> str:
    """A security report a human can read and disagree with."""
    counts = assessment.counts()
    lines = [
        f"# Skill security report: {skill}",
        "",
        f"- **Risk level:** {assessment.level}",
        f"- **Repository:** {repository}",
        f"- **Commit:** `{commit}`",
        f"- **Content hash:** `{assessment.content_hash}`",
        f"- **License:** {license_name or 'UNKNOWN'}",
        f"- **Files scanned:** {assessment.files_scanned}",
        f"- **Assessed:** {assessment.assessed_at.isoformat()}",
    ]
    if quality_summary:
        lines.append(f"- **Quality:** {quality_summary}")
    lines += ["", "## Verdict", ""]
    lines += [f"- {reason}" for reason in assessment.reasons]

    if assessment.capabilities:
        lines += ["", "## Capabilities demonstrated by the content", ""]
        lines += [f"- {capability}" for capability in assessment.capabilities]

    lines += [
        "",
        "## Findings",
        "",
        f"critical={counts['critical']} high={counts['high']} "
        f"medium={counts['medium']} low={counts['low']}",
        "",
    ]
    if assessment.findings:
        lines += ["| severity | rule | location | detail |", "| --- | --- | --- | --- |"]
        for finding in sorted(
            assessment.findings, key=lambda f: (-ORDER.get(f.severity.value.upper(), 0), f.path)
        ):
            location = finding.path + (f":{finding.line}" if finding.line else "")
            lines.append(
                f"| {finding.severity.value} | {finding.rule} | `{location}` | {finding.detail} |"
            )
    else:
        lines.append("No findings.")

    lines += [
        "",
        "## What this report is not",
        "",
        "A clean report is not proof of safety. Static inspection cannot decide intent,",
        "and natural-language instructions can be hostile without matching any pattern.",
        "DevForge never executes skill content, which is the control that does not depend",
        "on this report being right.",
        "",
    ]
    return "\n".join(lines)
