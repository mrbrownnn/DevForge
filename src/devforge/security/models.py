"""Types for the Security Center.

Two different questions produce two different result types, and conflating them
is how security tooling starts lying.

A :class:`Finding` says *something in this workspace looks dangerous* - a
credential in a file, an `eval` in generated code, injection-shaped text in a
README. It points at a location and it can be wrong.

A :class:`CheckResult` says *this control is or is not in place* - network is
denied by default, skills are pinned by hash, no gate is auto-approved. It points
at configuration and is checkable rather than heuristic.

Both carry a `threat` field linking back to the threat model, because a finding
that cannot be traced to a threat is a lint rule wearing a security badge.

On the absence of a "secure" verdict
------------------------------------

Nothing here computes a pass/fail for the system as a whole, and there is no
score. A tool that prints "SECURE" after eight checks teaches its user that eight
checks are what security means. The reports state what was examined, what was
found, and what was not looked at - the last of those being the part that matters.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from devforge.core.models import utcnow


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return ["info", "low", "medium", "high", "critical"].index(self.value)

    @property
    def blocking(self) -> bool:
        """What makes `devforge security scan` exit non-zero."""
        return self.rank >= Severity.HIGH.rank


class Category(str, Enum):
    """What kind of weakness this is, aligned with the layer that would stop it."""

    SECRET = "secret"
    INJECTION = "injection"
    UNSAFE_CODE = "unsafe-code"
    POLICY = "policy"
    SUPPLY_CHAIN = "supply-chain"
    PERMISSIONS = "permissions"
    AUDIT = "audit"


class Finding(BaseModel):
    """Something observed in the workspace that may be dangerous."""

    model_config = ConfigDict(extra="forbid")

    #: Stable rule id, e.g. ``SEC-SECRET-001``. Stable so a baseline can name it.
    id: str
    title: str
    severity: Severity
    category: Category
    #: ``path`` or ``path:line`` or a configuration key.
    location: str = ""
    #: Already redacted. A security report is not the place to publish the secret.
    evidence: str = ""
    remediation: str = ""
    #: Threat model id (T1..T12) this finding is evidence for.
    threat: str = ""

    def key(self) -> str:
        """Identity for baseline suppression: the rule plus where it fired."""
        return f"{self.id}:{self.location}"

    def describe(self) -> str:
        where = f" at {self.location}" if self.location else ""
        return f"[{self.severity.value}] {self.id} {self.title}{where}"


class CheckStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    #: The control does not apply to this project (no MCP servers configured, etc.).
    NOT_APPLICABLE = "n/a"
    #: The control could not be evaluated. Never silently treated as a pass.
    UNKNOWN = "unknown"

    @property
    def ok(self) -> bool:
        return self in (CheckStatus.PASS, CheckStatus.NOT_APPLICABLE)


class CheckResult(BaseModel):
    """Whether one named control is actually in place."""

    model_config = ConfigDict(extra="forbid")

    id: str
    layer: int
    title: str
    status: CheckStatus
    detail: str = ""
    remediation: str = ""
    threat: str = ""


class LayerStatus(str, Enum):
    IMPLEMENTED = "implemented"
    #: Real, but narrower than the name suggests. The detail says how.
    PARTIAL = "partial"
    #: Declared, deliberately absent, and documented as absent.
    NOT_IMPLEMENTED = "not-implemented"


class Layer(BaseModel):
    """One layer of the defence-in-depth model, and where it actually lives."""

    model_config = ConfigDict(extra="forbid")

    number: int
    name: str
    intent: str
    status: LayerStatus
    #: Modules that implement it. Asserted against the tree by the test suite, so a
    #: layer cannot keep claiming an implementation that was deleted.
    modules: list[str] = Field(default_factory=list)
    #: What this layer does *not* do. The most important field in the model.
    limits: str = ""


class Threat(BaseModel):
    """One entry in the threat model, with its controls and residual risk."""

    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    description: str
    severity: Severity
    #: Layer numbers that apply to this threat.
    layers: list[int] = Field(default_factory=list)
    controls: list[str] = Field(default_factory=list)
    #: What remains after the controls. Never empty - "none" is not an option.
    residual: str


class ScanReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    generated_at: datetime = Field(default_factory=utcnow)
    root: str = ""
    findings: list[Finding] = Field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    #: Findings matched by the baseline, kept visible rather than deleted.
    suppressed: list[Finding] = Field(default_factory=list)
    #: Paths the scanner could not read, or refused to.
    unreadable: list[str] = Field(default_factory=list)

    def by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
        return counts

    @property
    def blocking(self) -> list[Finding]:
        return [finding for finding in self.findings if finding.severity.blocking]

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (-f.severity.rank, f.id, f.location))


class AuditReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    generated_at: datetime = Field(default_factory=utcnow)
    root: str = ""
    results: list[CheckResult] = Field(default_factory=list)

    @property
    def failed(self) -> list[CheckResult]:
        return [r for r in self.results if r.status is CheckStatus.FAIL]

    @property
    def warned(self) -> list[CheckResult]:
        return [r for r in self.results if r.status is CheckStatus.WARN]

    @property
    def unknown(self) -> list[CheckResult]:
        return [r for r in self.results if r.status is CheckStatus.UNKNOWN]

    def by_layer(self) -> dict[int, list[CheckResult]]:
        grouped: dict[int, list[CheckResult]] = {}
        for result in self.results:
            grouped.setdefault(result.layer, []).append(result)
        return dict(sorted(grouped.items()))
