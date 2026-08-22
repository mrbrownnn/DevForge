"""What the radar produces: candidates, scores, verdicts and a report.

The scoring model is the part worth explaining.

``QualityScore`` (supply-chain layer) already answers *is this a well-made
thing?* across nine dimensions. The radar adds **fit** - *is it useful to this
project, and do we already have it?* - because those two are properties of the
relationship, not of the skill. A perfectly-made skill that duplicates one you
already run is a bad adoption, and no amount of scoring the skill alone will say
so.

Popularity is included and **capped at three points out of a hundred and ten**.
The brief allows stars to be considered and forbids them dominating; a cap is the
only way to guarantee the second part, and a test asserts that popularity alone
can never change a verdict.

Security does not add points. It **gates**: a candidate with a blocking finding
cannot be recommended however well it scores, because "install this" and "this
ships an arbitrary shell installer" are not two considerations to be traded off.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, model_validator

from devforge.core.models import utcnow
from devforge.supplychain.catalog import QualityScore

#: Popularity's whole contribution. Small enough that it cannot move a candidate
#: across a verdict boundary, present enough to break ties between equals.
MAX_POPULARITY_POINTS = 3
#: Fit is worth as much as two quality dimensions: useful, and not a duplicate.
MAX_FIT_POINTS = 20
#: Nine quality dimensions at ten points each.
MAX_QUALITY_POINTS = 90


class Verdict(str, Enum):
    """What the radar suggests a person do. Never what it does."""

    INSTALL = "INSTALL"
    REVIEW = "REVIEW"
    WATCH = "WATCH"
    WARN = "WARN"
    DEPRECATE = "DEPRECATE"

    @property
    def actionable(self) -> bool:
        return self in {Verdict.INSTALL, Verdict.REVIEW}


class Section(str, Enum):
    """The four sections of a radar report."""

    NEW = "NEW"
    UPDATE = "UPDATE"
    WARNING = "WARNING"
    DEPRECATE = "DEPRECATE"


class Provenance(BaseModel):
    """Where a candidate came from, and when the evidence was gathered.

    Recorded on every candidate because the radar's coverage is partial by
    construction, and a reader has to be able to tell "not found" from "not
    looked for".
    """

    model_config = ConfigDict(extra="forbid")

    source: str
    #: "registry", "catalog", "installed", "feed:<path>", "fork-of:<repo>"
    kind: str = "registry"
    observed_at: datetime | None = None
    #: What was actually read, in the operator's words. Never inferred.
    evidence: str = ""

    @property
    def stale(self) -> bool:
        """Whether the evidence predates any usable freshness claim."""
        return self.observed_at is None


class Fit(BaseModel):
    """How well a candidate suits *this* project. Scored out of 20."""

    model_config = ConfigDict(extra="forbid")

    #: Capabilities this project asks for that the candidate provides.
    covers: list[str] = Field(default_factory=list)
    #: Installed or built-in skills that already do this.
    duplicates: list[str] = Field(default_factory=list)
    usefulness: int = 0
    duplication_penalty: int = 0
    reason: str = ""

    @property
    def points(self) -> int:
        return max(0, self.usefulness - self.duplication_penalty)


class SecurityGate(BaseModel):
    """The security inspection's answer, separate from any score.

    ``blocking`` is what makes a verdict impossible rather than lower. Everything
    else is context a reviewer reads.
    """

    model_config = ConfigDict(extra="forbid")

    checked: list[str] = Field(default_factory=list)
    blocking: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    #: Checks that could not be performed here, with the reason. Never silently
    #: treated as passing.
    unavailable: list[str] = Field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not self.blocking and not self.warnings

    def summary(self) -> str:
        if self.blocking:
            return f"blocked: {self.blocking[0]}"
        if self.warnings:
            return f"{len(self.warnings)} warning(s)"
        if self.unavailable:
            return f"clean so far; {len(self.unavailable)} check(s) could not run"
        return "clean"


class RadarScore(BaseModel):
    """Quality plus fit plus a capped popularity term. Out of 113."""

    model_config = ConfigDict(extra="forbid")

    quality: QualityScore = Field(default_factory=QualityScore)
    fit: Fit = Field(default_factory=Fit)
    popularity: int = 0

    @model_validator(mode="after")
    def _cap(self) -> RadarScore:
        self.popularity = max(0, min(self.popularity, MAX_POPULARITY_POINTS))
        return self

    @property
    def total(self) -> int:
        return self.quality.total + self.fit.points + self.popularity

    @property
    def out_of(self) -> int:
        return MAX_QUALITY_POINTS + MAX_FIT_POINTS + MAX_POPULARITY_POINTS

    @property
    def normalised(self) -> int:
        """0-100, which is what a person reads. Rounded, never fabricated."""
        return round(self.total / self.out_of * 100)

    def breakdown(self) -> dict[str, int]:
        return {
            **self.quality.dimensions,
            "usefulness": self.fit.usefulness,
            "duplication": -self.fit.duplication_penalty,
            "popularity": self.popularity,
        }


class Candidate(BaseModel):
    """One skill the radar has looked at."""

    model_config = ConfigDict(extra="forbid")

    name: str
    repository: str = ""
    version: str = ""
    description: str = ""
    license: str | None = None
    capabilities: list[str] = Field(default_factory=list)
    provenance: Provenance
    score: RadarScore = Field(default_factory=RadarScore)
    security: SecurityGate = Field(default_factory=SecurityGate)
    verdict: Verdict = Verdict.WATCH
    #: One sentence saying why this verdict and not the next one up.
    rationale: str = ""
    #: Set for UPDATE entries.
    installed_version: str | None = None
    available_version: str | None = None

    @property
    def section(self) -> Section:
        if self.verdict is Verdict.DEPRECATE:
            return Section.DEPRECATE
        if self.verdict is Verdict.WARN:
            return Section.WARNING
        if self.installed_version and self.available_version:
            return Section.UPDATE
        return Section.NEW

    def line(self) -> str:
        return f"{self.name}  score: {self.score.normalised}  recommendation: {self.verdict.value}"


class RadarReport(BaseModel):
    """One sweep of the ecosystem, in four sections."""

    model_config = ConfigDict(extra="forbid")

    generated_at: datetime = Field(default_factory=utcnow)
    #: Every source consulted, so coverage is legible rather than assumed.
    sources: list[str] = Field(default_factory=list)
    candidates: list[Candidate] = Field(default_factory=list)
    #: Sources named in configuration that produced nothing, and why.
    unreachable: dict[str, str] = Field(default_factory=dict)

    def section(self, section: Section) -> list[Candidate]:
        return sorted(
            [candidate for candidate in self.candidates if candidate.section is section],
            key=lambda candidate: -candidate.score.normalised,
        )

    @property
    def actionable(self) -> list[Candidate]:
        return [candidate for candidate in self.candidates if candidate.verdict.actionable]

    def render(self) -> str:
        return render_report(self)


def render_report(report: RadarReport) -> str:
    """The report, in the shape the brief specifies."""
    lines = [
        "# Skill radar",
        "",
        f"{report.generated_at:%Y-%m-%d %H:%M UTC} - {len(report.candidates)} candidate(s) "
        f"from {len(report.sources)} source(s)",
        "",
    ]

    for section in Section:
        candidates = report.section(section)
        if not candidates:
            continue
        lines += [f"## {section.value}", ""]
        for candidate in candidates:
            lines.append(f"  {candidate.name}")
            if section is Section.UPDATE:
                lines.append(
                    f"    version: {candidate.installed_version} → {candidate.available_version}"
                )
                lines.append(f"    security: {candidate.security.summary()}")
            elif section in {Section.WARNING, Section.DEPRECATE}:
                lines.append(f"    reason: {candidate.rationale}")
            else:
                lines.append(f"    score: {candidate.score.normalised}")
                lines.append(f"    recommendation: {candidate.verdict.value}")
                lines.append(f"    why: {candidate.rationale}")
            lines.append("")

    if report.unreachable:
        lines += ["## Not consulted", ""]
        lines += [f"  {source}: {reason}" for source, reason in sorted(report.unreachable.items())]
        lines.append("")

    lines += ["## What this report does not cover", "", *_caveats(report)]
    return "\n".join(lines) + "\n"


def _caveats(report: RadarReport) -> list[str]:
    return [
        "DevForge does not crawl. Coverage is exactly the sources listed above - "
        "configured repositories, operator-supplied feeds, and what the local "
        "registry already knows. A skill that is not listed was not looked for.",
        "",
        "Every candidate is untrusted. A score is a reading of a repository's "
        "shape, not an audit of what its instructions will make a model do, and "
        "INSTALL means 'worth a person's review', never 'safe'.",
        "",
        "Nothing here is installed. `devforge skill install` is a separate, "
        "approval-gated act, and it stays that way.",
    ]
