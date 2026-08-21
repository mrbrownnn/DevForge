"""The skill catalogue: individual skills, not just the repositories they live in.

Phase 0 catalogued *sources* - whole repositories, pinned and dispositioned.
That is the right unit for a trust decision about a publisher, and the wrong unit
for installation: nobody wants all 41 Trail of Bits plugins because they wanted
one. This module is the skill-level index that installation works from.

Every entry carries the provenance needed to fetch exactly one tree
(`repository` + `commit_sha` + `path`), the evidence needed to judge it
(`license`, `risk_level`, `security_status`, `quality`), and the constraints
needed to run it safely (`required_tools`, `required_permissions`,
`supported_runtimes`).

Two fields are deliberately nullable until an audit has actually happened:
`content_hash` and `last_audited`. A catalogue entry is a *claim about where a
skill lives*; only an audit turns it into a claim about what the skill contains.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from devforge.core.errors import ConfigError
from devforge.supplychain.models import SHA_RE, VENDORABLE_LICENSES
from devforge.tools.descriptor import RiskLevel

CATALOG_FILENAME = "catalog.yaml"


class SourceType(str, Enum):
    """How a skill is obtained. Only ``git`` is implemented."""

    GIT = "git"
    LOCAL = "local"
    #: Declared so a config naming one fails loudly rather than being misread.
    ARCHIVE = "archive"
    REGISTRY = "registry"


class SecurityStatus(str, Enum):
    """What is known about this skill, not what is hoped."""

    UNAUDITED = "unaudited"
    AUDITED_CLEAN = "audited_clean"
    AUDITED_WITH_FINDINGS = "audited_with_findings"
    QUARANTINED = "quarantined"
    REJECTED = "rejected"

    @property
    def installable(self) -> bool:
        return self not in {SecurityStatus.QUARANTINED, SecurityStatus.REJECTED}


class Compatibility(BaseModel):
    """What this skill needs from the harness around it."""

    model_config = ConfigDict(extra="forbid")

    devforge_min_version: str = "0.1.0"
    #: Empty means "no constraint", not "unknown" - unknown is recorded in notes.
    agents: list[str] = Field(default_factory=list)
    platforms: list[str] = Field(default_factory=list)
    notes: str = ""


class QualityScore(BaseModel):
    """Nine dimensions, deliberately excluding popularity.

    Stars measure reach, not care. The Phase 0 survey found the most-starred
    source shipping auto-executing session hooks and the least-starred one
    shipping CODEOWNERS and pre-commit config; scoring on stars would have
    inverted that judgement.
    """

    model_config = ConfigDict(extra="forbid")

    maintenance: int = 0  # recency and regularity of commits
    activity: int = 0  # is anyone answering issues
    documentation: int = 0  # does the skill explain itself
    tests: int = 0  # does the repository test anything
    license: int = 0  # are the terms clear and usable
    portability: int = 0  # does it work outside one vendor
    security_posture: int = 0  # CODEOWNERS, pinned CI, security policy
    dependency_risk: int = 0  # fewer moving parts scores higher
    capability_coverage: int = 0  # does it do what it claims

    #: Free-text reasons, so a score is never an unexplained number.
    notes: list[str] = Field(default_factory=list)

    DIMENSIONS: tuple[str, ...] = ()

    @property
    def dimensions(self) -> dict[str, int]:
        return {
            "maintenance": self.maintenance,
            "activity": self.activity,
            "documentation": self.documentation,
            "tests": self.tests,
            "license": self.license,
            "portability": self.portability,
            "security_posture": self.security_posture,
            "dependency_risk": self.dependency_risk,
            "capability_coverage": self.capability_coverage,
        }

    @property
    def total(self) -> int:
        """Out of 90: nine dimensions, ten points each."""
        return sum(self.dimensions.values())

    @property
    def grade(self) -> str:
        total = self.total
        if total >= 72:
            return "A"
        if total >= 58:
            return "B"
        if total >= 45:
            return "C"
        if total >= 30:
            return "D"
        return "F"

    @property
    def weakest(self) -> list[str]:
        ranked = sorted(self.dimensions.items(), key=lambda item: item[1])
        return [name for name, score in ranked if score <= 3]


class SkillEntry(BaseModel):
    """One installable skill."""

    model_config = ConfigDict(extra="forbid")

    # -- identity
    name: str
    version: str = "0.0.0"
    description: str = ""
    author: str = ""

    # -- provenance: this is the identity that matters, not the name
    source: str
    source_type: SourceType = SourceType.GIT
    repository: str = ""
    commit_sha: str | None = None
    #: Path to the skill inside the repository, e.g. "skills/webapp-testing".
    path: str = "."
    content_hash: str | None = None

    # -- terms
    license: str | None = None
    license_file: str | None = None

    # -- what it does and needs
    capabilities: list[str] = Field(default_factory=list)
    dependencies: list[str] = Field(default_factory=list)
    supported_runtimes: list[str] = Field(default_factory=lambda: ["*"])
    required_tools: list[str] = Field(default_factory=list)
    required_permissions: list[str] = Field(default_factory=list)

    # -- what is known about it
    risk_level: RiskLevel = RiskLevel.READ
    security_status: SecurityStatus = SecurityStatus.UNAUDITED
    last_audited: datetime | None = None
    quality: QualityScore = Field(default_factory=QualityScore)
    compatibility: Compatibility = Field(default_factory=Compatibility)

    tags: list[str] = Field(default_factory=list)
    notes: str = ""

    @field_validator("commit_sha")
    @classmethod
    def _full_sha(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not SHA_RE.match(value):
            raise ValueError(f"commit_sha must be a full 40-character hex SHA, got {value!r}")
        return value

    @field_validator("path")
    @classmethod
    def _contained_path(cls, value: str) -> str:
        """A catalogue entry must not point outside the repository it names."""
        candidate = Path(value)
        if candidate.is_absolute() or ".." in candidate.parts:
            raise ValueError(f"path must stay inside the repository, got {value!r}")
        return value

    @property
    def pinned(self) -> bool:
        return self.commit_sha is not None

    @property
    def audited(self) -> bool:
        return self.security_status in {
            SecurityStatus.AUDITED_CLEAN,
            SecurityStatus.AUDITED_WITH_FINDINGS,
        }

    @property
    def license_permits_redistribution(self) -> bool:
        return bool(self.license and self.license in VENDORABLE_LICENSES)

    def matches(self, query: str) -> bool:
        """Substring search across the fields a person would actually search on."""
        needle = query.strip().lower()
        if not needle:
            return True
        haystack = " ".join(
            [
                self.name,
                self.description,
                self.author,
                " ".join(self.capabilities),
                " ".join(self.tags),
                self.repository,
            ]
        ).lower()
        return needle in haystack

    def summary_line(self) -> str:
        return (
            f"{self.name} ({self.version}) - {self.description[:70]} "
            f"[risk={self.risk_level.value}, {self.security_status.value}, "
            f"quality={self.quality.grade}]"
        )


class SkillCatalog(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int = 1
    generated_at: str = ""
    description: str = ""
    skills: list[SkillEntry] = Field(default_factory=list)

    def skill(self, name: str) -> SkillEntry | None:
        return next((entry for entry in self.skills if entry.name == name), None)

    def search(self, query: str) -> list[SkillEntry]:
        return [entry for entry in self.skills if entry.matches(query)]

    def by_repository(self, repository: str) -> list[SkillEntry]:
        return [entry for entry in self.skills if entry.repository == repository]

    @property
    def names(self) -> list[str]:
        return sorted(entry.name for entry in self.skills)


def packaged_catalog_path() -> Path:
    return Path(__file__).resolve().parents[3] / "registry" / CATALOG_FILENAME


def catalog_search_paths(project_root: Path | None) -> list[Path]:
    paths: list[Path] = []
    if project_root is not None:
        paths.append(project_root / ".devforge" / "registry" / CATALOG_FILENAME)
        paths.append(project_root / "registry" / CATALOG_FILENAME)
    paths.append(packaged_catalog_path())
    return paths


def load_catalog(project_root: Path | None = None) -> SkillCatalog:
    """Load the first catalogue found. A project with none has an empty catalogue."""
    for path in catalog_search_paths(project_root):
        if path.is_file():
            return load_catalog_file(path)
    return SkillCatalog()


def load_catalog_file(path: Path) -> SkillCatalog:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: the skill catalogue must be a YAML mapping")
    try:
        catalog = SkillCatalog.model_validate(raw)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(part) for part in error['loc'])}: {error['msg']}"
            for error in exc.errors()
        )
        raise ConfigError(f"{path}: {problems}") from exc

    seen: set[str] = set()
    for entry in catalog.skills:
        if entry.name in seen:
            raise ConfigError(f"{path}: duplicate skill name '{entry.name}'")
        seen.add(entry.name)
    return catalog
