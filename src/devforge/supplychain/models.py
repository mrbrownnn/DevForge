"""Schema for the third-party skill source registry.

The registry is evidence about external repositories plus decisions a human made
about them. It installs nothing and executes nothing.

Two ideas carry the design:

* **Identity is a URL plus a commit SHA.** Names are not identity - the ecosystem
  survey found three mirrors of one security repository and four repositories
  answering to one skill name (docs/skill-ecosystem.md).
* **Trust is granted, never inferred.** A source is ``untrusted`` until a human
  records a review at a specific pin, and changing the pin revokes that.

Models use ``extra="forbid"`` so a typo in the registry is a load error rather
than a silently ignored field.
"""

from __future__ import annotations

import re
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SHA_RE = re.compile(r"^[0-9a-f]{40}$")

#: Licenses under which vendoring (copying content into this repository) is allowed.
#: Share-alike licenses are excluded deliberately: CC-BY-SA would propagate its terms
#: to derived documentation in an MIT project.
VENDORABLE_LICENSES = frozenset({"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC"})


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TrustTier(str, Enum):
    UNTRUSTED = "untrusted"
    REVIEWED = "reviewed"
    AUDITED = "audited"
    FIRST_PARTY = "first_party"


class Disposition(str, Enum):
    REFERENCE = "reference"
    VENDOR = "vendor"
    DYNAMIC_INSTALL = "dynamic_install"
    REJECTED = "rejected"


class ReviewStatus(str, Enum):
    NOT_REVIEWED = "not_reviewed"
    REVIEWED = "reviewed"
    AUDITED = "audited"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class MaintainerType(str, Enum):
    ORGANIZATION = "Organization"
    USER = "User"
    UNKNOWN = "unknown"


class Evidence(_Model):
    """How the registry contents were established, and what was not checked."""

    method: str
    verified_at: str
    verified_fields: list[str] = Field(default_factory=list)
    unverified_fields: list[str] = Field(default_factory=list)
    notes: str = ""


class TierPolicy(_Model):
    description: str = ""
    allow_scripts: bool = False
    allow_network: bool = False
    allow_install_commands: bool = False
    requires_approval: bool = True

    @model_validator(mode="after")
    def _no_tier_grants_network_or_installs(self) -> TierPolicy:
        # Stated as policy in docs/security/skill-supply-chain.md and enforced here so
        # a registry edit cannot quietly widen it.
        if self.allow_network:
            raise ValueError("no trust tier may grant network access to a skill")
        if self.allow_install_commands:
            raise ValueError("no trust tier may grant install commands to a skill")
        return self


class Maintainer(_Model):
    name: str
    type: MaintainerType = MaintainerType.UNKNOWN
    identity_basis: str = ""


class License(_Model):
    spdx: str | None = None
    repo_level_license_file: bool = False
    per_skill_license: str | None = None
    notes: str | None = None

    @property
    def vendorable(self) -> bool:
        """A permissive, repository-level license is required to copy content in."""
        return bool(self.spdx and self.spdx in VENDORABLE_LICENSES)


class Activity(_Model):
    stars: int | None = None
    forks: int | None = None
    open_issues: int | None = None
    created_at: str | None = None
    last_push: str | None = None
    archived: bool = False


class Pin(_Model):
    """An immutable content identity. Tags and branches are not pins - both are mutable."""

    commit: str
    commit_date: str | None = None
    verified_at: str | None = None

    @field_validator("commit")
    @classmethod
    def _full_sha(cls, value: str) -> str:
        if not SHA_RE.match(value):
            raise ValueError(
                f"pin.commit must be a full 40-character lowercase hex SHA, got {value!r}"
            )
        return value


class ExecutableSurface(_Model):
    files_total: int | None = None
    by_extension: dict[str, int] = Field(default_factory=dict)
    opaque_archives: int = 0
    notes: str | None = None


class Dependencies(_Model):
    declared: str | None = None
    observed: list[str] = Field(default_factory=list)
    notes: str | None = None


class SecurityConcern(_Model):
    id: str
    severity: Severity
    evidence: str


class Review(_Model):
    status: ReviewStatus = ReviewStatus.NOT_REVIEWED
    reviewer: str | None = None
    reviewed_at: str | None = None

    @model_validator(mode="after")
    def _review_names_a_reviewer(self) -> Review:
        if self.status is not ReviewStatus.NOT_REVIEWED and not self.reviewer:
            raise ValueError("a recorded review must name a reviewer")
        return self


class SourceEntry(_Model):
    """One third-party skill source."""

    id: str
    name: str
    repository: str
    maintainer: Maintainer
    license: License
    activity: Activity = Field(default_factory=Activity)
    pin: Pin
    content_hash: str | None = None
    install_mechanism: str = "unknown"
    supported_agents: list[str] = Field(default_factory=list)
    skills: list[str] = Field(default_factory=list)
    capabilities: list[str] = Field(default_factory=list)
    executable_surface: ExecutableSurface = Field(default_factory=ExecutableSurface)
    dependencies: Dependencies = Field(default_factory=Dependencies)
    security_concerns: list[SecurityConcern] = Field(default_factory=list)
    known_issues: str = "no_known_issues_recorded"
    disposition: Disposition = Disposition.REFERENCE
    trust_tier: TrustTier = TrustTier.UNTRUSTED
    review: Review = Field(default_factory=Review)
    rationale: str = ""

    @field_validator("repository")
    @classmethod
    def _https_url(cls, value: str) -> str:
        if not value.startswith("https://"):
            raise ValueError(f"repository must be an https URL, got {value!r}")
        return value

    @model_validator(mode="after")
    def _decisions_are_justified(self) -> SourceEntry:
        # Trust above the default has to point at a recorded review, otherwise the tier
        # is an assertion nobody stands behind.
        needs_review = self.trust_tier in {TrustTier.REVIEWED, TrustTier.AUDITED}
        if needs_review and self.review.status is ReviewStatus.NOT_REVIEWED:
            raise ValueError(
                f"source '{self.id}': trust tier '{self.trust_tier.value}' requires a "
                "recorded review"
            )
        if self.trust_tier is TrustTier.AUDITED and self.review.status is not ReviewStatus.AUDITED:
            raise ValueError(
                f"source '{self.id}': the audited tier requires review.status == audited"
            )
        # Vendoring copies content into this repository: it needs a permissive license
        # and a review, both.
        if self.disposition is Disposition.VENDOR:
            if not self.license.vendorable:
                raise ValueError(
                    f"source '{self.id}': cannot vendor under license "
                    f"{self.license.spdx or 'NONE'} (allowed: {sorted(VENDORABLE_LICENSES)})"
                )
            if self.review.status is ReviewStatus.NOT_REVIEWED:
                raise ValueError(f"source '{self.id}': cannot vendor an unreviewed source")
        # A rejection nobody explained is not reviewable.
        if self.disposition is Disposition.REJECTED and not self.rationale.strip():
            raise ValueError(f"source '{self.id}': a rejected source must record a rationale")
        return self

    @property
    def concerns_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for concern in self.security_concerns:
            counts[concern.severity.value] = counts.get(concern.severity.value, 0) + 1
        return counts

    @property
    def usable(self) -> bool:
        return self.disposition is not Disposition.REJECTED


class DiscoverySource(_Model):
    """An aggregator list. A discovery aid, never a security signal."""

    repository: str
    stars: int | None = None
    license: str | None = None
    pin: Pin | None = None
    role: str = "aggregator"
    caution: str = ""


class Gap(_Model):
    """A category with no credible source - recorded rather than filled with something weak."""

    category: str
    finding: str
    action: str = ""


class Defaults(_Model):
    trust_tier: TrustTier = TrustTier.UNTRUSTED
    disposition: Disposition = Disposition.REFERENCE
    requires_approval: bool = True
    allow_scripts: bool = False

    @model_validator(mode="after")
    def _defaults_are_closed(self) -> Defaults:
        if self.trust_tier is not TrustTier.UNTRUSTED:
            raise ValueError("the default trust tier must be 'untrusted' (secure by default)")
        if self.allow_scripts or not self.requires_approval:
            raise ValueError("defaults must not allow scripts or skip approval")
        return self


class SkillRegistryFile(_Model):
    """The whole of ``registry/skills.yaml``."""

    version: int = 1
    generated_at: str
    evidence: Evidence
    trust_tiers: dict[str, TierPolicy]
    dispositions: list[Disposition]
    defaults: Defaults
    sources: list[SourceEntry] = Field(default_factory=list)
    discovery_sources: list[DiscoverySource] = Field(default_factory=list)
    gaps: list[Gap] = Field(default_factory=list)

    @model_validator(mode="after")
    def _consistent(self) -> SkillRegistryFile:
        seen: set[str] = set()
        for source in self.sources:
            if source.id in seen:
                raise ValueError(f"duplicate source id '{source.id}'")
            seen.add(source.id)
            if source.trust_tier.value not in self.trust_tiers:
                raise ValueError(
                    f"source '{source.id}': trust tier '{source.trust_tier.value}' is not declared"
                )
            if source.disposition not in self.dispositions:
                raise ValueError(
                    f"source '{source.id}': disposition "
                    f"'{source.disposition.value}' is not declared"
                )
        # Discovery lists must never be usable as sources.
        source_repos = {s.repository for s in self.sources}
        for discovery in self.discovery_sources:
            if discovery.repository in source_repos:
                raise ValueError(
                    f"{discovery.repository} is listed both as a source and a discovery list"
                )
        return self

    def source(self, source_id: str) -> SourceEntry | None:
        return next((s for s in self.sources if s.id == source_id), None)

    @property
    def rejected(self) -> list[SourceEntry]:
        return [s for s in self.sources if s.disposition is Disposition.REJECTED]

    @property
    def vendored(self) -> list[SourceEntry]:
        return [s for s in self.sources if s.disposition is Disposition.VENDOR]
