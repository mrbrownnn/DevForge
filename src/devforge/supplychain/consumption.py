"""Trust enforcement at skill consumption time.

Phase 0 built the registry, the pins and the inspector, and said plainly that
nothing enforced them yet. This module is that enforcement: the point where a
skill stops being a catalogue entry and becomes text inside a prompt handed to an
agent that holds tool permissions.

Origin decides the rule
-----------------------

``FIRST_PARTY``
    Shipped inside the DevForge package. Trusted - it is our own content, covered
    by our own review process.
``PROJECT``
    Found under the user's project root. Trusted like the rest of their
    repository, but still inspected: a skill copied in from elsewhere lands here,
    and a critical finding blocks it.
``EXTERNAL``
    Anywhere else. Blocked unless the registry records a review at a matching
    content hash - which, since DevForge ships no installer, is a deliberate
    manual act.

A blocked skill is never silently dropped. Composition fails loudly, because a
prompt missing the instructions it was supposed to carry is a different prompt,
and pretending otherwise would produce silently degraded work.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from devforge.core.registry.skills import Skill
from devforge.supplychain.inspect import Finding, InspectionReport, inspect_skill
from devforge.supplychain.models import Severity, SkillRegistryFile, TrustTier


class SkillOrigin(str, Enum):
    FIRST_PARTY = "first_party"
    PROJECT = "project"
    EXTERNAL = "external"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class SkillAssessment:
    skill: str
    origin: SkillOrigin
    tier: TrustTier
    allowed: bool
    reason: str = ""
    findings: list[Finding] = field(default_factory=list)
    content_hash: str = ""

    @property
    def blocking_findings(self) -> list[Finding]:
        return [finding for finding in self.findings if finding.severity is Severity.CRITICAL]


def builtin_skill_root() -> Path:
    from devforge import builtin

    return (Path(builtin.__file__).parent / "skills").resolve()


def _within(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def classify(skill: Skill, project_root: Path | None) -> SkillOrigin:
    """Where a skill came from, decided by resolved path - never by its declared name."""
    if not skill.source_path:
        return SkillOrigin.UNKNOWN
    path = Path(skill.source_path).resolve()

    if _within(path, builtin_skill_root()):
        return SkillOrigin.FIRST_PARTY
    if project_root is not None and _within(path, Path(project_root).resolve()):
        return SkillOrigin.PROJECT
    return SkillOrigin.EXTERNAL


def _registry_clears(registry: SkillRegistryFile | None, content_hash: str) -> bool:
    """An external skill needs a registry entry reviewed at exactly this content."""
    if registry is None or not content_hash:
        return False
    for source in registry.sources:
        if source.content_hash != content_hash:
            continue
        if source.trust_tier is TrustTier.UNTRUSTED:
            continue
        return source.usable
    return False


def assess(
    skill: Skill,
    *,
    project_root: Path | None,
    registry: SkillRegistryFile | None = None,
) -> SkillAssessment:
    """Decide whether this skill may be composed into a prompt."""
    origin = classify(skill, project_root)

    if origin is SkillOrigin.FIRST_PARTY:
        return SkillAssessment(
            skill=skill.name,
            origin=origin,
            tier=TrustTier.FIRST_PARTY,
            allowed=True,
            reason="ships with DevForge",
        )

    if origin is SkillOrigin.UNKNOWN:
        return SkillAssessment(
            skill=skill.name,
            origin=origin,
            tier=TrustTier.UNTRUSTED,
            allowed=False,
            reason="skill has no source path, so its origin cannot be established",
        )

    report = _inspect(skill)
    blocking = [f for f in report.findings if f.severity is Severity.CRITICAL]

    if origin is SkillOrigin.PROJECT:
        allowed = not blocking
        reason = (
            "project-local skill"
            if allowed
            else f"critical finding(s): {', '.join(sorted({f.rule for f in blocking}))}"
        )
        return SkillAssessment(
            skill=skill.name,
            origin=origin,
            tier=TrustTier.UNTRUSTED if blocking else TrustTier.REVIEWED,
            allowed=allowed,
            reason=reason,
            findings=report.findings,
            content_hash=report.content_hash,
        )

    cleared = _registry_clears(registry, report.content_hash)
    allowed = cleared and not blocking
    if blocking:
        reason = f"critical finding(s): {', '.join(sorted({f.rule for f in blocking}))}"
    elif not cleared:
        reason = (
            "external skill with no registry entry reviewed at this content hash "
            "(see docs/security/skill-supply-chain.md)"
        )
    else:
        reason = "cleared by a registry review at this content hash"
    return SkillAssessment(
        skill=skill.name,
        origin=origin,
        tier=TrustTier.REVIEWED if allowed else TrustTier.UNTRUSTED,
        allowed=allowed,
        reason=reason,
        findings=report.findings,
        content_hash=report.content_hash,
    )


def _inspect(skill: Skill) -> InspectionReport:
    """Inspect the directory holding the skill, or the file itself if it stands alone."""
    path = Path(skill.source_path).resolve()
    target = path.parent if path.name == "SKILL.md" else path
    if target.is_dir():
        return inspect_skill(target)
    report = inspect_skill(target.parent)
    return report


def assess_all(
    skills: list[Skill],
    *,
    project_root: Path | None,
    registry: SkillRegistryFile | None = None,
) -> list[SkillAssessment]:
    return [assess(skill, project_root=project_root, registry=registry) for skill in skills]
