"""Scoring a candidate, inspecting it, and deciding what to say about it.

Order matters here, and it is the same order the repair benchmark and the commit
guard use: **the security gate is applied before the score is consulted.** A
candidate that ships an arbitrary shell installer is not a high score with a
caveat; it is a WARN, whatever else is true about it. Trading those off against
each other is how a scoring system ends up recommending the thing it was built to
catch.

The three inputs:

*Quality* comes from the supply-chain scorer, unchanged. It already excludes
popularity, on evidence recorded in its own docstring.

*Fit* is computed here, because it is a property of the relationship between a
skill and this project - what we want, and what we already have.

*Security* comes from the supply-chain inspector when a local copy exists, and
from the operator's advisory file always. When there is no local copy the content
checks are reported as **unavailable**, never as passed.
"""

from __future__ import annotations

from pathlib import Path

from devforge.core.registry.skills import SkillRegistry
from devforge.radar.models import (
    MAX_FIT_POINTS,
    Candidate,
    Fit,
    Provenance,
    RadarScore,
    SecurityGate,
    Verdict,
)
from devforge.radar.sources import Advisory, FeedEntry, RadarConfig
from devforge.supplychain.catalog import QualityScore
from devforge.supplychain.inspect import inspect_skill
from devforge.supplychain.quality import RepoSignals, score_skill
from devforge.supplychain.risk import classify

#: Licences that are usable without a lawyer. Anything else is not a blocker,
#: but it is a warning, because "no licence" means "no permission".
CLEAR_LICENCES = frozenset(
    {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "MPL-2.0", "Unlicense"}
)

#: The seven checks the brief names. Listed so a report can say which ran.
SECURITY_CHECKS = (
    "source verification",
    "licence verification",
    "static inspection",
    "dependency inspection",
    "script inspection",
    "permission analysis",
    "security advisory check",
)


def evaluate(
    entry: FeedEntry,
    *,
    config: RadarConfig,
    provenance: Provenance,
    advisories: list[Advisory],
    installed: SkillRegistry | None = None,
    installed_version: str | None = None,
    known_quality: QualityScore | None = None,
) -> Candidate:
    """Score, inspect and judge one candidate.

    ``known_quality`` is a score somebody already measured - the packaged
    catalogue carries one per entry, derived from an actual inspection. Using it
    beats re-deriving from metadata: a recorded measurement is evidence, and
    scoring the same skill at zero because this process has no copy of it would
    be discarding evidence in favour of ignorance.
    """
    local = Path(entry.path) if entry.path else None
    security = inspect_candidate(entry, local=local, advisories=advisories)
    quality = measure_quality(entry, local=local, known=known_quality)
    fit = measure_fit(entry, config=config, installed=installed)

    score = RadarScore(quality=quality, fit=fit, popularity=_popularity(entry.stars))
    candidate = Candidate(
        name=entry.name,
        repository=entry.repository,
        version=entry.version,
        description=entry.description,
        license=entry.license,
        capabilities=list(entry.capabilities),
        provenance=provenance,
        score=score,
        security=security,
        installed_version=installed_version,
        available_version=entry.version if installed_version else None,
    )
    candidate.verdict, candidate.rationale = decide(candidate, entry=entry, config=config)
    return candidate


# --------------------------------------------------------------------------- security


def inspect_candidate(
    entry: FeedEntry, *, local: Path | None, advisories: list[Advisory]
) -> SecurityGate:
    """Run every check that can run here, and name the ones that cannot."""
    gate = SecurityGate()

    # 1. source verification
    if entry.repository:
        gate.checked.append("source verification")
        if not entry.repository.count("/") >= 1:
            gate.warnings.append(f"repository '{entry.repository}' is not an owner/name pair")
    else:
        gate.unavailable.append("source verification: the entry names no repository")

    # 2. licence verification
    gate.checked.append("licence verification")
    if not entry.license:
        gate.warnings.append("no licence declared, which means no permission to use it")
    elif entry.license not in CLEAR_LICENCES:
        gate.warnings.append(f"licence '{entry.license}' needs reading before adoption")

    # 3-6. content checks, which need content
    if local and local.is_dir():
        report = inspect_skill(local)
        assessment = classify(report)
        gate.checked += [
            "static inspection",
            "dependency inspection",
            "script inspection",
            "permission analysis",
        ]
        for finding in assessment.findings:
            line = f"{finding.rule} in {finding.path}: {finding.detail}"
            # A critical finding blocks; anything else is context a reviewer
            # reads. The inspector already made that judgement, and second-
            # guessing it here would put the same decision in two places.
            (gate.blocking if finding.blocking else gate.warnings).append(line)
        if assessment.blocked and not gate.blocking:
            gate.blocking.append(f"risk assessed as {assessment.level}")
    else:
        gate.unavailable += [
            f"{check}: no local copy to read"
            for check in (
                "static inspection",
                "dependency inspection",
                "script inspection",
                "permission analysis",
            )
        ]

    # 7. advisories
    gate.checked.append("security advisory check")
    matched = [
        advisory
        for advisory in advisories
        if advisory.applies_to(entry.name, entry.repository, entry.version)
    ]
    for advisory in matched:
        target = gate.blocking if advisory.severity in {"critical", "high"} else gate.warnings
        target.append(f"advisory ({advisory.severity}): {advisory.summary}")
    if not advisories:
        gate.unavailable.append(
            "security advisory check: no advisories are recorded locally, which is "
            "not the same as none existing"
        )

    return gate


# ---------------------------------------------------------------------------- quality


def measure_quality(
    entry: FeedEntry, *, local: Path | None, known: QualityScore | None = None
) -> QualityScore:
    """Score the repository, from content where there is content.

    Without a local copy only the metadata dimensions can be scored, and the rest
    stay at zero rather than being guessed upward. A candidate nobody has fetched
    therefore scores low - which is correct: nobody has looked at it.
    """
    signals = RepoSignals(last_commit=entry.last_commit, archived=entry.archived)
    if known is not None and known.total:
        return known
    if local and local.is_dir():
        return score_skill(
            local,
            assessment=classify(inspect_skill(local)),
            license_name=entry.license,
            capabilities=entry.capabilities,
            signals=signals,
        )

    score = QualityScore()
    if entry.license in CLEAR_LICENCES:
        score.license = 8
    elif entry.license:
        score.license = 4
    if entry.last_commit is not None and not entry.archived:
        score.maintenance = 6
    if entry.capabilities:
        score.capability_coverage = 4
    score.notes = [
        "scored from metadata only: no local copy was available, so documentation, "
        "tests, portability, security posture and dependency risk were not read"
    ]
    return score


# -------------------------------------------------------------------------------- fit


def measure_fit(
    entry: FeedEntry, *, config: RadarConfig, installed: SkillRegistry | None
) -> Fit:
    """Usefulness against what this project wants, minus what it already has."""
    wanted = {capability.lower() for capability in config.wanted_capabilities}
    provided = {capability.lower() for capability in entry.capabilities}
    covers = sorted(wanted & provided)

    if not wanted:
        # Nothing declared: the radar cannot tell useful from irrelevant, so it
        # awards the neutral half rather than assuming either.
        usefulness = MAX_FIT_POINTS // 2
        reason = "no wanted capabilities are configured, so usefulness is unscored"
    elif covers:
        usefulness = min(MAX_FIT_POINTS, len(covers) * 6)
        reason = f"covers {', '.join(covers)}"
    else:
        usefulness = 0
        reason = "covers none of the capabilities this project asked for"

    duplicates = _duplicates(entry, installed)
    penalty = min(usefulness, 8 * len(duplicates))
    if duplicates:
        reason += f"; already covered by {', '.join(duplicates)}"

    return Fit(
        covers=covers,
        duplicates=duplicates,
        usefulness=usefulness,
        duplication_penalty=penalty,
        reason=reason,
    )


def _duplicates(entry: FeedEntry, installed: SkillRegistry | None) -> list[str]:
    """Installed skills that already do what this candidate offers."""
    if installed is None:
        return []
    provided = {capability.lower() for capability in entry.capabilities}
    found: list[str] = []
    for skill in installed.all():
        if skill.name == entry.name:
            found.append(skill.name)
            continue
        existing = {capability.lower() for capability in getattr(skill, "capabilities", [])}
        if provided and existing and provided <= existing:
            found.append(skill.name)
    return sorted(set(found))


def _popularity(stars: int | None) -> int:
    """Stars, capped hard.

    Three points on a hundred-and-thirteen-point scale is enough to order two
    otherwise-equal candidates and not enough to move one across a threshold,
    which is exactly what the brief asks for.
    """
    if not stars or stars < 100:
        return 0
    if stars < 1_000:
        return 1
    if stars < 10_000:
        return 2
    return 3


# ------------------------------------------------------------------------- verdicts


def decide(
    candidate: Candidate, *, entry: FeedEntry, config: RadarConfig
) -> tuple[Verdict, str]:
    """What to say about a candidate, and why this and not the next one up."""
    if entry.deprecated or entry.archived:
        return (
            Verdict.DEPRECATE,
            "the upstream project is archived or marked deprecated; find a successor "
            "before it stops being patched",
        )

    if candidate.security.blocking:
        return Verdict.WARN, candidate.security.blocking[0]

    score = candidate.score.normalised

    if candidate.score.fit.duplicates:
        return (
            Verdict.WATCH,
            f"already covered by {', '.join(candidate.score.fit.duplicates)}; adopting it "
            "would mean two things to keep in step",
        )

    if score >= config.install_threshold and candidate.security.clean:
        return (
            Verdict.INSTALL,
            f"scores {score} with a clean inspection and {candidate.score.fit.reason}",
        )

    if score >= config.review_threshold:
        blockers = candidate.security.warnings or candidate.security.unavailable
        return (
            Verdict.REVIEW,
            f"scores {score}; "
            + (f"a person should read {blockers[0]}" if blockers else "worth a look"),
        )

    detail = (
        candidate.score.quality.notes[0]
        if candidate.score.quality.notes
        else "not enough evidence to say more"
    )
    return (
        Verdict.WATCH,
        f"scores {score}, below the {config.review_threshold} review threshold - {detail}",
    )
