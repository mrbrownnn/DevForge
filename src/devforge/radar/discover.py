"""Assembling a sweep: gather candidates, evaluate them, report coverage.

Candidates come from three places, and each one records where it came from:

* **feeds** an operator dropped in, which is the only path that carries genuinely
  new names;
* **the catalogue**, which is what DevForge already knows is installable;
* **installed skills**, which are what an UPDATE or a DEPRECATE is about.

Coverage is reported explicitly. A configured source that produced no candidate
appears under "not consulted" with the reason, because a report that lists only
what it found reads as though it looked everywhere.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from devforge.core.registry.skills import SkillRegistry
from devforge.radar.evaluate import evaluate
from devforge.radar.models import Candidate, Provenance, RadarReport, Verdict
from devforge.radar.sources import (
    Advisory,
    Feed,
    FeedEntry,
    RadarConfig,
    discovered_sources,
    feeds_dir,
    load_advisories,
    load_config,
    load_feeds,
)
from devforge.supplychain.catalog import SkillCatalog, load_catalog
from devforge.supplychain.install import load_lockfile


def sweep(root: Path, *, installed: SkillRegistry | None = None) -> RadarReport:
    """One pass over everything the radar can see from here."""
    config = load_config(root)
    feeds = load_feeds(root)
    advisories = load_advisories(root)
    installed = installed if installed is not None else SkillRegistry.discover(root)

    report = RadarReport()
    report.sources = list(config.watching())

    lock = _installed_versions(root)
    seen: set[str] = set()

    for path, feed in feeds:
        label = f"feed:{path.name}"
        report.sources.append(label)
        if not feed.entries:
            report.unreachable[label] = "the feed is empty"
            continue
        for entry in feed.entries:
            if entry.name in seen:
                continue
            seen.add(entry.name)
            report.candidates.append(
                evaluate(
                    entry,
                    config=config,
                    provenance=Provenance(
                        source=entry.repository or label,
                        kind=label,
                        observed_at=feed.generated_at,
                        evidence=feed.source or f"read from {path.name}",
                    ),
                    advisories=advisories,
                    installed=installed,
                    installed_version=lock.get(entry.name),
                )
            )

    catalog = _catalog(root, report)
    for entry in catalog.skills if catalog else []:
        if entry.name in seen:
            continue
        seen.add(entry.name)
        report.candidates.append(
            evaluate(
                _from_catalog(entry),
                config=config,
                provenance=Provenance(
                    source=entry.repository or entry.source,
                    kind="catalog",
                    evidence="the packaged skill catalogue",
                ),
                advisories=advisories,
                installed=installed,
                installed_version=lock.get(entry.name),
                known_quality=entry.quality,
            )
        )

    report.candidates += _advisories_against_installed(
        advisories, lock=lock, already=seen, config=config
    )

    for source in discovered_sources(feeds):
        if source.label not in report.sources:
            report.sources.append(source.label)
            report.unreachable[source.label] = (
                f"{source.reason}; nothing has been fetched for it yet"
            )

    if not feeds:
        report.unreachable["feeds"] = (
            f"no feed files under {feeds_dir(root)}; the radar cannot search the "
            "internet, so new names arrive only through a feed an operator supplies"
        )
    if not advisories:
        report.unreachable["advisories"] = (
            "no advisories recorded locally; DevForge queries no advisory feed, so "
            "this is silence rather than an all-clear"
        )
    return report


def _catalog(root: Path, report: RadarReport) -> SkillCatalog | None:
    try:
        catalog = load_catalog(root)
    except Exception as exc:  # a broken catalogue must not end the sweep
        report.unreachable["catalog"] = f"could not be read: {exc}"
        return None
    report.sources.append("catalog")
    return catalog


def _from_catalog(entry) -> FeedEntry:
    return FeedEntry(
        name=entry.name,
        repository=entry.repository,
        version=entry.version,
        description=entry.description,
        license=entry.license,
        capabilities=list(entry.capabilities),
    )


def _installed_versions(root: Path) -> dict[str, str]:
    """What is installed now, from the lockfile that records it."""
    try:
        lock = load_lockfile(root)
    except Exception:
        return {}
    return {entry.name: entry.version for entry in getattr(lock, "skills", []) or []}


def _advisories_against_installed(
    advisories: list[Advisory],
    *,
    lock: dict[str, str],
    already: set[str],
    config: RadarConfig,
) -> list[Candidate]:
    """An advisory against something installed is the most urgent thing here.

    It is raised even when nothing in a feed mentions the skill: the point of
    recording an advisory is that it applies to what you are already running.
    """
    raised: list[Candidate] = []
    for advisory in advisories:
        name = advisory.skill
        if not name or name in already or name not in lock:
            continue
        already.add(name)
        candidate = Candidate(
            name=name,
            repository=advisory.repository,
            version=lock[name],
            installed_version=lock[name],
            provenance=Provenance(
                source=advisory.reference or "local advisories",
                kind="advisory",
                observed_at=advisory.recorded_at,
                evidence=advisory.summary,
            ),
            verdict=Verdict.DEPRECATE
            if advisory.severity in {"critical", "high"}
            else Verdict.WARN,
            rationale=f"advisory ({advisory.severity}) against an installed skill: "
            f"{advisory.summary}",
        )
        candidate.security.blocking.append(advisory.summary)
        raised.append(candidate)
    return raised


def outdated(root: Path) -> list[Candidate]:
    """Installed skills a sweep found a newer version of."""
    report = sweep(root)
    return [
        candidate
        for candidate in report.candidates
        if candidate.installed_version
        and candidate.available_version
        and candidate.available_version != candidate.installed_version
    ]


def recommend(root: Path, *, limit: int = 5) -> list[Candidate]:
    """The candidates worth a person's time, best first."""
    report = sweep(root)
    ranked = sorted(report.actionable, key=lambda candidate: -candidate.score.normalised)
    return ranked[:limit]


def last_swept(root: Path) -> datetime | None:
    """When the freshest feed was gathered, if any of them said."""
    dates = [feed.generated_at for _, feed in load_feeds(root) if feed.generated_at]
    return max(dates) if dates else None


__all__ = ["Feed", "last_swept", "outdated", "recommend", "sweep"]
