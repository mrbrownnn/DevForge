"""Re-inspecting everything already installed.

`devforge skill audit` looks at one skill. This looks at all of them, which is a
different question: not "should I install this?" but "is what I am already
running still what I thought it was?"

Two things change under a skill's feet without anyone touching it. Its content
can drift from the hash the lockfile recorded - somebody edited a file in place,
or an update landed unreviewed. And an advisory can be published against a
version that was fine when it was installed. Neither is visible from inside the
skill, so both are checked here.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from devforge.radar.evaluate import inspect_candidate
from devforge.radar.models import SecurityGate
from devforge.radar.sources import FeedEntry, load_advisories
from devforge.supplychain.install import load_lockfile, skill_dir
from devforge.supplychain.registry import content_hash


class AuditResult(BaseModel):
    """What re-inspecting one installed skill found."""

    model_config = ConfigDict(extra="forbid")

    name: str
    version: str = ""
    repository: str = ""
    installed_at: str = ""
    #: True when the tree still hashes to what the lockfile recorded.
    intact: bool = True
    drift: str = ""
    security: SecurityGate = Field(default_factory=SecurityGate)

    @property
    def ok(self) -> bool:
        return self.intact and not self.security.blocking


def audit_installed(root: Path) -> list[AuditResult]:
    """Re-run the checks over every installed skill."""
    lock = load_lockfile(root)
    advisories = load_advisories(root)
    results: list[AuditResult] = []

    for entry in lock.skills:
        directory = skill_dir(root, entry.name)
        result = AuditResult(
            name=entry.name,
            version=entry.version,
            repository=getattr(entry, "repository", "") or "",
            installed_at=str(getattr(entry, "installed_at", "") or ""),
        )

        if not directory.is_dir():
            result.intact = False
            result.drift = "the lockfile records it, and it is not on disk"
            result.security.unavailable.append("every content check: nothing to read")
            results.append(result)
            continue

        recorded = getattr(entry, "content_hash", "") or ""
        observed = content_hash(directory)
        if recorded and observed != recorded:
            # Content drift is not a finding about the code; it is a finding
            # about the process. Something changed outside the install path.
            result.intact = False
            result.drift = (
                f"content hash is {observed[:12]}, the lockfile recorded "
                f"{recorded[:12]} - this tree changed outside 'devforge skill install'"
            )

        result.security = inspect_candidate(
            FeedEntry(
                name=entry.name,
                repository=result.repository,
                version=entry.version,
                license=getattr(entry, "license", None),
                path=str(directory),
            ),
            local=directory,
            advisories=advisories,
        )
        if not result.intact:
            result.security.blocking.append(result.drift)
        results.append(result)

    return results
