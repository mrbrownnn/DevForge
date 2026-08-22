"""Where the radar looks, and how that list stops being static.

The brief asks for discovery that is not limited to a fixed list. DevForge cannot
search GitHub - it has no HTTP client, by architecture rule and by threat model -
so the list grows three other ways, all of which are recorded as provenance:

**Configuration.** Organisations, repositories and topics an operator names in
``radar.yaml``. Editable, versioned, reviewed like anything else in the repo.

**Feeds.** Files an operator drops in ``radar/feeds/``: an export from a GitHub
search, a colleague's list, an advisory digest. The radar parses them, scores
what they contain, and records which feed each candidate came from and when the
feed was written. A feed with no date is treated as undated rather than fresh.

**Propagation.** Repositories named by things already known - a fork recorded in
the registry, a dependency declared by an installed skill, a related project a
catalogue entry mentions. Each new name is added as a candidate source with its
origin recorded, which is how the list grows without anyone editing it.

None of that is a crawler, and the report says so. The point is that coverage is
*legible*: every report lists what it consulted, so a reader knows the shape of
the hole rather than assuming there isn't one.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from devforge.core.errors import ConfigError

RADAR_DIRNAME = "radar"
CONFIG_FILENAME = "radar.yaml"
FEEDS_DIRNAME = "feeds"
ADVISORIES_FILENAME = "advisories.yaml"


class WatchedSource(BaseModel):
    """One place the radar is told to pay attention to."""

    model_config = ConfigDict(extra="forbid")

    #: "org", "repo" or "topic".
    kind: str = "repo"
    name: str
    #: Why an operator added it. Written down so a future reader can remove it.
    reason: str = ""
    #: How it got here: "configured", or "discovered via <origin>".
    origin: str = "configured"

    @property
    def label(self) -> str:
        return f"{self.kind}:{self.name}"


class Advisory(BaseModel):
    """A security advisory an operator has recorded.

    DevForge queries no advisory feed - that would be a network call and a new
    trust relationship. This is the local record: what somebody read elsewhere
    and wrote down here, so the radar can act on it.
    """

    model_config = ConfigDict(extra="forbid")

    skill: str = ""
    repository: str = ""
    severity: str = "medium"
    summary: str
    reference: str = ""
    recorded_at: datetime | None = None
    #: Versions known to be affected. Empty means "all of them".
    affected_versions: list[str] = Field(default_factory=list)

    def applies_to(self, name: str, repository: str, version: str = "") -> bool:
        if self.skill and self.skill != name:
            return False
        if self.repository and self.repository != repository:
            return False
        if self.affected_versions and version and version not in self.affected_versions:
            return False
        return bool(self.skill or self.repository)


class FeedEntry(BaseModel):
    """One candidate from an operator-supplied feed."""

    model_config = ConfigDict(extra="forbid")

    name: str
    repository: str = ""
    version: str = ""
    description: str = ""
    license: str | None = None
    capabilities: list[str] = Field(default_factory=list)
    #: Popularity, if the feed carried it. Capped hard when it is scored.
    stars: int | None = None
    #: Repositories this one is related to: forks, mirrors, successors. These
    #: become sources of their own on the next sweep.
    related: list[str] = Field(default_factory=list)
    archived: bool = False
    deprecated: bool = False
    last_commit: datetime | None = None
    #: Local path to a fetched copy, when the operator has one. Without it the
    #: radar can score metadata but cannot inspect content, and says so.
    path: str | None = None


class Feed(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int = 1
    #: When the operator gathered this. Undated feeds are reported as undated.
    generated_at: datetime | None = None
    source: str = ""
    entries: list[FeedEntry] = Field(default_factory=list)


class RadarConfig(BaseModel):
    """What to watch, and what this project is looking for."""

    model_config = ConfigDict(extra="forbid")

    version: int = 1
    watch: list[WatchedSource] = Field(default_factory=list)
    #: Capabilities this project wants. Drives the usefulness half of fit; a
    #: skill that covers none of them scores low however well it is made.
    wanted_capabilities: list[str] = Field(default_factory=list)
    #: Minimum normalised score for an INSTALL recommendation.
    install_threshold: int = 75
    #: Minimum for REVIEW. Below this, WATCH.
    review_threshold: int = 55

    def watching(self) -> list[str]:
        return [source.label for source in self.watch]


def radar_dir(root: Path) -> Path:
    return Path(root) / RADAR_DIRNAME


def config_path(root: Path) -> Path:
    return radar_dir(root) / CONFIG_FILENAME


def feeds_dir(root: Path) -> Path:
    return radar_dir(root) / FEEDS_DIRNAME


def advisories_path(root: Path) -> Path:
    return radar_dir(root) / ADVISORIES_FILENAME


def load_config(root: Path) -> RadarConfig:
    path = config_path(root)
    if not path.is_file():
        return RadarConfig()
    return _load(path, RadarConfig, "radar configuration")


def load_feeds(root: Path) -> list[tuple[Path, Feed]]:
    directory = feeds_dir(root)
    if not directory.is_dir():
        return []
    feeds: list[tuple[Path, Feed]] = []
    for path in sorted(directory.glob("*.y*ml")):
        feeds.append((path, _load(path, Feed, "feed")))
    return feeds


def load_advisories(root: Path) -> list[Advisory]:
    path = advisories_path(root)
    if not path.is_file():
        return []
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"could not read {path}: {exc}") from exc
    entries = raw.get("advisories", raw) if isinstance(raw, dict) else raw
    if not isinstance(entries, list):
        raise ConfigError(f"{path}: expected a list under 'advisories'")
    try:
        return [Advisory.model_validate(entry) for entry in entries]
    except ValidationError as exc:
        raise ConfigError(f"{path}: invalid advisory: {exc}") from exc


def discovered_sources(feeds: list[tuple[Path, Feed]]) -> list[WatchedSource]:
    """Sources the feeds themselves named. This is how the list grows.

    A fork, a mirror or a successor mentioned by a candidate becomes something to
    watch next time, with its origin recorded so a reader can tell a configured
    source from a propagated one.
    """
    found: dict[str, WatchedSource] = {}
    for path, feed in feeds:
        for entry in feed.entries:
            for repository in entry.related:
                if repository in found:
                    continue
                found[repository] = WatchedSource(
                    kind="repo",
                    name=repository,
                    reason=f"named as related to '{entry.name}'",
                    origin=f"discovered via {path.name}",
                )
    return sorted(found.values(), key=lambda source: source.name)


def _load(path: Path, model: type, what: str):
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"could not read {path}: {exc}") from exc
    try:
        return model.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(f"{path}: invalid {what}: {exc}") from exc
