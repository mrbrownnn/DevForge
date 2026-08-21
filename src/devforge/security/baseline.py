"""Accepted findings, with a reason and an expiry date.

Every scanner needs a way to say "we looked at this one and it is fine", or its
output becomes noise and people stop reading it. Every such mechanism is also the
obvious way to make a scanner useless, so this one has three properties that make
suppression expensive rather than free:

* a suppression names one rule at one location, never a whole rule;
* a written ``reason`` is required - "why is this acceptable?" answered in the
  file, where a reviewer will see it;
* an ``expires`` date is required. Suppressions rot. A finding accepted in March
  because a migration was in flight should not still be silently accepted in
  December, so an expired entry stops suppressing *and* raises a finding of its
  own.

Suppressed findings are reported, not deleted. They move to a separate section of
the report with their reasons attached; a report that silently omits them would
misrepresent what was found.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from devforge.core.errors import ConfigError

BASELINE_DIRNAME = "security"
BASELINE_FILENAME = "baseline.yaml"


class Suppression(BaseModel):
    model_config = ConfigDict(extra="forbid")

    #: Rule id, e.g. SEC-CODE-001.
    id: str
    #: Where the finding was reported. Either ``path:line`` for one occurrence, or
    #: a bare ``path`` to accept this one rule anywhere in that one file.
    #:
    #: Wildcards are deliberately absent - a suppression that can match a file you
    #: have not seen yet is not a review. File scope exists because line numbers
    #: move: an adversarial test fixture whose whole point is to contain the
    #: dangerous construct would otherwise need its acceptance re-pinned on every
    #: edit, and an acceptance nobody can keep accurate is one people delete.
    location: str
    reason: str
    expires: date
    accepted_by: str = ""

    @property
    def file_scoped(self) -> bool:
        """True when the location names a file rather than one line in it."""
        return ":" not in self.location.rsplit("/", 1)[-1]

    def covers(self, finding_id: str, location: str, *, today: date) -> bool:
        if self.expired(today) or self.id != finding_id:
            return False
        if self.location == location:
            return True
        return self.file_scoped and location.rsplit(":", 1)[0] == self.location

    def expired(self, today: date) -> bool:
        return today > self.expires


class Baseline(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int = 1
    description: str = ""
    suppressions: list[Suppression] = Field(default_factory=list)

    def match(self, finding_id: str, location: str, *, today: date) -> Suppression | None:
        for entry in self.suppressions:
            if entry.covers(finding_id, location, today=today):
                return entry
        return None

    def expired(self, today: date) -> list[Suppression]:
        return [entry for entry in self.suppressions if entry.expired(today)]


def baseline_path(root: Path) -> Path:
    return Path(root) / BASELINE_DIRNAME / BASELINE_FILENAME


def load_baseline(root: Path) -> Baseline:
    """Load the project's baseline, or an empty one. A missing file suppresses nothing."""
    path = baseline_path(root)
    if not path.is_file():
        return Baseline()
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: the baseline must be a YAML mapping")
    try:
        return Baseline.model_validate(raw)
    except ValidationError as exc:
        # Failing closed here matters: a baseline that does not parse must not be
        # treated as an empty one, or a typo becomes a silent suppression of nothing
        # while the author believes something is suppressed.
        raise ConfigError(f"{path}: invalid security baseline: {exc}") from exc
