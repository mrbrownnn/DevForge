"""Assistant integration profiles.

DevForge's skills are markdown with frontmatter. Every coding assistant reads
project instructions from somewhere, and they all disagree about where and in what
shape: a rules directory, a single instructions file, a skill folder per capability.
An integration profile is the translation table for one assistant - where its files
go, what format they take, and what the file is called.

**Profiles are data, not classes.** Fourteen subclasses differing only by a path and
a frontmatter style would be an abstraction with no content, and DevForge already
made this decision for agents (``builtin/agents/*.yaml``) and workflows. There is a
second reason here: ``tests/test_architecture.py`` forbids naming a vendor anywhere
in the source outside its adapter, so the assistant names live in
``builtin/assistants/*.yaml`` and the code below never mentions one.

Adding support for an assistant means adding a YAML file. No Python changes.

**Layouts are declared with the confidence behind them.** Some of these conventions
are long-established and documented; others are newer and were inferred. A profile
records which it is, and the installer prints the difference rather than presenting
a guess as a fact. Being wrong about a path is cheap to fix; being confidently wrong
about it silently is not.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from devforge.core.errors import ConfigError

#: Selector meaning "every profile", accepted by the CLI.
ALL = "all"


class Format(str, Enum):
    """How one target file is written.

    Deliberately a small closed set. A profile that needs a genuinely new shape adds
    a member here; a profile that merely needs a different path or filename does not
    touch Python at all.
    """

    #: Markdown with DevForge's own YAML frontmatter, unchanged.
    SKILL = "skill"
    #: Markdown with a rules-style frontmatter block (description/globs/alwaysApply).
    RULES = "rules"
    #: Plain markdown, frontmatter stripped.
    MARKDOWN = "markdown"


class Confidence(str, Enum):
    """How well established the layout in this profile is.

    ``ESTABLISHED`` means the location is documented by the assistant and stable.
    ``INFERRED`` means it was derived from convention and should be checked before
    being relied on. The installer says which it wrote, because a file written to
    the wrong path is silently ignored by the assistant and looks like DevForge
    doing nothing.
    """

    ESTABLISHED = "established"
    INFERRED = "inferred"


class Target(BaseModel):
    """One file or directory this assistant reads."""

    model_config = ConfigDict(extra="forbid")

    #: Directory the files go in, relative to the project root (or to the home
    #: directory for a global install).
    path: str
    format: Format = Format.MARKDOWN
    #: Filename template for per-skill files. ``{skill}`` is substituted. When empty
    #: every skill is concatenated into ``path`` treated as a single file.
    filename: str = ""
    #: Written once, alongside the skills: how to drive DevForge from this assistant.
    instructions: str = ""

    @property
    def per_skill(self) -> bool:
        """Whether this target gets one file per skill or one file in total."""
        return bool(self.filename)


class AssistantProfile(BaseModel):
    """Where one assistant expects to find project instructions."""

    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    description: str = ""
    #: Project-relative install target.
    target: Target
    #: Home-relative target for ``--global``. Absent means this assistant has no
    #: documented global location, and ``--global`` refuses rather than guessing.
    global_target: Target | None = None
    confidence: Confidence = Confidence.INFERRED
    #: Why the layout is what it is, and what to check if it turns out wrong.
    notes: str = ""
    source_path: str | None = None

    @model_validator(mode="after")
    def _check(self) -> AssistantProfile:
        if not self.id.replace("-", "").isalnum():
            raise ValueError(f"assistant id '{self.id}' must be alphanumeric or hyphenated")
        for target in (self.target, self.global_target):
            if target is None:
                continue
            if _escapes(target.path):
                raise ValueError(
                    f"assistant '{self.id}': target path '{target.path}' must be relative "
                    "and must not escape its root"
                )
        return self

    @property
    def supports_global(self) -> bool:
        return self.global_target is not None


def load_profile(path: Path) -> AssistantProfile:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"could not read assistant profile {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: an assistant profile must be a YAML mapping")
    raw.setdefault("id", path.stem)
    raw["source_path"] = str(path)
    try:
        return AssistantProfile.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(f"{path}: invalid assistant profile: {exc}") from exc


class AssistantRegistry(BaseModel):
    """Every known assistant profile, by id."""

    model_config = ConfigDict(extra="forbid")

    profiles: list[AssistantProfile] = Field(default_factory=list)

    @classmethod
    def discover(cls, project_root: Path | None = None) -> AssistantRegistry:
        """Built-in profiles, overridable per project.

        A project that needs a different path for an assistant drops a file in
        ``.devforge/assistants/`` and it wins, exactly as workflows and agents do.
        """
        found: dict[str, AssistantProfile] = {}
        for directory in _search_paths(project_root):
            if not directory.is_dir():
                continue
            for path in sorted(directory.iterdir()):
                if path.suffix in {".yaml", ".yml"} and path.is_file():
                    profile = load_profile(path)
                    found.setdefault(profile.id, profile)
        return cls(profiles=[found[key] for key in sorted(found)])

    def get(self, assistant_id: str) -> AssistantProfile:
        profile = next((p for p in self.profiles if p.id == assistant_id), None)
        if profile is None:
            raise ConfigError(
                f"unknown assistant '{assistant_id}'. Available: "
                f"{', '.join(self.ids())}, {ALL}"
            )
        return profile

    def select(self, assistant_id: str) -> list[AssistantProfile]:
        """One profile, or every profile for the ``all`` selector."""
        if assistant_id == ALL:
            return list(self.profiles)
        return [self.get(assistant_id)]

    def ids(self) -> list[str]:
        return [profile.id for profile in self.profiles]


def _escapes(path: str) -> bool:
    """Whether a declared target path could write outside the root it belongs to.

    Checked without asking the operating system, because the operating systems
    disagree in a way that matters here: on Windows ``Path("/x").is_absolute()`` is
    False - a leading slash is drive-relative, not absolute - so relying on
    ``is_absolute`` alone lets a rooted path through on one platform and not the
    other. A profile is data that may come from a project directory, so the check
    has to behave the same everywhere.
    """
    text = str(path).strip()
    if not text:
        return True
    if text[0] in "/\\":
        return True
    if Path(text).is_absolute() or Path(text).drive or Path(text).anchor:
        return True
    return ".." in Path(text).parts or ".." in text.split("/")


def builtin_assistant_dir() -> Path:
    from devforge import builtin

    return Path(builtin.__file__).parent / "assistants"


def _search_paths(project_root: Path | None) -> list[Path]:
    paths: list[Path] = []
    if project_root is not None:
        paths.append(project_root / ".devforge" / "assistants")
        paths.append(project_root / "assistants")
    paths.append(builtin_assistant_dir())
    return paths
