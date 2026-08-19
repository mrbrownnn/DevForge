"""Skill model, parser and registry.

A skill is reusable agent knowledge stored as Markdown with a YAML frontmatter
header, so it is readable and editable without any DevForge tooling::

    ---
    name: testing
    version: 1.0.0
    description: Write meaningful tests
    capabilities: [unit-testing, regression-testing]
    dependencies: [debugging]
    compatible_runtimes: ["*"]
    ---

    # Testing

    ...instructions the agent receives verbatim...

Skills are composed into an agent's prompt at invocation time - instructions are
never hardcoded in Python.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from devforge.core.errors import ConfigError
from devforge.core.registry.base import Registry

ANY_RUNTIME = "*"


class Skill(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    version: str = "1.0.0"
    description: str = ""
    capabilities: list[str] = Field(default_factory=list)
    dependencies: list[str] = Field(default_factory=list)
    compatible_runtimes: list[str] = Field(default_factory=lambda: [ANY_RUNTIME])
    instructions: str = ""
    source_path: str | None = None

    def supports_runtime(self, runtime: str) -> bool:
        return ANY_RUNTIME in self.compatible_runtimes or runtime in self.compatible_runtimes


def parse_frontmatter(text: str, *, source: str = "<string>") -> tuple[dict, str]:
    """Split ``---`` YAML frontmatter from the Markdown body."""
    stripped = text.lstrip("﻿")
    if not stripped.startswith("---"):
        raise ConfigError(f"{source}: missing '---' YAML frontmatter header")
    parts = stripped.split("---", 2)
    if len(parts) < 3:
        raise ConfigError(f"{source}: frontmatter is not terminated by a closing '---'")
    try:
        meta = yaml.safe_load(parts[1]) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"{source}: invalid YAML frontmatter: {exc}") from exc
    if not isinstance(meta, dict):
        raise ConfigError(f"{source}: frontmatter must be a mapping")
    return meta, parts[2].strip()


def load_skill_file(path: Path) -> Skill:
    meta, body = parse_frontmatter(path.read_text(encoding="utf-8"), source=str(path))
    meta.setdefault("name", path.parent.name if path.name == "SKILL.md" else path.stem)
    meta["instructions"] = body
    meta["source_path"] = str(path)
    try:
        return Skill.model_validate(meta)
    except ValidationError as exc:
        raise ConfigError(f"{path}: invalid skill definition: {exc}") from exc


def builtin_skill_dir() -> Path:
    from devforge import builtin

    return Path(builtin.__file__).parent / "skills"


def skill_search_paths(project_root: Path | None) -> list[Path]:
    paths: list[Path] = []
    if project_root is not None:
        paths.append(project_root / ".devforge" / "skills")
        paths.append(project_root / "skills")
    paths.append(builtin_skill_dir())
    return paths


def discover_skill_files(directory: Path) -> list[Path]:
    """``<dir>/<name>/SKILL.md`` (preferred) and ``<dir>/<name>.md``."""
    if not directory.is_dir():
        return []
    found = [p for p in sorted(directory.glob("*/SKILL.md")) if p.is_file()]
    found += [p for p in sorted(directory.glob("*.md")) if p.is_file()]
    return found


class SkillRegistry(Registry[Skill]):
    def __init__(self) -> None:
        super().__init__("skill")

    @classmethod
    def discover(cls, project_root: Path | None = None) -> SkillRegistry:
        """Load every skill found on the search path; earlier paths win."""
        registry = cls()
        for directory in skill_search_paths(project_root):
            for path in discover_skill_files(directory):
                skill = load_skill_file(path)
                if skill.name not in registry:
                    registry.register(skill.name, skill)
        return registry

    def resolve(self, names: list[str], *, runtime: str | None = None) -> list[Skill]:
        """Resolve skill names plus their transitive dependencies, order preserved."""
        resolved: list[Skill] = []
        seen: set[str] = set()

        def visit(name: str, trail: tuple[str, ...]) -> None:
            if name in seen:
                return
            if name in trail:
                raise ConfigError(f"circular skill dependency: {' -> '.join([*trail, name])}")
            skill = self.get(name)
            for dependency in skill.dependencies:
                visit(dependency, (*trail, name))
            seen.add(name)
            resolved.append(skill)

        for name in names:
            visit(name, ())

        if runtime is not None:
            incompatible = [s.name for s in resolved if not s.supports_runtime(runtime)]
            if incompatible:
                raise ConfigError(
                    f"skills {incompatible} are not compatible with runtime '{runtime}'"
                )
        return resolved

    def unresolved_dependencies(self) -> dict[str, list[str]]:
        """Skills whose declared dependencies are not registered (used by ``devforge doctor``)."""
        broken: dict[str, list[str]] = {}
        for skill in self.all():
            missing = [d for d in skill.dependencies if d not in self]
            if missing:
                broken[skill.name] = missing
        return broken
