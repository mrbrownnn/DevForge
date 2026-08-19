"""Declarative agent specifications.

An agent is configuration, not a class: role, prompt templates, default skills,
allowed tools and an optional preferred runtime. Six subclasses of an ``Agent``
base that differ only by prompt string would be an abstraction with no content,
so DevForge ships ``planner.yaml``, ``coder.yaml`` and friends instead. Adding an
agent means adding a YAML file.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from devforge.core.errors import ConfigError
from devforge.core.registry.base import Registry

AGENT_SUFFIXES = (".yaml", ".yml")


class AgentSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    version: str = "1.0.0"
    role: str = ""
    description: str = ""
    # Rendered with {{placeholders}}; see devforge.agents.prompt.
    system_prompt: str = ""
    prompt_template: str = ""
    repair_template: str = ""
    skills: list[str] = Field(default_factory=list)
    tools: list[str] = Field(default_factory=list)
    preferred_runtime: str | None = None
    timeout_s: int = 900
    source_path: str | None = None


def builtin_agent_dir() -> Path:
    from devforge import builtin

    return Path(builtin.__file__).parent / "agents"


def agent_search_paths(project_root: Path | None) -> list[Path]:
    paths: list[Path] = []
    if project_root is not None:
        paths.append(project_root / ".devforge" / "agents")
        paths.append(project_root / "agents")
    paths.append(builtin_agent_dir())
    return paths


def load_agent_file(path: Path) -> AgentSpec:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: agent definition must be a YAML mapping")
    raw.setdefault("name", path.stem)
    raw["source_path"] = str(path)
    try:
        return AgentSpec.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(f"{path}: invalid agent definition: {exc}") from exc


class AgentRegistry(Registry[AgentSpec]):
    def __init__(self) -> None:
        super().__init__("agent")

    @classmethod
    def discover(cls, project_root: Path | None = None) -> AgentRegistry:
        registry = cls()
        for directory in agent_search_paths(project_root):
            if not directory.is_dir():
                continue
            for path in sorted(directory.iterdir()):
                if path.suffix in AGENT_SUFFIXES and path.is_file():
                    spec = load_agent_file(path)
                    if spec.name not in registry:
                        registry.register(spec.name, spec)
        return registry
