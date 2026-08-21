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


class AgentPermissions(BaseModel):
    """What one agent may touch. Least privilege, declared per role.

    A documentation agent that can run shell commands is a documentation agent that
    can do anything; a security auditor that can write source can edit away the
    finding it just reported. Declaring the narrow set is what makes a multi-agent
    graph safer than one agent with every tool.

    These are *narrowing* overlays on the project policy, never widening ones: an
    agent cannot grant itself a path the project denies.
    """

    model_config = ConfigDict(extra="forbid")

    #: Globs this agent may read. Empty means "whatever the project policy allows".
    read: list[str] = Field(default_factory=list)
    #: Globs this agent may write. Empty means it writes nothing.
    write: list[str] = Field(default_factory=list)
    #: Shell command patterns. Empty means no shell at all.
    shell: list[str] = Field(default_factory=list)
    #: Set false to refuse process execution outright, whatever the tool list says.
    allow_shell: bool = False
    network: bool = False

    def summary(self) -> str:
        parts = [
            f"read={self.read or ['(project default)']}",
            f"write={self.write or ['(none)']}",
            f"shell={'yes' if self.allow_shell else 'no'}",
        ]
        return ", ".join(parts)


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
    permissions: AgentPermissions = Field(default_factory=AgentPermissions)
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
