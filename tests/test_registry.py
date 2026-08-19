from __future__ import annotations

from pathlib import Path

import pytest

from devforge.agents.spec import AgentRegistry, load_agent_file
from devforge.core.errors import ConfigError, RegistryError
from devforge.core.registry.base import Registry
from devforge.core.registry.skills import Skill, SkillRegistry, load_skill_file, parse_frontmatter

SKILL_TEMPLATE = """---
name: {name}
version: 1.0.0
description: {name} skill
capabilities: [{name}-cap]
dependencies: [{deps}]
compatible_runtimes: ["*"]
---

# {name}

Instructions for {name}.
"""


def write_skill(directory: Path, name: str, deps: str = "") -> Path:
    skill_dir = directory / name
    skill_dir.mkdir(parents=True, exist_ok=True)
    path = skill_dir / "SKILL.md"
    path.write_text(SKILL_TEMPLATE.format(name=name, deps=deps), encoding="utf-8")
    return path


def test_registry_rejects_duplicates_unless_replacing() -> None:
    registry: Registry[str] = Registry("thing")
    registry.register("a", "first")

    with pytest.raises(RegistryError, match="already registered"):
        registry.register("a", "second")

    registry.register("a", "second", replace=True)
    assert registry.get("a") == "second"


def test_registry_unknown_lookup_lists_available() -> None:
    registry: Registry[str] = Registry("tool")
    registry.register("git", "x")

    with pytest.raises(RegistryError, match="Available: git"):
        registry.get("browser")
    assert registry.try_get("browser") is None


def test_parse_frontmatter_requires_header() -> None:
    with pytest.raises(ConfigError, match="frontmatter"):
        parse_frontmatter("# no header\n")
    with pytest.raises(ConfigError, match="not terminated"):
        parse_frontmatter("---\nname: x\n")

    meta, body = parse_frontmatter("---\nname: x\n---\n\nbody text\n")
    assert meta == {"name": "x"} and body == "body text"


def test_load_skill_uses_directory_name_when_absent(tmp_path: Path) -> None:
    path = tmp_path / "testing" / "SKILL.md"
    path.parent.mkdir(parents=True)
    path.write_text("---\ndescription: d\n---\n\nbody\n", encoding="utf-8")

    skill = load_skill_file(path)
    assert skill.name == "testing"
    assert skill.instructions == "body"


def test_builtin_skills_discover_and_resolve() -> None:
    registry = SkillRegistry.discover(project_root=None)

    for expected in (
        "requirements",
        "planning",
        "architecture",
        "frontend",
        "backend",
        "testing",
        "debugging",
        "security",
    ):
        assert expected in registry, f"built-in skill '{expected}' should be discoverable"
    assert registry.unresolved_dependencies() == {}
    assert all(skill.instructions.strip() for skill in registry.all())


def test_project_skills_override_builtins(tmp_path: Path) -> None:
    write_skill(tmp_path / "skills", "testing")
    registry = SkillRegistry.discover(project_root=tmp_path)

    assert registry.get("testing").source_path.startswith(str(tmp_path))
    assert "backend" in registry, "built-ins still load when a project only overrides one skill"


def test_resolve_pulls_in_transitive_dependencies() -> None:
    registry = SkillRegistry.discover(project_root=None)
    resolved = [skill.name for skill in registry.resolve(["architecture"])]

    # architecture -> planning -> requirements, dependencies first
    assert resolved == ["requirements", "planning", "architecture"]


def test_resolve_detects_cycles(tmp_path: Path) -> None:
    skills = tmp_path / "skills"
    write_skill(skills, "alpha", deps="beta")
    write_skill(skills, "beta", deps="alpha")
    registry = SkillRegistry.discover(project_root=tmp_path)

    with pytest.raises(ConfigError, match="circular skill dependency"):
        registry.resolve(["alpha"])


def test_resolve_rejects_incompatible_runtime(tmp_path: Path) -> None:
    registry = SkillRegistry()
    registry.register(
        "clauded", Skill(name="clauded", compatible_runtimes=["claude-code"], instructions="x")
    )

    assert registry.resolve(["clauded"], runtime="claude-code")
    with pytest.raises(ConfigError, match="not compatible"):
        registry.resolve(["clauded"], runtime="mock")


def test_builtin_agents_discover_with_prompts() -> None:
    registry = AgentRegistry.discover(project_root=None)

    for expected in ("planner", "architect", "coder", "tester", "reviewer", "security"):
        assert expected in registry
    coder = registry.get("coder")
    assert coder.role and coder.system_prompt and coder.prompt_template
    assert coder.repair_template, (
        "coder must know how to be re-prompted after a failed verification"
    )


def test_agent_file_rejects_unknown_keys(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("name: bad\nnot_a_field: 1\n", encoding="utf-8")

    with pytest.raises(ConfigError, match="invalid agent definition"):
        load_agent_file(path)


def test_agent_skills_all_exist_in_skill_registry() -> None:
    agents = AgentRegistry.discover(project_root=None)
    skills = SkillRegistry.discover(project_root=None)

    for agent in agents.all():
        missing = [name for name in agent.skills if name not in skills]
        assert not missing, f"agent '{agent.name}' references unknown skills {missing}"
