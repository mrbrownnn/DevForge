"""Assistant integration: profiles are data, and the installer keeps its promises.

Two things are worth pinning here beyond "the files appear".

The first is that assistant knowledge stays out of Python. `tests/test_architecture.py`
forbids naming a vendor in the source outside its adapter, and the reason this
feature can support thirteen assistants without touching that rule is that every one
of them is a YAML file. A test asserts it, so adding an assistant in code fails
loudly rather than quietly eroding the rule.

The second is that the installer never writes where it was not asked to, and never
replaces a file somebody wrote by hand without being told to.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from devforge.assistants.install import MARKER, install
from devforge.assistants.models import (
    ALL,
    AssistantProfile,
    AssistantRegistry,
    Confidence,
    Format,
    Target,
)
from devforge.core.errors import ConfigError
from devforge.core.registry.skills import SkillRegistry

SRC = Path(__file__).resolve().parents[1] / "src" / "devforge"

#: The command surface this feature was asked to provide.
EXPECTED_ASSISTANTS = {
    "claude",
    "cursor",
    "windsurf",
    "antigravity",
    "copilot",
    "kiro",
    "codex",
    "roocode",
    "qoder",
    "gemini",
    "trae",
    "opencode",
    "universal",
}


@pytest.fixture()
def registry() -> AssistantRegistry:
    return AssistantRegistry.discover(None)


@pytest.fixture()
def skills() -> SkillRegistry:
    return SkillRegistry.discover(None)


# --------------------------------------------------------------------- the profiles


def test_every_requested_assistant_has_a_profile(registry: AssistantRegistry) -> None:
    missing = EXPECTED_ASSISTANTS - set(registry.ids())

    assert not missing, f"no profile for: {sorted(missing)}"


def test_assistant_knowledge_lives_in_yaml_not_python() -> None:
    """The rule that lets thirteen vendors ship without touching the architecture test."""
    from devforge.assistants.models import builtin_assistant_dir

    profiles = sorted(builtin_assistant_dir().glob("*.yaml"))
    assert len(profiles) >= len(EXPECTED_ASSISTANTS)

    banned = ("claude", "cursor", "windsurf", "copilot", "gemini", "codex", "kiro")
    for path in sorted((SRC / "assistants").rglob("*.py")):
        text = path.read_text(encoding="utf-8").lower()
        hits = [token for token in banned if token in text]
        assert not hits, f"{path.name} names an assistant: {hits}"


def test_a_profile_cannot_write_outside_its_root() -> None:
    for path in ("../escape", "/absolute", "a/../../b"):
        with pytest.raises(ValueError, match="must be relative"):
            AssistantProfile(
                id="probe", name="Probe", target=Target(path=path, filename="x-{skill}.md")
            )


def test_an_unknown_assistant_is_refused_with_the_list(registry: AssistantRegistry) -> None:
    with pytest.raises(ConfigError, match="unknown assistant"):
        registry.get("notanassistant")


def test_the_all_selector_returns_every_profile(registry: AssistantRegistry) -> None:
    assert len(registry.select(ALL)) == len(registry.profiles)
    assert len(registry.select("cursor")) == 1


def test_every_profile_states_how_confident_its_layout_is(
    registry: AssistantRegistry,
) -> None:
    """An inferred path that is wrong looks exactly like DevForge doing nothing."""
    for profile in registry.profiles:
        assert profile.confidence in {Confidence.ESTABLISHED, Confidence.INFERRED}
        if profile.confidence is Confidence.INFERRED:
            assert profile.notes, f"{profile.id}: an inferred layout must say what to check"


def test_a_project_can_override_a_builtin_profile(tmp_path: Path) -> None:
    override = tmp_path / ".devforge" / "assistants"
    override.mkdir(parents=True)
    (override / "cursor.yaml").write_text(
        "id: cursor\nname: Cursor\nconfidence: established\n"
        "target:\n  path: custom/rules\n  format: markdown\n  filename: 'x-{skill}.md'\n",
        encoding="utf-8",
    )

    profile = AssistantRegistry.discover(tmp_path).get("cursor")

    assert profile.target.path == "custom/rules"


# --------------------------------------------------------------------- installing


def test_a_per_skill_profile_writes_one_file_per_skill(
    tmp_path: Path, registry: AssistantRegistry, skills: SkillRegistry
) -> None:
    result = install(registry.get("cursor"), root=tmp_path, skills=skills)

    written = {path.name for path in tmp_path.rglob("*.mdc")}
    assert len(written) == len(skills.all()) + 1, "one per skill, plus the instructions"
    assert "devforge.mdc" in written
    assert len(result.written) == len(written)


def test_a_single_file_profile_concatenates_everything(
    tmp_path: Path, registry: AssistantRegistry, skills: SkillRegistry
) -> None:
    install(registry.get("copilot"), root=tmp_path, skills=skills)

    content = (tmp_path / ".github" / "copilot-instructions.md").read_text(encoding="utf-8")
    for skill in skills.all():
        assert skill.name.title() in content
    assert content.count("\n# ") <= 1, "a single file gets one top-level heading"


def test_generated_files_are_marked_as_generated(
    tmp_path: Path, registry: AssistantRegistry, skills: SkillRegistry
) -> None:
    """So a later run can tell its own output from something a person wrote."""
    install(registry.get("universal"), root=tmp_path, skills=skills)

    for path in (tmp_path / ".agents" / "skills").glob("*.md"):
        assert MARKER in path.read_text(encoding="utf-8")


def test_an_existing_file_is_left_alone_without_force(
    tmp_path: Path, registry: AssistantRegistry, skills: SkillRegistry
) -> None:
    target = tmp_path / ".github" / "copilot-instructions.md"
    target.parent.mkdir(parents=True)
    target.write_text("my own instructions\n", encoding="utf-8")

    result = install(registry.get("copilot"), root=tmp_path, skills=skills)

    assert target.read_text(encoding="utf-8") == "my own instructions\n"
    assert result.skipped and not result.written


def test_force_replaces_it(
    tmp_path: Path, registry: AssistantRegistry, skills: SkillRegistry
) -> None:
    target = tmp_path / ".github" / "copilot-instructions.md"
    target.parent.mkdir(parents=True)
    target.write_text("my own instructions\n", encoding="utf-8")

    result = install(registry.get("copilot"), root=tmp_path, skills=skills, force=True)

    assert MARKER in target.read_text(encoding="utf-8")
    assert result.written and not result.skipped


def test_a_dry_run_writes_nothing(
    tmp_path: Path, registry: AssistantRegistry, skills: SkillRegistry
) -> None:
    result = install(registry.get("cursor"), root=tmp_path, skills=skills, dry_run=True)

    assert result.written, "it still reports what it would have written"
    assert not list(tmp_path.rglob("*.mdc")), "but nothing reached the filesystem"


def test_global_install_is_refused_where_no_location_is_documented(
    tmp_path: Path, registry: AssistantRegistry, skills: SkillRegistry
) -> None:
    """Guessing a home-directory path is worse than declining to."""
    profile = next(p for p in registry.profiles if not p.supports_global)

    with pytest.raises(ConfigError, match="no global location"):
        install(profile, root=tmp_path, skills=skills, global_install=True)


def test_the_installed_instructions_describe_the_harness(
    tmp_path: Path, registry: AssistantRegistry, skills: SkillRegistry
) -> None:
    """The assistant already knows how to code; what it does not know is this."""
    install(registry.get("universal"), root=tmp_path, skills=skills)

    content = (tmp_path / ".agents" / "skills" / "devforge.md").read_text(encoding="utf-8")

    assert "Nothing passes because you say it passed" in content
    assert "falsification" in content
    assert "devforge verify" in content
    assert "Never weaken an assertion" in content


def test_skill_frontmatter_is_translated_not_leaked(
    tmp_path: Path, registry: AssistantRegistry, skills: SkillRegistry
) -> None:
    """A rules file gets rules frontmatter, not DevForge's own."""
    install(registry.get("cursor"), root=tmp_path, skills=skills)

    content = (tmp_path / ".cursor" / "rules" / "devforge-testing.mdc").read_text(
        encoding="utf-8"
    )

    assert content.startswith("---\ndescription:")
    assert "alwaysApply:" in content
    assert "compatible_runtimes" not in content, "DevForge's own frontmatter must not leak"


@pytest.mark.parametrize("fmt", list(Format))
def test_every_format_produces_non_empty_output(
    fmt: Format, tmp_path: Path, skills: SkillRegistry
) -> None:
    profile = AssistantProfile(
        id="probe",
        name="Probe",
        target=Target(path="out", format=fmt, filename="p-{skill}.md"),
    )

    result = install(profile, root=tmp_path, skills=skills)

    for item in result.written:
        assert item.path.read_text(encoding="utf-8").strip()
