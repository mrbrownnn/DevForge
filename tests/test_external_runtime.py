"""External CLI runtimes: one adapter, many providers, described by data.

The tests here pin two things beyond "it spawns a process".

Provider knowledge stays out of Python, for the same reason it does for assistants:
`tests/test_architecture.py` forbids naming a vendor in the source outside its own
adapter, and profiles in YAML are what let a dozen providers ship without eroding
that rule.

And the adapter never improves on what actually happened. A missing binary is
unavailable rather than a failed agent; a non-zero exit is an error even when the
payload parses; a token count nobody reported stays `None` rather than becoming 0.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from devforge.core.errors import ConfigError, RuntimeExecutionError
from devforge.core.models import AgentInvocation, AgentResultStatus
from devforge.runtime.base import RuntimeContext
from devforge.runtime.cli_profile import (
    CliRuntimeProfile,
    Confidence,
    OutputFormat,
    OutputSpec,
    PromptStyle,
    discover_profiles,
)
from devforge.runtime.external import ExternalCliRuntime
from devforge.runtime.registry import RuntimeRegistry

SRC = Path(__file__).resolve().parents[1] / "src" / "devforge"


def _profile(**fields) -> CliRuntimeProfile:
    defaults = {"id": "probe", "name": "Probe", "binary": "probe-tool"}
    return CliRuntimeProfile(**(defaults | fields))


def _invocation(**fields) -> AgentInvocation:
    defaults = {"task_id": "t", "step_id": "s", "agent": "coder", "prompt": "do the thing"}
    return AgentInvocation(**(defaults | fields))


# --------------------------------------------------------------------- the profiles


def test_provider_knowledge_lives_in_yaml_not_python() -> None:
    """What lets a dozen providers ship without touching the architecture rule."""
    banned = ("codex", "gemini", "cursor", "copilot", "opencode", "openai", "anthropic")

    for name in ("cli_profile.py", "external.py"):
        text = (SRC / "runtime" / name).read_text(encoding="utf-8").lower()
        hits = [token for token in banned if token in text]
        assert not hits, f"{name} names a provider: {hits}"


def test_the_shipped_profiles_load(tmp_path: Path) -> None:
    profiles = discover_profiles(None)

    assert profiles, "no runtime profiles are bundled"
    for profile in profiles:
        assert profile.binary
        assert profile.notes, f"{profile.id}: a profile must say where its shape came from"


def test_every_unverified_profile_says_what_to_check() -> None:
    """An unverified flag produces an error from someone else's binary."""
    for profile in discover_profiles(None):
        if profile.confidence is not Confidence.VERIFIED:
            assert "help" in profile.notes.lower() or "check" in profile.notes.lower(), (
                f"{profile.id}: an unverified profile must say how to confirm it"
            )


def test_a_profile_cannot_point_at_an_arbitrary_executable() -> None:
    """The binary is resolved on PATH; a path here would be a run-anything primitive."""
    for binary in ("/usr/bin/evil", "..\\evil.exe", "dir/tool"):
        with pytest.raises(ValueError, match="not a path"):
            _profile(binary=binary)


def test_a_flag_style_profile_needs_a_flag() -> None:
    with pytest.raises(ValueError, match="needs a prompt_flag"):
        _profile(prompt_style=PromptStyle.FLAG, prompt_flag="")


# --------------------------------------------------------------------- argv building


def test_a_positional_prompt_goes_last() -> None:
    argv, stdin = _profile(subcommand="exec", prompt_style=PromptStyle.POSITIONAL).build_argv(
        "tool", "PROMPT"
    )

    assert argv == ["tool", "exec", "PROMPT"]
    assert stdin == ""


def test_a_flag_prompt_goes_behind_its_flag() -> None:
    argv, _ = _profile(prompt_style=PromptStyle.FLAG, prompt_flag="-p").build_argv(
        "tool", "PROMPT"
    )

    assert argv == ["tool", "-p", "PROMPT"]


def test_a_stdin_prompt_never_reaches_the_argv() -> None:
    argv, stdin = _profile(prompt_style=PromptStyle.STDIN).build_argv("tool", "PROMPT")

    assert "PROMPT" not in argv
    assert stdin == "PROMPT"


def test_a_system_prompt_is_folded_in_when_the_tool_has_no_flag_for_it() -> None:
    """Dropping it would quietly change the agent into a different one."""
    argv, _ = _profile(prompt_style=PromptStyle.POSITIONAL).build_argv(
        "tool", "PROMPT", system_prompt="SYSTEM"
    )

    assert "SYSTEM" in argv[-1]
    assert "PROMPT" in argv[-1]


def test_a_system_prompt_uses_the_flag_when_there_is_one() -> None:
    argv, _ = _profile(
        prompt_style=PromptStyle.POSITIONAL, system_prompt_flag="--system"
    ).build_argv("tool", "PROMPT", system_prompt="SYSTEM")

    assert "--system" in argv
    assert argv[-1] == "PROMPT"


def test_the_model_flag_is_omitted_when_no_model_is_configured() -> None:
    argv, _ = _profile(prompt_style=PromptStyle.POSITIONAL).build_argv("tool", "P")

    assert "--model" not in argv


# --------------------------------------------------------------------- availability


def test_a_missing_binary_is_unavailable_not_a_failed_agent() -> None:
    runtime = ExternalCliRuntime(_profile(binary="definitely-not-installed-xyz"))

    status = runtime.availability()

    assert not status.available
    assert "not found on PATH" in status.detail


def test_running_an_unavailable_runtime_refuses_rather_than_reporting_a_result(
    tmp_path: Path,
) -> None:
    """An AgentResult here would read as the model declining to work."""
    runtime = ExternalCliRuntime(_profile(binary="definitely-not-installed-xyz"))

    with pytest.raises(RuntimeExecutionError, match="unavailable"):
        asyncio.run(runtime.execute(_invocation(), RuntimeContext(workspace=tmp_path)))


def test_an_unverified_shape_is_reported_in_the_capabilities() -> None:
    runtime = ExternalCliRuntime(_profile(confidence=Confidence.INFERRED))

    assert "has not been exercised" in runtime.capabilities().notes


# --------------------------------------------------------------------- parsing


def _parse(profile: CliRuntimeProfile, **fields):
    defaults = {"stdout": "", "stderr": "", "returncode": 0, "duration_ms": 5}
    return ExternalCliRuntime(profile).parse_result(_invocation(), **(defaults | fields))


def test_text_output_becomes_the_agent_output() -> None:
    result = _parse(_profile(), stdout="the agent said this")

    assert result.status is AgentResultStatus.OK
    assert result.output == "the agent said this"


def test_a_non_zero_exit_is_an_error_even_when_the_payload_parses() -> None:
    """Believing the payload over the exit code records a failed run as a success."""
    profile = _profile(output=OutputSpec(format=OutputFormat.JSON))

    result = _parse(profile, stdout='{"result": "looks fine"}', returncode=2, stderr="boom")

    assert result.status is AgentResultStatus.ERROR
    assert result.error


def test_json_output_is_read_through_the_declared_keys() -> None:
    profile = _profile(
        output=OutputSpec(format=OutputFormat.JSON, text_keys=["answer"])
    )

    result = _parse(profile, stdout='{"answer": "42", "session_id": "abc"}')

    assert result.output == "42"
    assert result.metadata["session_id"] == "abc"


def test_a_jsonl_stream_is_read_from_its_last_object() -> None:
    """Several tools emit one event per line and put the result last."""
    profile = _profile(output=OutputSpec(format=OutputFormat.JSON))

    result = _parse(
        profile,
        stdout='{"type": "start"}\n{"type": "token"}\n{"result": "done"}',
    )

    assert result.output == "done"


def test_unparseable_json_is_a_profile_problem_not_a_silent_pass() -> None:
    profile = _profile(output=OutputSpec(format=OutputFormat.JSON))

    result = _parse(profile, stdout="this is prose, not json")

    assert result.status is AgentResultStatus.ERROR
    assert "wrong output format" in result.error


def test_a_token_count_nobody_reported_stays_unknown() -> None:
    """None means unmeasured. Zero would be a fabricated number in a cost report."""
    profile = _profile(output=OutputSpec(format=OutputFormat.JSON))

    result = _parse(profile, stdout='{"result": "done"}')

    assert "total_tokens" not in result.metadata


def test_a_reported_token_count_is_kept() -> None:
    profile = _profile(output=OutputSpec(format=OutputFormat.JSON))

    result = _parse(profile, stdout='{"result": "done", "usage": {"total_tokens": 1234}}')

    assert result.metadata["total_tokens"] == 1234


# --------------------------------------------------------------------- the registry


def test_profiles_are_registered_alongside_the_built_in_runtimes() -> None:
    registry = RuntimeRegistry.default()

    assert "mock" in registry
    for profile in discover_profiles(None):
        assert profile.id in registry, f"{profile.id} was not registered"


def test_a_profile_never_shadows_a_hand_written_adapter(tmp_path: Path) -> None:
    """A real adapter knows things a profile cannot express."""
    override = tmp_path / ".devforge" / "runtimes"
    override.mkdir(parents=True)
    (override / "mock.yaml").write_text(
        "id: mock\nname: Impostor\nbinary: nothing\nnotes: check --help\n", encoding="utf-8"
    )

    registry = RuntimeRegistry.default()
    added = registry.register_profiles(tmp_path)

    assert "mock" not in added
    assert registry.create("mock").name == "mock"
    assert not isinstance(registry.create("mock"), ExternalCliRuntime)


def test_a_project_can_override_a_bundled_profile(tmp_path: Path) -> None:
    override = tmp_path / ".devforge" / "runtimes"
    override.mkdir(parents=True)
    (override / "codex-cli.yaml").write_text(
        "id: codex-cli\nname: Custom\nbinary: mytool\nprompt_style: stdin\n"
        "notes: local override; check --help\n",
        encoding="utf-8",
    )

    profile = next(p for p in discover_profiles(tmp_path) if p.id == "codex-cli")

    assert profile.binary == "mytool"
    assert profile.prompt_style is PromptStyle.STDIN


def test_a_broken_profile_names_the_file(tmp_path: Path) -> None:
    override = tmp_path / ".devforge" / "runtimes"
    override.mkdir(parents=True)
    (override / "broken.yaml").write_text("id: broken\nname: Broken\n", encoding="utf-8")

    with pytest.raises(ConfigError, match="broken.yaml"):
        discover_profiles(tmp_path)
