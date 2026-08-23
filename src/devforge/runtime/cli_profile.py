"""Profiles describing how to drive an external agent CLI.

DevForge executes agents by spawning a command-line tool, never by calling an HTTP
API - it imports no HTTP client, and an architecture test enforces that. So adding a
provider means describing its CLI: what the binary is called, where the prompt goes
in the argument vector, and how to read a result back out.

**Those descriptions are data.** A dozen adapter classes differing only by a flag
name would be an abstraction with no content, and the same architecture test forbids
naming a vendor anywhere in the source outside its own adapter module. Keeping the
descriptions in ``builtin/runtimes/*.yaml`` satisfies both: adding a provider is a
file, and the code below never mentions one.

**Invocation shapes are declared with the confidence behind them.** A flag that has
been checked against a real installation is not the same claim as one taken from a
tool's documentation and never run here. A profile records which it is, and the
runtime reports it, because a wrong flag produces an error message from someone
else's binary and looks like DevForge being broken.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from devforge.core.errors import ConfigError


class PromptStyle(str, Enum):
    """Where the prompt goes in the argument vector."""

    #: Passed as a bare argument: ``tool exec "<prompt>"``.
    POSITIONAL = "positional"
    #: Passed behind a flag: ``tool -p "<prompt>"``.
    FLAG = "flag"
    #: Written to the process's stdin instead of the argv.
    STDIN = "stdin"


class OutputFormat(str, Enum):
    """How the tool reports what it did."""

    JSON = "json"
    TEXT = "text"


class Confidence(str, Enum):
    """How well established this invocation shape is.

    ``VERIFIED`` means the argument vector was checked against a real installation's
    own ``--help``, with the version recorded in the profile's notes. It does not
    mean a full agent run was performed - that costs money and edits files, so it is
    the user's call, not the packager's.

    ``DOCUMENTED`` means the shape comes from the tool's published documentation but
    no installation was available to check it against. ``INFERRED`` means it follows
    the conventions of similar tools and should be checked before being relied on.
    """

    VERIFIED = "verified"
    DOCUMENTED = "documented"
    INFERRED = "inferred"

    @property
    def trustworthy(self) -> bool:
        return self is Confidence.VERIFIED


class OutputSpec(BaseModel):
    """How to turn the tool's output into an :class:`AgentResult`."""

    model_config = ConfigDict(extra="forbid")

    format: OutputFormat = OutputFormat.TEXT
    #: JSON keys to try, in order, for the agent's text. First hit wins.
    text_keys: list[str] = Field(default_factory=lambda: ["result", "response", "output", "text"])
    #: JSON keys carrying an error message when the tool reports failure in-band.
    error_keys: list[str] = Field(default_factory=lambda: ["error", "message"])
    #: JSON keys carrying a session or conversation id, kept in metadata.
    session_keys: list[str] = Field(default_factory=lambda: ["session_id", "conversation_id"])
    #: JSON keys carrying a token count. Absent means the tool reports none, and the
    #: cost metric stays unknown rather than being recorded as zero.
    token_keys: list[str] = Field(default_factory=lambda: ["total_tokens", "tokens"])
    #: Exit codes other than 0 that still mean the agent ran.
    success_exit_codes: list[int] = Field(default_factory=lambda: [0])


class CliRuntimeProfile(BaseModel):
    """Everything needed to drive one external agent CLI."""

    # `model_flag` names a CLI flag, not a pydantic model attribute, so the
    # reserved namespace is cleared rather than the field given a worse name.
    model_config = ConfigDict(extra="forbid", protected_namespaces=())

    id: str
    name: str
    binary: str
    description: str = ""
    confidence: Confidence = Confidence.INFERRED
    notes: str = ""

    #: Subcommand placed before everything else, e.g. ``exec`` or ``run``.
    subcommand: str = ""
    prompt_style: PromptStyle = PromptStyle.FLAG
    #: Flag carrying the prompt when ``prompt_style`` is ``flag``.
    prompt_flag: str = "-p"
    #: Flag carrying a system prompt. Empty means the tool has none, and the system
    #: prompt is prepended to the user prompt instead of being silently dropped.
    system_prompt_flag: str = ""
    model_flag: str = "--model"
    #: Arguments always appended, e.g. an output-format selector.
    fixed_args: list[str] = Field(default_factory=list)
    #: Argv used to check the tool is installed and runnable.
    version_args: list[str] = Field(default_factory=lambda: ["--version"])

    output: OutputSpec = Field(default_factory=OutputSpec)
    source_path: str | None = None

    @model_validator(mode="after")
    def _check(self) -> CliRuntimeProfile:
        if not self.id.replace("-", "").isalnum():
            raise ValueError(f"runtime id '{self.id}' must be alphanumeric or hyphenated")
        if not self.binary.strip():
            raise ValueError(f"runtime '{self.id}': a binary name is required")
        if "/" in self.binary or "\\" in self.binary:
            # A path here would let a profile point at any executable on the box.
            # The binary is resolved on PATH, deliberately.
            raise ValueError(
                f"runtime '{self.id}': binary must be a command name, not a path"
            )
        if self.prompt_style is PromptStyle.FLAG and not self.prompt_flag:
            raise ValueError(f"runtime '{self.id}': prompt_style 'flag' needs a prompt_flag")
        return self

    def build_argv(
        self, binary: str, prompt: str, *, model: str | None = None, system_prompt: str = ""
    ) -> tuple[list[str], str]:
        """The argument vector, and whatever must go to stdin.

        Returns ``(argv, stdin)``. ``stdin`` is empty unless the profile puts the
        prompt there.
        """
        argv = [binary]
        if self.subcommand:
            argv.append(self.subcommand)

        body = prompt
        if system_prompt:
            if self.system_prompt_flag:
                argv += [self.system_prompt_flag, system_prompt]
            else:
                # No flag for it. Folding it into the prompt keeps the instructions
                # in front of the model; dropping it would quietly change the agent.
                body = f"{system_prompt}\n\n---\n\n{prompt}"

        if model and self.model_flag:
            argv += [self.model_flag, model]
        argv += self.fixed_args

        if self.prompt_style is PromptStyle.STDIN:
            return argv, body
        if self.prompt_style is PromptStyle.FLAG:
            argv += [self.prompt_flag, body]
        else:
            argv.append(body)
        return argv, ""


def load_profile(path: Path) -> CliRuntimeProfile:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"could not read runtime profile {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: a runtime profile must be a YAML mapping")
    raw.setdefault("id", path.stem)
    raw["source_path"] = str(path)
    try:
        return CliRuntimeProfile.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(f"{path}: invalid runtime profile: {exc}") from exc


def builtin_runtime_dir() -> Path:
    from devforge import builtin

    return Path(builtin.__file__).parent / "runtimes"


def discover_profiles(project_root: Path | None = None) -> list[CliRuntimeProfile]:
    """Built-in CLI profiles, overridable per project.

    A project whose tool takes a different flag drops a file in
    ``.devforge/runtimes/`` and it wins - the same override order workflows, agents
    and assistant profiles already use.
    """
    found: dict[str, CliRuntimeProfile] = {}
    directories: list[Path] = []
    if project_root is not None:
        directories.append(project_root / ".devforge" / "runtimes")
    directories.append(builtin_runtime_dir())

    for directory in directories:
        if not directory.is_dir():
            continue
        for path in sorted(directory.iterdir()):
            if path.suffix in {".yaml", ".yml"} and path.is_file():
                profile = load_profile(path)
                found.setdefault(profile.id, profile)
    return [found[key] for key in sorted(found)]
