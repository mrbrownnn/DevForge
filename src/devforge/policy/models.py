"""Permission and approval policy models.

Policy is data in ``policies/permissions.yaml`` and ``policies/approvals.yaml``.
Tools ask the policy engine before acting; the engine never trusts a caller to
have asked.

**This is not a sandbox.** See :mod:`devforge.policy.engine` and docs/security.md
for exactly what it does and does not protect against.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from devforge.core.errors import ConfigError


class Effect(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class ShellPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    #: What happens to a command that matches no rule at all.
    default: Effect = Effect.DENY
    #: fnmatch patterns tested against the joined argv, e.g. "git status*".
    allow: list[str] = Field(default_factory=list)
    #: Denials win over everything else.
    deny: list[str] = Field(default_factory=list)
    #: Matches here need a human decision before running.
    require_approval: list[str] = Field(default_factory=list)
    timeout_s: int = 600


class FilesystemPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    #: Refuse any path that resolves outside the workspace root.
    workspace_only: bool = True
    read: list[str] = Field(default_factory=lambda: ["**"])
    write: list[str] = Field(default_factory=list)
    deny: list[str] = Field(default_factory=list)
    #: Deleting is separate from writing: it is destructive and gated on its own.
    delete: Effect = Effect.REQUIRE_APPROVAL
    max_read_bytes: int = 1_000_000


class NetworkPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    allow_hosts: list[str] = Field(default_factory=list)
    #: Resolve hostnames and refuse private/loopback/metadata targets (SSRF defence).
    #: Disabling this is a real decision, not a convenience.
    block_private_addresses: bool = True
    #: Permit http://localhost and 127.0.0.1 specifically, while every other private
    #: address stays blocked. Screenshotting your own dev server is the one legitimate
    #: reason to reach loopback, so it is a narrow opt-in rather than turning the whole
    #: SSRF defence off to get it.
    allow_loopback: bool = False


class ProcessPolicy(BaseModel):
    """What a child process inherits and how much it may emit."""

    model_config = ConfigDict(extra="forbid")

    #: Extra environment variables to carry through to children, by exact name.
    #: Everything not on the base allowlist or named here is dropped.
    allow_env: list[str] = Field(default_factory=list)
    max_output_chars: int = 200_000


class PermissionPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int = 1
    description: str = ""
    shell: ShellPolicy = Field(default_factory=ShellPolicy)
    process: ProcessPolicy = Field(default_factory=ProcessPolicy)
    filesystem: FilesystemPolicy = Field(default_factory=FilesystemPolicy)
    network: NetworkPolicy = Field(default_factory=NetworkPolicy)

    @classmethod
    def load(cls, path: Path) -> PermissionPolicy:
        return _load_yaml_model(cls, path, "permission policy")


class GatePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    description: str = ""
    #: When false the gate is recorded but does not block the run.
    blocking: bool = True
    #: Only an explicit opt-in here lets a gate pass without a human.
    auto_approve: bool = False


class ApprovalPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int = 1
    description: str = ""
    gates: dict[str, GatePolicy] = Field(default_factory=dict)

    @classmethod
    def load(cls, path: Path) -> ApprovalPolicy:
        return _load_yaml_model(cls, path, "approval policy")

    def gate(self, name: str) -> GatePolicy:
        """Unknown gates are blocking by default - fail closed, never open."""
        return self.gates.get(name, GatePolicy(description=f"undeclared gate '{name}'"))


def _load_yaml_model(model: type[BaseModel], path: Path, label: str):
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except FileNotFoundError as exc:
        raise ConfigError(f"{label} file not found: {path}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: {label} must be a YAML mapping")
    try:
        return model.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(f"{path}: invalid {label}: {exc}") from exc
