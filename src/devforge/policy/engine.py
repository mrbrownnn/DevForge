"""Permission decisions.

What this layer actually provides
---------------------------------

* A **deny-by-default allowlist** for shell commands, matched against the argv
  DevForge itself will pass to ``exec`` - never a shell string, because DevForge
  never spawns a shell.
* **Path confinement**: every filesystem path is fully resolved (symlinks
  included) and rejected if it lands outside the workspace root or matches a deny
  pattern.
* **Explicit approval** for destructive operations, routed to a human gate.

What it does NOT provide
------------------------

This is **not a sandbox**. Commands run as the current user with that user's full
privileges. An allowed command can do anything that command can do (``python``
can open sockets and delete files). Escaping is trivial for an adversarial agent
- for example by writing a script and asking an allowed interpreter to run it.
It protects against *accidents and drift*, not against a hostile agent. Real
isolation needs an OS-level boundary (container, VM, seccomp/AppArmor); that is
deliberately out of MVP scope and is documented in docs/security.md.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from fnmatch import fnmatch
from functools import lru_cache
from pathlib import Path

from devforge.policy.models import (
    ApprovalPolicy,
    Effect,
    PermissionPolicy,
)


@dataclass(frozen=True)
class PolicyDecision:
    effect: Effect
    reason: str
    rule: str = ""
    gate: str = ""

    @property
    def allowed(self) -> bool:
        return self.effect is Effect.ALLOW

    @property
    def needs_approval(self) -> bool:
        return self.effect is Effect.REQUIRE_APPROVAL


#: Tokens that only appear in an argv when someone expects shell interpretation.
#: DevForge never spawns a shell, so they would be passed through as literal
#: arguments - which is confusing at best and an attempted bypass at worst.
SHELL_METACHARACTERS = frozenset({"&&", "||", "|", ";", "&", ">", ">>", "<", "`"})

DESTRUCTIVE_SHELL_GATE = "destructive_command"
DESTRUCTIVE_FS_GATE = "destructive_filesystem"
NETWORK_GATE = "network_access"


def builtin_policy_dir() -> Path:
    from devforge import builtin

    return Path(builtin.__file__).parent / "policies"


def policy_search_paths(project_root: Path | None) -> list[Path]:
    paths: list[Path] = []
    if project_root is not None:
        paths.append(project_root / ".devforge" / "policies")
        paths.append(project_root / "policies")
    paths.append(builtin_policy_dir())
    return paths


def resolve_policy_file(filename: str, project_root: Path | None) -> Path:
    for directory in policy_search_paths(project_root):
        candidate = directory / filename
        if candidate.is_file():
            return candidate
    return builtin_policy_dir() / filename


class PolicyEngine:
    """Answers "may I?" for shell commands, filesystem paths and network access."""

    def __init__(
        self,
        permissions: PermissionPolicy,
        approvals: ApprovalPolicy,
        *,
        workspace: Path,
    ) -> None:
        self.permissions = permissions
        self.approvals = approvals
        self.workspace = Path(workspace).resolve()

    @classmethod
    def load(cls, project_root: Path | None, *, workspace: Path | None = None) -> PolicyEngine:
        permissions = PermissionPolicy.load(resolve_policy_file("permissions.yaml", project_root))
        approvals = ApprovalPolicy.load(resolve_policy_file("approvals.yaml", project_root))
        return cls(permissions, approvals, workspace=workspace or project_root or Path.cwd())

    # -- shell ------------------------------------------------------------------

    def check_command(self, argv: list[str]) -> PolicyDecision:
        """Evaluate an argument vector. Deny wins, then approval, then allow."""
        if not argv:
            return PolicyDecision(Effect.DENY, "empty command")

        joined = shlex.join(argv)
        plain = " ".join(argv)
        shell = self.permissions.shell

        smuggled = _shell_syntax_tokens(argv)
        if smuggled:
            return PolicyDecision(
                Effect.DENY,
                f"argument(s) {smuggled} look like shell syntax; DevForge executes argv "
                "directly and never spawns a shell, so chaining is not supported",
            )

        for pattern in shell.deny:
            if _matches(pattern, joined, plain):
                return PolicyDecision(
                    Effect.DENY, f"command matches deny rule '{pattern}'", rule=pattern
                )

        for pattern in shell.require_approval:
            if _matches(pattern, joined, plain):
                return PolicyDecision(
                    Effect.REQUIRE_APPROVAL,
                    f"command matches destructive rule '{pattern}'",
                    rule=pattern,
                    gate=DESTRUCTIVE_SHELL_GATE,
                )

        for pattern in shell.allow:
            if _matches(pattern, joined, plain):
                return PolicyDecision(Effect.ALLOW, f"allowed by rule '{pattern}'", rule=pattern)

        if shell.default is Effect.ALLOW:
            return PolicyDecision(Effect.ALLOW, "shell default is allow")
        if shell.default is Effect.REQUIRE_APPROVAL:
            return PolicyDecision(
                Effect.REQUIRE_APPROVAL,
                "no rule matched; shell default requires approval",
                gate=DESTRUCTIVE_SHELL_GATE,
            )
        return PolicyDecision(
            Effect.DENY,
            f"command '{argv[0]}' matches no allow rule (shell default is deny)",
        )

    # -- filesystem -------------------------------------------------------------

    def resolve_path(self, path: str | Path) -> Path:
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = self.workspace / candidate
        # strict=False so a not-yet-created file still gets symlinks resolved.
        return candidate.resolve()

    def check_path(self, path: str | Path, *, mode: str = "read") -> PolicyDecision:
        resolved = self.resolve_path(path)
        fs = self.permissions.filesystem

        if fs.workspace_only and not _within(resolved, self.workspace):
            return PolicyDecision(
                Effect.DENY, f"path escapes the workspace root {self.workspace}: {resolved}"
            )

        relative = _relative_to(resolved, self.workspace)
        for pattern in fs.deny:
            if _path_matches(pattern, relative):
                return PolicyDecision(
                    Effect.DENY, f"path matches deny rule '{pattern}'", rule=pattern
                )

        if mode == "delete":
            if fs.delete is Effect.ALLOW:
                return PolicyDecision(Effect.ALLOW, "delete is allowed by policy")
            if fs.delete is Effect.DENY:
                return PolicyDecision(Effect.DENY, "delete is denied by policy")
            return PolicyDecision(
                Effect.REQUIRE_APPROVAL,
                "deleting files requires approval",
                gate=DESTRUCTIVE_FS_GATE,
            )

        patterns = fs.write if mode == "write" else fs.read
        for pattern in patterns:
            if _path_matches(pattern, relative):
                return PolicyDecision(
                    Effect.ALLOW, f"{mode} allowed by rule '{pattern}'", rule=pattern
                )
        return PolicyDecision(Effect.DENY, f"no {mode} rule allows '{relative}'")

    # -- network ----------------------------------------------------------------

    def check_network(self, host: str) -> PolicyDecision:
        network = self.permissions.network
        if not network.enabled:
            return PolicyDecision(Effect.DENY, "network access is disabled by policy")
        for pattern in network.allow_hosts:
            if fnmatch(host, pattern):
                return PolicyDecision(Effect.ALLOW, f"host allowed by rule '{pattern}'", rule=pattern)
        return PolicyDecision(
            Effect.REQUIRE_APPROVAL, f"host '{host}' is not in the allow list", gate=NETWORK_GATE
        )

    # -- approvals --------------------------------------------------------------

    def gate_is_blocking(self, gate: str) -> bool:
        policy = self.approvals.gate(gate)
        return policy.blocking and not policy.auto_approve

    def gate_auto_approved(self, gate: str) -> bool:
        return self.approvals.gate(gate).auto_approve


def _matches(pattern: str, joined: str, plain: str) -> bool:
    return fnmatch(joined, pattern) or fnmatch(plain, pattern)


def _within(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _relative_to(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _shell_syntax_tokens(argv: list[str]) -> list[str]:
    found = [arg for arg in argv if arg in SHELL_METACHARACTERS or arg.startswith("$(")]
    return sorted(set(found))


@lru_cache(maxsize=512)
def _compile_path_pattern(pattern: str) -> re.Pattern[str]:
    """Translate a glob to a regex with real path semantics.

    ``*`` and ``?`` do not cross a ``/``; only ``**`` does. Plain ``fnmatch`` gets
    this wrong - it would let ``*.js`` match ``node_modules/pkg/index.js`` and
    quietly widen every write rule.
    """
    out = ["(?s:"]
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if pattern.startswith("**/", index):
            out.append("(?:.*/)?")
            index += 3
        elif pattern.startswith("**", index):
            out.append(".*")
            index += 2
        elif char == "*":
            out.append("[^/]*")
            index += 1
        elif char == "?":
            out.append("[^/]")
            index += 1
        else:
            out.append(re.escape(char))
            index += 1
    out.append(")\Z")
    return re.compile("".join(out))


def _path_matches(pattern: str, relative: str) -> bool:
    if pattern in {"**", "*"}:
        return True
    if _compile_path_pattern(pattern).match(relative):
        return True
    # "src/**" also covers the directory itself.
    if pattern.endswith("/**") and relative == pattern[:-3]:
        return True
    return False
