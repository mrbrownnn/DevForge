from __future__ import annotations

from pathlib import Path

import pytest

from devforge.core.errors import ConfigError
from devforge.policy.engine import PolicyEngine, resolve_policy_file
from devforge.policy.models import ApprovalPolicy, Effect, PermissionPolicy


@pytest.fixture()
def engine(tmp_path: Path) -> PolicyEngine:
    return PolicyEngine.load(None, workspace=tmp_path)


def test_builtin_policies_load() -> None:
    permissions = PermissionPolicy.load(resolve_policy_file("permissions.yaml", None))
    approvals = ApprovalPolicy.load(resolve_policy_file("approvals.yaml", None))

    assert permissions.shell.default is Effect.DENY
    assert permissions.filesystem.workspace_only is True
    assert permissions.network.enabled is False
    assert "architecture" in approvals.gates and "final_review" in approvals.gates


def test_allowlisted_command_is_allowed(engine: PolicyEngine) -> None:
    assert engine.check_command(["python", "-m", "pytest", "-q"]).allowed
    assert engine.check_command(["git", "status", "--short"]).allowed


def test_unlisted_command_is_denied_by_default(engine: PolicyEngine) -> None:
    decision = engine.check_command(["curl", "https://example.com"])

    assert decision.effect is Effect.DENY
    assert "matches no allow rule" in decision.reason


def test_destructive_command_requires_approval(engine: PolicyEngine) -> None:
    decision = engine.check_command(["git", "push", "origin", "main"])

    assert decision.effect is Effect.REQUIRE_APPROVAL
    assert decision.gate == "destructive_command"


def test_deny_beats_approval_and_allow(engine: PolicyEngine) -> None:
    assert engine.check_command(["git", "push", "--force", "origin", "main"]).effect is Effect.DENY
    assert engine.check_command(["rm", "-rf", "/"]).effect is Effect.DENY


def test_empty_command_denied(engine: PolicyEngine) -> None:
    assert engine.check_command([]).effect is Effect.DENY


def test_shell_metacharacters_do_not_smuggle_a_second_command(engine: PolicyEngine) -> None:
    # argv is exec'd, never interpreted; chaining tokens are rejected outright so a
    # rule like "git status*" cannot be widened by appending arguments.
    decision = engine.check_command(["git", "status", "&&", "rm", "-rf", "/"])

    assert decision.effect is Effect.DENY
    assert "shell syntax" in decision.reason
    # Command substitution is denied outright, and that beats the inline-code gate:
    # deny > require_approval, so a refusal is never downgraded to a question.
    assert engine.check_command(["python", "-c", "$(whoami)"]).effect is Effect.DENY
    assert engine.check_command(["python", "-c", "print(1)"]).effect is Effect.REQUIRE_APPROVAL


def test_path_outside_workspace_is_denied(engine: PolicyEngine, tmp_path: Path) -> None:
    decision = engine.check_path(tmp_path.parent / "elsewhere.txt", mode="read")

    assert decision.effect is Effect.DENY
    assert "escapes the workspace root" in decision.reason


def test_relative_traversal_is_denied(engine: PolicyEngine) -> None:
    assert engine.check_path("../../etc/passwd", mode="read").effect is Effect.DENY


def test_symlink_escape_is_denied(engine: PolicyEngine, tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside_target"
    outside.mkdir(exist_ok=True)
    link = tmp_path / "link"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is not permitted in this environment")

    assert engine.check_path(link / "secret.txt", mode="read").effect is Effect.DENY


def test_denied_paths_beat_read_rules(engine: PolicyEngine) -> None:
    assert engine.check_path(".env", mode="read").effect is Effect.DENY
    assert engine.check_path("config/secrets/api.key", mode="read").effect is Effect.DENY
    assert engine.check_path(".git/config", mode="read").effect is Effect.DENY


def test_write_rules_are_narrower_than_read_rules(engine: PolicyEngine) -> None:
    assert engine.check_path("src/app.py", mode="write").allowed
    assert engine.check_path("README.md", mode="write").allowed
    assert engine.check_path("node_modules/pkg/index.js", mode="write").effect is Effect.DENY
    assert engine.check_path("node_modules/pkg/index.js", mode="read").allowed


def test_delete_requires_approval_by_default(engine: PolicyEngine) -> None:
    decision = engine.check_path("src/app.py", mode="delete")

    assert decision.effect is Effect.REQUIRE_APPROVAL
    assert decision.gate == "destructive_filesystem"


def test_network_disabled_by_default(engine: PolicyEngine) -> None:
    assert engine.check_network("example.com").effect is Effect.DENY


def test_network_allow_list(tmp_path: Path) -> None:
    permissions = PermissionPolicy.model_validate(
        {"network": {"enabled": True, "allow_hosts": ["*.internal"]}}
    )
    engine = PolicyEngine(permissions, ApprovalPolicy(), workspace=tmp_path)

    assert engine.check_network("api.internal").allowed
    assert engine.check_network("evil.com").effect is Effect.REQUIRE_APPROVAL


def test_unknown_gate_fails_closed() -> None:
    policy = ApprovalPolicy(gates={})

    gate = policy.gate("never_declared")
    assert gate.blocking is True and gate.auto_approve is False


def test_invalid_policy_file_reports_path(tmp_path: Path) -> None:
    path = tmp_path / "permissions.yaml"
    path.write_text("shell:\n  default: sideways\n", encoding="utf-8")

    with pytest.raises(ConfigError, match="invalid permission policy"):
        PermissionPolicy.load(path)


def test_project_policy_overrides_builtin(tmp_path: Path) -> None:
    directory = tmp_path / "policies"
    directory.mkdir()
    (directory / "permissions.yaml").write_text(
        "shell:\n  default: deny\n  allow: ['echo *']\n", encoding="utf-8"
    )

    engine = PolicyEngine.load(tmp_path, workspace=tmp_path)
    assert engine.check_command(["echo", "hi"]).allowed
    assert engine.check_command(["python", "-m", "pytest"]).effect is Effect.DENY
