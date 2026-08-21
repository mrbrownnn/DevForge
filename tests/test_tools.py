from __future__ import annotations

import sys
from pathlib import Path

import pytest

from devforge.approval.gate import ApprovalGate
from devforge.core.errors import RegistryError
from devforge.core.models import ApprovalStatus, Task, ToolStatus
from devforge.mcp.tool import McpTool
from devforge.policy.engine import PolicyEngine
from devforge.tools.base import ToolContext, ToolRegistry
from devforge.tools.browser import BrowserTool
from devforge.tools.filesystem import FilesystemTool
from devforge.tools.shell import ShellTool


@pytest.fixture()
def policy(tmp_path: Path) -> PolicyEngine:
    return PolicyEngine.load(None, workspace=tmp_path)


@pytest.fixture()
def ctx(tmp_path: Path, policy: PolicyEngine) -> ToolContext:
    return ToolContext(workspace=tmp_path, policy=policy)


@pytest.fixture()
def gated_ctx(tmp_path: Path, policy: PolicyEngine) -> ToolContext:
    task = Task(project_id="p", description="d", workflow="feature")
    return ToolContext(
        workspace=tmp_path,
        policy=policy,
        task=task,
        approval_gate=ApprovalGate(policy),
        step_id="implementation",
    )


# ------------------------------------------------------------------------ registry


def test_default_registry_contains_expected_tools() -> None:
    registry = ToolRegistry.default()

    assert registry.names() == ["browser", "debug", "filesystem", "git", "mcp", "shell"]
    with pytest.raises(RegistryError):
        registry.get("teleporter")


def test_registry_subset_scopes_a_step() -> None:
    scoped = ToolRegistry.default().subset(["filesystem", "git"])

    assert scoped.names() == ["filesystem", "git"]
    assert "shell" not in scoped


def test_registry_reports_unavailable_tools() -> None:
    """Availability is discovered, not declared: the browser tool is usable only when
    a driver is installed, so this asserts the mechanism rather than a fixed answer."""
    registry = ToolRegistry.default()

    assert registry.unavailable_names(["filesystem", "shell", "git", "mcp"]) == []
    browser_available = registry.get("browser").availability().available
    expected = [] if browser_available else ["browser"]
    assert registry.unavailable_names(["browser"]) == expected


# ---------------------------------------------------------------------- filesystem


async def test_filesystem_write_then_read(ctx: ToolContext) -> None:
    tool = FilesystemTool()

    written = await tool.invoke("write", {"path": "src/app.py", "content": "x = 1\n"}, ctx)
    read = await tool.invoke("read", {"path": "src/app.py"}, ctx)

    assert written.ok and read.ok
    assert read.output == "x = 1\n"


async def test_filesystem_denies_write_outside_allowed_globs(ctx: ToolContext) -> None:
    result = await FilesystemTool().invoke(
        "write", {"path": "node_modules/pkg/index.js", "content": "x"}, ctx
    )

    assert result.status is ToolStatus.DENIED
    assert not (ctx.workspace / "node_modules" / "pkg" / "index.js").exists()


async def test_filesystem_denies_traversal(ctx: ToolContext) -> None:
    result = await FilesystemTool().invoke("read", {"path": "../../etc/passwd"}, ctx)

    assert result.status is ToolStatus.DENIED
    assert "escapes the workspace root" in result.error


async def test_filesystem_denies_protected_files(ctx: ToolContext) -> None:
    (ctx.workspace / ".env").write_text("SECRET=1", encoding="utf-8")

    result = await FilesystemTool().invoke("read", {"path": ".env"}, ctx)

    assert result.status is ToolStatus.DENIED
    assert "SECRET" not in result.output


async def test_filesystem_delete_blocks_without_approval(ctx: ToolContext) -> None:
    (ctx.workspace / "junk.py").write_text("x", encoding="utf-8")

    result = await FilesystemTool().invoke("delete", {"path": "junk.py"}, ctx)

    assert result.status is ToolStatus.DENIED
    assert (ctx.workspace / "junk.py").exists(), "a denied delete must not touch the file"


async def test_filesystem_delete_proceeds_after_approval(gated_ctx: ToolContext) -> None:
    target = gated_ctx.workspace / "junk.py"
    target.write_text("x", encoding="utf-8")
    tool = FilesystemTool()

    first = await tool.invoke("delete", {"path": "junk.py"}, gated_ctx)
    assert first.status is ToolStatus.DENIED
    assert first.data["awaiting_approval"] is True
    assert target.exists()

    gated_ctx.approval_gate.resolve(
        gated_ctx.task, gate="destructive_filesystem", approved=True, by="tester"
    )
    second = await tool.invoke("delete", {"path": "junk.py"}, gated_ctx)

    assert second.ok
    assert not target.exists()


async def test_filesystem_rejects_missing_path_and_unknown_action(ctx: ToolContext) -> None:
    tool = FilesystemTool()

    assert (await tool.invoke("read", {}, ctx)).status is ToolStatus.ERROR
    assert (await tool.invoke("teleport", {"path": "a"}, ctx)).status is ToolStatus.ERROR


async def test_filesystem_read_limit(ctx: ToolContext) -> None:
    ctx.policy.permissions.filesystem.max_read_bytes = 4
    (ctx.workspace / "big.py").write_text("0123456789", encoding="utf-8")

    result = await FilesystemTool().invoke("read", {"path": "big.py"}, ctx)

    assert result.status is ToolStatus.ERROR and "read limit" in result.error


# --------------------------------------------------------------------------- shell


async def test_shell_runs_allowlisted_command(ctx: ToolContext) -> None:
    script = ctx.workspace / "hello.py"
    script.write_text("print('hello')\n", encoding="utf-8")
    ctx.policy.permissions.shell.allow.append("*")

    result = await ShellTool().invoke("run", {"argv": [sys.executable, str(script)]}, ctx)

    assert result.ok
    assert "hello" in result.output


async def test_shell_denies_unlisted_command(ctx: ToolContext) -> None:
    result = await ShellTool().invoke("run", {"argv": ["curl", "https://example.com"]}, ctx)

    assert result.status is ToolStatus.DENIED
    assert "no allow rule" in result.error


async def test_shell_command_string_is_split_not_interpreted(ctx: ToolContext) -> None:
    result = await ShellTool().invoke("run", {"command": "git status && rm -rf /"}, ctx)

    assert result.status is ToolStatus.DENIED
    assert "shell syntax" in result.error


async def test_shell_destructive_command_needs_approval(gated_ctx: ToolContext) -> None:
    result = await ShellTool().invoke("run", {"argv": ["git", "push", "origin", "main"]}, gated_ctx)

    assert result.status is ToolStatus.DENIED
    assert result.data.get("gate") == "destructive_command"
    approval = gated_ctx.task.approval("destructive_command")
    assert approval is not None and approval.status is ApprovalStatus.PENDING


async def test_shell_reports_nonzero_exit(ctx: ToolContext) -> None:
    # A script file, not `python -c`: inline code is approval-gated regardless of the
    # allowlist, because a glob cannot constrain what inline code does.
    script = ctx.workspace / "exit3.py"
    script.write_text("import sys; sys.exit(3)\n", encoding="utf-8")
    ctx.policy.permissions.shell.allow.append("*")

    result = await ShellTool().invoke("run", {"argv": [sys.executable, str(script)]}, ctx)

    assert result.status is ToolStatus.ERROR
    assert result.data["exit_code"] == 3


async def test_shell_times_out(ctx: ToolContext) -> None:
    script = ctx.workspace / "sleep.py"
    script.write_text("import time; time.sleep(30)\n", encoding="utf-8")
    ctx.policy.permissions.shell.allow.append("*")

    result = await ShellTool().invoke(
        "run", {"argv": [sys.executable, str(script)], "timeout_s": 1}, ctx
    )

    assert result.status is ToolStatus.ERROR
    assert result.data["timed_out"] is True


async def test_shell_rejects_malformed_input(ctx: ToolContext) -> None:
    tool = ShellTool()

    assert (await tool.invoke("run", {}, ctx)).status is ToolStatus.ERROR
    assert (await tool.invoke("run", {"argv": "not a list"}, ctx)).status is ToolStatus.ERROR
    assert (await tool.invoke("explode", {"argv": ["x"]}, ctx)).status is ToolStatus.ERROR


# ------------------------------------------------------------- unavailable adapters


async def test_browser_tool_reports_status_but_never_fabricates(ctx: ToolContext) -> None:
    tool = BrowserTool()
    available = tool.availability().available

    result = await tool.invoke("text", {"url": "https://example.com"}, ctx)

    if available:
        # Playwright is installed, so the refusal must come from the network policy,
        # which is disabled by default - not from a missing driver.
        assert result.status is ToolStatus.DENIED
        assert "network access is disabled" in result.error
    else:
        assert result.status is ToolStatus.UNAVAILABLE
        assert "playwright is not installed" in result.error
    assert result.output == "", "no page content may be fabricated either way"


async def test_mcp_tool_denies_unknown_servers(ctx: ToolContext) -> None:
    tool = McpTool()

    assert tool.availability().available, "the MCP bridge is implemented as of Phase 2"

    result = await tool.invoke("call", {"server": "ghost", "tool": "anything"}, ctx)

    assert result.status is ToolStatus.DENIED
    assert "no MCP server named 'ghost'" in result.error


async def test_mcp_list_servers_is_empty_without_configuration(ctx: ToolContext) -> None:
    result = await McpTool().invoke("list_servers", {}, ctx)

    assert result.ok
    assert result.data["servers"] == []
