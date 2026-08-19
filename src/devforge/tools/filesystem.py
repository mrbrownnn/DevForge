"""Filesystem tool.

Every path goes through :meth:`PolicyEngine.check_path`, which fully resolves it
(symlinks included) and rejects anything outside the workspace or matching a deny
rule. Deleting is a separate, approval-gated mode - it is not a kind of write.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from devforge.core.models import ToolResult
from devforge.tools.base import Tool, ToolContext
from devforge.tools.descriptor import (
    TOOL_OUTPUT_SCHEMA,
    RiskLevel,
    ToolDescriptor,
    ToolPermissions,
)

_PATH_ONLY = {
    "type": "object",
    "properties": {"path": {"type": "string"}},
    "required": ["path"],
    "additionalProperties": False,
}
_PATH_AND_CONTENT = {
    "type": "object",
    "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
    "required": ["path"],
    "additionalProperties": False,
}
_EMPTY = {"type": "object", "properties": {}, "additionalProperties": False}


class FilesystemTool(Tool):
    name = "filesystem"
    description = "Read, write, list and delete files inside the workspace."
    actions = ("read", "write", "append", "list", "exists", "mkdir", "delete")

    descriptor = ToolDescriptor(
        name="filesystem",
        version="1.0.0",
        description="Read, write, list and delete files inside the workspace.",
        capabilities=["read", "write", "list", "delete"],
        permissions=ToolPermissions(
            filesystem_read=True,
            filesystem_write=True,
            filesystem_delete=True,
            gates=["destructive_filesystem"],
        ),
        risk=RiskLevel.WRITE,
        input_schema={
            "read": _PATH_ONLY,
            "list": {
                "type": "object",
                "properties": {"path": {"type": "string"}, "pattern": {"type": "string"}},
                "required": ["path"],
                "additionalProperties": False,
            },
            "exists": _PATH_ONLY,
            "mkdir": _PATH_ONLY,
            "delete": _PATH_ONLY,
            "write": _PATH_AND_CONTENT,
            "append": _PATH_AND_CONTENT,
        },
        output_schema=TOOL_OUTPUT_SCHEMA,
    )

    async def invoke(self, action: str, params: dict[str, Any], ctx: ToolContext) -> ToolResult:
        handler = {
            "read": self._read,
            "write": self._write,
            "append": self._append,
            "list": self._list,
            "exists": self._exists,
            "mkdir": self._mkdir,
            "delete": self._delete,
        }.get(action)
        if handler is None:
            return self.unknown_action(action)

        raw_path = params.get("path")
        if not raw_path:
            return self.fail(action, "missing required parameter 'path'")

        mode = {"read": "read", "list": "read", "exists": "read", "delete": "delete"}.get(
            action, "write"
        )
        decision = ctx.policy.check_path(raw_path, mode=mode)
        blocked = self.authorize(action, decision, ctx, gate_prompt=f"{action} {raw_path}")
        if blocked is not None:
            return blocked

        path = ctx.policy.resolve_path(raw_path)
        try:
            return handler(path, params, ctx)
        except OSError as exc:
            return self.fail(action, f"{type(exc).__name__}: {exc}", path=str(path))

    # -- handlers ---------------------------------------------------------------

    def _read(self, path: Path, params: dict[str, Any], ctx: ToolContext) -> ToolResult:
        if not path.is_file():
            return self.fail("read", f"not a file: {path}")
        limit = ctx.policy.permissions.filesystem.max_read_bytes
        size = path.stat().st_size
        if size > limit:
            return self.fail("read", f"file is {size} bytes, over the {limit} byte read limit")
        return self.ok(
            "read", path.read_text(encoding="utf-8", errors="replace"), path=str(path), bytes=size
        )

    def _write(self, path: Path, params: dict[str, Any], ctx: ToolContext) -> ToolResult:
        content = params.get("content", "")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return self.ok("write", f"wrote {len(content)} chars to {path}", path=str(path))

    def _append(self, path: Path, params: dict[str, Any], ctx: ToolContext) -> ToolResult:
        content = params.get("content", "")
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(content)
        return self.ok("append", f"appended {len(content)} chars to {path}", path=str(path))

    def _list(self, path: Path, params: dict[str, Any], ctx: ToolContext) -> ToolResult:
        if not path.is_dir():
            return self.fail("list", f"not a directory: {path}")
        pattern = params.get("pattern", "*")
        entries = sorted(p.name + ("/" if p.is_dir() else "") for p in path.glob(pattern))
        return self.ok("list", "\n".join(entries), path=str(path), count=len(entries))

    def _exists(self, path: Path, params: dict[str, Any], ctx: ToolContext) -> ToolResult:
        return self.ok("exists", str(path.exists()).lower(), path=str(path), exists=path.exists())

    def _mkdir(self, path: Path, params: dict[str, Any], ctx: ToolContext) -> ToolResult:
        path.mkdir(parents=True, exist_ok=True)
        return self.ok("mkdir", f"created {path}", path=str(path))

    def _delete(self, path: Path, params: dict[str, Any], ctx: ToolContext) -> ToolResult:
        if not path.exists():
            return self.fail("delete", f"nothing to delete at {path}")
        if path.is_dir():
            # Recursive directory removal is not offered: too easy to get catastrophically wrong.
            try:
                path.rmdir()
            except OSError as exc:
                return self.fail("delete", f"refusing to remove non-empty directory {path}: {exc}")
            return self.ok("delete", f"removed empty directory {path}", path=str(path))
        path.unlink()
        return self.ok("delete", f"deleted {path}", path=str(path))
