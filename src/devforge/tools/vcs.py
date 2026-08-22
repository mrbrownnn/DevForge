"""The git-native tool: worktrees, guarded commits, pull-request artifacts.

Separate from :mod:`devforge.tools.git`, which is a thin wrapper over the binary.
This one exposes *operations with rules attached* - a commit that screens its own
content, a worktree that refuses to attach to a branch someone is on, a pull
request that is a file rather than a network call.

Three things this tool deliberately cannot do: push, delete a branch, or rewrite
history. They are absent from the action list, not gated within it, so an agent
cannot reach them by finding the right parameters. A human runs those commands.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from devforge.core.errors import DevForgeError
from devforge.core.models import ToolResult
from devforge.tools.base import Tool, ToolAvailability, ToolContext
from devforge.tools.descriptor import (
    TOOL_OUTPUT_SCHEMA,
    RiskLevel,
    ToolDescriptor,
    ToolPermissions,
)
from devforge.vcs.commit import apply_commit, changed_paths, plan_commit
from devforge.vcs.issue import issue_from_text
from devforge.vcs.models import COMMIT_TYPES
from devforge.vcs.pr import build_pull_request, write_pull_request
from devforge.vcs.worktree import (
    GitError,
    active_branch,
    create_worktree,
    is_linked_worktree,
    list_worktrees,
    worktree_status,
)

_EMPTY = {"type": "object", "properties": {}, "additionalProperties": False}
_STRINGS = {"type": "array", "items": {"type": "string"}}


class VcsTool(Tool):
    name = "vcs"
    description = "Isolated worktrees, screened commits and pull-request artifacts."
    actions = ("worktree", "worktrees", "status", "plan_commit", "commit", "pull_request")

    descriptor = ToolDescriptor(
        name="vcs",
        version="1.0.0",
        description=(
            "Git-native engineering: create an isolated worktree, screen and record a "
            "commit, and write a pull-request artifact. Cannot push, delete branches "
            "or rewrite history."
        ),
        capabilities=["vcs-write", "vcs-isolate", "artifact-write"],
        permissions=ToolPermissions(
            process_execution=True,
            filesystem_read=True,
            filesystem_write=True,
            gates=["destructive_command"],
        ),
        risk=RiskLevel.WRITE,
        input_schema={
            "worktrees": _EMPTY,
            "status": _EMPTY,
            "worktree": {
                "type": "object",
                "properties": {
                    "branch": {"type": "string"},
                    "base": {"type": "string"},
                    "issue": {"type": "string"},
                },
                "required": ["branch"],
                "additionalProperties": False,
            },
            "plan_commit": {
                "type": "object",
                "properties": {
                    "paths": _STRINGS,
                    "subject": {"type": "string"},
                    "body": {"type": "string"},
                    "type": {"type": "string", "enum": list(COMMIT_TYPES)},
                    "scope": {"type": "string"},
                    "scope_globs": _STRINGS,
                },
                "additionalProperties": False,
            },
            "commit": {
                "type": "object",
                "properties": {
                    "paths": _STRINGS,
                    "subject": {"type": "string"},
                    "body": {"type": "string"},
                    "type": {"type": "string", "enum": list(COMMIT_TYPES)},
                    "scope": {"type": "string"},
                    "scope_globs": _STRINGS,
                },
                "required": ["subject"],
                "additionalProperties": False,
            },
            "pull_request": {
                "type": "object",
                "properties": {
                    "base": {"type": "string"},
                    "summary": {"type": "string"},
                    "limitations": _STRINGS,
                    "issue": {"type": "string"},
                },
                "required": ["base"],
                "additionalProperties": False,
            },
        },
        output_schema=TOOL_OUTPUT_SCHEMA,
    )

    def availability(self) -> ToolAvailability:
        import shutil

        if shutil.which("git") is None:
            return ToolAvailability(False, "git is not installed or not on PATH")
        return ToolAvailability(True)

    async def invoke(self, action: str, params: dict[str, Any], ctx: ToolContext) -> ToolResult:
        if action not in self.actions:
            return self.unknown_action(action)

        availability = self.availability()
        if not availability.available:
            return self.unavailable(action, availability.detail)

        invalid = self.validate(action, params)
        if invalid is not None:
            return invalid

        try:
            return self._dispatch(action, params, ctx)
        except (GitError, DevForgeError) as exc:
            return self.fail(action, str(exc))

    # -- actions ----------------------------------------------------------------

    def _dispatch(self, action: str, params: dict[str, Any], ctx: ToolContext) -> ToolResult:
        root = Path(ctx.workspace)

        if action == "worktrees":
            entries = list_worktrees(root)
            return self.ok(
                action,
                "\n".join(f"{e.get('branch', '(detached)')}  {e['path']}" for e in entries),
                worktrees=entries,
                active_branch=active_branch(root),
            )

        if action == "status":
            lines = worktree_status(root)
            return self.ok(
                action,
                "\n".join(lines) or "clean",
                dirty=bool(lines),
                changes=lines,
                branch=active_branch(root),
            )

        if action == "worktree":
            worktree = create_worktree(
                root,
                branch=str(params["branch"]),
                base=str(params.get("base", "")),
                task_id=ctx.task.task_id if ctx.task else "",
                issue_id=str(params.get("issue", "")),
            )
            ctx.logger.info(
                "vcs.worktree", branch=worktree.branch, base=worktree.base, path=worktree.path
            )
            return self.ok(
                action,
                f"created {worktree.path} on {worktree.branch} (from {worktree.base})",
                worktree=worktree.model_dump(mode="json"),
            )

        if action in {"plan_commit", "commit"}:
            if action == "commit" and not is_linked_worktree(root):
                # The brief's rule, enforced rather than described: autonomous
                # work does not land on the branch the user is standing on. The
                # human CLI has no such restriction - a person who types
                # `devforge git commit` has chosen where they are.
                return self.fail(
                    action,
                    "this is the main checkout, not a DevForge worktree. Create one "
                    "with the 'worktree' action first; an agent does not commit to "
                    f"the branch the user is standing on ('{active_branch(root)}').",
                )
            return self._commit(action, params, ctx, root)

        return self._pull_request(action, params, ctx, root)

    def _commit(
        self, action: str, params: dict[str, Any], ctx: ToolContext, root: Path
    ) -> ToolResult:
        plan = plan_commit(
            root,
            paths=[str(p) for p in params["paths"]] if params.get("paths") else None,
            subject=str(params.get("subject", "")),
            body=str(params.get("body", "")),
            commit_type=str(params.get("type", "")) or "chore",
            scope=str(params["scope"]) if "scope" in params else None,
            task_id=ctx.task.task_id if ctx.task else "",
            scope_globs=[str(g) for g in params.get("scope_globs", [])] or None,
        )
        flags = [flag.describe() for flag in plan.flags]

        if action == "plan_commit":
            return self.ok(
                action,
                plan.message() + ("\n" + "\n".join(flags) if flags else ""),
                plan=plan.model_dump(mode="json"),
                safe=plan.safe,
                flags=flags,
            )

        if not plan.safe:
            # Not an approval gate. A credential in a commit is not a judgement
            # call, and offering to approve one teaches people to approve them.
            return self.fail(
                action,
                "refusing to commit: " + "; ".join(f.describe() for f in plan.blocking_flags),
                flags=flags,
            )

        record = apply_commit(root, plan)
        ctx.logger.info("vcs.commit", sha=record.sha, files=len(record.files))
        return self.ok(
            action,
            f"{record.sha[:8]} {record.header}",
            commit=record.model_dump(mode="json"),
            flags=flags,
        )

    def _pull_request(
        self, action: str, params: dict[str, Any], ctx: ToolContext, root: Path
    ) -> ToolResult:
        issue_text = str(params.get("issue", ""))
        artifact = build_pull_request(
            root,
            branch=active_branch(root),
            base=str(params["base"]),
            issue=issue_from_text(issue_text) if issue_text.strip() else None,
            task=ctx.task,
            summary=str(params.get("summary", "")),
            limitations=[str(item) for item in params.get("limitations", [])],
        )
        destination = root / ".devforge" / "artifacts"
        path = write_pull_request(artifact, destination)
        ctx.logger.info(
            "vcs.pull_request",
            branch=artifact.branch,
            base=artifact.base,
            missing=artifact.missing_sections(),
        )
        return self.ok(
            action,
            f"wrote {path}",
            path=str(path),
            missing_sections=artifact.missing_sections(),
            uncommitted=bool(changed_paths(root)),
        )
