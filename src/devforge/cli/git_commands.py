"""`devforge git` - worktrees, guarded commits and pull-request artifacts.

What this command group does *not* offer is as deliberate as what it does. There
is no push, no branch deletion and no rebase. Those are the operations whose
damage cannot be undone from inside the tool that caused it, and running them is
a person's job with a person's `git` in front of them.

`devforge git guard` exists so that the refusal is inspectable: you can ask what
would happen to a command without running it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from devforge.cli import render
from devforge.core.errors import DevForgeError
from devforge.core.state.store import ProjectStore
from devforge.vcs.commit import apply_commit, changed_paths, plan_commit
from devforge.vcs.guard import check_operation
from devforge.vcs.issue import issue_from_text, load_issue
from devforge.vcs.models import BranchPlan, Effect
from devforge.vcs.pr import build_pull_request, write_pull_request
from devforge.vcs.worktree import (
    GitError,
    active_branch,
    create_worktree,
    default_base,
    list_worktrees,
    remove_worktree,
    repository_root,
    worktree_root,
)

app = typer.Typer(
    help="Git-native engineering: worktrees, screened commits, PR artifacts.",
    no_args_is_help=True,
)
worktree_app = typer.Typer(
    help="Isolated worktrees, one per autonomous task.", no_args_is_help=True
)
app.add_typer(worktree_app, name="worktree")


def _root(path: Path | None) -> Path:
    """Where to run git: the directory you are standing in, not the project root.

    These commands are git-first on purpose. A worktree lives under the project's
    `.devforge/`, so resolving the DevForge project would walk *out* of the
    worktree and operate on the main checkout - which is exactly the thing this
    whole module exists to avoid. `git rev-parse --show-toplevel` inside a
    worktree answers with the worktree, which is the right answer.
    """
    return Path(path).resolve() if path is not None else Path.cwd().resolve()


def _fail(message: str) -> None:
    render.error(message)
    raise typer.Exit(code=1)


# --------------------------------------------------------------------------- worktree


@worktree_app.command("create")
def worktree_create(
    branch: Annotated[
        str | None, typer.Option("--branch", "-b", help="Branch to create.")
    ] = None,
    issue: Annotated[
        Path | None, typer.Option("--issue", help="Issue file; names the branch.")
    ] = None,
    task: Annotated[str | None, typer.Option("--task", "-t", help="Issue text instead.")] = None,
    base: Annotated[str | None, typer.Option("--base", help="Branch to cut from.")] = None,
    path: Annotated[Path | None, typer.Option("--path", help="Repository root.")] = None,
) -> None:
    """Create an isolated worktree for one task."""
    root = _root(path)
    try:
        repository = repository_root(root)
        record = load_issue(issue) if issue else (issue_from_text(task) if task else None)
        base_branch = base or default_base(repository)

        if branch:
            name = branch
        elif record is not None:
            name = BranchPlan.for_issue(
                record, base=base_branch, worktree_path=str(worktree_root(repository))
            ).branch
        else:
            _fail("name a branch with --branch, or an issue with --issue/--task")
            return

        worktree = create_worktree(
            repository,
            branch=name,
            base=base_branch,
            issue_id=record.id if record else "",
        )
    except DevForgeError as exc:
        _fail(str(exc))
        return

    render.success(f"worktree {worktree.path}")
    render.info(f"  branch: {worktree.branch} (from {worktree.base})")
    render.info(f"  your branch '{active_branch(repository) or '(detached)'}' was not touched")


@worktree_app.command("list")
def worktree_list(
    path: Annotated[Path | None, typer.Option("--path", help="Repository root.")] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """List every worktree in this repository."""
    root = _root(path)
    try:
        repository = repository_root(root)
        entries = list_worktrees(repository)
        current = active_branch(repository)
    except DevForgeError as exc:
        _fail(str(exc))
        return

    if as_json:
        render.emit_json({"active_branch": current, "worktrees": entries})
        return
    render.render_worktrees(entries, current)


@worktree_app.command("remove")
def worktree_remove(
    target: Annotated[Path, typer.Argument(help="Worktree path to remove.")],
    force: Annotated[
        bool, typer.Option("--force", help="Discard uncommitted changes in it.")
    ] = False,
    path: Annotated[Path | None, typer.Option("--path", help="Repository root.")] = None,
) -> None:
    """Remove a worktree, keeping it when it still holds uncommitted work."""
    root = _root(path)
    try:
        dirty = remove_worktree(repository_root(root), target, force=force)
    except DevForgeError as exc:
        _fail(str(exc))
        return

    if dirty:
        render.warn(f"{target} still holds uncommitted changes; it was kept:")
        for line in dirty[:20]:
            render.info(f"  {line}")
        render.info("\nCommit them, or re-run with --force to discard them.")
        raise typer.Exit(code=1)
    render.success(f"removed {target}")


# --------------------------------------------------------------------------- guard


@app.command(
    # The command being judged carries its own flags - `git push --force` - and
    # they belong to it, not to this CLI.
    context_settings={"ignore_unknown_options": True},
)
def guard(
    argv: Annotated[list[str], typer.Argument(help="The git command to judge.")],
    approve: Annotated[
        list[str] | None,
        typer.Option("--approve", help="Operation class to treat as approved."),
    ] = None,
    path: Annotated[Path | None, typer.Option("--path", help="Repository root.")] = None,
) -> None:
    """Say what would happen to a git command, without running it."""
    root = _root(path)
    try:
        branch = active_branch(repository_root(root))
    except DevForgeError:
        branch = ""

    verdict = check_operation(list(argv), active_branch=branch, approvals=set(approve or []))
    render.render_git_verdict(list(argv), verdict)
    if verdict.effect is not Effect.ALLOW:
        raise typer.Exit(code=1)


# --------------------------------------------------------------------------- commit


@app.command()
def commit(
    subject: Annotated[str, typer.Option("--subject", "-m", help="Commit subject.")],
    commit_type: Annotated[str, typer.Option("--type", help="Conventional type.")] = "chore",
    scope: Annotated[str | None, typer.Option("--scope", help="Conventional scope.")] = None,
    body: Annotated[str, typer.Option("--body", help="Commit body.")] = "",
    file: Annotated[
        list[str] | None, typer.Option("--file", help="Limit to these paths.")
    ] = None,
    scope_glob: Annotated[
        list[str] | None,
        typer.Option("--scope-glob", help="Paths this task was meant to touch."),
    ] = None,
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Plan only.")] = False,
    reviewed: Annotated[
        bool,
        typer.Option(
            "--i-have-reviewed-the-flags",
            help="Commit despite blocking flags. Read them first.",
        ),
    ] = False,
    path: Annotated[Path | None, typer.Option("--path", help="Repository root.")] = None,
) -> None:
    """Plan a commit, screen what it contains, then record it."""
    root = _root(path)
    try:
        repository = repository_root(root)
        plan = plan_commit(
            repository,
            paths=list(file) if file else None,
            subject=subject,
            body=body,
            commit_type=commit_type,
            scope=scope,
            scope_globs=list(scope_glob) if scope_glob else None,
        )
    except (DevForgeError, ValueError) as exc:
        _fail(str(exc))
        return

    render.render_commit_plan(plan)

    if dry_run:
        raise typer.Exit(code=0 if plan.safe else 1)
    if not plan.files:
        _fail("nothing to commit")
        return
    if not plan.safe and not reviewed:
        _fail(
            "refusing to commit while blocking flags stand. Fix them, or pass "
            "--i-have-reviewed-the-flags if they are wrong."
        )
        return

    try:
        record = apply_commit(repository, plan, allow_flagged=reviewed)
    except DevForgeError as exc:
        _fail(str(exc))
        return
    render.success(f"{record.sha[:8]} {record.header}")


# --------------------------------------------------------------------------- pr


@app.command("pr")
def pull_request(
    base: Annotated[str | None, typer.Option("--base", help="Branch this merges into.")] = None,
    issue: Annotated[Path | None, typer.Option("--issue", help="Issue file.")] = None,
    task_id: Annotated[
        str | None, typer.Option("--task-id", help="Run whose results to include.")
    ] = None,
    summary: Annotated[str, typer.Option("--summary", help="Override the summary.")] = "",
    limitation: Annotated[
        list[str] | None, typer.Option("--limitation", help="A known limitation.")
    ] = None,
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Directory for the artifact.")
    ] = None,
    path: Annotated[Path | None, typer.Option("--path", help="Repository root.")] = None,
) -> None:
    """Write the pull-request artifact. Does not push and does not open anything."""
    root = _root(path)
    try:
        repository = repository_root(root)
        record = load_issue(issue) if issue else None
        task = None
        if task_id:
            task = ProjectStore.discover(root).load_task(task_id)
        artifact = build_pull_request(
            repository,
            branch=active_branch(repository),
            base=base or default_base(repository),
            issue=record,
            task=task,
            summary=summary,
            limitations=list(limitation or []),
        )
    except (DevForgeError, GitError) as exc:
        _fail(str(exc))
        return

    destination = output or (repository / ".devforge" / "artifacts")
    written = write_pull_request(artifact, destination)
    render.success(f"wrote {written}")

    uncommitted = changed_paths(repository)
    if uncommitted:
        render.warn(
            f"{len(uncommitted)} uncommitted change(s) are not in this branch's history "
            "and therefore not in the artifact"
        )
    missing = artifact.missing_sections()
    if missing:
        render.warn("incomplete artifact - missing: " + ", ".join(missing))
        raise typer.Exit(code=1)
    render.info("\nDevForge does not push and does not open pull requests. Next, by hand:")
    render.info(f"  git push -u origin {artifact.branch}")
