"""Planning a commit, screening it, and making it.

The order matters. A commit is planned - message, files, findings - and the plan
is inspectable *before* anything is recorded. Only then, and only if nothing
blocking was found, does the commit happen.

That ordering is what makes the guarantee stateable: DevForge does not commit a
credential, a key file, or an unexplained binary, because the screening runs on
the content between staging and committing rather than as a review afterwards.
A commit that has already happened is in the reflog whatever you do next.
"""

from __future__ import annotations

import os
from pathlib import Path

from devforge.vcs.guard import screen_paths
from devforge.vcs.models import (
    COMMIT_TYPES,
    CommitPlan,
    CommitRecord,
    Issue,
    slugify,
)
from devforge.vcs.worktree import GitError, git

#: Directories whose name is the natural scope of a change in most layouts.
_SCOPE_HINTS = ("src", "lib", "app", "packages", "tests", "docs")


#: DevForge's own state directory. Excluded from an automatically-derived file
#: list because it is run state - tasks, event logs, worktrees - and not part of
#: anybody's change. Naming it explicitly still works, for the rare case of
#: committing a policy or workflow that happens to live there.
HARNESS_STATE = ".devforge/"


def changed_paths(root: Path, *, staged: bool = False) -> list[str]:
    """Repository-relative paths with changes.

    Includes untracked files, because a new file nobody staged is exactly the
    kind of thing that gets committed by accident.
    """
    argv = ["diff", "--name-only", "--cached"] if staged else ["diff", "--name-only"]
    result = git(argv, cwd=root)
    if not result.ok:
        raise GitError(f"could not list changes: {result.message}")
    paths = [line.strip() for line in result.stdout.splitlines() if line.strip()]

    if not staged:
        untracked = git(["ls-files", "--others", "--exclude-standard"], cwd=root)
        if untracked.ok:
            paths += [line.strip() for line in untracked.stdout.splitlines() if line.strip()]
    return sorted({path for path in paths if not path.startswith(HARNESS_STATE)})


def infer_scope(paths: list[str]) -> str:
    """A Conventional-Commit scope from the paths, or nothing.

    The scope is the deepest directory every path shares, minus the layout
    prefixes that say nothing about the change - `src/devforge/vcs/{a,b}.py` is
    about `vcs`, not about `src`.

    A wrong scope is worse than none: it makes `git log --grep` lie. So anything
    ambiguous - paths in different trees, a file at the repository root, a common
    directory that is only a layout prefix - answers with nothing.
    """
    if not paths:
        return ""
    directories = [Path(path).as_posix().split("/")[:-1] for path in paths]
    if any(not parts for parts in directories):
        return ""

    common = list(os.path.commonprefix(directories))
    meaningful = [part for part in common if part not in _SCOPE_HINTS]
    return slugify(meaningful[-1], limit=20) if meaningful else ""


def plan_commit(
    root: Path,
    *,
    paths: list[str] | None = None,
    issue: Issue | None = None,
    subject: str = "",
    body: str = "",
    commit_type: str = "",
    scope: str | None = None,
    task_id: str = "",
    scope_globs: list[str] | None = None,
) -> CommitPlan:
    """Build a commit plan and screen everything it would contain.

    ``scope_globs`` is what the task said it would touch. Files outside it are
    flagged, not blocked - real work routinely touches something the plan did not
    anticipate, and a guard that blocks on that gets bypassed until it blocks on
    nothing.
    """
    files = sorted(set(paths if paths is not None else changed_paths(root)))
    kind = commit_type or (issue.kind if issue else "chore")
    if kind not in COMMIT_TYPES:
        raise ValueError(f"unknown commit type '{kind}'; expected one of {COMMIT_TYPES}")

    plan = CommitPlan(
        type=kind,
        scope=infer_scope(files) if scope is None else scope,
        subject=subject or (issue.title if issue else "record the current changes"),
        body=body,
        files=files,
        issue_id=issue.id if issue else "",
        task_id=task_id,
        flags=screen_paths(root, files, scope=scope_globs),
    )
    return plan


def apply_commit(root: Path, plan: CommitPlan, *, allow_flagged: bool = False) -> CommitRecord:
    """Stage the planned files and commit them.

    Refuses while the plan carries a blocking flag. ``allow_flagged`` exists
    because a false positive must have a way out, and it is deliberately a
    parameter a caller has to pass rather than a default - the CLI requires
    ``--i-have-reviewed-the-flags`` and prints every flag first.
    """
    if not plan.files:
        raise GitError("nothing to commit: the plan contains no files")
    if plan.blocking_flags and not allow_flagged:
        listed = "; ".join(flag.describe() for flag in plan.blocking_flags)
        raise GitError(f"refusing to commit: {listed}")

    staged = git(["add", "--", *plan.files], cwd=root)
    if not staged.ok:
        raise GitError(f"could not stage the change: {staged.message}")

    result = git(["-c", "commit.gpgsign=false", "commit", "-m", plan.message()], cwd=root)
    if not result.ok:
        raise GitError(f"could not commit: {result.message}")

    sha = git(["rev-parse", "HEAD"], cwd=root)
    branch = git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=root)
    return CommitRecord(
        sha=sha.stdout.strip() if sha.ok else "",
        header=plan.header(),
        files=list(plan.files),
        branch=branch.stdout.strip() if branch.ok else "",
    )


def commits_since(root: Path, base: str) -> list[CommitRecord]:
    """Commits on this branch that the base does not have."""
    result = git(["log", f"{base}..HEAD", "--format=%H%x1f%s"], cwd=root)
    if not result.ok:
        return []
    records: list[CommitRecord] = []
    for line in result.stdout.splitlines():
        sha, _, header = line.partition("\x1f")
        if sha.strip():
            records.append(CommitRecord(sha=sha.strip(), header=header.strip()))
    return records
