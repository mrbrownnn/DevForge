"""Isolated worktrees, one per autonomous task.

A git worktree is a second checkout of the same repository on a different branch.
It is the mechanism that makes autonomous work safe to run in a repository someone
is using: the agent's branch is checked out somewhere else entirely, so nothing it
does touches the files under the developer's editor.

Three rules this module enforces rather than documents:

**A branch that is checked out anywhere is not available.** git enforces this for
its own reasons; the check exists here too so the refusal names the reason instead
of surfacing a porcelain error.

**Worktrees live under ``.devforge/worktrees/``**, outside the source tree, so a
worktree is never collected by a build, a test run or a scan of the project.

**Removal never discards work silently.** A worktree with uncommitted changes is
kept, and the caller is told what is in it. Losing an agent's work is recoverable
only if somebody notices, and the moment to notice is now.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from devforge.core.errors import DevForgeError
from devforge.vcs.models import Worktree

WORKTREE_DIRNAME = "worktrees"
GIT_TIMEOUT_S = 120


class GitError(DevForgeError):
    """A git command failed in a way the caller has to handle."""


@dataclass(frozen=True)
class GitResult:
    exit_code: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.exit_code == 0

    @property
    def message(self) -> str:
        return (self.stderr.strip() or self.stdout.strip() or f"exit {self.exit_code}").strip()


def git(argv: list[str], *, cwd: Path, timeout_s: int = GIT_TIMEOUT_S) -> GitResult:
    """Run a git command. Never a shell string, so quoting cannot become injection."""
    if shutil.which("git") is None:
        raise GitError("git is not installed or not on PATH")
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, never a shell
            ["git", *argv],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise GitError(f"git {' '.join(argv)} timed out after {timeout_s}s") from exc
    except OSError as exc:
        raise GitError(f"could not run git: {exc}") from exc
    return GitResult(completed.returncode, completed.stdout, completed.stderr)


def repository_root(start: Path) -> Path:
    result = git(["rev-parse", "--show-toplevel"], cwd=start)
    if not result.ok:
        raise GitError(f"{start} is not inside a git repository")
    return Path(result.stdout.strip()).resolve()


def active_branch(root: Path) -> str:
    """The branch the user is standing on, or "" when detached."""
    result = git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=root)
    name = result.stdout.strip() if result.ok else ""
    return "" if name == "HEAD" else name


def default_base(root: Path) -> str:
    """A sensible branch to cut from: the current one, else main, else master."""
    current = active_branch(root)
    if current:
        return current
    for candidate in ("main", "master"):
        if git(["rev-parse", "--verify", "--quiet", candidate], cwd=root).ok:
            return candidate
    raise GitError("could not determine a base branch; name one explicitly")


def branch_exists(root: Path, branch: str) -> bool:
    return git(["rev-parse", "--verify", "--quiet", f"refs/heads/{branch}"], cwd=root).ok


def is_linked_worktree(path: Path) -> bool:
    """Whether this directory is a linked worktree rather than the main checkout.

    git keeps one common directory and one per-worktree directory; in the main
    checkout they are the same path, and in a linked worktree they are not. That
    is the reliable test, and it is what lets an agent's commit refuse to land on
    the branch the user is standing on.
    """
    common = git(["rev-parse", "--git-common-dir"], cwd=path)
    own = git(["rev-parse", "--git-dir"], cwd=path)
    if not (common.ok and own.ok):
        return False
    return Path(common.stdout.strip()).resolve() != Path(own.stdout.strip()).resolve()


def worktree_root(root: Path) -> Path:
    return root / ".devforge" / WORKTREE_DIRNAME


def list_worktrees(root: Path) -> list[dict[str, str]]:
    """Every worktree git knows about, including the main one."""
    result = git(["worktree", "list", "--porcelain"], cwd=root)
    if not result.ok:
        raise GitError(f"could not list worktrees: {result.message}")

    entries: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in result.stdout.splitlines():
        if not line.strip():
            if current:
                entries.append(current)
                current = {}
            continue
        key, _, value = line.partition(" ")
        if key == "worktree":
            current["path"] = value
        elif key == "branch":
            current["branch"] = value.removeprefix("refs/heads/")
        elif key == "detached":
            current["branch"] = ""
    if current:
        entries.append(current)
    return entries


def checked_out_branches(root: Path) -> set[str]:
    return {entry.get("branch", "") for entry in list_worktrees(root)} - {""}


def create_worktree(
    root: Path,
    *,
    branch: str,
    base: str = "",
    task_id: str = "",
    issue_id: str = "",
    path: Path | None = None,
) -> Worktree:
    """Create an isolated worktree on a new branch.

    Refuses when the branch is already checked out somewhere. That is not merely
    a git restriction being echoed - a second checkout of a branch someone is
    working on is exactly the situation this whole module exists to prevent.
    """
    root = repository_root(root)
    base = base or default_base(root)

    if branch == active_branch(root):
        raise GitError(
            f"'{branch}' is the branch you are standing on. Autonomous work gets its "
            "own branch and its own worktree."
        )
    if branch in checked_out_branches(root):
        raise GitError(
            f"branch '{branch}' is already checked out. DevForge will not attach to a "
            "branch someone may be working on; use a different branch name."
        )
    if not git(["rev-parse", "--verify", "--quiet", base], cwd=root).ok:
        raise GitError(f"base '{base}' does not exist in this repository")

    destination = Path(path) if path is not None else worktree_root(root) / _dirname(branch)
    if destination.exists():
        raise GitError(f"{destination} already exists; remove it or choose another path")
    destination.parent.mkdir(parents=True, exist_ok=True)

    if branch_exists(root, branch):
        argv = ["worktree", "add", str(destination), branch]
    else:
        argv = ["worktree", "add", "-b", branch, str(destination), base]

    result = git(argv, cwd=root)
    if not result.ok:
        raise GitError(f"could not create the worktree: {result.message}")

    return Worktree(
        path=str(destination.resolve()),
        branch=branch,
        base=base,
        task_id=task_id,
        issue_id=issue_id,
    )


def worktree_status(path: Path) -> list[str]:
    """Porcelain status lines for a worktree; empty means clean."""
    result = git(["status", "--porcelain"], cwd=path)
    if not result.ok:
        raise GitError(f"could not read the worktree status: {result.message}")
    return [line for line in result.stdout.splitlines() if line.strip()]


def remove_worktree(root: Path, path: Path, *, force: bool = False) -> list[str]:
    """Remove a worktree. Returns the uncommitted changes that stopped it, if any.

    ``force`` discards work, so it is the caller's job to have obtained a human
    decision first - `devforge git worktree remove` asks, and the tool action
    routes through the approval gate.
    """
    root = repository_root(root)
    path = Path(path).resolve()

    if not force:
        dirty = worktree_status(path)
        if dirty:
            return dirty

    result = git(["worktree", "remove", *(["--force"] if force else []), str(path)], cwd=root)
    if not result.ok:
        raise GitError(f"could not remove the worktree: {result.message}")
    return []


def _dirname(branch: str) -> str:
    """A directory name from a branch name. Never a path, however the branch reads."""
    return branch.replace("/", "-").replace("\\", "-").strip("-.") or "worktree"
