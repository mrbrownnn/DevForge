"""Isolated workspaces for falsification.

Mutation testing edits source and runs it. Doing that in the user's working tree is
not a risk to be managed, it is a defect: an interrupted run would leave mutated
code on disk under an open editor, and a crashed one would leave it there for good.

Three tiers, in preference order, each honestly labelled:

``worktree``
    A linked git worktree under ``.devforge/worktrees/``. Cheap, shares the object
    store, removed when the run ends. Reuses :mod:`devforge.vcs.worktree`.
``copy``
    A filtered copy of the tree into a temporary directory. Used when the project is
    not a git repository or a worktree could not be created. Slower, and it drops
    ``.git``, which is why a strategy needing history records the limitation instead
    of pretending.
``none``
    Nothing worked. The engine refuses to run and says why. There is no fourth tier
    in which falsification proceeds against the real tree.

**What isolation means here, exactly.** The user's files are not touched. That is
the entire claim. It is *not* an OS-level sandbox: a test runner started inside a
worktree executes as the current user with that user's privileges and can reach
whatever that user can reach. ``docs/falsification/security.md`` states this in the
same terms, and nothing in this module ever reports a stronger isolation than the
one it actually obtained.
"""

from __future__ import annotations

import hashlib
import shutil
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from devforge.core.models import new_id

#: Directories never copied into a sandbox. Copying them is slow, and two of them
#: (``.git``, ``.devforge``) would give the sandbox a route back into the real
#: project's history and state.
EXCLUDED_DIRS = frozenset(
    {
        ".git",
        ".devforge",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".pytest_cache",
        ".ruff_cache",
        ".mypy_cache",
        ".tox",
        "build",
        "dist",
        ".idea",
        ".vscode",
    }
)

#: Files never copied in, whatever any other rule says. Defence in depth: the
#: permission policy already denies reading them, and the sandbox declines to hold a
#: copy of them at all.
EXCLUDED_GLOBS = (
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "id_rsa*",
    "*.p12",
    "*.pfx",
)

#: Where generated tests and falsification artifacts go inside a sandbox. One named
#: directory, so the write-scope guard can state exactly what was allowed to change.
SCRATCH_DIRNAME = ".falsification"


class Isolation(str, Enum):
    WORKTREE = "worktree"
    COPY = "copy"
    NONE = "none"


@dataclass
class Sandbox:
    """An isolated workspace, and an honest record of how it was obtained."""

    root: Path
    isolation: Isolation
    detail: str = ""
    #: Set when the sandbox owns a temporary directory and must delete it.
    temp_dir: Path | None = None
    worktree_parent: Path | None = None
    worktree_branch: str = ""
    _released: bool = field(default=False, repr=False)

    @property
    def available(self) -> bool:
        return self.isolation is not Isolation.NONE

    @property
    def scratch(self) -> Path:
        path = self.root / SCRATCH_DIRNAME
        path.mkdir(parents=True, exist_ok=True)
        return path

    def describe(self) -> str:
        if not self.available:
            return f"ISOLATION_UNAVAILABLE: {self.detail}"
        return f"{self.isolation.value} at {self.root}"

    def release(self) -> None:
        """Discard the sandbox. Touches nothing it did not create."""
        if self._released:
            return
        self._released = True
        if self.worktree_parent is not None:
            from devforge.vcs.worktree import GitError, git

            try:
                git(["worktree", "remove", "--force", str(self.root)], cwd=self.worktree_parent)
                if self.worktree_branch:
                    git(["branch", "-D", self.worktree_branch], cwd=self.worktree_parent)
            except GitError:  # pragma: no cover - best-effort cleanup
                shutil.rmtree(self.root, ignore_errors=True)
            return
        if self.temp_dir is not None:
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def __enter__(self) -> Sandbox:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.release()


def create_sandbox(
    source_root: Path,
    *,
    run_id: str = "",
    prefer: Isolation | None = None,
) -> Sandbox:
    """An isolated copy of ``source_root``, by the strongest mechanism available.

    ``prefer`` pins a tier. It exists so the tests can exercise the copy path on a
    machine that has git, and so a caller can *require* a worktree rather than
    silently accepting the weaker tier. It can never ask for less checking than a
    tier performs.
    """
    source_root = Path(source_root).resolve()
    run_id = run_id or new_id("fals")

    if prefer is not Isolation.COPY:
        sandbox = _try_worktree(source_root, run_id)
        if sandbox is not None:
            return sandbox
        if prefer is Isolation.WORKTREE:
            return Sandbox(
                root=source_root,
                isolation=Isolation.NONE,
                detail=(
                    "a git worktree was required but could not be created; "
                    "falsification will not fall back to a weaker isolation when a "
                    "specific one was demanded"
                ),
            )

    return _copy_sandbox(source_root, run_id)


def _try_worktree(source_root: Path, run_id: str) -> Sandbox | None:
    """A linked worktree on a throwaway branch, or ``None`` when git cannot give one."""
    from devforge.vcs.worktree import GitError, create_worktree, repository_root

    try:
        repo = repository_root(source_root)
    except GitError:
        return None

    branch = f"devforge/falsify/{run_id}"
    try:
        worktree = create_worktree(repo, branch=branch, task_id=run_id)
    except GitError:
        return None

    return Sandbox(
        root=Path(worktree.path),
        isolation=Isolation.WORKTREE,
        detail=f"linked git worktree on '{branch}' cut from '{worktree.base}'",
        worktree_parent=repo,
        worktree_branch=branch,
    )


def _copy_sandbox(source_root: Path, run_id: str) -> Sandbox:
    """A filtered copy of the tree. Secrets and heavy directories are left behind."""
    try:
        temp_root = Path(tempfile.mkdtemp(prefix=f"devforge-falsify-{run_id}-"))
    except OSError as exc:
        return Sandbox(
            root=source_root,
            isolation=Isolation.NONE,
            detail=f"no temporary directory could be created: {exc}",
        )

    destination = temp_root / source_root.name
    try:
        shutil.copytree(source_root, destination, ignore=_ignore, symlinks=False)
    except (OSError, shutil.Error) as exc:
        shutil.rmtree(temp_root, ignore_errors=True)
        return Sandbox(
            root=source_root,
            isolation=Isolation.NONE,
            detail=f"the project tree could not be copied: {exc}",
        )

    return Sandbox(
        root=destination,
        isolation=Isolation.COPY,
        detail=(
            "filtered copy of the project tree; version-control history and "
            "environment files were not copied"
        ),
        temp_dir=temp_root,
    )


@dataclass
class Lane:
    """One concurrent worker's private copy of a sandbox.

    Mutation testing writes a mutant to disk and then runs the whole suite. Two
    mutants sharing one directory therefore share one test run: whichever fault the
    suite reports, *both* are recorded against it. A mutant in an untested file gets
    credited as killed by a mutant in a tested one, and the score comes out higher
    than the suite deserves.

    A lane is the fix. Each concurrent job owns a directory nothing else writes to,
    so a verdict is about exactly one injected fault. ``primary`` marks the sandbox
    root itself, which is lent out as lane 0 and must never be deleted here.
    """

    root: Path
    primary: bool = False
    temp_dir: Path | None = None

    def release(self) -> None:
        if self.primary or self.temp_dir is None:
            return
        shutil.rmtree(self.temp_dir, ignore_errors=True)


def open_lanes(root: Path, count: int) -> tuple[list[Lane], str]:
    """``count`` independent workspaces, and a note when fewer were obtained.

    Lane 0 is the sandbox itself; every other lane is a filtered copy of it. Copies
    are made once per *worker*, not once per mutant, so the cost is bounded by the
    parallelism rather than by the number of mutants.

    A copy that fails is not an error: the pool simply runs narrower, which is slower
    and still correct. Silently running wider than the number of lanes obtained would
    be the one outcome that is neither.
    """
    root = Path(root)
    lanes = [Lane(root=root, primary=True)]
    if count <= 1:
        return lanes, ""

    for index in range(1, count):
        try:
            temp_root = Path(tempfile.mkdtemp(prefix=f"devforge-lane{index}-"))
            destination = temp_root / root.name
            shutil.copytree(root, destination, ignore=_ignore, symlinks=False)
        except (OSError, shutil.Error) as exc:
            # Keep the lanes already obtained; the caller reports the shortfall.
            return lanes, (
                f"only {len(lanes)} of {count} parallel workspace(s) could be created "
                f"({exc}); mutants were evaluated with less parallelism"
            )
        lanes.append(Lane(root=destination, temp_dir=temp_root))
    return lanes, ""


def _ignore(directory: str, names: list[str]) -> set[str]:
    from fnmatch import fnmatch

    skipped = {name for name in names if name in EXCLUDED_DIRS}
    for name in names:
        if any(fnmatch(name, pattern) for pattern in EXCLUDED_GLOBS):
            skipped.add(name)
    return skipped


# --------------------------------------------------------------------------- guards


def snapshot_tree(root: Path) -> dict[str, str]:
    """Relative path -> a content digest, for detecting writes.

    Content is hashed rather than fingerprinted from ``mtime`` and size. Both of the
    cheaper signals miss the case that matters most here: an edit that replaces one
    character with another keeps the size identical, and filesystem timestamp
    resolution is coarse enough that a fast write can keep the mtime identical too.
    A guard that misses a same-length edit to a source file is not a guard, and this
    is the check that turns the falsifier's write restriction into a control.
    """
    snapshot: dict[str, str] = {}
    root = Path(root)
    if not root.is_dir():
        return snapshot
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if set(relative.parts) & EXCLUDED_DIRS:
            continue
        try:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:  # pragma: no cover - racing with the run
            continue
        snapshot[relative.as_posix()] = digest
    return snapshot


def scope_violations(root: Path, before: dict[str, str]) -> list[str]:
    """Paths that changed outside the scratch directory since ``before`` was taken.

    This is what makes the adversarial agent's write restriction a control rather
    than a request. The agent is *told* it may only write tests; this reads the
    filesystem and reports what it actually did.
    """
    after = snapshot_tree(root)
    scratch_prefix = f"{SCRATCH_DIRNAME}/"
    violations: list[str] = []

    for path, digest in after.items():
        if path.startswith(scratch_prefix):
            continue
        if path not in before:
            violations.append(f"created: {path}")
        elif before[path] != digest:
            violations.append(f"modified: {path}")

    for path in before:
        if path.startswith(scratch_prefix):
            continue
        if path not in after:
            violations.append(f"deleted: {path}")

    return sorted(violations)
