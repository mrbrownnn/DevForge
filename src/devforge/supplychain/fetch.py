"""Fetching a skill source, reproducibly.

DevForge imports no HTTP client - that invariant is enforced by
``tests/test_architecture.py`` and it survives Phase 3. Fetching goes through
``git``, run as a policy-checked subprocess with a sanitised environment, which
buys three things a bare download does not:

* **Commit pinning is native.** A tree is identified by SHA, and the SHA is
  verified *after* checkout against what was asked for. A moved tag or a
  substituted branch fails the comparison.
* **No new attack surface.** No TLS stack, no redirect handling, no archive
  extraction in-process. Git already does that, outside our address space.
* **One permission path.** ``git clone`` is refused by the default policy and
  routes to an approval gate like any other network-touching command.

What this does NOT do: verify signatures. A commit SHA proves the tree matches
what GitHub served for that identifier; it does not prove who authored it. Commit
signature verification is the next honest step and is not implemented.
"""

from __future__ import annotations

import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from devforge.core.errors import DevForgeError
from devforge.policy.engine import PolicyEngine
from devforge.supplychain.registry import content_hash
from devforge.tools.process import run_process

CLONE_TIMEOUT_S = 300
#: Refuse a source tree larger than this before hashing or inspecting it.
MAX_TREE_BYTES = 200_000_000
MAX_TREE_FILES = 20_000


class FetchError(DevForgeError):
    """The source could not be fetched, or was not what it claimed to be."""


@dataclass
class FetchedSource:
    """A checked-out tree plus what we verified about it."""

    repository: str
    commit_sha: str
    root: Path
    skill_root: Path
    content_hash: str
    file_count: int
    total_bytes: int
    #: Populated when a pin was requested and the checkout matched it.
    pin_verified: bool = False
    warnings: list[str] = field(default_factory=list)

    def cleanup(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)


ALLOWED_SCHEMES = ("https://", "file://")


def _remote_url(repository: str) -> str:
    """Accept https and file remotes only.

    ``ssh://`` and ``git://`` are refused: the first drags in agent credentials, the
    second has no transport security at all. ``http://`` is refused for the same
    reason DevForge refuses it everywhere else. ``file://`` is allowed because a
    local mirror has no transport to secure - it is how air-gapped installs and the
    test suite exercise the identical code path.
    """
    url = repository.strip()
    if not url.startswith(ALLOWED_SCHEMES):
        raise FetchError(
            f"only https:// or file:// repositories may be fetched, got {repository!r}"
        )
    if url.startswith("file://"):
        return url
    return url if url.endswith(".git") else f"{url}.git"


async def _git(argv: list[str], *, cwd: Path, policy: PolicyEngine, timeout_s: int):
    decision = policy.check_command(argv)
    if not decision.allowed:
        raise FetchError(
            f"git command refused by policy ({decision.effect.value}): {decision.reason}. "
            "Fetching a skill needs 'git clone' permitted - see docs/security/skills.md."
        )
    result = await run_process(argv, cwd=cwd, timeout_s=timeout_s)
    if not result.started:
        raise FetchError(result.error or f"could not start {argv[0]!r}")
    if result.exit_code != 0:
        raise FetchError(f"{' '.join(argv[:2])} failed: {result.excerpt(600) or result.error}")
    return result


def _measure(root: Path) -> tuple[int, int]:
    files = 0
    total = 0
    for path in root.rglob("*"):
        if path.is_symlink() or not path.is_file():
            continue
        files += 1
        total += path.stat().st_size
        if files > MAX_TREE_FILES or total > MAX_TREE_BYTES:
            break
    return files, total


def _relative_name(path: Path, root: Path) -> str:
    """A symlink's own path relative to the checkout, without following the link.

    ``resolve()`` on the link itself would follow it out of the tree, which is the
    one thing this listing must not do. The parent - a real directory inside the
    checkout - is resolved instead and the link's name appended, so both sides of
    the comparison are in the same form. That matters on Windows, where the same
    directory is handed out as ``RUNNER~1`` in one place and ``runneradmin`` in
    another and a plain ``relative_to`` raises ``ValueError`` on a path that is
    plainly inside the tree.
    """
    try:
        return (path.parent.resolve() / path.name).relative_to(root.resolve()).as_posix()
    except ValueError:  # pragma: no cover - defensive; the caller already bounded it
        return path.name


def _strip_git_metadata(root: Path) -> None:
    """Remove .git before hashing.

    Two reasons. Object files differ between clones of the same commit, so leaving
    them in makes the content hash unreproducible. And .git can carry hooks, which
    are executable code we have no reason to keep near an installed skill.
    """
    shutil.rmtree(root / ".git", ignore_errors=True)


async def fetch_git_source(
    repository: str,
    *,
    policy: PolicyEngine,
    commit: str | None = None,
    subpath: str = ".",
    workdir: Path | None = None,
    timeout_s: int = CLONE_TIMEOUT_S,
) -> FetchedSource:
    """Clone a repository, check out an exact commit, and hash what arrived.

    When ``commit`` is given the checkout is verified against it and a mismatch is
    a hard failure. When it is omitted the resolved HEAD is reported back so the
    caller can pin it - fetching unpinned is allowed, *installing* unpinned is not.
    """
    url = _remote_url(repository)
    root = Path(tempfile.mkdtemp(prefix="devforge-fetch-", dir=str(workdir) if workdir else None))
    checkout = root / "src"

    try:
        # A blobless clone still lets us check out any commit, without paying for
        # the full history of a large skill repository.
        await _git(
            ["git", "clone", "--filter=blob:none", "--quiet", url, str(checkout)],
            cwd=root,
            policy=policy,
            timeout_s=timeout_s,
        )
        if commit:
            await _git(
                ["git", "-C", str(checkout), "checkout", "--quiet", commit],
                cwd=root,
                policy=policy,
                timeout_s=timeout_s,
            )

        resolved = (
            await _git(
                ["git", "-C", str(checkout), "rev-parse", "HEAD"],
                cwd=root,
                policy=policy,
                timeout_s=60,
            )
        ).stdout.strip()

        if commit and resolved.lower() != commit.lower():
            raise FetchError(
                f"pin mismatch: asked for {commit}, checkout resolved to {resolved}. "
                "Refusing to install a tree that is not the one that was reviewed."
            )

        # Resolved once and reused. On Windows a temporary directory is often handed
        # out in 8.3 short form (``RUNNER~1``) while rglob yields the long form
        # (``runneradmin``), and mixing the two makes relative_to raise ValueError on
        # paths that are plainly inside the checkout.
        checkout_root = checkout.resolve()
        skill_root = (checkout / subpath).resolve()
        if checkout_root != skill_root and checkout_root not in skill_root.parents:
            raise FetchError(f"subpath {subpath!r} escapes the cloned repository")
        if not skill_root.is_dir():
            raise FetchError(f"path {subpath!r} does not exist in {repository} at {resolved[:8]}")

        warnings: list[str] = []
        symlinks = [
            _relative_name(p, checkout_root) for p in skill_root.rglob("*") if p.is_symlink()
        ]
        if symlinks:
            # A symlink in a fetched tree can point anywhere once installed.
            for link in skill_root.rglob("*"):
                if link.is_symlink():
                    link.unlink()
            warnings.append(
                f"removed {len(symlinks)} symlink(s) from the fetched tree: {symlinks[:5]}"
            )

        _strip_git_metadata(checkout)
        files, total = _measure(skill_root)
        if files > MAX_TREE_FILES or total > MAX_TREE_BYTES:
            raise FetchError(
                f"source tree is too large to review ({files} files, {total} bytes); "
                "narrow the catalogue entry's path to the skill itself"
            )

        return FetchedSource(
            repository=repository,
            commit_sha=resolved,
            root=root,
            skill_root=skill_root,
            content_hash=content_hash(skill_root),
            file_count=files,
            total_bytes=total,
            pin_verified=bool(commit),
            warnings=warnings,
        )
    except BaseException:
        shutil.rmtree(root, ignore_errors=True)
        raise


async def resolve_head(repository: str, *, policy: PolicyEngine, timeout_s: int = 60) -> str:
    """Ask the remote for the current default-branch commit, without cloning."""
    url = _remote_url(repository)
    result = await _git(
        ["git", "ls-remote", url, "HEAD"],
        cwd=Path.cwd(),
        policy=policy,
        timeout_s=timeout_s,
    )
    line = result.stdout.strip().split("\n")[0] if result.stdout.strip() else ""
    sha = line.split("\t")[0].strip() if line else ""
    if len(sha) != 40:
        raise FetchError(f"could not resolve HEAD for {repository}")
    return sha
