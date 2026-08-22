"""What DevForge will not do to a repository, and what it will not put in a commit.

Two guards, because they answer different questions.

The **operation guard** reads an argv and decides whether the operation may run
at all. It is deliberately stricter than the shell policy: the policy protects
against a dangerous *command*, this protects against a dangerous *outcome*. Force
push, branch deletion and history rewriting are refused outright unless a human
approval exists for that operation, because they are the operations whose damage
cannot be undone from inside the tool that caused it.

The **content guard** reads what is about to be committed. A commit is the moment
a mistake becomes permanent and shareable, so it is the right place to look for
credentials, machine-generated key material, binaries nobody asked for, and
changes outside what the task was about.

Neither guard is a substitute for review. Both catch what they have patterns for.
"""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path

from devforge.observability.redaction import contains_secret
from devforge.security.scan import (
    CREDENTIAL_FILE_EXCEPTIONS,
    CREDENTIAL_FILES,
    scan_text,
)
from devforge.vcs.models import ContentFlag, ContentFlagKind, Effect, OperationVerdict

#: Operations that rewrite or destroy history. Refused unless a human approval
#: for this specific operation has been recorded. The names are matched against
#: the joined argv, so `git push --force-with-lease` is caught as surely as
#: `git push -f` - a lease makes a force push safer for other people, not
#: reversible for this one.
HISTORY_OPERATIONS: tuple[tuple[str, str, str], ...] = (
    ("force-push", "push --force", "rewrites a branch other people may have pulled"),
    ("force-push", "push -f", "rewrites a branch other people may have pulled"),
    ("force-push", "push --force-with-lease", "still rewrites the remote branch"),
    ("branch-delete", "push --delete", "deletes a branch on the remote"),
    ("branch-delete", "push :", "deletes a branch on the remote by refspec"),
    ("branch-delete", "branch -d", "deletes a local branch"),
    ("branch-delete", "branch -D", "deletes a local branch, merged or not"),
    ("branch-delete", "branch --delete", "deletes a local branch"),
    ("history-rewrite", "rebase", "replaces commits with new ones"),
    ("history-rewrite", "commit --amend", "replaces the previous commit"),
    ("history-rewrite", "reset --hard", "discards commits and working-tree changes"),
    ("history-rewrite", "filter-branch", "rewrites every commit it touches"),
    ("history-rewrite", "filter-repo", "rewrites every commit it touches"),
    ("history-rewrite", "reflog delete", "removes the record that makes recovery possible"),
    ("history-rewrite", "reflog expire", "removes the record that makes recovery possible"),
    ("history-rewrite", "update-ref -d", "deletes a ref directly"),
    ("history-rewrite", "gc --prune=now", "discards unreachable objects immediately"),
    ("history-rewrite", "checkout --orphan", "starts a branch with no history"),
)

#: The approval gate each class of operation needs. Distinct gates on purpose:
#: approving one deletion is not approving a rewrite.
GATES = {
    "force-push": "force_push",
    "branch-delete": "branch_delete",
    "history-rewrite": "history_rewrite",
}

#: Operations that change what the user is standing on. Refused when they target
#: the checked-out branch; harmless in a worktree of our own.
CHECKOUT_OPERATIONS = ("checkout", "switch", "restore")

#: Extensions that are binaries someone deliberately committed, not build output.
#: Everything else binary is flagged, because "why is this here" is the right
#: question to ask about a compiled object appearing in a source change.
EXPECTED_BINARY_SUFFIXES = frozenset(
    {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".pdf", ".woff", ".woff2", ".ttf"}
)

#: Suffixes that are executable or loadable code in binary form.
SUSPICIOUS_BINARY_SUFFIXES = frozenset(
    {".exe", ".dll", ".so", ".dylib", ".bin", ".jar", ".class", ".pyc", ".pyd", ".msi", ".apk"}
)

#: A file this large in a source commit is worth a human glance whatever it is.
LARGE_FILE_BYTES = 2_000_000
#: How much of a file to read when deciding whether it is text.
SNIFF_BYTES = 8_000

_WHITESPACE = re.compile(r"\s+")


# --------------------------------------------------------------------- operations


def check_operation(
    argv: list[str],
    *,
    active_branch: str = "",
    approvals: set[str] | None = None,
) -> OperationVerdict:
    """Decide whether a git operation may run.

    ``approvals`` holds the operation classes a human has approved for this run -
    ``{"force-push"}``, say. Absent one, a matching operation is refused rather
    than queued, because these are not operations that become safe by waiting.
    """
    if not argv:
        return OperationVerdict(effect=Effect.REFUSE, reason="empty command")
    if Path(argv[0]).stem != "git":
        return OperationVerdict(
            effect=Effect.REFUSE,
            reason=f"this guard only judges git commands, not '{argv[0]}'",
        )

    granted = approvals or set()
    joined = _WHITESPACE.sub(" ", " ".join(argv[1:])).strip()

    for kind, pattern, why in HISTORY_OPERATIONS:
        if pattern not in joined:
            continue
        if kind in granted:
            return OperationVerdict(
                effect=Effect.ALLOW,
                reason=f"{kind} was approved for this run",
                gate=GATES[kind],
                rule=pattern,
            )
        return OperationVerdict(
            effect=Effect.REFUSE,
            reason=(
                f"'{pattern}' {why}. DevForge refuses it without an explicit human "
                f"approval for '{kind}'."
            ),
            gate=GATES[kind],
            rule=pattern,
        )

    if active_branch and _targets_branch(argv, active_branch):
        return OperationVerdict(
            effect=Effect.REFUSE,
            reason=(
                f"'{argv[1]}' targets '{active_branch}', which is checked out. "
                "Autonomous work belongs in its own worktree; the branch you are "
                "standing on is not DevForge's to move."
            ),
            gate="active_branch",
            rule=argv[1],
        )

    if "push" in argv[1:2]:
        return OperationVerdict(
            effect=Effect.REQUIRE_APPROVAL,
            reason="pushing publishes work to a remote, which is a person's decision",
            gate="git_push",
            rule="push",
        )

    return OperationVerdict(effect=Effect.ALLOW, reason="no guarded pattern matched")


def _targets_branch(argv: list[str], branch: str) -> bool:
    """Whether a checkout-shaped command names the branch that is checked out."""
    if len(argv) < 2 or argv[1] not in CHECKOUT_OPERATIONS:
        return False
    return branch in argv[2:]


# ------------------------------------------------------------------------ content


def screen_paths(
    root: Path,
    paths: list[str],
    *,
    scope: list[str] | None = None,
) -> list[ContentFlag]:
    """Look at what is about to be committed.

    ``scope`` is what the task said it would touch, as glob patterns. Files
    outside it are flagged non-blocking: scope is a heuristic, and real work
    routinely touches something the plan did not anticipate. Everything else here
    blocks, because a secret in a commit is not a judgement call.
    """
    flags: list[ContentFlag] = []
    for relative in paths:
        path = (root / relative).resolve()
        flags.extend(_screen_one(path, relative))
        if scope and not _in_scope(relative, scope):
            flags.append(
                ContentFlag(
                    kind=ContentFlagKind.UNRELATED,
                    path=relative,
                    detail=(
                        "outside the declared scope "
                        f"({', '.join(scope)}); commit it separately if it is "
                        "unrelated work"
                    ),
                    blocking=False,
                )
            )
    return flags


def _screen_one(path: Path, relative: str) -> list[ContentFlag]:
    if _is_credential_file(relative):
        # Deliberately not opened. Confirming what is already known would pull the
        # credential into memory, into a report, and possibly into a prompt.
        return [
            ContentFlag(
                kind=ContentFlagKind.CREDENTIAL_FILE,
                path=relative,
                detail="credential material by name; not read, and not committable",
            )
        ]

    if not path.is_file():
        # A deletion. There is nothing to screen, and refusing to record one would
        # make removing a leaked file impossible.
        return []

    flags: list[ContentFlag] = []
    size = path.stat().st_size
    raw = path.read_bytes()[:SNIFF_BYTES]

    if b"\x00" in raw or path.suffix.lower() in SUSPICIOUS_BINARY_SUFFIXES:
        if path.suffix.lower() not in EXPECTED_BINARY_SUFFIXES:
            flags.append(
                ContentFlag(
                    kind=ContentFlagKind.BINARY,
                    path=relative,
                    detail=(
                        f"binary content ({size:,} bytes). Compiled or opaque files do "
                        "not belong in a source change unless someone says why"
                    ),
                )
            )
        return flags

    if size > LARGE_FILE_BYTES:
        flags.append(
            ContentFlag(
                kind=ContentFlagKind.OVERSIZED,
                path=relative,
                detail=f"{size:,} bytes; large enough that a human should look first",
                blocking=False,
            )
        )

    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return flags

    findings = [f for f in scan_text(text, relative) if f.id.startswith("SEC-SECRET")]
    for finding in findings:
        flags.append(
            ContentFlag(
                kind=ContentFlagKind.SECRET,
                path=relative,
                detail=f"{finding.id} at {finding.location}: {finding.title}",
            )
        )
    # The name-based fallback is deliberately skipped for example and template
    # files. It is aggressive by design - `API_TOKEN=` in a log almost certainly
    # precedes a real one - and `.env.example` exists precisely to show the shape
    # without the value. Blocking documentation is how a guard gets bypassed on
    # every commit.
    if not findings and not CREDENTIAL_FILE_EXCEPTIONS.search(relative) and contains_secret(text):
        flags.append(
            ContentFlag(
                kind=ContentFlagKind.SECRET,
                path=relative,
                detail="credential-shaped content; the value is not repeated here",
            )
        )
    return flags


def _is_credential_file(relative: str) -> bool:
    """Credential material by name.

    The scanner's own exception list applies: `.env.example` and `key.sample` are
    documentation, and blocking them would teach people to pass `--force` on
    every commit, which is how a guard stops guarding anything.
    """
    name = relative.replace("\\", "/")
    if CREDENTIAL_FILE_EXCEPTIONS.search(name):
        return False
    return any(pattern.search(name) for pattern in CREDENTIAL_FILES)


def _in_scope(relative: str, scope: list[str]) -> bool:
    name = relative.replace("\\", "/")
    return any(fnmatch.fnmatch(name, pattern) for pattern in scope)
