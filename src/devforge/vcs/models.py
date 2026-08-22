"""The records the git-native flow produces.

Issue → Plan → Branch → Worktree → Implementation → Tests → Review → Security →
Commit → Pull Request. Each stage leaves something inspectable behind, because a
flow whose steps are invisible cannot be reviewed and cannot be resumed.

Nothing here talks to a network. A pull request is produced as an *artifact* - a
file with the summary, the changes, the test results, the security results and
the known limitations - and pushing it is a human action. DevForge can prepare a
proposal; deciding to publish it is not a decision a harness should make.
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, model_validator

from devforge.core.models import utcnow

#: Conventional Commit types. A closed vocabulary, because a commit history is
#: only greppable if the words in it are the same words every time.
COMMIT_TYPES = (
    "feat",
    "fix",
    "docs",
    "style",
    "refactor",
    "perf",
    "test",
    "build",
    "ci",
    "chore",
    "revert",
)

#: Subject-line budget. Long enough to say what changed, short enough that
#: `git log --oneline` stays readable.
MAX_SUBJECT = 72

_SLUG = re.compile(r"[^a-z0-9]+")


def slugify(text: str, *, limit: int = 40) -> str:
    """A branch-safe fragment: lowercase, hyphenated, bounded."""
    slug = _SLUG.sub("-", text.lower()).strip("-")
    if len(slug) <= limit:
        return slug or "task"
    return slug[:limit].rstrip("-") or "task"


class Issue(BaseModel):
    """The unit of work entering the flow.

    It may come from an issue tracker export, a file in the repository, or a
    sentence someone typed. What matters is that the work has an identifier and
    written acceptance criteria before a branch exists, so that the pull request
    at the other end can be checked against something.
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    body: str = ""
    #: Where this came from: a file path, a tracker id, "cli". Recorded, not
    #: trusted - issue text is untrusted input like any other external document.
    source: str = "cli"
    labels: list[str] = Field(default_factory=list)
    #: What "done" means, in the issue author's words.
    acceptance: list[str] = Field(default_factory=list)

    @property
    def kind(self) -> str:
        """The commit type this issue implies, from its labels."""
        for label in self.labels:
            if label in COMMIT_TYPES:
                return label
        lowered = f"{self.title} {' '.join(self.labels)}".lower()
        if any(word in lowered for word in ("bug", "fix", "broken", "regression")):
            return "fix"
        if any(word in lowered for word in ("doc", "readme")):
            return "docs"
        if "refactor" in lowered:
            return "refactor"
        if "test" in lowered:
            return "test"
        return "feat"


def branch_slug(issue: Issue) -> str:
    """The identifying part of a branch name.

    An issue filed from a sentence has an id derived from its own title, so the
    naive `<id>-<title>` produces `add-a-greeting-add-a-greeting`. When one slug
    already contains the other, the longer one is the whole name.
    """
    ident = slugify(issue.id, limit=24)
    title = slugify(issue.title)
    if title.startswith(ident) or ident.startswith(title):
        return title if len(title) >= len(ident) else ident
    return f"{ident}-{title}"


class BranchPlan(BaseModel):
    """What will be created, decided before anything is."""

    model_config = ConfigDict(extra="forbid")

    branch: str
    base: str
    worktree_path: str
    issue_id: str = ""
    task_id: str = ""

    @classmethod
    def for_issue(
        cls, issue: Issue, *, base: str, worktree_path: str, task_id: str = "", prefix: str = ""
    ) -> BranchPlan:
        kind = prefix or issue.kind
        return cls(
            branch=f"{kind}/{branch_slug(issue)}",
            base=base,
            worktree_path=worktree_path,
            issue_id=issue.id,
            task_id=task_id,
        )


class Worktree(BaseModel):
    """An isolated checkout. One autonomous task, one worktree, one branch."""

    model_config = ConfigDict(extra="forbid")

    path: str
    branch: str
    base: str = ""
    task_id: str = ""
    issue_id: str = ""
    created_at: datetime = Field(default_factory=utcnow)
    #: False once the worktree has been removed; the record survives removal so a
    #: report can still say where the work happened.
    live: bool = True


# --------------------------------------------------------------------------- guarding


class Effect(str, Enum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    REFUSE = "refuse"


class OperationVerdict(BaseModel):
    """What the git guard decided about one operation, and why.

    ``REFUSE`` is not "ask a human" - it is "this is not something DevForge does".
    ``REQUIRE_APPROVAL`` names the gate a person has to pass through.
    """

    model_config = ConfigDict(extra="forbid")

    effect: Effect
    reason: str
    gate: str = ""
    rule: str = ""

    @property
    def allowed(self) -> bool:
        return self.effect is Effect.ALLOW


class ContentFlagKind(str, Enum):
    SECRET = "secret"
    CREDENTIAL_FILE = "credential_file"
    BINARY = "binary"
    OVERSIZED = "oversized"
    UNRELATED = "unrelated"


class ContentFlag(BaseModel):
    """A reason not to commit a particular file.

    ``blocking`` separates "this must not be committed" from "a human should
    look". A secret is the former; a file outside the declared scope is the
    latter, because scope is a heuristic and a legitimate change often touches
    something the plan did not anticipate.
    """

    model_config = ConfigDict(extra="forbid")

    kind: ContentFlagKind
    path: str
    detail: str
    blocking: bool = True

    def describe(self) -> str:
        return f"[{self.kind.value}] {self.path}: {self.detail}"


class CommitPlan(BaseModel):
    """A commit before it exists: message, files, and what was found in them."""

    model_config = ConfigDict(extra="forbid")

    type: str = "chore"
    scope: str = ""
    subject: str = ""
    body: str = ""
    #: Repository-relative paths this commit will contain.
    files: list[str] = Field(default_factory=list)
    flags: list[ContentFlag] = Field(default_factory=list)
    issue_id: str = ""
    task_id: str = ""

    @model_validator(mode="after")
    def _check(self) -> CommitPlan:
        if self.type not in COMMIT_TYPES:
            raise ValueError(f"unknown commit type '{self.type}'; expected one of {COMMIT_TYPES}")
        return self

    @property
    def blocking_flags(self) -> list[ContentFlag]:
        return [flag for flag in self.flags if flag.blocking]

    @property
    def safe(self) -> bool:
        return not self.blocking_flags

    def header(self) -> str:
        scope = f"({self.scope})" if self.scope else ""
        subject = self.subject.strip().rstrip(".")
        header = f"{self.type}{scope}: {subject}"
        return header if len(header) <= MAX_SUBJECT else header[: MAX_SUBJECT - 1] + "…"

    def message(self) -> str:
        """The full message.

        No trailers naming the tool or the model are added. A commit records what
        changed and why; who typed it is a question about the repository's
        contributors, and inventing an answer in every commit is not this layer's
        call to make.
        """
        parts = [self.header()]
        if self.body.strip():
            parts.append(self.body.strip())
        if self.issue_id:
            parts.append(f"Refs: {self.issue_id}")
        return "\n\n".join(parts) + "\n"


class CommitRecord(BaseModel):
    """A commit that happened."""

    model_config = ConfigDict(extra="forbid")

    sha: str
    header: str
    files: list[str] = Field(default_factory=list)
    branch: str = ""
    created_at: datetime = Field(default_factory=utcnow)


class PullRequestArtifact(BaseModel):
    """The proposal, as a file.

    The five sections the brief names are fields rather than free text, so a
    missing one is detectable. ``limitations`` in particular: a pull request that
    lists none has usually not looked, and ``render`` says so rather than leaving
    the section blank.
    """

    model_config = ConfigDict(extra="forbid")

    title: str
    branch: str
    base: str
    issue_id: str = ""
    task_id: str = ""
    summary: str = ""
    changes: list[str] = Field(default_factory=list)
    commits: list[CommitRecord] = Field(default_factory=list)
    tests: list[str] = Field(default_factory=list)
    security: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utcnow)

    def missing_sections(self) -> list[str]:
        missing = []
        if not self.summary.strip():
            missing.append("summary")
        if not self.changes:
            missing.append("changes")
        if not self.tests:
            missing.append("tests")
        if not self.security:
            missing.append("security results")
        return missing

    def render(self) -> str:
        lines = [
            f"# {self.title}",
            "",
            f"`{self.branch}` → `{self.base}`"
            + (f" - closes {self.issue_id}" if self.issue_id else ""),
            "",
            "## Summary",
            "",
            self.summary.strip() or "_No summary was written._",
            "",
            "## Changes",
            "",
        ]
        lines += [f"- {change}" for change in self.changes] or ["_No files changed._"]

        if self.commits:
            lines += ["", "### Commits", ""]
            lines += [f"- `{commit.sha[:8]}` {commit.header}" for commit in self.commits]

        lines += ["", "## Tests", ""]
        lines += [f"- {entry}" for entry in self.tests] or [
            "_No test results were recorded, which is not the same as passing._"
        ]

        lines += ["", "## Security results", ""]
        lines += [f"- {entry}" for entry in self.security] or [
            "_No security check was recorded, which is not the same as clean._"
        ]

        lines += ["", "## Known limitations", ""]
        if self.limitations:
            lines += [f"- {entry}" for entry in self.limitations]
        else:
            lines.append(
                "_None recorded. A change with no stated limitations has usually not "
                "been asked for any; treat this as an unanswered question rather than "
                "a clean bill of health._"
            )

        missing = self.missing_sections()
        if missing:
            lines += [
                "",
                "---",
                "",
                "**Incomplete.** This artifact is missing: " + ", ".join(missing) + ".",
            ]
        return "\n".join(lines) + "\n"
