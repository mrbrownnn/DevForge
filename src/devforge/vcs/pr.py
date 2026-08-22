"""The pull request, as an artifact.

DevForge does not open pull requests. It writes the proposal to a file - summary,
changes, tests, security results, known limitations - and a person pushes the
branch and opens the request.

That boundary is deliberate. Opening a pull request notifies people, starts CI,
and in many repositories begins an auto-merge path. Those are consequences that
reach beyond the machine, and a harness that produces them without a human in the
loop has made a decision that was not its to make. Preparing the proposal is the
part that benefits from automation; publishing it is the part that benefits from
a person reading it first.

Two sections are filled from *evidence* rather than from what an agent says it
did: the change list comes from git, and the test and security lines come from
recorded verification results. An agent's own account of its work is exactly the
thing a reviewer cannot check.
"""

from __future__ import annotations

from pathlib import Path

from devforge.core.models import Task, VerificationResult
from devforge.vcs.commit import commits_since
from devforge.vcs.guard import screen_paths
from devforge.vcs.models import Issue, PullRequestArtifact
from devforge.vcs.worktree import git

#: Verifier kinds whose results belong in the security section rather than tests.
SECURITY_KINDS = frozenset({"security", "patch-guard", "secret-scan", "sast"})


def changed_files(root: Path, base: str) -> list[str]:
    """Files this branch changes relative to its base, read from git."""
    result = git(["diff", "--name-status", f"{base}...HEAD"], cwd=root)
    if not result.ok:
        return []
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def build_pull_request(
    root: Path,
    *,
    branch: str,
    base: str,
    issue: Issue | None = None,
    task: Task | None = None,
    summary: str = "",
    limitations: list[str] | None = None,
) -> PullRequestArtifact:
    """Assemble the artifact from the repository and the task record."""
    files = changed_files(root, base)
    commits = commits_since(root, base)

    tests: list[str] = []
    security: list[str] = []
    if task is not None:
        for result in task.verification_results:
            line = _verification_line(result)
            (security if result.kind in SECURITY_KINDS else tests).append(line)

    flags = screen_paths(root, [line.split("\t")[-1] for line in files])
    security += [f"commit screening: {flag.describe()}" for flag in flags]

    stated = list(limitations or [])
    if task is not None:
        stated += _limitations_from(task)

    return PullRequestArtifact(
        title=_title(issue, branch),
        branch=branch,
        base=base,
        issue_id=issue.id if issue else "",
        task_id=task.task_id if task else "",
        summary=summary or _summary(issue, task),
        changes=files,
        commits=commits,
        tests=_deduplicate(tests),
        security=_deduplicate(security),
        limitations=_deduplicate(stated),
    )


def write_pull_request(artifact: PullRequestArtifact, destination: Path) -> Path:
    """Write the Markdown next to the JSON, both under the given directory."""
    destination.mkdir(parents=True, exist_ok=True)
    stem = artifact.branch.replace("/", "-") or "pull-request"
    markdown = destination / f"PR-{stem}.md"
    markdown.write_text(artifact.render(), encoding="utf-8")
    (destination / f"PR-{stem}.json").write_text(
        artifact.model_dump_json(indent=1), encoding="utf-8"
    )
    return markdown


# --------------------------------------------------------------------------- helpers


def _title(issue: Issue | None, branch: str) -> str:
    if issue is not None:
        return issue.title
    return branch.split("/", 1)[-1].replace("-", " ").capitalize()


def _summary(issue: Issue | None, task: Task | None) -> str:
    parts = []
    if issue is not None:
        parts.append(issue.body.strip() or issue.title.strip())
        if issue.acceptance:
            parts.append(
                "Acceptance criteria:\n"
                + "\n".join(f"- {item}" for item in issue.acceptance)
            )
    elif task is not None:
        parts.append(task.description.strip())
    return "\n\n".join(part for part in parts if part)


def _verification_line(result: VerificationResult) -> str:
    status = result.status.value
    detail = result.summary.strip() or f"exit {result.exit_code}"
    required = "required" if result.required else "advisory"
    return f"`{result.verifier}` ({result.kind}, {required}): **{status}** - {detail}"


def _limitations_from(task: Task) -> list[str]:
    """Limitations the run itself demonstrates.

    A failed optional verifier, a step that used all its attempts, an approval
    still pending: each is something a reviewer would want to know and none of
    them is something an agent reliably volunteers.
    """
    limitations: list[str] = []

    unavailable = {
        result.verifier
        for result in task.verification_results
        if result.status.value == "unavailable"
    }
    for verifier in sorted(unavailable):
        limitations.append(
            f"`{verifier}` could not run in this environment, so that check is "
            "unverified rather than passing"
        )

    advisory_failures = {
        result.verifier
        for result in task.verification_results
        if not result.required and not result.status.ok
    }
    for verifier in sorted(advisory_failures):
        limitations.append(f"`{verifier}` failed but is advisory, so it did not stop the run")

    for step in task.steps:
        if step.attempt_count > 1:
            limitations.append(
                f"step `{step.step_id}` needed {step.attempt_count} attempts; the "
                "earlier ones are in the run record"
            )

    pending = [approval.gate for approval in task.approvals if approval.status.value == "pending"]
    for gate in pending:
        limitations.append(f"approval gate `{gate}` is still pending")

    return limitations


def _deduplicate(items: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            ordered.append(item)
    return ordered
