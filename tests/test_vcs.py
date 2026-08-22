"""Tests for git-native engineering.

The load-bearing tests here are the refusals. A guard that is merely documented
is a guard that stops working the first time someone refactors around it, so
every rule the brief names - no force push, no branch deletion, no history
rewriting, no touching the user's branch, no committing secrets - is asserted as
behaviour rather than described in a docstring.
"""

from __future__ import annotations

import asyncio
import subprocess
from pathlib import Path

import pytest

from devforge.core.errors import ConfigError, DevForgeError
from devforge.core.models import (
    Approval,
    ApprovalStatus,
    StepAttempt,
    StepRecord,
    Task,
    VerificationResult,
    VerificationStatus,
)
from devforge.observability.logging import null_logger
from devforge.policy.engine import PolicyEngine
from devforge.tools.base import ToolContext, ToolRegistry
from devforge.tools.vcs import VcsTool
from devforge.vcs.commit import apply_commit, changed_paths, infer_scope, plan_commit
from devforge.vcs.guard import check_operation, screen_paths
from devforge.vcs.issue import issue_from_text, load_issue
from devforge.vcs.models import (
    BranchPlan,
    CommitPlan,
    ContentFlagKind,
    Effect,
    Issue,
    PullRequestArtifact,
)
from devforge.vcs.pr import build_pull_request, write_pull_request
from devforge.vcs.worktree import (
    GitError,
    active_branch,
    create_worktree,
    is_linked_worktree,
    list_worktrees,
    remove_worktree,
    worktree_status,
)


def run_git(argv: list[str], cwd: Path) -> None:
    subprocess.run(["git", *argv], cwd=cwd, check=True, capture_output=True, text=True)


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    """A repository with one commit on `main`."""
    root = tmp_path / "repo"
    root.mkdir()
    run_git(["init", "--quiet", "-b", "main"], root)
    run_git(["config", "user.email", "test@devforge.invalid"], root)
    run_git(["config", "user.name", "devforge-test"], root)
    (root / "src").mkdir()
    (root / "src" / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    run_git(["add", "--all"], root)
    run_git(["-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "initial"], root)
    return root


def context_for(root: Path, task: Task | None = None) -> ToolContext:
    return ToolContext(
        workspace=root,
        policy=PolicyEngine.load(None, workspace=root),
        logger=null_logger(),
        task=task,
    )


# ------------------------------------------------------------------ operation guard


@pytest.mark.parametrize(
    "argv",
    [
        ["git", "push", "--force", "origin", "main"],
        ["git", "push", "-f"],
        ["git", "push", "--force-with-lease", "origin", "main"],
        ["git", "push", "--delete", "origin", "feature"],
        ["git", "branch", "-D", "feature"],
        ["git", "branch", "--delete", "feature"],
        ["git", "rebase", "-i", "HEAD~3"],
        ["git", "commit", "--amend", "-m", "x"],
        ["git", "reset", "--hard", "HEAD~1"],
        ["git", "filter-branch", "--all"],
        ["git", "reflog", "expire", "--all"],
        ["git", "update-ref", "-d", "refs/heads/main"],
    ],
)
def test_destructive_operations_are_refused(argv: list[str]) -> None:
    verdict = check_operation(argv)

    assert verdict.effect is Effect.REFUSE, f"{' '.join(argv)} was not refused"
    assert verdict.gate, "a refusal must name the gate that could override it"


def test_a_force_push_runs_only_with_an_explicit_approval() -> None:
    """The approval is per operation class, not a general "git is fine"."""
    argv = ["git", "push", "--force", "origin", "main"]

    assert check_operation(argv, approvals={"history-rewrite"}).effect is Effect.REFUSE
    assert check_operation(argv, approvals={"force-push"}).effect is Effect.ALLOW


def test_pushing_at_all_needs_a_person() -> None:
    verdict = check_operation(["git", "push", "origin", "feature"])

    assert verdict.effect is Effect.REQUIRE_APPROVAL
    assert verdict.gate == "git_push"


def test_checking_out_the_users_branch_is_refused() -> None:
    verdict = check_operation(["git", "checkout", "main"], active_branch="main")

    assert verdict.effect is Effect.REFUSE
    assert "not DevForge's to move" in verdict.reason


def test_checking_out_another_branch_is_fine() -> None:
    assert check_operation(["git", "checkout", "feature"], active_branch="main").allowed


def test_ordinary_operations_are_allowed() -> None:
    for argv in (["git", "status"], ["git", "diff"], ["git", "add", "."], ["git", "log"]):
        assert check_operation(argv).allowed, argv


def test_the_guard_only_judges_git() -> None:
    """A guard that answers about commands it does not understand is worse than
    one that refuses to."""
    assert check_operation(["rm", "-rf", "/"]).effect is Effect.REFUSE


# ----------------------------------------------------------------------- worktrees


def test_a_worktree_leaves_the_users_branch_alone(repo: Path) -> None:
    before = (repo / "src" / "app.py").read_text(encoding="utf-8")

    worktree = create_worktree(repo, branch="feat/thing", base="main")

    assert active_branch(repo) == "main", "the user's branch must not move"
    assert (repo / "src" / "app.py").read_text(encoding="utf-8") == before
    assert Path(worktree.path).is_dir()
    assert (Path(worktree.path) / "src" / "app.py").is_file()


def test_a_worktree_refuses_the_checked_out_branch(repo: Path) -> None:
    with pytest.raises(GitError, match="branch you are standing on"):
        create_worktree(repo, branch="main", base="main")

    assert active_branch(repo) == "main"


def test_a_branch_cannot_be_checked_out_twice(repo: Path) -> None:
    create_worktree(repo, branch="feat/thing", base="main")

    with pytest.raises(GitError, match="already checked out"):
        create_worktree(repo, branch="feat/thing", base="main")


def test_worktrees_live_outside_the_source_tree(repo: Path) -> None:
    worktree = create_worktree(repo, branch="feat/thing", base="main")

    assert ".devforge" in Path(worktree.path).parts


def test_a_nested_branch_name_stays_one_directory_deep(repo: Path) -> None:
    """Branch names contain slashes, and a slash is a path separator."""
    worktree = create_worktree(repo, branch="feat/area/thing", base="main")

    assert Path(worktree.path).parent == repo / ".devforge" / "worktrees"
    assert Path(worktree.path).name == "feat-area-thing"


def test_a_traversing_branch_name_creates_nothing(repo: Path) -> None:
    with pytest.raises(GitError):
        create_worktree(repo, branch="feat/../../escaped", base="main")

    assert not (repo.parent / "escaped").exists()
    assert len(list_worktrees(repo)) == 1


def test_removing_a_dirty_worktree_keeps_it(repo: Path) -> None:
    """Losing an agent's work is recoverable only if somebody notices."""
    worktree = create_worktree(repo, branch="feat/thing", base="main")
    (Path(worktree.path) / "new.py").write_text("work in progress\n", encoding="utf-8")

    dirty = remove_worktree(repo, Path(worktree.path))

    assert dirty, "the caller must be told what was in it"
    assert Path(worktree.path).is_dir()


def test_a_clean_worktree_is_removed(repo: Path) -> None:
    worktree = create_worktree(repo, branch="feat/thing", base="main")

    assert remove_worktree(repo, Path(worktree.path)) == []
    assert not Path(worktree.path).exists()
    assert len(list_worktrees(repo)) == 1


def test_the_main_checkout_is_not_a_linked_worktree(repo: Path) -> None:
    worktree = create_worktree(repo, branch="feat/thing", base="main")

    assert not is_linked_worktree(repo)
    assert is_linked_worktree(Path(worktree.path))


# ------------------------------------------------------------------- content guard


def test_a_credential_file_blocks_the_commit_and_is_never_opened(repo: Path) -> None:
    (repo / ".env").write_text("API_TOKEN=sk-live-not-a-real-key-000\n", encoding="utf-8")

    flags = screen_paths(repo, [".env"])

    assert [flag.kind for flag in flags] == [ContentFlagKind.CREDENTIAL_FILE]
    assert flags[0].blocking
    assert "sk-live" not in flags[0].detail, "the guard must not republish the value"


def test_an_example_env_file_is_not_a_credential(repo: Path) -> None:
    """A guard that blocks documentation gets bypassed on every commit."""
    (repo / ".env.example").write_text("API_TOKEN=replace-me\n", encoding="utf-8")

    assert screen_paths(repo, [".env.example"]) == []


def test_a_credential_shaped_literal_blocks_the_commit(repo: Path) -> None:
    (repo / "config.py").write_text(
        'AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"\n', encoding="utf-8"
    )

    flags = screen_paths(repo, ["config.py"])

    assert any(flag.kind is ContentFlagKind.SECRET for flag in flags)
    assert all("wJalrXUtnFEMI" not in flag.detail for flag in flags)


def test_an_unexplained_binary_blocks_the_commit(repo: Path) -> None:
    (repo / "payload.exe").write_bytes(b"MZ\x00\x90binary")

    flags = screen_paths(repo, ["payload.exe"])

    assert [flag.kind for flag in flags] == [ContentFlagKind.BINARY]
    assert flags[0].blocking


def test_an_image_is_not_a_suspicious_binary(repo: Path) -> None:
    (repo / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00")

    assert screen_paths(repo, ["logo.png"]) == []


def test_a_file_outside_the_scope_is_flagged_but_does_not_block(repo: Path) -> None:
    """Scope is a heuristic; a guard that blocks on it gets switched off."""
    (repo / "unrelated.py").write_text("x = 1\n", encoding="utf-8")

    flags = screen_paths(repo, ["unrelated.py"], scope=["src/*"])

    assert [flag.kind for flag in flags] == [ContentFlagKind.UNRELATED]
    assert not flags[0].blocking


def test_a_deleted_file_is_not_screened(repo: Path) -> None:
    """Refusing to record a deletion would make removing a leaked file impossible."""
    assert screen_paths(repo, ["never-existed.py"]) == []


# ---------------------------------------------------------------------- commits


def test_a_commit_plan_is_conventional(repo: Path) -> None:
    (repo / "src" / "app.py").write_text("VALUE = 2\n", encoding="utf-8")

    plan = plan_commit(repo, subject="raise the value", commit_type="fix")

    assert plan.header() == "fix: raise the value"
    assert plan.message().endswith("\n")


def test_a_commit_message_carries_no_tool_attribution(repo: Path) -> None:
    plan = CommitPlan(type="feat", subject="do the thing", body="because")

    message = plan.message().lower()

    for trailer in ("co-authored-by", "generated with", "assistant", "agent:"):
        assert trailer not in message


def test_an_over_long_subject_is_trimmed() -> None:
    plan = CommitPlan(type="feat", subject="x" * 200)

    assert len(plan.header()) <= 72


def test_an_unknown_commit_type_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown commit type"):
        CommitPlan(type="magic", subject="x")


def test_a_scope_is_inferred_only_when_it_is_unambiguous() -> None:
    assert infer_scope(["src/devforge/vcs/commit.py", "src/devforge/vcs/pr.py"]) == "vcs"
    assert infer_scope(["src/devforge/vcs/x.py", "docs/other.md"]) == ""
    assert infer_scope(["README.md"]) == ""


def test_harness_state_is_not_part_of_a_change(repo: Path) -> None:
    (repo / ".devforge").mkdir()
    (repo / ".devforge" / "state.json").write_text("{}", encoding="utf-8")
    (repo / "src" / "app.py").write_text("VALUE = 2\n", encoding="utf-8")

    assert changed_paths(repo) == ["src/app.py"]


def test_a_flagged_commit_is_refused(repo: Path) -> None:
    (repo / ".env").write_text("TOKEN=abc123def456\n", encoding="utf-8")
    plan = plan_commit(repo, subject="add config", commit_type="chore")

    assert not plan.safe
    with pytest.raises(GitError, match="refusing to commit"):
        apply_commit(repo, plan)


def test_a_clean_commit_is_recorded(repo: Path) -> None:
    (repo / "src" / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
    plan = plan_commit(repo, subject="raise the value", commit_type="fix")

    record = apply_commit(repo, plan)

    assert record.sha
    assert record.files == ["src/app.py"]
    assert changed_paths(repo) == []


# ------------------------------------------------------------------------ issues


def test_an_issue_from_a_sentence_gets_an_id_and_a_title() -> None:
    issue = issue_from_text("Add a greeting helper\nUsers need hello().")

    assert issue.title == "Add a greeting helper"
    assert issue.body == "Users need hello()."
    assert issue.id


def test_acceptance_criteria_are_read_from_checkboxes() -> None:
    issue = issue_from_text("Title\n- [ ] returns a string\n- [x] handles empty input")

    assert issue.acceptance == ["returns a string", "handles empty input"]


def test_an_empty_issue_is_an_error() -> None:
    with pytest.raises(ConfigError, match="at least a title"):
        issue_from_text("   ")


def test_an_issue_loads_from_markdown_front_matter(tmp_path: Path) -> None:
    path = tmp_path / "ISSUE-12.md"
    path.write_text(
        "---\nid: ISSUE-12\ntitle: Fix the parser\nlabels: [fix]\n---\n\nIt crashes.\n",
        encoding="utf-8",
    )

    issue = load_issue(path)

    assert issue.id == "ISSUE-12"
    assert issue.kind == "fix"
    assert issue.source == str(path)


def test_an_issue_loads_from_yaml(tmp_path: Path) -> None:
    path = tmp_path / "issue.yaml"
    path.write_text("title: Add docs\nlabels: [docs]\n", encoding="utf-8")

    assert load_issue(path).kind == "docs"


def test_a_broken_issue_file_is_an_error(tmp_path: Path) -> None:
    path = tmp_path / "issue.yaml"
    path.write_text("- not\n- a mapping\n", encoding="utf-8")

    with pytest.raises(ConfigError, match="expected a mapping"):
        load_issue(path)


def test_a_branch_name_does_not_repeat_itself() -> None:
    """An issue filed from a sentence derives its id from its own title."""
    issue = issue_from_text("Add a greeting helper")

    plan = BranchPlan.for_issue(issue, base="main", worktree_path="/tmp/x")

    assert plan.branch == "feat/add-a-greeting-helper"


def test_a_bug_issue_becomes_a_fix_branch() -> None:
    issue = Issue(id="ISSUE-9", title="Login is broken")

    assert BranchPlan.for_issue(issue, base="main", worktree_path="/x").branch.startswith("fix/")


# -------------------------------------------------------------- pull request artifact


def test_the_artifact_has_the_five_required_sections(repo: Path) -> None:
    artifact = PullRequestArtifact(
        title="Add a greeting",
        branch="feat/greeting",
        base="main",
        summary="Adds hello().",
        changes=["A\tsrc/app.py"],
        tests=["`tests` (tests, required): **passed**"],
        security=["`scan`: nothing matched"],
        limitations=["Only English."],
    )

    text = artifact.render()

    for heading in ("## Summary", "## Changes", "## Tests", "## Security results",
                    "## Known limitations"):
        assert heading in text
    assert artifact.missing_sections() == []


def test_a_missing_section_is_stated_not_left_blank() -> None:
    artifact = PullRequestArtifact(title="x", branch="b", base="main")

    text = artifact.render()

    assert "**Incomplete.**" in text
    assert "not the same as passing" in text
    assert "not the same as clean" in text


def test_no_stated_limitations_is_an_unanswered_question() -> None:
    artifact = PullRequestArtifact(
        title="x", branch="b", base="main", summary="s", changes=["c"], tests=["t"], security=["s"]
    )

    assert "unanswered question" in artifact.render()


def test_the_change_list_comes_from_git_not_from_a_claim(repo: Path) -> None:
    run_git(["checkout", "-q", "-b", "feat/thing"], repo)
    (repo / "src" / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
    apply_commit(repo, plan_commit(repo, subject="raise the value", commit_type="fix"))

    artifact = build_pull_request(repo, branch="feat/thing", base="main")

    assert any("src/app.py" in change for change in artifact.changes)
    assert artifact.commits and artifact.commits[0].header.startswith("fix")


def test_verification_results_land_in_the_right_section(repo: Path) -> None:
    task = Task(project_id="p", description="d", workflow="git-feature")
    task.verification_results = [
        VerificationResult(verifier="tests", kind="tests", status=VerificationStatus.PASSED),
        VerificationResult(
            verifier="patch-guard", kind="patch-guard", status=VerificationStatus.PASSED
        ),
    ]

    artifact = build_pull_request(repo, branch="feat/x", base="main", task=task)

    assert any("tests" in line for line in artifact.tests)
    assert any("patch-guard" in line for line in artifact.security)


def test_limitations_are_derived_from_what_the_run_actually_did(repo: Path) -> None:
    """A reviewer wants these and an agent does not reliably volunteer them."""
    task = Task(project_id="p", description="d", workflow="git-feature")
    task.verification_results = [
        VerificationResult(
            verifier="typecheck", kind="typecheck", status=VerificationStatus.UNAVAILABLE
        ),
        VerificationResult(
            verifier="lint", kind="lint", status=VerificationStatus.FAILED, required=False
        ),
    ]
    task.steps = [
        StepRecord(
            step_id="implementation",
            attempts=[StepAttempt(attempt=1), StepAttempt(attempt=2)],
        )
    ]
    task.approvals = [
        Approval(gate="final_review", step_id="approve", status=ApprovalStatus.PENDING)
    ]

    artifact = build_pull_request(repo, branch="feat/x", base="main", task=task)
    text = " ".join(artifact.limitations)

    assert "typecheck" in text and "unverified" in text
    assert "lint" in text and "advisory" in text
    assert "2 attempts" in text
    assert "final_review" in text


def test_the_artifact_is_written_as_markdown_and_json(repo: Path, tmp_path: Path) -> None:
    artifact = PullRequestArtifact(title="x", branch="feat/thing", base="main")

    path = write_pull_request(artifact, tmp_path / "out")

    assert path.name == "PR-feat-thing.md"
    assert (tmp_path / "out" / "PR-feat-thing.json").is_file()


# --------------------------------------------------------------------------- tool


def test_the_tool_is_registered_and_cannot_push() -> None:
    tool = ToolRegistry.default().get("vcs")

    assert isinstance(tool, VcsTool)
    for forbidden in ("push", "force_push", "delete", "rebase", "amend", "reset"):
        assert forbidden not in tool.actions


def test_an_agent_cannot_commit_to_the_main_checkout(repo: Path) -> None:
    """The brief's rule, enforced: not the user's active branch."""
    (repo / "src" / "app.py").write_text("VALUE = 2\n", encoding="utf-8")

    result = asyncio.run(
        VcsTool().invoke("commit", {"subject": "change it"}, context_for(repo))
    )

    assert not result.ok
    assert "not a DevForge worktree" in result.error
    assert changed_paths(repo) == ["src/app.py"], "the change must still be uncommitted"


def test_an_agent_commits_inside_its_worktree(repo: Path) -> None:
    worktree = Path(create_worktree(repo, branch="feat/thing", base="main").path)
    (worktree / "src" / "app.py").write_text("VALUE = 2\n", encoding="utf-8")

    result = asyncio.run(
        VcsTool().invoke(
            "commit", {"subject": "raise the value", "type": "fix"}, context_for(worktree)
        )
    )

    assert result.ok, result.error
    assert worktree_status(worktree) == []
    assert active_branch(repo) == "main"


def test_the_tool_refuses_to_commit_a_secret(repo: Path) -> None:
    worktree = Path(create_worktree(repo, branch="feat/thing", base="main").path)
    (worktree / ".env").write_text("TOKEN=abc123def456ghi\n", encoding="utf-8")

    result = asyncio.run(
        VcsTool().invoke("commit", {"subject": "add config"}, context_for(worktree))
    )

    assert not result.ok
    assert "refusing to commit" in result.error
    # Not an approval gate: offering to approve a secret teaches people to do it.
    assert result.status.value == "error"


def test_planning_a_commit_changes_nothing(repo: Path) -> None:
    (repo / "src" / "app.py").write_text("VALUE = 2\n", encoding="utf-8")

    result = asyncio.run(
        VcsTool().invoke("plan_commit", {"subject": "raise it"}, context_for(repo))
    )

    assert result.ok
    assert changed_paths(repo) == ["src/app.py"]


def test_the_tool_reports_an_unknown_action(repo: Path) -> None:
    result = asyncio.run(VcsTool().invoke("push", {}, context_for(repo)))

    assert not result.ok
    assert "unknown action" in result.error


# ------------------------------------------------------------------------ workflow


def test_the_git_feature_workflow_covers_the_whole_flow() -> None:
    from devforge.core.workflow.loader import WorkflowLoader

    spec = WorkflowLoader.for_project(None).load("git-feature")
    ids = [step.id for step in spec.steps]

    for stage in ("intake", "plan", "isolate", "implementation", "tests", "review",
                  "security", "commit-screen", "pull-request"):
        assert stage in ids, f"the flow is missing '{stage}'"
    assert ids.index("isolate") < ids.index("implementation")
    assert ids.index("security") < ids.index("commit-screen"), (
        "screening after the commit would be a review, not a guard"
    )
    assert ids.index("commit-screen") < ids.index("pull-request")


def test_the_workflow_gates_the_plan_and_the_publication() -> None:
    from devforge.core.workflow.loader import WorkflowLoader

    spec = WorkflowLoader.for_project(None).load("git-feature")
    gates = [step.gate for step in spec.steps if step.gate]

    assert "architecture" in gates
    assert "final_review" in gates


def test_the_git_gates_exist_and_are_blocking() -> None:
    from devforge.policy.engine import resolve_policy_file
    from devforge.policy.models import ApprovalPolicy

    policy = ApprovalPolicy.load(resolve_policy_file("approvals.yaml", None))

    for gate in ("git_push", "force_push", "branch_delete", "history_rewrite"):
        assert policy.gate(gate).blocking, f"gate '{gate}' must block"
        assert not policy.gate(gate).auto_approve


def test_the_shell_policy_still_denies_a_force_push() -> None:
    """Two layers, not one: the vcs guard and the command allowlist."""
    engine = PolicyEngine.load(None, workspace=Path.cwd())

    assert not engine.check_command(["git", "push", "--force", "origin", "main"]).allowed


def test_devforge_error_is_the_base_of_git_error() -> None:
    """So a caller catching DevForgeError does not miss a git failure."""
    assert issubclass(GitError, DevForgeError)
