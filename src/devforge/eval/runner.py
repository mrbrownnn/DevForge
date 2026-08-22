"""Running an evaluation: prepare, attempt, grade.

Each case gets its own temporary directory and its own git repository. The
repository is not ceremony - grading inspects a *diff*, and a diff needs a
baseline commit, without which a deletion is invisible and any patch passes.

The order of operations is the part worth reading:

1. materialise the case and commit it;
2. run the **guards** - checks that must already pass. One that fails here makes
   the case *invalid*, not failed: the benchmark is broken, and blaming the
   configuration for it would corrupt every number in the report;
3. let the driver attempt the case;
4. review the diff with the patch guard;
5. run the checks, then the guards again.

Grading then applies in a fixed order: a suspicious patch is rejected *before*
success is considered. Evaluating success first would let a configuration that
deleted the assertions record a win and never look at what it changed.
"""

from __future__ import annotations

import asyncio
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from devforge import __version__
from devforge.core.models import new_id
from devforge.debug.models import PatchVerdict
from devforge.debug.patch_guard import review_patch
from devforge.eval.drivers import Driver, DriverOutcome, build_driver
from devforge.eval.metrics import compute_metrics
from devforge.eval.models import (
    MAX_CHECK_EXCERPT,
    CaseOutcome,
    CaseResult,
    Check,
    CheckOutcome,
    EvalCase,
    EvalConfig,
    EvalReport,
)
from devforge.observability.logging import RunLogger, null_logger
from devforge.policy.engine import PolicyEngine
from devforge.tools.process import run_process

#: Written into every case workspace before the baseline commit. Harness state
#: and bytecode are not part of the work under review, and letting them into the
#: diff would drown the patch guard in noise it cannot judge.
WORKSPACE_IGNORES = "\n".join([".devforge/", "__pycache__/", "*.pyc", ".pytest_cache/", ""])

#: Capabilities a case may declare in ``requires``, and how to tell if they exist.
CAPABILITY_PROBES: dict[str, str] = {
    "git": "git",
    "browser": "playwright",
    "node": "node",
}


@dataclass
class EvalRunner:
    """Runs a set of cases under one configuration."""

    config: EvalConfig
    policy: PolicyEngine
    logger: RunLogger = field(default_factory=null_logger)
    #: Extension seam used by the tests: a zero-argument callable returning an
    #: AgentRuntime, for measuring a runtime the registry cannot name.
    runtime_factory: object | None = None
    keep_workspaces: Path | None = None

    async def run(self, cases: list[EvalCase], *, suites: list[str] | None = None) -> EvalReport:
        driver = build_driver(self.config, runtime_factory=self.runtime_factory)
        results: list[CaseResult] = []
        unhonoured: list[str] = []

        for case in cases:
            result, extra = await self.run_case(case, driver)
            results.append(result)
            for item in extra:
                if item not in unhonoured:
                    unhonoured.append(item)
            self.logger.info(
                "eval.case",
                case=case.id,
                category=case.category.value,
                outcome=result.outcome.value,
                duration_ms=result.duration_ms,
            )

        return EvalReport(
            report_id=new_id("eval"),
            devforge_version=__version__,
            git_commit=_head_commit(),
            config=self.config,
            suites=list(suites or []),
            results=results,
            metrics=compute_metrics(results),
            unhonoured=unhonoured,
        )

    async def run_case(self, case: EvalCase, driver: Driver) -> tuple[CaseResult, list[str]]:
        started = asyncio.get_running_loop().time()
        result = CaseResult(case_id=case.id, category=case.category, title=case.title)
        unhonoured: list[str] = []

        missing = [name for name in case.requires if not _capability_present(name)]
        if missing:
            result.outcome = CaseOutcome.UNAVAILABLE
            result.detail = f"requires {', '.join(missing)}, which is not installed here"
            return result, unhonoured

        root = Path(tempfile.mkdtemp(prefix=f"devforge-eval-{case.id}-"))
        keep = False
        try:
            case.materialise(root)
            _write_ignores(root)
            if not _init_repo(root):
                result.outcome = CaseOutcome.UNAVAILABLE
                result.detail = "git is unavailable, so the patch could not be reviewed"
                return result, unhonoured

            policy = self.policy.for_workspace(root)

            result.guards_before = await self._run_checks(case.guards, root, policy)
            broken = [check.id for check in result.guards_before if not check.passed]
            if broken:
                result.outcome = CaseOutcome.INVALID
                result.detail = (
                    f"guard(s) {', '.join(broken)} already failed before the attempt; "
                    "the case is broken, not the configuration"
                )
                keep = True
                return result, unhonoured

            outcome = await driver.attempt(root, case, self.logger)
            unhonoured = list(outcome.unhonoured)
            _apply_telemetry(result, outcome)
            if not outcome.available:
                result.outcome = CaseOutcome.UNAVAILABLE
                result.detail = outcome.detail
                return result, unhonoured

            review = _review_worktree(root)
            result.patch_verdict = review.verdict().value
            result.files_changed = list(review.files_changed)
            result.findings = [finding.describe() for finding in review.findings]
            result.security_violations += len(review.major)

            result.checks = await self._run_checks(case.checks, root, policy)
            result.guards_after = await self._run_checks(case.guards, root, policy)
            result.regressed = [
                after.id
                for after in result.guards_after
                if not after.passed and _passed_before(result.guards_before, after.id)
            ]

            result.outcome, detail = _grade(result, review.verdict(), outcome)
            result.detail = detail
            keep = not result.outcome.success
            return result, unhonoured
        finally:
            result.duration_ms = int((asyncio.get_running_loop().time() - started) * 1000)
            self._dispose(root, case, keep=keep)

    # -- internals --------------------------------------------------------------

    async def _run_checks(
        self, checks: list[Check], root: Path, policy: PolicyEngine
    ) -> list[CheckOutcome]:
        outcomes: list[CheckOutcome] = []
        for check in checks:
            decision = policy.check_command(check.argv)
            if not decision.allowed:
                outcomes.append(
                    CheckOutcome(
                        id=check.id,
                        passed=False,
                        expect=check.expect,
                        exit_code=126,
                        excerpt=f"policy refused this check: {decision.reason}",
                    )
                )
                continue
            process = await run_process(
                check.argv,
                cwd=root,
                timeout_s=check.timeout_s,
                allow_env=policy.permissions.process.allow_env,
                max_output_chars=policy.permissions.process.max_output_chars,
            )
            outcomes.append(
                CheckOutcome(
                    id=check.id,
                    passed=check.satisfied_by(process.exit_code),
                    expect=check.expect,
                    exit_code=process.exit_code,
                    duration_ms=process.duration_ms,
                    excerpt=process.excerpt(MAX_CHECK_EXCERPT),
                )
            )
        return outcomes

    def _dispose(self, root: Path, case: EvalCase, *, keep: bool) -> None:
        """Delete the workspace, or move it aside when a human will want to look.

        A failure nobody can inspect is a failure nobody can fix, so failed and
        invalid cases are preserved when ``--keep`` names somewhere to put them.
        Successes are always deleted; there is nothing to see.
        """
        if keep and self.keep_workspaces is not None:
            destination = self.keep_workspaces / case.id
            shutil.rmtree(destination, ignore_errors=True)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(root), str(destination))
            return
        shutil.rmtree(root, ignore_errors=True)


# --------------------------------------------------------------------------- grading


def _grade(
    result: CaseResult, verdict: PatchVerdict, outcome: DriverOutcome
) -> tuple[CaseOutcome, str]:
    """Turn observations into a verdict, in the order that cannot be gamed."""
    if verdict is PatchVerdict.SUSPICIOUS:
        return (
            CaseOutcome.REJECTED_SUSPICIOUS,
            f"{len(result.findings)} suspicious pattern(s): the checks may be green, "
            "but the change weakened what checks them",
        )
    if result.regressed:
        return (
            CaseOutcome.REGRESSED,
            f"broke {', '.join(result.regressed)}, which passed before the attempt",
        )
    failed = [check.id for check in result.checks if not check.passed]
    if failed:
        return CaseOutcome.FAILED, f"check(s) {', '.join(failed)} did not pass"
    if verdict is PatchVerdict.EMPTY:
        return CaseOutcome.FAILED, "nothing was changed, so nothing was solved"
    return CaseOutcome.SUCCESS, outcome.detail or "every check passed and no guard regressed"


def _apply_telemetry(result: CaseResult, outcome: DriverOutcome) -> None:
    result.attempts = outcome.attempts
    result.steps_total = outcome.steps_total
    result.verifications_passed = outcome.verifications_passed
    result.verifications_failed = outcome.verifications_failed
    result.tool_calls = outcome.tool_calls
    result.tool_failures = outcome.tool_failures
    result.security_violations += outcome.security_violations
    result.interventions = outcome.interventions
    result.tokens = outcome.tokens
    result.cost_usd = outcome.cost_usd


def _passed_before(before: list[CheckOutcome], check_id: str) -> bool:
    return any(check.id == check_id and check.passed for check in before)


# --------------------------------------------------------------------------- workspace


def _write_ignores(root: Path) -> None:
    path = root / ".gitignore"
    existing = path.read_text(encoding="utf-8") if path.is_file() else ""
    if ".devforge/" in existing:
        return
    path.write_text(f"{existing.rstrip()}\n{WORKSPACE_IGNORES}".lstrip(), encoding="utf-8")


def _init_repo(root: Path) -> bool:
    if shutil.which("git") is None:
        return False
    commands = [
        ["git", "init", "--quiet"],
        ["git", "config", "user.email", "eval@devforge.invalid"],
        ["git", "config", "user.name", "devforge-eval"],
        ["git", "add", "--all"],
        ["git", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "eval case"],
    ]
    return all(_git(argv, root) is not None for argv in commands)


def _review_worktree(root: Path):
    """Diff the workspace against its baseline commit and review the result."""
    _git(["git", "add", "--all"], root)
    diff = _git(["git", "diff", "--no-color", "--cached"], root)
    return review_patch(diff or "")


def _git(argv: list[str], root: Path) -> str | None:
    """Run a git command synchronously; ``None`` when it failed.

    Synchronous on purpose: this is bookkeeping around the attempt, not part of
    the measured work, and an event loop buys nothing for five short commands.
    """
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, never a shell string
            argv, cwd=root, capture_output=True, text=True, timeout=120, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return completed.stdout if completed.returncode == 0 else None


def _head_commit() -> str:
    """The DevForge commit under evaluation, so a report is traceable to a build."""
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=Path(__file__).resolve().parent,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return completed.stdout.strip() if completed.returncode == 0 else ""


def _capability_present(name: str) -> bool:
    """Whether a declared requirement exists here.

    Unknown requirement names are treated as absent. A case that asks for
    something the runner does not understand has not had its requirement met, and
    guessing "probably fine" is how an unsupported case silently counts as a
    failure of the configuration.
    """
    probe = CAPABILITY_PROBES.get(name)
    if probe is None:
        return False
    if probe == "playwright":
        try:
            import playwright  # noqa: F401
        except ImportError:
            return False
        return True
    return shutil.which(probe) is not None


__all__ = ["CAPABILITY_PROBES", "EvalRunner"]
