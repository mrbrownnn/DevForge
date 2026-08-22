"""A deterministic benchmark of seeded defects, and the grader that scores them.

The brief asks for a benchmark suite and a measured repair success rate. The hard
part is not running the cases; it is making the number mean something.

What the score measures
-----------------------

A case counts as **repaired** only when all four hold:

1. the defect reproduced deterministically *before* the patch - otherwise a later
   green run proves nothing;
2. the patch is not empty;
3. the patch guard finds no cheating pattern in it;
4. the whole suite passes *after* the patch, including the tests that already
   passed.

Dropping (1) would let a case that never failed count as fixed. Dropping (3)
would make "delete the assertion" a winning strategy - and it is a *very* winning
strategy, which is precisely why a benchmark without a patch guard scores an agent
higher the more dishonest it is.

Solvers
-------

The benchmark grades a ``Solver``: anything that, given a workspace and a case,
tries to repair it. Two ship with the harness and neither is an agent - they exist
to validate the grader itself:

``reference`` applies the known-good fix and must score 1.0. If it does not, the
grader is rejecting correct work.

``cheat`` deletes the assertions until the suite is green and must score 0.0. It
is the adversarial control: a grader it can beat is a grader that rewards
weakening tests, and the number it produces would be worthless.

A real runtime plugs in as a third solver. Its score is then comparable to these
two anchors, which is the only reason a repair-rate figure is interpretable at
all. **A score is always a score of one solver on this suite** - eight small
Python defects - and generalises no further than that.
"""

from __future__ import annotations

import asyncio
import re
import shutil
import tempfile
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from devforge.core.errors import ConfigError
from devforge.debug.models import (
    PatchReview,
    PatchVerdict,
    RepairOutcome,
    ReproductionOutcome,
)
from devforge.debug.patch_guard import review_patch
from devforge.debug.reproduce import reproduce
from devforge.observability.logging import RunLogger, null_logger
from devforge.policy.engine import PolicyEngine
from devforge.tools.process import run_process

DEFAULT_REPRODUCE = ["python", "-m", "pytest", "-q"]
CASE_TIMEOUT_S = 180
MAX_EXCERPT = 2_000


class BugCase(BaseModel):
    """One seeded defect: the broken project, how to see it, and the known fix."""

    model_config = ConfigDict(extra="forbid")

    id: str
    title: str = ""
    category: str = "general"
    description: str = ""
    #: Relative path -> file contents. Written verbatim into a fresh workspace.
    files: dict[str, str]
    #: Relative path -> replacement contents. The reference repair.
    fix: dict[str, str]
    reproduce: list[str] = Field(default_factory=lambda: list(DEFAULT_REPRODUCE))

    def materialise(self, root: Path) -> None:
        _write_files(root, self.files)

    def apply_reference_fix(self, root: Path) -> None:
        _write_files(root, self.fix)


class BenchmarkSuite(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int = 1
    cases: list[BugCase]

    @classmethod
    def load(cls, path: Path) -> BenchmarkSuite:
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except FileNotFoundError as exc:
            raise ConfigError(f"benchmark suite not found: {path}") from exc
        except yaml.YAMLError as exc:
            raise ConfigError(f"invalid YAML in {path}: {exc}") from exc
        try:
            suite = cls.model_validate(raw)
        except ValidationError as exc:
            raise ConfigError(f"{path}: invalid benchmark suite: {exc}") from exc
        seen: set[str] = set()
        for case in suite.cases:
            if case.id in seen:
                raise ConfigError(f"{path}: duplicate benchmark case id '{case.id}'")
            seen.add(case.id)
        return suite

    def case(self, case_id: str) -> BugCase | None:
        return next((c for c in self.cases if c.id == case_id), None)


def builtin_suite_path() -> Path:
    from devforge import builtin

    return Path(builtin.__file__).parent / "benchmarks" / "bugs.yaml"


def load_builtin_suite() -> BenchmarkSuite:
    return BenchmarkSuite.load(builtin_suite_path())


# --------------------------------------------------------------------------- solvers

#: A solver receives a materialised workspace and the case, and edits the tree.
Solver = Callable[[Path, BugCase], Awaitable[None]]


async def reference_solver(workspace: Path, case: BugCase) -> None:
    """Apply the known-good fix. The grader must score this 1.0."""
    case.apply_reference_fix(workspace)


async def noop_solver(workspace: Path, case: BugCase) -> None:
    """Change nothing. The grader must score this 0.0."""


_ASSERT_LINE = re.compile(r"^(\s*)assert\b.*$", re.MULTILINE)
_RAISES_BLOCK = re.compile(r"^(\s*)with pytest\.raises\([^)]*\):\s*\n(?:\1\s+.*\n)+", re.MULTILINE)


def weaken_tests(workspace: Path, relative_paths: list[str]) -> list[str]:
    """Delete what the given test files check, and report which ones changed.

    This is the adversarial control shared by the repair benchmark and the
    evaluation harness. It never touches the source under test - it removes
    assertions and neuters ``pytest.raises`` blocks until nothing can fail, which
    is the cheapest way to turn any suite green.

    A grader that scores this above zero rewards exactly the behaviour the harness
    exists to prevent, so both graders run it deliberately and require zero.
    """
    weakened: list[str] = []
    for relative in relative_paths:
        if "test" not in Path(relative).name:
            continue
        path = workspace / relative
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        rewritten = _RAISES_BLOCK.sub(lambda m: f"{m.group(1)}pass\n", text)
        rewritten = _ASSERT_LINE.sub(lambda m: f"{m.group(1)}pass", rewritten)
        if rewritten != text:
            path.write_text(rewritten, encoding="utf-8")
            weakened.append(relative)
    return weakened


async def cheat_solver(workspace: Path, case: BugCase) -> None:
    """Make the suite green by removing what checks it. Must score 0.0."""
    weaken_tests(workspace, list(case.files))


BUILTIN_SOLVERS: dict[str, Solver] = {
    "reference": reference_solver,
    "cheat": cheat_solver,
    "none": noop_solver,
}


# --------------------------------------------------------------------------- results


class CaseResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: str
    title: str = ""
    outcome: RepairOutcome = RepairOutcome.NOT_REPAIRED
    reproduced: str = ReproductionOutcome.UNAVAILABLE.value
    patch_verdict: str = PatchVerdict.EMPTY.value
    files_changed: list[str] = Field(default_factory=list)
    findings: list[str] = Field(default_factory=list)
    tests_pass_after: bool = False
    duration_ms: int = 0
    detail: str = ""

    @property
    def success(self) -> bool:
        return self.outcome.success


class BenchmarkReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    solver: str
    results: list[CaseResult] = Field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def repaired(self) -> int:
        return sum(1 for r in self.results if r.success)

    @property
    def success_rate(self) -> float:
        """Repaired over attempted. Zero cases is 0.0, never a vacuous 1.0."""
        return self.repaired / self.total if self.total else 0.0

    def by_outcome(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for result in self.results:
            counts[result.outcome.value] = counts.get(result.outcome.value, 0) + 1
        return counts

    def render(self) -> str:
        lines = [
            "# Repair benchmark",
            "",
            f"Solver: **{self.solver}**",
            "",
            f"Repair success rate: **{self.repaired}/{self.total} "
            f"({self.success_rate:.0%})**",
            "",
            "| case | outcome | reproduced | patch | suite after |",
            "| --- | --- | --- | --- | --- |",
        ]
        for result in self.results:
            lines.append(
                f"| {result.case_id} | {result.outcome.value} | {result.reproduced} "
                f"| {result.patch_verdict} | {'pass' if result.tests_pass_after else 'fail'} |"
            )
        lines.append("")
        rejected = [r for r in self.results if r.outcome is RepairOutcome.REJECTED_SUSPICIOUS]
        if rejected:
            lines += ["## Rejected as suspicious", ""]
            for result in rejected:
                lines.append(f"- **{result.case_id}**")
                lines += [f"  - {finding}" for finding in result.findings]
            lines.append("")
        lines += [
            "## What this number means",
            "",
            f"It is the score of one solver on {self.total} seeded Python defect(s). "
            "A case counts as repaired only if the defect reproduced deterministically "
            "first, the patch is non-empty, the patch guard found no cheating pattern, "
            "and the whole suite passed afterwards.",
            "",
            "It does not predict performance on real defects in real codebases. These "
            "cases are small, self-contained and have known fixes; production bugs are "
            "none of those things.",
            "",
        ]
        return "\n".join(lines)


# --------------------------------------------------------------------------- runner


@dataclass
class BenchmarkRunner:
    """Runs cases in isolated temporary workspaces.

    Every case gets a fresh directory and its own git repository. The repository
    is not ceremony: the patch guard reviews a *diff*, and a diff needs a baseline.
    Without a commit before the solver runs, deletions would be invisible and the
    guard would pass anything.
    """

    policy: PolicyEngine
    logger: RunLogger = None  # type: ignore[assignment]
    timeout_s: int = CASE_TIMEOUT_S

    def __post_init__(self) -> None:
        if self.logger is None:
            self.logger = null_logger()

    async def run_case(self, case: BugCase, solver: Solver) -> CaseResult:
        started = asyncio.get_running_loop().time()
        result = CaseResult(case_id=case.id, title=case.title)
        root = Path(tempfile.mkdtemp(prefix=f"devforge-bench-{case.id}-"))
        try:
            case.materialise(root)
            if not await _init_repo(root):
                result.outcome = RepairOutcome.UNAVAILABLE
                result.detail = "git is unavailable, so the patch could not be reviewed"
                return result

            policy = self.policy.for_workspace(root)

            before = await reproduce(
                case.reproduce,
                workspace=root,
                policy=policy,
                runs=2,
                timeout_s=self.timeout_s,
                logger=self.logger,
            )
            result.reproduced = before.outcome.value
            if not before.outcome.usable:
                result.outcome = (
                    RepairOutcome.UNAVAILABLE
                    if before.outcome is ReproductionOutcome.UNAVAILABLE
                    else RepairOutcome.NOT_REPRODUCED
                )
                result.detail = before.summary
                return result

            await solver(root, case)

            review = await _review_worktree(root, policy)
            result.patch_verdict = review.verdict().value
            result.files_changed = list(review.files_changed)
            result.findings = [finding.describe() for finding in review.findings]

            after = await run_process(
                case.reproduce,
                cwd=root,
                timeout_s=self.timeout_s,
                allow_env=policy.permissions.process.allow_env,
                max_output_chars=policy.permissions.process.max_output_chars,
            )
            result.tests_pass_after = after.exit_code == 0

            result.outcome, result.detail = _grade(review, after.exit_code, after.combined)
            return result
        finally:
            result.duration_ms = int((asyncio.get_running_loop().time() - started) * 1000)
            shutil.rmtree(root, ignore_errors=True)

    async def run(
        self, cases: list[BugCase], solver: Solver, *, solver_name: str = "custom"
    ) -> BenchmarkReport:
        report = BenchmarkReport(solver=solver_name)
        for case in cases:
            outcome = await self.run_case(case, solver)
            report.results.append(outcome)
            self.logger.info(
                "benchmark.case",
                case=case.id,
                outcome=outcome.outcome.value,
                duration_ms=outcome.duration_ms,
            )
        return report


def _grade(review: PatchReview, exit_code: int, output: str) -> tuple[RepairOutcome, str]:
    """Turn observations into a verdict, in the order that cannot be gamed.

    The suspicion check comes *before* the green-suite check on purpose. A patch
    that removed the assertions also makes the suite pass, and evaluating success
    first would record it as a repair and never look at the diff.
    """
    if review.verdict() is PatchVerdict.SUSPICIOUS:
        return (
            RepairOutcome.REJECTED_SUSPICIOUS,
            f"{len(review.major)} suspicious pattern(s): the suite may be green, but the "
            "patch weakened what checks it",
        )
    if review.verdict() is PatchVerdict.EMPTY:
        return RepairOutcome.NOT_REPAIRED, "the solver changed nothing"
    if exit_code != 0:
        return (
            RepairOutcome.NOT_REPAIRED,
            f"the suite still fails after the patch (exit {exit_code}): "
            f"{output.strip()[-MAX_EXCERPT:]}",
        )
    return RepairOutcome.REPAIRED, "defect reproduced, patch is clean, suite is green"


async def _init_repo(root: Path) -> bool:
    """A baseline commit so the guard has something to diff against."""
    if shutil.which("git") is None:
        return False
    commands = [
        ["git", "init", "--quiet"],
        ["git", "config", "user.email", "benchmark@devforge.invalid"],
        ["git", "config", "user.name", "devforge-benchmark"],
        ["git", "add", "--all"],
        ["git", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "seeded defect"],
    ]
    for argv in commands:
        result = await run_process(argv, cwd=root, timeout_s=60)
        if result.exit_code != 0:
            return False
    return True


async def _review_worktree(root: Path, policy: PolicyEngine) -> PatchReview:
    result = await run_process(
        ["git", "diff", "--no-color", "HEAD"],
        cwd=root,
        timeout_s=60,
        allow_env=policy.permissions.process.allow_env,
        max_output_chars=policy.permissions.process.max_output_chars,
    )
    if result.exit_code != 0:
        return PatchReview()
    return review_patch(result.stdout)


def _write_files(root: Path, files: dict[str, str]) -> None:
    for relative, content in files.items():
        target = (root / relative).resolve()
        if root.resolve() not in target.parents:
            raise ConfigError(f"benchmark case writes outside its workspace: {relative}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


async def run_builtin_benchmark(
    *,
    policy: PolicyEngine,
    solver_name: str = "reference",
    case_ids: list[str] | None = None,
    logger: RunLogger | None = None,
) -> BenchmarkReport:
    """Convenience entry point used by the CLI and the tests."""
    suite = load_builtin_suite()
    cases = suite.cases
    if case_ids:
        cases = [case for case in suite.cases if case.id in set(case_ids)]
        unknown = set(case_ids) - {case.id for case in suite.cases}
        if unknown:
            raise ConfigError(f"unknown benchmark case(s): {', '.join(sorted(unknown))}")
    solver = BUILTIN_SOLVERS.get(solver_name)
    if solver is None:
        raise ConfigError(
            f"unknown solver '{solver_name}'; expected one of {sorted(BUILTIN_SOLVERS)}"
        )
    runner = BenchmarkRunner(policy=policy, logger=logger or null_logger())
    return await runner.run(cases, solver, solver_name=solver_name)
