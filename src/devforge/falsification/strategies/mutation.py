"""Mutation testing: can the existing tests detect realistic faults in this patch?

The question is about the **test suite**, not the code. A mutant that survives is
evidence that a realistic fault could be introduced at that line without any test
noticing - which is a gap in the checks, not a defect in the implementation. The
report says so in those words, and the score is never called correctness.

Pipeline::

    diff -> candidates -> mutate in the sandbox -> run relevant tests
         -> killed / survived -> classify survivors -> report

Five things this implementation refuses to do, each of which would make the numbers
look better and mean less:

* **Mutate outside the patch.** Scope defaults to lines the diff touched. A
  pre-existing defect in unchanged code is out of scope by design, and the report
  states that boundary rather than leaving it to be inferred.
* **Trust a flaky verdict.** Every kill and every survival is checked against the
  quarantine list from the reliability probe. A verdict resting on a quarantined
  test is ``UNRELIABLE`` and leaves the score entirely.
* **Assume a survivor is equivalent.** Survivors go through the layered classifier,
  and anything it cannot decide stays ``SURVIVED``.
* **Report a score over nothing.** Zero valid mutants gives ``None``, not 100%.
* **Judge two mutants with one test run.** Concurrent mutants get private copies of
  the sandbox. Sharing one directory meant sharing one verdict: a mutant in an
  untested file was recorded as killed by a fault injected somewhere else, and the
  score measured the overlap between two mutations rather than the suite.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from devforge.falsification import mutation_operators as operators
from devforge.falsification.equivalence import classify, describes_constant_noise
from devforge.falsification.models import (
    Confidence,
    Mutant,
    MutantStatus,
    Severity,
    StrategyName,
    StrategyReport,
    StrategyStatus,
    TestWeakness,
)
from devforge.falsification.mutation_operators import MutationCandidate
from devforge.falsification.reliability import verdict_is_reliable
from devforge.falsification.sandbox import Lane, open_lanes
from devforge.falsification.strategies.base import (
    Availability,
    FalsificationContext,
    FalsificationStrategy,
)
from devforge.falsification.testrun import run_tests

#: Files that are never mutated. Mutating a test to see whether the tests notice is
#: circular, and mutating the harness's own configuration is not a code fault.
SKIPPED_PARTS = frozenset({"tests", "test", ".falsification", "__pycache__"})


class MutationStrategy(FalsificationStrategy):
    """Inject realistic faults into the patch and see whether anything notices."""

    name = StrategyName.MUTATION

    def available(self, ctx: FalsificationContext) -> Availability:
        if not ctx.test_command:
            return Availability(False, "no test command is configured to judge mutants")
        targets = self._files(ctx)
        if not targets:
            return Availability(
                False,
                "no mutable Python file was found in the patch; mutation currently "
                "supports Python only",
            )
        return Availability(True)

    async def attack(self, ctx: FalsificationContext) -> StrategyReport:
        availability = self.available(ctx)
        if not availability.available:
            return self.unavailable(availability.detail)

        candidates, skipped = self._candidates(ctx)
        if not candidates:
            return self.report(
                status=StrategyStatus.UNAVAILABLE,
                summary="the patch contains nothing this operator set can mutate",
                limitations=[
                    "mutation: no candidate was generated, so the suite was not "
                    "exercised against any injected fault"
                ],
            )

        baseline = await run_tests(
            ctx.test_command,
            workspace=ctx.workspace,
            policy=ctx.policy,
            timeout_s=ctx.test_timeout_s,
        )
        if not baseline.ran:
            return self.report(
                status=StrategyStatus.UNAVAILABLE,
                summary=f"the baseline test run could not be judged: {baseline.error}",
                limitations=[f"mutation: {baseline.error}"],
            )
        if not baseline.passed:
            # Mutants are judged by whether tests *start* failing. If they already
            # fail, every mutant looks killed and the score is meaningless.
            return self.report(
                status=StrategyStatus.UNAVAILABLE,
                summary="the test suite fails before any mutation, so no mutant can be judged",
                limitations=[
                    "mutation: the baseline suite was already failing; a mutation "
                    "score computed against a red suite measures nothing"
                ],
                usage=ctx.ledger.snapshot(),
            )

        mutants, lane_notes = await self._evaluate(ctx, candidates)
        weaknesses = self._weaknesses(mutants, ctx)
        usage = ctx.ledger.snapshot()

        limitations = list(skipped) + lane_notes
        if usage.truncated:
            limitations.append(
                f"mutation: stopped by {', '.join(usage.exhausted)} after "
                f"{len(mutants)} of {len(candidates)} candidate(s)"
            )
        unreliable = sum(1 for m in mutants if m.status is MutantStatus.UNRELIABLE)
        if unreliable:
            limitations.append(
                f"mutation: {unreliable} mutant(s) were excluded from the score "
                "because their verdict depended on a quarantined flaky test"
            )

        status = self._status(mutants, usage.truncated)
        return self.report(
            status=status,
            attempts=len(mutants),
            duration_ms=usage.duration_ms,
            targets=sorted({mutant.target for mutant in mutants}),
            mutants=mutants,
            weaknesses=weaknesses,
            usage=usage,
            limitations=limitations,
            summary=self._summary(mutants),
        )

    # -- candidate generation ---------------------------------------------------

    def _files(self, ctx: FalsificationContext) -> list[str]:
        """Python files in scope, filtered to what exists in the sandbox."""
        selected: list[str] = []
        for relative in ctx.changed_files:
            if not relative.endswith(".py"):
                continue
            if set(Path(relative).parts) & SKIPPED_PARTS:
                continue
            if Path(relative).name.startswith("test_"):
                continue
            if (ctx.workspace / relative).is_file():
                selected.append(relative)
        return selected

    def _candidates(
        self, ctx: FalsificationContext
    ) -> tuple[list[MutationCandidate], list[str]]:
        options = ctx.options(StrategyName.MUTATION)
        # Diff-scoped by default. The orchestrator supplies the touched lines at
        # the top level; a step may override them under the strategy key.
        changed_lines: dict[str, set[int]] | None = options.get("lines") or ctx.config.get(
            "lines"
        )
        include_branch = bool(options.get("branch_mutation", True))

        candidates: list[MutationCandidate] = []
        skipped: list[str] = []

        for relative in self._files(ctx):
            path = ctx.workspace / relative
            try:
                source = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                skipped.append(f"mutation: {relative} could not be read ({exc})")
                continue

            lines = changed_lines.get(relative) if changed_lines else None
            produced = operators.generate(source, filename=relative, lines=lines)
            if include_branch:
                produced += operators.branch_removal(source, filename=relative, lines=lines)
            if not produced:
                skipped.append(f"mutation: no candidate was generated for {relative}")
            candidates.extend(produced)

        return candidates, skipped

    # -- evaluation -------------------------------------------------------------

    async def _evaluate(
        self, ctx: FalsificationContext, candidates: list[MutationCandidate]
    ) -> tuple[list[Mutant], list[str]]:
        """Run each mutant, bounded by the budget, one per private workspace.

        Concurrency here is **not** across files in a shared directory. A mutant is
        judged by running the whole suite, so two mutants living in one directory are
        judged by one run: whichever fault it reports is recorded against both, and a
        mutant in an untested file is credited as killed by a mutant in a tested one.
        The score then measures the overlap of the two faults rather than the suite.

        So each concurrent worker gets its own copy of the sandbox - a lane - and a
        mutant is only ever alone in the tree that judges it. Copies cost one per
        worker, not one per mutant. When fewer lanes than requested can be created
        the pool simply runs narrower, and says so.
        """
        scheduled: list[MutationCandidate] = []
        for candidate in candidates:
            if not ctx.ledger.allows("mutants_generated", "max_mutants"):
                break
            ctx.ledger.spend("mutants_generated")
            scheduled.append(candidate)

        if not scheduled:
            return [], []

        wanted = max(1, min(ctx.ledger.budget.max_parallel_jobs, len(scheduled)))
        lanes, shortfall = open_lanes(ctx.workspace, wanted)
        notes = [f"mutation: {shortfall}"] if shortfall else []
        if len(lanes) > 1:
            ctx.logger.info("mutation.lanes", requested=wanted, obtained=len(lanes))

        available: asyncio.Queue[Lane] = asyncio.Queue()
        for lane in lanes:
            available.put_nowait(lane)

        async def run_one(candidate: MutationCandidate) -> Mutant:
            lane = await available.get()
            try:
                return await self._evaluate_one(ctx, candidate, workspace=lane.root)
            finally:
                available.put_nowait(lane)

        try:
            results = list(await asyncio.gather(*(run_one(c) for c in scheduled)))
        finally:
            for lane in lanes:
                lane.release()
        return results, notes

    async def _evaluate_one(
        self, ctx: FalsificationContext, candidate: MutationCandidate, *, workspace: Path
    ) -> Mutant:
        """Judge one mutant in ``workspace``, which nothing else is writing to."""
        path = workspace / candidate.file
        try:
            original = path.read_text(encoding="utf-8")
        except OSError as exc:
            return self._mutant(
                candidate,
                status=MutantStatus.ERROR,
                reason=f"the file to mutate could not be read in this lane: {exc}",
            )

        ctx.logger.info(
            "mutation.generated",
            file=candidate.file,
            line=candidate.line,
            operator=candidate.operator,
        )

        try:
            path.write_text(candidate.source, encoding="utf-8")
            outcome = await run_tests(
                ctx.test_command,
                workspace=workspace,
                policy=ctx.policy,
                timeout_s=ctx.test_timeout_s,
            )
        except OSError as exc:
            return self._mutant(
                candidate,
                status=MutantStatus.ERROR,
                reason=f"the mutant could not be written: {exc}",
            )
        finally:
            # Restoring in `finally` is what keeps one failed mutant from poisoning
            # every mutant that follows it in the same file.
            path.write_text(original, encoding="utf-8")

        if not outcome.ran:
            return self._mutant(
                candidate,
                status=MutantStatus.ERROR,
                reason=f"the suite could not be run against this mutant: {outcome.error}",
                duration_ms=outcome.duration_ms,
            )

        reliable, tainted = verdict_is_reliable(outcome.failures, ctx.quarantined_tests)
        if not reliable:
            ctx.logger.warn(
                "mutation.unreliable",
                file=candidate.file,
                line=candidate.line,
                operator=candidate.operator,
                tests=tainted,
            )
            return self._mutant(
                candidate,
                status=MutantStatus.UNRELIABLE,
                reason=(
                    "the verdict depended on test(s) the reliability probe "
                    "quarantined, so it is excluded from the mutation score"
                ),
                unreliable_tests=tainted,
                duration_ms=outcome.duration_ms,
            )

        if not outcome.passed:
            ctx.logger.info(
                "mutation.killed",
                file=candidate.file,
                line=candidate.line,
                operator=candidate.operator,
                killed_by=outcome.failures[:3],
            )
            return self._mutant(
                candidate,
                status=MutantStatus.KILLED,
                killed_by=", ".join(outcome.failures[:3]) or f"exit {outcome.exit_code}",
                duration_ms=outcome.duration_ms,
            )

        return self._classify_survivor(ctx, candidate, original, outcome.duration_ms)

    def _classify_survivor(
        self,
        ctx: FalsificationContext,
        candidate: MutationCandidate,
        original_source: str,
        duration_ms: int,
    ) -> Mutant:
        """A survivor is a weak test until a layer proves otherwise."""
        if describes_constant_noise(candidate):
            # Backstop for anything the generator let through: a docstring change is
            # not an equivalent implementation, it is not an implementation change at
            # all, so it is INVALID rather than a survivor or an equivalence.
            return self._mutant(
                candidate,
                status=MutantStatus.INVALID,
                reason="the mutated constant is documentation, not behaviour",
                duration_ms=duration_ms,
            )

        options = ctx.options(StrategyName.MUTATION)
        judgement = classify(
            candidate,
            original_source=original_source,
            assisted=bool(options.get("assisted_equivalence", False)),
            assistant=options.get("assistant"),
        )

        if judgement.equivalent:
            ctx.logger.info(
                "mutation.equivalent",
                file=candidate.file,
                line=candidate.line,
                layer=judgement.layer.value,
                confidence=judgement.confidence.value,
            )
            return self._mutant(
                candidate,
                status=MutantStatus.EQUIVALENT,
                reason=judgement.reason,
                equivalence_layer=judgement.layer,
                equivalence_confidence=judgement.confidence,
                duration_ms=duration_ms,
            )

        ctx.logger.warn(
            "mutation.survived",
            file=candidate.file,
            line=candidate.line,
            operator=candidate.operator,
            detail="no test detected this injected fault",
        )
        return self._mutant(
            candidate,
            status=MutantStatus.SURVIVED,
            reason="",
            equivalence_confidence=Confidence.NONE,
            duration_ms=duration_ms,
        )

    @staticmethod
    def _mutant(candidate: MutationCandidate, **fields) -> Mutant:
        return Mutant(
            file=candidate.file,
            line=candidate.line,
            operator=candidate.operator,
            original=candidate.original,
            mutated=candidate.mutated,
            target=candidate.target,
            **fields,
        )

    # -- findings ---------------------------------------------------------------

    def _weaknesses(
        self, mutants: list[Mutant], ctx: FalsificationContext
    ) -> list[TestWeakness]:
        """Turn every surviving mutant into something a person can act on.

        The proposed test is a suggestion carried in the report. It is never written
        into the permanent suite here - the workflow decides whether to accept it.
        """
        weaknesses: list[TestWeakness] = []
        for mutant in mutants:
            if mutant.status is not MutantStatus.SURVIVED:
                continue
            weaknesses.append(
                TestWeakness(
                    mutant_id=mutant.mutant_id,
                    file=mutant.file,
                    line=mutant.line,
                    operator=mutant.operator,
                    unchecked_behavior=(
                        f"changing {mutant.original.strip()!r} to "
                        f"{mutant.mutated.strip()!r} at {mutant.file}:{mutant.line} "
                        "did not fail any test"
                    ),
                    relevant_tests=self._related_tests(ctx, mutant.file),
                    proposed_test=self._propose_test(mutant),
                    reproduction=list(ctx.test_command),
                    severity=Severity.HIGH
                    if mutant.operator == operators.EXCEPTION
                    else Severity.MEDIUM,
                )
            )
        return weaknesses

    @staticmethod
    def _related_tests(ctx: FalsificationContext, source_file: str) -> list[str]:
        """Test files that mention the mutated module, as a starting point.

        Deliberately a textual heuristic and labelled as such: computing real
        coverage attribution would need a coverage run per mutant, which is exactly
        the cost this strategy is already fighting.
        """
        stem = Path(source_file).stem
        found: list[str] = []
        for directory in ("tests", "test"):
            root = ctx.workspace / directory
            if not root.is_dir():
                continue
            for path in sorted(root.rglob("test_*.py")):
                try:
                    if stem in path.read_text(encoding="utf-8", errors="replace"):
                        found.append(path.relative_to(ctx.workspace).as_posix())
                except OSError:  # pragma: no cover - unreadable test file
                    continue
        return found[:10]

    @staticmethod
    def _propose_test(mutant: Mutant) -> str:
        """A skeleton test that would have killed this mutant.

        A skeleton on purpose. Generating a full assertion would require knowing the
        intended behaviour, which is precisely what the missing test was supposed to
        state, and inventing it would produce a test that passes without checking
        anything - the failure mode this whole subsystem exists to catch.
        """
        return (
            f"def test_{Path(mutant.file).stem}_line_{mutant.line}_behaviour():\n"
            f"    # A realistic fault survived here: {mutant.original.strip()!r} was\n"
            f"    # changed to {mutant.mutated.strip()!r} and no test failed.\n"
            f"    # Assert the behaviour that distinguishes the two.\n"
            f"    raise AssertionError('write this assertion')\n"
        )

    # -- verdict ----------------------------------------------------------------

    @staticmethod
    def _status(mutants: list[Mutant], truncated: bool) -> StrategyStatus:
        if not mutants:
            return StrategyStatus.INCOMPLETE if truncated else StrategyStatus.UNAVAILABLE
        if any(mutant.status is MutantStatus.SURVIVED for mutant in mutants):
            # A survivor is a finding: the suite failed to detect a realistic fault.
            return StrategyStatus.FAILED
        if truncated:
            return StrategyStatus.INCOMPLETE
        return StrategyStatus.SURVIVED

    @staticmethod
    def _summary(mutants: list[Mutant]) -> str:
        killed = sum(1 for m in mutants if m.status is MutantStatus.KILLED)
        survived = sum(1 for m in mutants if m.status is MutantStatus.SURVIVED)
        equivalent = sum(1 for m in mutants if m.status is MutantStatus.EQUIVALENT)
        unreliable = sum(1 for m in mutants if m.status is MutantStatus.UNRELIABLE)
        return (
            f"{len(mutants)} mutant(s): {killed} killed, {survived} survived, "
            f"{equivalent} equivalent, {unreliable} unreliable"
        )
