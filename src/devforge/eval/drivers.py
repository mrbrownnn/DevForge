"""What attempts a case.

Four drivers ship. Three of them are not agents at all, and that is the point:
a grader nobody has calibrated produces numbers nobody can read.

``reference``
    Writes the case's known-good solution. **Must score 1.0.** If it does not, the
    grader is rejecting correct work and every other number in the report is
    suspect.
``cheat``
    Deletes the assertions until the checks stop objecting. **Must score 0.0.** A
    grader it can beat is one that rewards weakening tests, which is the failure
    mode a coding benchmark falls into by default.
``none``
    Changes nothing. **Must score 0.0.** It measures how many cases pass without
    anyone doing anything - the floor a real score has to clear to mean something.
``harness``
    Runs DevForge: the orchestrator, a workflow, a runtime, the verifiers, the
    approval gates. This is the one under measurement; the other three exist so
    its number can be placed between two known points.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from devforge.core.errors import DevForgeError
from devforge.core.models import Approval, Task, ToolStatus
from devforge.debug.benchmark import weaken_tests
from devforge.eval.models import EvalCase, EvalConfig
from devforge.observability.logging import RunLogger


@dataclass
class DriverOutcome:
    """What the driver did, before anything is graded.

    ``available=False`` means the attempt never happened - a missing runtime, an
    unloadable workflow. The runner turns that into an *unavailable* case rather
    than a failed one, because a configuration that could not run has not been
    measured.

    Every telemetry field defaults to ``None``: "this driver cannot report it".
    A scripted driver runs no steps and makes no tool calls, and reporting zeros
    for those would put it in the same column as a harness run that genuinely made
    none.
    """

    available: bool = True
    detail: str = ""
    status: str = ""
    attempts: int | None = None
    steps_total: int | None = None
    verifications_passed: int | None = None
    verifications_failed: int | None = None
    tool_calls: int | None = None
    tool_failures: int | None = None
    security_violations: int = 0
    interventions: int = 0
    tokens: int | None = None
    cost_usd: float | None = None
    unhonoured: list[str] = field(default_factory=list)


class Driver(Protocol):
    """Anything that can attempt a case in a prepared workspace."""

    name: str

    async def attempt(
        self, workspace: Path, case: EvalCase, logger: RunLogger
    ) -> DriverOutcome: ...


# --------------------------------------------------------------------------- anchors


class ReferenceDriver:
    """Applies the known-good solution. The grader's upper anchor."""

    name = "reference"

    async def attempt(self, workspace: Path, case: EvalCase, logger: RunLogger) -> DriverOutcome:
        if not case.solution:
            return DriverOutcome(
                available=False,
                detail=(
                    f"case '{case.id}' ships no reference solution, so the grader "
                    "cannot be anchored on it"
                ),
            )
        case.apply_solution(workspace)
        return DriverOutcome(detail="applied the reference solution")


class CheatDriver:
    """Removes what the checks check. The grader's lower anchor."""

    name = "cheat"

    async def attempt(self, workspace: Path, case: EvalCase, logger: RunLogger) -> DriverOutcome:
        weakened = weaken_tests(workspace, list(case.files))
        return DriverOutcome(
            detail=(
                f"weakened {len(weakened)} test file(s) instead of doing the work"
                if weakened
                else "found no assertions to remove"
            )
        )


class NoopDriver:
    """Changes nothing. The floor."""

    name = "none"

    async def attempt(self, workspace: Path, case: EvalCase, logger: RunLogger) -> DriverOutcome:
        return DriverOutcome(detail="did nothing")


# --------------------------------------------------------------------------- harness


class HarnessDriver:
    """Runs DevForge itself against the case.

    This constructs the same objects ``devforge run`` does - store, policy,
    registries, orchestrator - inside the case's temporary workspace. It is
    deliberately not a call into the CLI: the CLI resolves a project from the
    current directory, and an evaluation must never touch the directory it was
    launched from.

    Approvals are answered automatically. A benchmark cannot wait for a human, and
    stopping at the first gate would measure nothing. Each answered gate is counted
    and surfaces as the human-intervention metric, so the report shows how often a
    real run would have needed a person rather than pretending it would not.
    """

    name = "harness"

    def __init__(
        self,
        config: EvalConfig,
        *,
        runtime_factory: object | None = None,
    ) -> None:
        self.config = config
        #: Test and extension seam: a zero-argument callable returning an
        #: AgentRuntime, used when a run needs a runtime the registry has no
        #: name for.
        self.runtime_factory = runtime_factory

    async def attempt(self, workspace: Path, case: EvalCase, logger: RunLogger) -> DriverOutcome:
        from devforge.core.orchestrator.context import AppContext
        from devforge.core.state.store import ProjectStore

        try:
            ProjectStore.initialize(
                workspace, name=f"eval-{case.id}", default_runtime=self.config.runtime, force=True
            )
            ctx = AppContext.load(workspace)
            spec = ctx.workflows.load(self.config.workflow or case.workflow)
        except DevForgeError as exc:
            return DriverOutcome(available=False, detail=str(exc))

        spec = _restrict_skills(spec, self.config.skills)
        unhonoured = _prepare_context(workspace, ctx, self.config.context_strategy)

        try:
            runtime = (
                self.runtime_factory()  # type: ignore[operator]
                if self.runtime_factory is not None
                else ctx.runtimes.create(self.config.runtime)
            )
        except DevForgeError as exc:
            return DriverOutcome(available=False, detail=str(exc))

        availability = runtime.availability()
        if not availability.available:
            return DriverOutcome(
                available=False,
                detail=f"runtime '{self.config.runtime}' is unavailable: {availability.detail}",
            )
        unhonoured += [
            f"model={self.config.model!r} (runtime '{runtime.name}' takes no model)"
            for name in runtime.configure(model=self.config.model)
            if name == "model"
        ]

        interventions = _InterventionCounter()
        task = Task(
            project_id=ctx.config.project_id,
            description=case.description,
            workflow=spec.name,
            runtime=self.config.runtime,
        )
        orchestrator = ctx.orchestrator(
            runtime=runtime, logger=logger, prompter=interventions.approve
        )
        orchestrator.workspace = workspace

        try:
            result = await orchestrator.run(task, spec)
        except DevForgeError as exc:
            return _telemetry(
                task,
                status="error",
                detail=f"the run raised: {exc}",
                interventions=interventions.count,
                unhonoured=unhonoured,
            )

        return _telemetry(
            task,
            status=result.status.value,
            detail=result.reason or f"run {result.status.value}",
            interventions=interventions.count,
            unhonoured=unhonoured,
        )


class _InterventionCounter:
    """Answers every gate yes, and counts how many there were.

    Answering yes is the only option that measures the rest of the workflow. The
    count is the honest half: it is reported as the human-intervention rate, so an
    unattended number never implies an unattended process.
    """

    def __init__(self) -> None:
        self.count = 0

    def approve(self, approval: Approval) -> bool:
        self.count += 1
        return True


def _restrict_skills(spec, skills: list[str]):
    """Narrow every step to the configured skill set.

    Comparing skill sets means actually withholding skills. A configuration that
    only *labels* itself "minimal" while every step keeps its declared skills would
    produce two identical runs and a difference attributed to the label.
    """
    if not skills:
        return spec
    allowed = set(skills)
    narrowed = spec.model_copy(deep=True)
    for step in narrowed.steps:
        step.skills = [skill for skill in step.skills if skill in allowed]
    return narrowed


def _prepare_context(workspace: Path, ctx, strategy: str) -> list[str]:
    """Set up the retrieval index, or deliberately leave none.

    ``none`` and ``indexed`` are the two states the orchestrator actually behaves
    differently in: with an index it packs retrieved files into the prompt, without
    one it falls back to project memory. Any other value is recorded as unhonoured
    rather than silently treated as one of them.
    """
    if strategy == "none":
        return []
    if strategy != "indexed":
        return [f"context_strategy={strategy!r} (expected 'none' or 'indexed')"]

    from devforge.context.indexer import build_index
    from devforge.context.pack import save_index

    try:
        index = build_index(workspace, project_id=ctx.config.project_id)
        save_index(workspace, index)
    except (DevForgeError, OSError) as exc:
        return [f"context_strategy='indexed' (index could not be built: {exc})"]
    return []


def _telemetry(
    task: Task,
    *,
    status: str,
    detail: str,
    interventions: int,
    unhonoured: list[str],
) -> DriverOutcome:
    """Read the metrics off the persisted task record.

    Everything here comes from what the orchestrator wrote down, not from what any
    agent said about itself. ``security_violations`` counts tool calls the policy
    engine refused, which is a fact the executor recorded at the door.
    """
    agent_steps = [step for step in task.steps if step.kind == "agent"]
    attempts = sum(step.attempt_count for step in agent_steps)

    passed = sum(1 for result in task.verification_results if result.status.ok)
    failed = len(task.verification_results) - passed

    tool_calls = 0
    denied = 0
    tool_failures = 0
    tokens = 0
    tokens_seen = False
    cost = 0.0
    cost_seen = False

    for step in task.steps:
        for attempt in step.attempts:
            result = attempt.agent_result
            if result is None:
                continue
            for call in result.tool_calls:
                tool_calls += 1
                if call.status is ToolStatus.DENIED:
                    denied += 1
                elif call.status is ToolStatus.ERROR:
                    tool_failures += 1
            counted, found = _tokens_of(result.metadata)
            tokens += counted
            tokens_seen = tokens_seen or found
            spent = result.metadata.get("total_cost_usd")
            if isinstance(spent, int | float):
                cost += float(spent)
                cost_seen = True

    return DriverOutcome(
        status=status,
        detail=detail,
        attempts=attempts,
        steps_total=len(agent_steps),
        verifications_passed=passed,
        verifications_failed=failed,
        tool_calls=tool_calls,
        tool_failures=tool_failures,
        security_violations=denied,
        interventions=interventions,
        tokens=tokens if tokens_seen else None,
        cost_usd=cost if cost_seen else None,
        unhonoured=unhonoured,
    )


#: Keys a runtime may report token counts under. A runtime that reports none
#: leaves the metric unknown rather than zero.
_TOKEN_KEYS = ("total_tokens", "input_tokens", "output_tokens")


def _tokens_of(metadata: dict) -> tuple[int, bool]:
    """Sum whatever token counts a runtime reported, and say whether it reported any."""
    source = metadata.get("usage") if isinstance(metadata.get("usage"), dict) else metadata
    if "total_tokens" in source and isinstance(source["total_tokens"], int):
        return int(source["total_tokens"]), True
    total = 0
    found = False
    for key in _TOKEN_KEYS[1:]:
        value = source.get(key)
        if isinstance(value, int):
            total += value
            found = True
    return total, found


BUILTIN_DRIVERS: dict[str, type] = {
    ReferenceDriver.name: ReferenceDriver,
    CheatDriver.name: CheatDriver,
    NoopDriver.name: NoopDriver,
}


def build_driver(config: EvalConfig, *, runtime_factory: object | None = None) -> Driver:
    """Construct the driver a configuration names."""
    if config.driver == HarnessDriver.name:
        return HarnessDriver(config, runtime_factory=runtime_factory)
    factory = BUILTIN_DRIVERS.get(config.driver)
    if factory is None:
        known = sorted([*BUILTIN_DRIVERS, HarnessDriver.name])
        raise DevForgeError(f"unknown driver '{config.driver}'; expected one of {known}")
    return factory()


def is_anchor(config: EvalConfig) -> bool:
    """Whether this configuration is a calibration anchor rather than a measurement."""
    return config.driver in BUILTIN_DRIVERS


__all__ = [
    "BUILTIN_DRIVERS",
    "CheatDriver",
    "Driver",
    "DriverOutcome",
    "HarnessDriver",
    "NoopDriver",
    "ReferenceDriver",
    "build_driver",
    "is_anchor",
]
