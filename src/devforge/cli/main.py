"""DevForge command line interface.

Commands are thin: they build an :class:`~devforge.core.orchestrator.context.AppContext`,
call into the domain, and hand the result to :mod:`devforge.cli.render`. Any
:class:`~devforge.core.errors.DevForgeError` becomes a clean message and exit
code 1 rather than a traceback.
"""

from __future__ import annotations

import asyncio
import contextlib
import sys
from pathlib import Path
from typing import Annotated

import typer

from devforge import __version__
from devforge.cli import (
    context_commands,
    eval_commands,
    git_commands,
    render,
    security_commands,
    skill_commands,
    supplychain_commands,
)
from devforge.core.errors import DevForgeError
from devforge.core.models import Approval, ApprovalStatus, Task, TaskStatus
from devforge.core.orchestrator.context import AppContext
from devforge.core.state.store import ProjectStore
from devforge.debug.benchmark import run_builtin_benchmark
from devforge.observability.logging import stream_sink
from devforge.verification.base import VerificationContext
from devforge.verification.engine import VerificationEngine


def _make_streams_unicode_safe() -> None:
    """Third-party skill text is not ASCII and consoles are not always UTF-8.

    Without this a single character outside the terminal codec aborts a render
    part-written. Replacing unencodable characters degrades the display; crashing
    destroys the output.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            with contextlib.suppress(ValueError, OSError):  # pragma: no cover
                reconfigure(encoding="utf-8", errors="replace")


_make_streams_unicode_safe()

app = typer.Typer(
    name="devforge",
    help="DevForge - an extensible AI software-engineering harness.",
    add_completion=False,
)


def _fail(message: str) -> None:
    render.error(message)
    raise typer.Exit(code=1)


def _context(events: bool = False) -> AppContext:
    try:
        return AppContext.load(extra_sinks=[stream_sink()] if events else None)
    except DevForgeError as exc:
        _fail(str(exc))
        raise


def _interactive_prompter(approval: Approval) -> bool:
    render.console.print(
        f"\n[yellow]approval required[/yellow] gate '{approval.gate}' at step '{approval.step_id}'"
    )
    if approval.prompt:
        render.console.print(f"  {approval.prompt}")
    return typer.confirm("approve?", default=False)


@app.callback(invoke_without_command=True)
def _root(
    ctx: typer.Context,
    version: Annotated[bool, typer.Option("--version", help="Show the version and exit.")] = False,
) -> None:
    if version:
        render.info(f"devforge {__version__}")
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        render.info(ctx.get_help())
        raise typer.Exit()


# --------------------------------------------------------------------------- init


@app.command()
def init(
    path: Annotated[Path | None, typer.Argument(help="Project directory.")] = None,
    name: Annotated[str | None, typer.Option("--name", help="Project name.")] = None,
    runtime: Annotated[str, typer.Option("--runtime", help="Default agent runtime.")] = "mock",
    force: Annotated[
        bool, typer.Option("--force", help="Re-initialise an existing project.")
    ] = False,
) -> None:
    """Create the .devforge project state directory."""
    root = (path or Path.cwd()).resolve()
    try:
        store = ProjectStore.initialize(root, name=name, default_runtime=runtime, force=force)
    except DevForgeError as exc:
        _fail(str(exc))
        return

    config = store.load_config()
    render.success(f"initialised DevForge project '{config.name}' ({config.project_id})")
    render.info(f"  state:   {store.devforge_dir}")
    render.info(f"  runtime: {config.default_runtime}")
    render.info(
        "\nNext:\n"
        "  devforge doctor\n"
        '  devforge run --workflow demo --task "Add authentication" --interactive\n'
        "\nThe demo workflow completes in any project. The feature workflow runs your real\n"
        "tests, linters and build, so it needs a project that has them."
    )


# --------------------------------------------------------------------------- plan


@app.command()
def plan(
    workflow: Annotated[str, typer.Option("--workflow", "-w", help="Workflow name.")] = "feature",
    task: Annotated[str | None, typer.Option("--task", "-t", help="Task description.")] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Show what a workflow would do, without running anything."""
    ctx = _context()
    try:
        spec = ctx.workflows.load(workflow)
    except DevForgeError as exc:
        _fail(str(exc))
        return

    if as_json:
        render.emit_json(spec.model_dump(mode="json"))
        return

    if task:
        render.info(f"[bold]task[/bold] {task}\n")
    render.render_workflow(spec)

    unknown_agents = [s.agent for s in spec.steps if s.agent and s.agent not in ctx.agents]
    unknown_skills = [name for s in spec.steps for name in s.skills if name not in ctx.skills]
    blocked = sorted(
        {
            t
            for s in spec.steps
            for t in s.tools
            if t in ctx.tools and not ctx.tools.get(t).availability().available
        }
    )

    for label, items in (("unknown agents", unknown_agents), ("unknown skills", unknown_skills)):
        if items:
            render.warn(f"{label}: {sorted(set(items))}")
    if blocked:
        render.warn(
            f"unavailable tools required by this workflow: {blocked} - those steps will fail"
        )
    gates = [s.gate for s in spec.steps if s.gate]
    if gates:
        render.info(f"\nhuman approval gates: {', '.join(gates)}")


# ---------------------------------------------------------------------------- run


@app.command()
def run(
    workflow: Annotated[str, typer.Option("--workflow", "-w", help="Workflow name.")] = "feature",
    task: Annotated[str | None, typer.Option("--task", "-t", help="What to build.")] = None,
    runtime: Annotated[str | None, typer.Option("--runtime", help="Agent runtime.")] = None,
    resume: Annotated[
        str | None, typer.Option("--resume", help="Resume an existing task id.")
    ] = None,
    interactive: Annotated[
        bool, typer.Option("--interactive", "-i", help="Decide approvals inline.")
    ] = False,
    events: Annotated[bool, typer.Option("--events", help="Stream JSON events to stderr.")] = False,
) -> None:
    """Execute a workflow, or resume one that is waiting."""
    ctx = _context(events=events)

    try:
        if resume:
            record = ctx.store.load_task(resume)
            spec = ctx.workflows.load(record.workflow)
            if record.status is TaskStatus.COMPLETED:
                render.warn(f"task {record.task_id} is already completed")
                raise typer.Exit()
        else:
            if not task:
                _fail("--task is required (or use --resume TASK_ID)")
                return
            spec = ctx.workflows.load(workflow)
            record = Task(
                project_id=ctx.config.project_id,
                description=task,
                workflow=spec.name,
                runtime=runtime or ctx.config.default_runtime,
            )
        runtime_name = runtime or record.runtime
        record.runtime = runtime_name
        agent_runtime = ctx.runtimes.create(runtime_name)
    except DevForgeError as exc:
        _fail(str(exc))
        return

    availability = agent_runtime.availability()
    if not availability.available:
        _fail(f"runtime '{runtime_name}' is unavailable: {availability.detail}")
        return

    logger = ctx.run_logger(record.task_id)
    orchestrator = ctx.orchestrator(
        runtime=agent_runtime,
        logger=logger,
        prompter=_interactive_prompter if interactive else None,
    )

    render.info(
        f"[bold]{spec.name}[/bold] workflow - {len(spec.steps)} steps - runtime {runtime_name}"
    )
    render.info(f"task {record.task_id}: {record.description}\n")

    try:
        outcome = asyncio.run(orchestrator.run(record, spec))
    except DevForgeError as exc:
        _fail(str(exc))
        return

    render.render_steps(record)
    render.render_approvals(record)
    render.render_errors(record)

    if outcome.completed:
        render.success(f"\nrun completed: {outcome.task_id}")
        return
    if outcome.awaiting_approval:
        render.info(f"\n[yellow]paused[/yellow] {outcome.reason}")
        render.info(f"then: devforge run --resume {outcome.task_id}")
        raise typer.Exit(code=2)
    render.error(f"run failed at '{outcome.stopped_at}': {outcome.reason}")
    raise typer.Exit(code=1)


# ------------------------------------------------------------------------- status


@app.command()
def status(
    task_id: Annotated[
        str | None, typer.Argument(help="Task id (defaults to the latest run).")
    ] = None,
    all_runs: Annotated[bool, typer.Option("--all", help="List every run instead.")] = False,
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Show the state of a run."""
    ctx = _context()

    if all_runs:
        entries = ctx.store.list_tasks()
        if as_json:
            render.emit_json([entry.model_dump(mode="json") for entry in entries])
            return
        if not entries:
            render.info("no runs recorded yet")
            return
        table = render.Table("task", "workflow", "status", "step", "description", box=None)
        for entry in entries:
            table.add_row(
                entry.task_id,
                entry.workflow,
                entry.status,
                entry.current_step or "-",
                entry.description,
            )
        render.console.print(table)
        return

    try:
        record = ctx.store.resolve_task(task_id)
    except DevForgeError as exc:
        _fail(str(exc))
        return

    if as_json:
        render.emit_json(record.model_dump(mode="json"))
        return

    render.render_task_summary(record)
    render.render_steps(record)
    render.render_approvals(record)
    render.render_errors(record)


# ------------------------------------------------------------------------- review


@app.command()
def review(
    task_id: Annotated[
        str | None, typer.Argument(help="Task id (defaults to the latest run).")
    ] = None,
    step: Annotated[str | None, typer.Option("--step", help="Only this step.")] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Show what the agents produced and how it verified."""
    ctx = _context()
    try:
        record = ctx.store.resolve_task(task_id)
    except DevForgeError as exc:
        _fail(str(exc))
        return

    steps = [s for s in record.steps if step is None or s.step_id == step]
    if as_json:
        render.emit_json([s.model_dump(mode="json") for s in steps])
        return

    render.render_task_summary(record)
    for entry in steps:
        render.console.rule(f"{entry.step_id} ({entry.status.value})")
        for attempt in entry.attempts:
            result = attempt.agent_result
            if result is not None:
                render.info(
                    f"[bold]attempt {attempt.attempt}[/bold] "
                    f"{result.runtime}/{entry.agent or '-'}: {result.summary}"
                )
                if result.output:
                    render.console.print(render.Panel(result.output, expand=False))
                if result.error:
                    render.error(result.error)
            if attempt.verification:
                render.render_verification(attempt.verification, show_output=True)
    if record.artifacts:
        table = render.Table("artifact", "kind", "step", "description", box=None)
        for artifact in record.artifacts:
            table.add_row(
                artifact.path, artifact.kind, artifact.step_id or "-", artifact.description
            )
        render.console.print(table)


# ------------------------------------------------------------------------- verify


@app.command()
def verify(
    workflow: Annotated[
        str, typer.Option("--workflow", "-w", help="Workflow defining the verifiers.")
    ] = "feature",
    verifier: Annotated[
        list[str] | None, typer.Option("--verifier", help="Run only these verifier ids.")
    ] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Run verifiers against the working tree, outside any run."""
    ctx = _context()
    try:
        spec = ctx.workflows.load(workflow)
        specs = VerificationEngine.collect_specs(spec, ctx.config.verifiers)
        selected = VerificationEngine.select(specs, list(verifier) if verifier else sorted(specs))
    except DevForgeError as exc:
        _fail(str(exc))
        return

    if not selected:
        render.info("no verifiers defined")
        return

    context = VerificationContext(workspace=ctx.store.root, policy=ctx.policy, logger=ctx.logger)
    report = asyncio.run(ctx.verification.run(selected, context))

    if as_json:
        render.emit_json([result.model_dump(mode="json") for result in report.results])
    else:
        render.render_verification(report.results, show_output=True)

    if not report.passed:
        raise typer.Exit(code=1)


# ------------------------------------------------------------------------ approve


@app.command()
def approve(
    task_id: Annotated[
        str | None, typer.Argument(help="Task id (defaults to the latest run).")
    ] = None,
    gate: Annotated[
        str | None, typer.Option("--gate", help="Gate to decide (defaults to the pending one).")
    ] = None,
    reject: Annotated[bool, typer.Option("--reject", help="Reject instead of approve.")] = False,
    reason: Annotated[str, typer.Option("--reason", help="Why.")] = "",
    by: Annotated[str, typer.Option("--by", help="Who decided.")] = "human",
) -> None:
    """Approve or reject a pending gate."""
    from devforge.approval.gate import ApprovalGate

    ctx = _context()
    try:
        record = ctx.store.resolve_task(task_id)
    except DevForgeError as exc:
        _fail(str(exc))
        return

    pending = [a for a in record.approvals if a.status is ApprovalStatus.PENDING]
    if not pending:
        render.info(f"task {record.task_id} has no pending approvals")
        return
    if gate is None:
        if len(pending) > 1:
            _fail(f"several gates are pending ({[a.gate for a in pending]}); pass --gate")
            return
        gate = pending[0].gate

    approval = ApprovalGate(ctx.policy).resolve(
        record, gate=gate, approved=not reject, by=by, reason=reason
    )
    if approval.status is ApprovalStatus.APPROVED and record.status is TaskStatus.AWAITING_APPROVAL:
        record.status = TaskStatus.PENDING
    if approval.status is ApprovalStatus.REJECTED:
        record.status = TaskStatus.FAILED
    ctx.store.save_task(record)

    render.success(f"gate '{gate}' {approval.status.value} by {by}")
    if approval.status is ApprovalStatus.APPROVED:
        render.info(f"resume with: devforge run --resume {record.task_id}")


# ----------------------------------------------------------------- catalogue views


@app.command()
def skills(
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """List discoverable skills."""
    ctx = _context()
    items = ctx.skills.all()
    if as_json:
        render.emit_json([skill.model_dump(mode="json") for skill in items])
        return
    table = render.Table(
        "skill", "version", "capabilities", "dependencies", "description", box=None
    )
    for skill in items:
        table.add_row(
            skill.name,
            skill.version,
            ", ".join(skill.capabilities) or "-",
            ", ".join(skill.dependencies) or "-",
            skill.description,
        )
    render.console.print(table)


@app.command()
def workflows(
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """List available workflows."""
    ctx = _context()
    available = ctx.workflows.available()
    rows = []
    for name, path in available.items():
        try:
            spec = ctx.workflows.load(name)
            rows.append(
                (
                    name,
                    str(len(spec.steps)),
                    ", ".join(spec.tags) or "-",
                    spec.description.strip().splitlines()[0] if spec.description.strip() else "",
                    str(path),
                )
            )
        except DevForgeError as exc:
            rows.append((name, "-", "-", f"INVALID: {exc}", str(path)))

    if as_json:
        render.emit_json(
            [
                {"name": r[0], "steps": r[1], "tags": r[2], "description": r[3], "path": r[4]}
                for r in rows
            ]
        )
        return
    table = render.Table("workflow", "steps", "tags", "description", box=None)
    for row in rows:
        table.add_row(row[0], row[1], row[2], row[3])
    render.console.print(table)


@app.command()
def runtimes(
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """List agent runtimes and whether they are usable here."""
    ctx = _context()
    report = ctx.runtimes.availability()
    if as_json:
        render.emit_json(
            {name: {"available": ok, "detail": detail} for name, (ok, detail) in report.items()}
        )
        return
    table = render.Table("runtime", "available", "detail", box=None)
    for name, (ok, detail) in report.items():
        table.add_row(name, "[green]yes[/green]" if ok else "[red]no[/red]", detail)
    render.console.print(table)


# -------------------------------------------------------------------------- bench


@app.command()
def bench(
    solver: Annotated[
        str,
        typer.Option(
            "--solver",
            help="reference (known-good fix), cheat (weakens tests), none (no change).",
        ),
    ] = "reference",
    case: Annotated[
        list[str] | None, typer.Option("--case", help="Run only these case ids.")
    ] = None,
    report_path: Annotated[
        Path | None, typer.Option("--report", help="Write the Markdown report here.")
    ] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Measure repair success rate against the seeded-defect benchmark.

    The two built-in solvers are controls, not agents. `reference` applies the known
    fix and must score 100%; `cheat` deletes assertions until the suite is green and
    must score 0%. A run where those two anchors move is a broken grader, and any
    repair rate measured with it is meaningless.
    """
    ctx = _context()
    try:
        report = asyncio.run(
            run_builtin_benchmark(
                policy=ctx.policy,
                solver_name=solver,
                case_ids=list(case) if case else None,
                logger=ctx.logger,
            )
        )
    except DevForgeError as exc:
        _fail(str(exc))
        return

    if report_path is not None:
        report_path.write_text(report.render(), encoding="utf-8")

    if as_json:
        render.emit_json(
            {
                "solver": report.solver,
                "total": report.total,
                "repaired": report.repaired,
                "success_rate": report.success_rate,
                "by_outcome": report.by_outcome(),
                "results": [result.model_dump(mode="json") for result in report.results],
            }
        )
        return

    render.render_benchmark(report)
    if report_path is not None:
        render.info(f"report written to {report_path}")


# ------------------------------------------------------------------------- doctor


@app.command()
def doctor(
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Check the project and environment, and report what is unavailable."""
    problems: list[str] = []
    report: dict = {}

    try:
        ctx = AppContext.load()
    except DevForgeError as exc:
        if as_json:
            render.emit_json({"ok": False, "problems": [str(exc)]})
        else:
            render.error(str(exc))
        raise typer.Exit(code=1) from exc

    report["project"] = {"root": str(ctx.store.root), "project_id": ctx.config.project_id}
    report["runtimes"] = {
        name: {"available": ok, "detail": detail}
        for name, (ok, detail) in ctx.runtimes.availability().items()
    }
    report["tools"] = {
        name: {"available": status.available, "detail": status.detail}
        for name, status in ctx.tools.availability().items()
    }

    workflow_report: dict[str, str] = {}
    for name in ctx.workflows.available():
        try:
            spec = ctx.workflows.load(name)
            missing = spec.missing_verifiers({v.id for v in ctx.config.verifiers})
            workflow_report[name] = (
                f"ok ({len(spec.steps)} steps)"
                if not missing
                else f"missing verifiers {sorted(missing)}"
            )
            if missing:
                problems.append(
                    f"workflow '{name}' references undefined verifiers {sorted(missing)}"
                )
        except DevForgeError as exc:
            workflow_report[name] = f"INVALID: {exc}"
            problems.append(f"workflow '{name}' is invalid: {exc}")
    report["workflows"] = workflow_report

    broken_skills = ctx.skills.unresolved_dependencies()
    report["skills"] = {"count": len(ctx.skills), "unresolved_dependencies": broken_skills}
    problems += [f"skill '{n}' depends on unknown skills {d}" for n, d in broken_skills.items()]

    unknown_agent_skills = {
        agent.name: [s for s in agent.skills if s not in ctx.skills] for agent in ctx.agents.all()
    }
    unknown_agent_skills = {k: v for k, v in unknown_agent_skills.items() if v}
    report["agents"] = {"count": len(ctx.agents), "unknown_skills": unknown_agent_skills}
    problems += [
        f"agent '{n}' references unknown skills {s}" for n, s in unknown_agent_skills.items()
    ]

    if not any(ok for ok, _ in ctx.runtimes.availability().values()):
        problems.append("no agent runtime is available")

    report["ok"] = not problems
    report["problems"] = problems

    if as_json:
        render.emit_json(report)
    else:
        render.info(f"project  {ctx.store.root} ({ctx.config.project_id})")
        table = render.Table("component", "status", "detail", box=None)
        for name, (ok, detail) in ctx.runtimes.availability().items():
            table.add_row(
                f"runtime:{name}", "[green]ok[/green]" if ok else "[red]unavailable[/red]", detail
            )
        for name, status in ctx.tools.availability().items():
            table.add_row(
                f"tool:{name}",
                "[green]ok[/green]" if status.available else "[yellow]unavailable[/yellow]",
                status.detail,
            )
        for name, state in workflow_report.items():
            table.add_row(
                f"workflow:{name}",
                "[green]ok[/green]" if state.startswith("ok") else "[red]problem[/red]",
                state,
            )
        table.add_row(
            "skills",
            "[green]ok[/green]" if not broken_skills else "[red]problem[/red]",
            f"{len(ctx.skills)} discovered",
        )
        table.add_row(
            "agents",
            "[green]ok[/green]" if not unknown_agent_skills else "[red]problem[/red]",
            f"{len(ctx.agents)} discovered",
        )
        render.console.print(table)

        render.warn(
            "DevForge is not a sandbox: the permission policy is an allowlist over "
            "processes run as you. See docs/security.md."
        )
        if problems:
            for problem in problems:
                render.error(problem)
            raise typer.Exit(code=1)
        render.success("no problems found")


# --------------------------------------------------------------- skill supply chain
#
# Read-only. See devforge/cli/supplychain_commands.py and
# docs/security/skill-supply-chain.md.
app.add_typer(supplychain_commands.registry_app, name="registry")
# Third-party skill lifecycle: search, inspect, audit, install, update, remove, list.
app.add_typer(skill_commands.skill_app, name="skill")
app.add_typer(security_commands.app, name="security")
app.add_typer(eval_commands.app, name="eval")
app.add_typer(git_commands.app, name="git")
# Codebase intelligence: build the map, inspect what an agent will be given.
app.command("index")(context_commands.index_command)
app.command("context")(context_commands.context_command)
app.command("context-doctor")(context_commands.doctor_command)
app.command("inspect-skill")(supplychain_commands.inspect_skill_command)


if __name__ == "__main__":  # pragma: no cover
    app()
