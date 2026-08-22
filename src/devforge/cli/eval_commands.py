"""`devforge eval` - run, compare, report.

Exit codes, chosen so this is usable in CI:

* ``0`` - the run completed and nothing regressed against the baseline;
* ``1`` - a regression against the named baseline, or a broken benchmark
  (``invalid`` cases), or a calibration anchor that scored what it must not.

A low success rate is **not** an error. It is a measurement, and a command that
fails the build for it teaches people to stop running it. Only two things fail:
something got worse than a recorded baseline, and the benchmark itself is broken.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated

import typer
from rich.markdown import Markdown

from devforge.cli import render
from devforge.core.errors import DevForgeError
from devforge.core.state.store import ProjectStore
from devforge.eval.compare import compare_reports
from devforge.eval.models import CaseOutcome, Category
from devforge.eval.runner import EvalRunner
from devforge.eval.store import list_reports, resolve_report, save_report
from devforge.eval.suites import load_cases, load_config, load_configs
from devforge.observability.logging import RunLogger, null_logger
from devforge.policy.engine import PolicyEngine

app = typer.Typer(
    help="Measure DevForge against benchmark cases with known answers.",
    no_args_is_help=True,
)


def _root(path: Path | None) -> Path:
    """The project root, or the current directory when there is no project."""
    if path is not None:
        return Path(path).resolve()
    try:
        return ProjectStore.discover(None).root
    except DevForgeError:
        return Path.cwd().resolve()


def _fail(message: str) -> None:
    render.error(message)
    raise typer.Exit(code=1)


@app.command()
def run(
    config_id: Annotated[str, typer.Argument(help="Configuration id to measure.")],
    category: Annotated[
        list[str] | None, typer.Option("--category", "-c", help="Limit to a category.")
    ] = None,
    case: Annotated[
        list[str] | None, typer.Option("--case", help="Run only these case ids.")
    ] = None,
    baseline: Annotated[
        str | None,
        typer.Option("--baseline", help="Report path or config id to compare against."),
    ] = None,
    path: Annotated[Path | None, typer.Option("--path", help="Project root.")] = None,
    save: Annotated[bool, typer.Option("--save/--no-save", help="Write to reports/.")] = True,
    keep_failures: Annotated[
        bool, typer.Option("--keep-failures", help="Keep failed workspaces under reports/.")
    ] = False,
    events: Annotated[bool, typer.Option("--events", help="Stream JSON events to stderr.")] = False,
    as_json: Annotated[bool, typer.Option("--json", help="Emit the report as JSON.")] = False,
) -> None:
    """Run a benchmark suite under one configuration."""
    root = _root(path)
    try:
        config = load_config(config_id, root)
        cases, suites = load_cases(root, categories=category, case_ids=case)
    except DevForgeError as exc:
        _fail(str(exc))
        return

    if not cases:
        _fail("no cases matched the filters")
        return

    logger = _logger(events)
    runner = EvalRunner(
        config=config,
        policy=PolicyEngine.load(root, workspace=root),
        logger=logger,
        keep_workspaces=(root / "reports" / "workspaces") if keep_failures else None,
    )

    render.info(
        f"[bold]{config.id}[/bold] - {len(cases)} case(s) "
        f"- driver {config.driver} - runtime {config.runtime}"
    )
    report = asyncio.run(runner.run(cases, suites=suites))

    if as_json:
        render.emit_json(report.model_dump(mode="json"))
    else:
        render.render_eval(report)

    saved: Path | None = None
    if save:
        saved = save_report(report, root)
        render.info(f"\nsaved {saved}")

    problems = _calibration_problems(report)
    exit_code = 0

    if baseline:
        try:
            previous = resolve_report(baseline, root)
        except DevForgeError as exc:
            _fail(str(exc))
            return
        comparison = compare_reports(previous, report)
        if not as_json:
            render.console.print(Markdown(comparison.render()))
        if comparison.has_regression:
            names = ", ".join(case.case_id for case in comparison.regressions)
            render.error(f"\nregression against {baseline}: {names}")
            exit_code = 1

    for problem in problems:
        render.error(problem)
        exit_code = 1

    if exit_code:
        raise typer.Exit(code=exit_code)


@app.command()
def compare(
    baseline: Annotated[str, typer.Argument(help="Report path or config id.")],
    candidate: Annotated[str, typer.Argument(help="Report path or config id.")],
    path: Annotated[Path | None, typer.Option("--path", help="Project root.")] = None,
    fail_on_regression: Annotated[
        bool, typer.Option("--fail-on-regression", help="Exit 1 if a case stopped passing.")
    ] = False,
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Compare two saved reports. Names a difference; never names a winner."""
    root = _root(path)
    try:
        first = resolve_report(baseline, root)
        second = resolve_report(candidate, root)
    except DevForgeError as exc:
        _fail(str(exc))
        return

    comparison = compare_reports(first, second)
    if as_json:
        render.emit_json(comparison.model_dump(mode="json"))
    else:
        render.console.print(Markdown(comparison.render()))

    if fail_on_regression and comparison.has_regression:
        raise typer.Exit(code=1)


@app.command()
def report(
    reference: Annotated[
        str | None, typer.Argument(help="Report path or config id (default: the latest).")
    ] = None,
    path: Annotated[Path | None, typer.Option("--path", help="Project root.")] = None,
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write the Markdown here.")
    ] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Render a saved report as Markdown."""
    root = _root(path)
    try:
        if reference is None:
            reports = list_reports(root)
            if not reports:
                _fail(f"no reports under {root / 'reports'}; run 'devforge eval run' first")
                return
            saved = resolve_report(str(reports[0]), root)
        else:
            saved = resolve_report(reference, root)
    except DevForgeError as exc:
        _fail(str(exc))
        return

    if as_json:
        render.emit_json(saved.model_dump(mode="json"))
        return

    markdown = saved.render()
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(markdown, encoding="utf-8")
        render.success(f"wrote {output}")
        return
    render.console.print(Markdown(markdown))


@app.command("cases")
def list_cases(
    category: Annotated[
        list[str] | None, typer.Option("--category", "-c", help="Limit to a category.")
    ] = None,
    path: Annotated[Path | None, typer.Option("--path", help="Project root.")] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """List the benchmark cases that apply here."""
    root = _root(path)
    try:
        cases, suites = load_cases(root, categories=category)
    except DevForgeError as exc:
        _fail(str(exc))
        return

    if as_json:
        render.emit_json(
            {
                "suites": suites,
                "cases": [
                    {
                        "id": case.id,
                        "category": case.category.value,
                        "title": case.title,
                        "workflow": case.workflow,
                        "requires": case.requires,
                    }
                    for case in cases
                ],
            }
        )
        return
    render.render_eval_cases(cases, [category.value for category in Category])


@app.command("configs")
def list_configs(
    path: Annotated[Path | None, typer.Option("--path", help="Project root.")] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """List the evaluation configurations that apply here."""
    configs = load_configs(_root(path))
    if as_json:
        render.emit_json({key: value.model_dump(mode="json") for key, value in configs.items()})
        return
    render.render_eval_configs(list(configs.values()))


def _logger(events: bool) -> RunLogger:
    if not events:
        return null_logger()
    from devforge.observability.logging import stream_sink

    return RunLogger([stream_sink()])


def _calibration_problems(report) -> list[str]:
    """Things that make the run's numbers unreadable rather than merely bad.

    An invalid case means a check was already failing before anything was
    attempted; an anchor that scores wrong means the grader itself is off. Both
    invalidate the rest of the report, so both fail the command - unlike a low
    score, which is a result.
    """
    problems: list[str] = []
    invalid = [r.case_id for r in report.results if r.outcome is CaseOutcome.INVALID]
    if invalid:
        problems.append(
            f"\nbroken benchmark: {', '.join(invalid)} failed a guard before the attempt"
        )

    rate = report.metrics.value_of("task_success_rate")
    if rate is None:
        return problems
    if report.config.driver == "reference" and rate < 1.0:
        problems.append(
            f"\ncalibration failed: the reference solution scored {rate:.0%}, not 100%. "
            "The grader is rejecting correct work, so no other number here can be read."
        )
    if report.config.driver in {"cheat", "none"} and rate > 0.0:
        problems.append(
            f"\ncalibration failed: the '{report.config.driver}' anchor scored {rate:.0%}, "
            "not 0%. The grader can be beaten without doing the work."
        )
    return problems
