"""`devforge falsify` - search for counterexamples, read reports, explain findings.

Exit codes, chosen so this is usable in CI:

* ``0`` - the search completed and found no counterexample, **or** it could not run
  and said so. Surviving is not passing, and the command says as much in its output.
* ``1`` - a counterexample was found, or the search could not complete. Both mean
  there is something to act on: evidence against the change, or a gap in the search
  that nobody has looked at.

``INCOMPLETE`` shares an exit code with ``FAILED`` on purpose. A truncated search
that exits 0 is indistinguishable in CI from a clean one, and that indistinguishability
is the failure mode this whole subsystem exists to prevent.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated

import typer

from devforge.cli import render
from devforge.core.errors import DevForgeError
from devforge.core.state.store import ProjectStore
from devforge.falsification.engine import FalsificationEngine
from devforge.falsification.models import (
    Budget,
    FalsificationStatus,
    MutationScope,
    StrategyName,
)
from devforge.falsification.patch import collect_patch
from devforge.falsification.regression import render_regression_test, render_weakness_test
from devforge.falsification.store import (
    corpus_entries,
    find_finding,
    list_reports,
    record_corpus,
    resolve_report,
    save_report,
)
from devforge.observability.logging import RunLogger, stream_sink
from devforge.policy.engine import PolicyEngine

app = typer.Typer(
    help=(
        "Search adversarially for counterexamples. Falsification does not prove "
        "correctness - it looks for evidence that the change or its tests are wrong."
    ),
    no_args_is_help=False,
    invoke_without_command=True,
)


def _fail(message: str) -> None:
    render.error(message)
    raise typer.Exit(code=1)


def _store(path: Path | None = None) -> ProjectStore:
    try:
        return ProjectStore.discover(path)
    except DevForgeError as exc:
        _fail(str(exc))
        raise


@app.callback(invoke_without_command=True)
def _root(
    ctx: typer.Context,
    task: Annotated[
        str | None, typer.Option("--task", help="Attribute the run to this task id.")
    ] = None,
    strategy: Annotated[
        list[str] | None,
        typer.Option("--strategy", "-s", help="Strategy to run. Repeatable."),
    ] = None,
    run_all: Annotated[
        bool, typer.Option("--all", help="Run every strategy applicable to the targets.")
    ] = False,
    target: Annotated[
        list[str] | None, typer.Option("--target", "-t", help="What to attack. Repeatable.")
    ] = None,
    scope: Annotated[
        str, typer.Option("--scope", help="diff (default), files or module.")
    ] = "diff",
    max_mutants: Annotated[
        int | None, typer.Option("--max-mutants", help="Cap on generated mutants.")
    ] = None,
    max_duration: Annotated[
        int | None, typer.Option("--max-duration", help="Wall-clock budget in seconds.")
    ] = None,
    probes: Annotated[
        int | None,
        typer.Option("--flakiness-probes", help="Baseline runs used to detect flaky tests."),
    ] = None,
    events: Annotated[
        bool, typer.Option("--events", help="Stream JSON events to stderr.")
    ] = False,
    as_json: Annotated[bool, typer.Option("--json", help="Emit the report as JSON.")] = False,
) -> None:
    """Run a falsification pass over the current patch."""
    if ctx.invoked_subcommand is not None:
        return

    store = _store()
    policy = PolicyEngine.load(store.root, workspace=store.root)
    logger = RunLogger([stream_sink()] if events else [])

    strategies = list(strategy or [])
    if run_all:
        strategies = [name.value for name in StrategyName]

    budget_fields: dict[str, int] = {}
    if max_mutants is not None:
        budget_fields["max_mutants"] = max_mutants
    if max_duration is not None:
        budget_fields["max_duration_s"] = max_duration
    if probes is not None:
        budget_fields["flakiness_probes"] = probes

    try:
        budget = Budget(**budget_fields)
        mutation_scope = MutationScope(scope)
    except (ValueError, TypeError) as exc:
        _fail(str(exc))
        return

    async def run() -> object:
        patch = await collect_patch(store.root, policy, logger=logger)
        if patch.empty:
            render.warn(
                "no patch was found to attack"
                + (f": {patch.unavailable_reason}" if patch.unavailable_reason else "")
            )
        return await FalsificationEngine().run(
            source_root=store.root,
            policy=policy,
            strategies=strategies or None,
            target_names=target or None,
            budget=budget,
            config={"lines": patch.lines},
            diff=patch.diff,
            changed_files=patch.files,
            scope=mutation_scope,
            task_id=task or "",
            logger=logger,
        )

    try:
        report = asyncio.run(run())
    except (DevForgeError, ValueError) as exc:
        _fail(str(exc))
        return

    try:
        path = save_report(store, report)
        record_corpus(store, report)
    except OSError as exc:  # pragma: no cover - disk failure
        render.warn(f"the report could not be persisted: {exc}")
        path = None

    if as_json:
        render.emit_json(report.model_dump(mode="json"))
    else:
        render.console.print(report.render())
        if path is not None:
            render.info(f"report written to {path}")

    if report.status in {FalsificationStatus.FAILED, FalsificationStatus.INCOMPLETE}:
        raise typer.Exit(code=1)


@app.command("report")
def report_command(
    run_id: Annotated[
        str | None, typer.Argument(help="Run id. Defaults to the most recent run.")
    ] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Emit the report as JSON.")] = False,
) -> None:
    """Show a persisted falsification report."""
    store = _store()
    try:
        report = resolve_report(store, run_id)
    except DevForgeError as exc:
        _fail(str(exc))
        return

    if as_json:
        render.emit_json(report.model_dump(mode="json"))
        return
    render.console.print(report.render())


@app.command("explain")
def explain_command(
    finding_id: Annotated[str, typer.Argument(help="Finding id from a report.")],
    regression: Annotated[
        bool,
        typer.Option("--regression", help="Print a regression test reproducing the finding."),
    ] = False,
) -> None:
    """Explain one finding: what was attacked, what happened, how to reproduce it."""
    store = _store()
    found = find_finding(store, finding_id)
    if found is None:
        _fail(f"unknown finding '{finding_id}'")
        return
    finding, report = found

    lines = [f"[bold]{finding_id}[/bold]", ""]
    if hasattr(finding, "strategy"):
        lines += [
            f"strategy   : {finding.strategy.value}",
            f"target     : {finding.target}",
            f"severity   : {finding.severity.value}",
            f"location   : {finding.file or '(unknown)'}"
            + (f"::{finding.symbol}" if finding.symbol else ""),
            "",
            f"input      : {finding.input or '(none recorded)'}",
        ]
        if finding.reduction and finding.reduction.succeeded:
            lines.append(f"minimised  : {finding.reduction.minimized}")
            lines.append(f"             ({finding.reduction.detail})")
        lines += [
            f"expected   : {finding.expected}",
            f"actual     : {finding.actual}",
            "",
            f"reproduce  : {' '.join(finding.reproduction) or '(not recorded)'}",
        ]
        if finding.evidence:
            lines += ["", "evidence:", finding.evidence]
    else:
        lines += [
            "kind       : TEST_WEAKNESS",
            f"site       : {finding.file}:{finding.line}",
            f"operator   : {finding.operator}",
            f"severity   : {finding.severity.value}",
            "",
            f"unchecked  : {finding.unchecked_behavior}",
            f"tests      : {', '.join(finding.relevant_tests) or '(none identified)'}",
            "",
            f"reproduce  : {' '.join(finding.reproduction) or '(not recorded)'}",
            "",
            "A surviving mutant is a gap in the tests, not necessarily a defect in "
            "the code.",
        ]

    lines += ["", f"from run   : {report.run_id} ({report.status.value})"]
    render.console.print("\n".join(lines))

    if regression:
        render.console.print("\n[bold]proposed regression test[/bold]\n")
        source = (
            render_regression_test(finding)
            if hasattr(finding, "strategy")
            else render_weakness_test(finding)
        )
        render.console.print(source)


@app.command("list")
def list_command(
    task: Annotated[str | None, typer.Option("--task", help="Limit to one task.")] = None,
) -> None:
    """List persisted falsification runs, newest first."""
    store = _store()
    paths = list_reports(store, task)
    if not paths:
        render.info("no falsification run has been recorded yet")
        return
    for path in paths[:25]:
        render.console.print(f"  {path.stem}  {path.parent.parent.name}")


@app.command("corpus")
def corpus_command() -> None:
    """Show the falsification corpus: counterexamples preserved across runs."""
    store = _store()
    entries = corpus_entries(store)
    if not entries:
        render.info("the falsification corpus is empty")
        return
    render.console.print(f"[bold]{len(entries)} counterexample(s) in the corpus[/bold]\n")
    for entry in entries[:50]:
        render.console.print(
            f"  {entry.get('finding_id')}  [{entry.get('strategy')}/{entry.get('target')}]  "
            f"{entry.get('file') or '?'}  {entry.get('severity')}"
        )
