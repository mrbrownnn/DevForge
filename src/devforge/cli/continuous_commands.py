"""`devforge continuous` - detect, propose, approve, execute, verify.

The pipeline the brief names, one command per stage, with the approval in the
middle where it belongs. Nothing before it changes a file and nothing after it
runs without it.

Exit codes: `0` normally; `1` when something needs a decision that has not been
made - an unapproved proposal handed to `execute`, a verification that found the
finding still firing. Detecting findings is never an error. A backlog is a
measurement of a repository, and a command that fails the build for having one
teaches people to stop running it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from devforge.cli import render
from devforge.continuous.backlog import (
    approve as approve_proposal,
)
from devforge.continuous.backlog import (
    execute as execute_proposal,
)
from devforge.continuous.backlog import (
    load_accepted,
    load_backlog,
    save_backlog,
    summarise,
)
from devforge.continuous.backlog import (
    reject as reject_proposal,
)
from devforge.continuous.backlog import (
    verify as verify_proposal,
)
from devforge.continuous.engine import detect, prioritize, propose
from devforge.continuous.models import DEFAULT_MIN_CONFIDENCE, Category
from devforge.core.errors import DevForgeError
from devforge.core.state.store import ProjectStore

app = typer.Typer(
    help="Find engineering work nobody has filed yet, and propose it.",
    no_args_is_help=True,
)


def _root(path: Path | None) -> Path:
    if path is not None:
        return Path(path).resolve()
    try:
        return ProjectStore.discover(None).root
    except DevForgeError:
        return Path.cwd().resolve()


def _fail(message: str) -> None:
    render.error(message)
    raise typer.Exit(code=1)


def _categories(names: list[str] | None) -> list[Category] | None:
    if not names:
        return None
    known = {category.value: category for category in Category}
    unknown = [name for name in names if name not in known]
    if unknown:
        _fail(f"unknown categor(ies) {unknown}; expected some of {sorted(known)}")
    return [known[name] for name in names]


@app.command("detect")
def detect_command(
    path: Annotated[Path | None, typer.Option("--path", help="Project root.")] = None,
    category: Annotated[
        list[str] | None, typer.Option("--category", "-c", help="Limit to a category.")
    ] = None,
    min_confidence: Annotated[
        float, typer.Option("--min-confidence", help="Withhold findings below this.")
    ] = DEFAULT_MIN_CONFIDENCE,
    show_withheld: Annotated[
        bool, typer.Option("--show-withheld", help="Include low-confidence findings.")
    ] = False,
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Scan the repository for work worth doing. Changes nothing."""
    root = _root(path)
    try:
        report = detect(
            root,
            categories=_categories(category),
            min_confidence=0.0 if show_withheld else min_confidence,
            suppressions=load_accepted(root),
        )
    except DevForgeError as exc:
        _fail(str(exc))
        return

    if as_json:
        render.emit_json(report.model_dump(mode="json"))
        return
    render.render_findings(report)


@app.command("propose")
def propose_command(
    path: Annotated[Path | None, typer.Option("--path", help="Project root.")] = None,
    category: Annotated[
        list[str] | None, typer.Option("--category", "-c", help="Limit to a category.")
    ] = None,
    limit: Annotated[int, typer.Option("--limit", help="Most proposals to add.")] = 10,
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Detect, then record proposals in the backlog. Still changes no code."""
    root = _root(path)
    try:
        report = detect(root, categories=_categories(category), suppressions=load_accepted(root))
        backlog = load_backlog(root)
        added, known = backlog.merge(propose(prioritize(report.findings), limit=limit))
        save_backlog(backlog, root)
    except DevForgeError as exc:
        _fail(str(exc))
        return

    if as_json:
        render.emit_json(
            {
                "added": [proposal.model_dump(mode="json") for proposal in added],
                "already_known": [proposal.proposal_id for proposal in known],
            }
        )
        return

    render.render_proposals(added, title="proposed")
    if known:
        render.info(
            f"\n[dim]{len(known)} proposal(s) already in the backlog; their decisions "
            "were left alone[/dim]"
        )
    if added:
        render.info("\nNothing runs until someone approves it:")
        render.info(f"  devforge continuous approve {added[0].proposal_id}")


@app.command("backlog")
def show_backlog(
    path: Annotated[Path | None, typer.Option("--path", help="Project root.")] = None,
    all_states: Annotated[bool, typer.Option("--all", help="Include closed ones.")] = False,
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Show the proposals this project has, and what happened to them."""
    root = _root(path)
    try:
        backlog = load_backlog(root)
    except DevForgeError as exc:
        _fail(str(exc))
        return

    proposals = backlog.proposals if all_states else backlog.open
    if as_json:
        render.emit_json(
            {
                "counts": summarise(backlog),
                "proposals": [proposal.model_dump(mode="json") for proposal in proposals],
            }
        )
        return
    render.render_proposals(proposals, title="backlog", counts=summarise(backlog))


@app.command()
def approve(
    proposal_id: Annotated[str, typer.Argument(help="Proposal to approve.")],
    by: Annotated[str, typer.Option("--by", help="Who approved it.")] = "",
    reason: Annotated[str, typer.Option("--reason", help="Why.")] = "",
    path: Annotated[Path | None, typer.Option("--path", help="Project root.")] = None,
) -> None:
    """Agree that a proposal is worth doing."""
    root = _root(path)
    try:
        backlog = load_backlog(root)
        proposal = approve_proposal(backlog, proposal_id, by=by, reason=reason)
        save_backlog(backlog, root)
    except DevForgeError as exc:
        _fail(str(exc))
        return
    render.success(f"approved {proposal.proposal_id}: {proposal.title}")
    render.info(f"  next: devforge continuous execute {proposal.proposal_id}")


@app.command()
def reject(
    proposal_id: Annotated[str, typer.Argument(help="Proposal to reject.")],
    by: Annotated[str, typer.Option("--by", help="Who rejected it.")] = "",
    reason: Annotated[str, typer.Option("--reason", help="Why.")] = "",
    path: Annotated[Path | None, typer.Option("--path", help="Project root.")] = None,
) -> None:
    """Decide a proposal is not worth doing. The decision survives re-detection."""
    root = _root(path)
    try:
        backlog = load_backlog(root)
        proposal = reject_proposal(backlog, proposal_id, by=by, reason=reason)
        save_backlog(backlog, root)
    except DevForgeError as exc:
        _fail(str(exc))
        return
    render.info(f"rejected {proposal.proposal_id}: {proposal.title}")


@app.command()
def execute(
    proposal_id: Annotated[str, typer.Argument(help="Approved proposal to prepare.")],
    path: Annotated[Path | None, typer.Option("--path", help="Project root.")] = None,
) -> None:
    """Prepare an approved proposal: an isolated worktree and the issue to work from.

    This does not edit code. It creates the place where the work can happen and
    writes down what the work is; the work itself runs through the ordinary
    workflow with its ordinary gates.
    """
    root = _root(path)
    try:
        backlog = load_backlog(root)
        preparation = execute_proposal(backlog, proposal_id, root)
        save_backlog(backlog, root)
    except DevForgeError as exc:
        _fail(str(exc))
        return

    render.success(f"prepared {preparation.proposal_id}")
    render.info(f"  worktree: {preparation.worktree}")
    render.info(f"  branch:   {preparation.branch}")
    render.info(f"  issue:    {preparation.issue_path}")
    render.info(f"\nNo source file was changed. In that worktree:\n  {preparation.next_command()}")


@app.command()
def verify(
    proposal_id: Annotated[str, typer.Argument(help="Proposal to verify.")],
    path: Annotated[Path | None, typer.Option("--path", help="Where to re-detect.")] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Re-run the detectors and check whether the findings stopped firing.

    Point `--path` at the worktree where the work happened. Verification is a
    fresh detection, not a report of what a workflow said about itself.
    """
    root = _root(path)
    try:
        backlog = load_backlog(_root(None))
        result = verify_proposal(backlog, proposal_id, root)
        save_backlog(backlog, _root(None))
    except DevForgeError as exc:
        _fail(str(exc))
        return

    if as_json:
        render.emit_json(result.model_dump(mode="json"))
    else:
        render.render_continuous_verification(result)

    if not result.complete:
        raise typer.Exit(code=1)
