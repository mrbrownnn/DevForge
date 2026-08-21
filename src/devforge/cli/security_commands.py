"""`devforge security` - scan, audit, sbom, threats, report.

Exit codes are chosen so this is usable in CI without anyone having to invent a
convention:

* ``0`` - nothing blocking;
* ``1`` - a high or critical finding, or a failed control check.

Warnings never fail a build. The audit warns on every run that there is no
OS-level sandbox, and a permanent, unfixable warning that breaks CI is a warning
people delete. Findings at ``medium`` and below do not fail either: they are for a
human to triage, and a scanner that blocks on its own false positives gets
switched off.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.markdown import Markdown

from devforge.cli import render
from devforge.core.errors import DevForgeError
from devforge.core.state.store import ProjectStore
from devforge.security.audit import audit_project
from devforge.security.catalog import LAYERS, THREATS
from devforge.security.report import NO_GUARANTEE, render_report
from devforge.security.sbom import build_sbom
from devforge.security.scan import scan_workspace

app = typer.Typer(
    help="Security scanning, configuration audit and reporting.",
    no_args_is_help=True,
)


def _root(path: Path | None) -> Path:
    """The project root, or the given directory when there is no project yet.

    A security scan should work on a directory nobody has run `devforge init` in -
    the moment you most want to look at a repository is before you have set
    anything up in it.
    """
    if path is not None:
        return Path(path).resolve()
    try:
        return ProjectStore.discover(None).root
    except DevForgeError:
        return Path.cwd().resolve()


@app.command()
def scan(
    path: Annotated[Path | None, typer.Argument(help="Directory to scan.")] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
    show_suppressed: Annotated[
        bool, typer.Option("--show-suppressed", help="Also list baseline-accepted findings.")
    ] = False,
) -> None:
    """Scan a workspace for secrets, injection-shaped text and dangerous code."""
    root = _root(path)
    try:
        report = scan_workspace(root)
    except DevForgeError as exc:
        render.error(str(exc))
        raise typer.Exit(code=1) from exc

    if as_json:
        render.emit_json(report.model_dump(mode="json"))
    else:
        render.render_scan(report, show_suppressed=show_suppressed)

    if report.blocking:
        raise typer.Exit(code=1)


@app.command()
def audit(
    path: Annotated[Path | None, typer.Argument(help="Project to audit.")] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Check whether the declared security controls are actually in place."""
    root = _root(path)
    try:
        report = audit_project(root)
    except DevForgeError as exc:
        render.error(str(exc))
        raise typer.Exit(code=1) from exc

    if as_json:
        render.emit_json(report.model_dump(mode="json"))
    else:
        render.render_audit(report)

    if report.failed:
        raise typer.Exit(code=1)


@app.command()
def sbom(
    path: Annotated[Path | None, typer.Argument(help="Project to inventory.")] = None,
    out: Annotated[Path | None, typer.Option("--out", help="Write the SBOM here.")] = None,
) -> None:
    """Emit a CycloneDX inventory of packages, skills, MCP servers and runtimes."""
    document = build_sbom(_root(path))
    text = json.dumps(document, indent=2, ensure_ascii=True)
    if out is not None:
        out.write_text(text + "\n", encoding="utf-8")
        render.success(f"wrote {out}")
        return
    render.emit_json(document)


@app.command()
def threats(
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Show the threat model and the defence-in-depth layers."""
    if as_json:
        render.emit_json(
            {
                "layers": [layer.model_dump(mode="json") for layer in LAYERS],
                "threats": [threat.model_dump(mode="json") for threat in THREATS],
            }
        )
        return
    render.render_threats(LAYERS, THREATS)


@app.command()
def report(
    path: Annotated[Path | None, typer.Argument(help="Project to report on.")] = None,
    out: Annotated[
        Path | None, typer.Option("--out", help="Write the Markdown report here.")
    ] = None,
    no_sbom: Annotated[
        bool, typer.Option("--no-sbom", help="Skip the inventory section.")
    ] = False,
) -> None:
    """Produce the full security report: audit, scan, inventory and residual risk."""
    root = _root(path)
    try:
        scan_result = scan_workspace(root)
        audit_result = audit_project(root)
    except DevForgeError as exc:
        render.error(str(exc))
        raise typer.Exit(code=1) from exc

    document = None if no_sbom else build_sbom(root)
    text = render_report(root=root, scan=scan_result, audit=audit_result, sbom=document)

    if out is not None:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        render.success(f"wrote {out}")
    else:
        render.console.print(Markdown(text))

    render.warn(NO_GUARANTEE)
    if scan_result.blocking or audit_result.failed:
        raise typer.Exit(code=1)
