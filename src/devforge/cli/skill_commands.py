"""`devforge skill ...` - discover, inspect, install, update, remove, audit, list.

Every command that touches the network says so, and nothing installs without an
explicit invocation. Risk above the policy ceiling stops and asks; CRITICAL stops
and refuses.
"""

from __future__ import annotations

import asyncio
from datetime import UTC
from typing import Annotated

import typer

from devforge.cli import render
from devforge.core.errors import DevForgeError
from devforge.core.orchestrator.context import AppContext
from devforge.supplychain.catalog import SkillEntry, load_catalog
from devforge.supplychain.install import (
    DEFAULT_RISK_CEILING,
    ApprovalRequiredError,
    InstallError,
    LockEntry,
    SkillInstaller,
    load_lockfile,
    skill_dir,
    verify_installed,
)
from devforge.supplychain.quality import RepoSignals
from devforge.supplychain.registry import load_registry
from devforge.supplychain.risk import SkillRisk

skill_app = typer.Typer(
    help="Discover, install and audit third-party skills.", no_args_is_help=True
)

RISK_STYLE = {
    SkillRisk.LOW: "green",
    SkillRisk.MEDIUM: "yellow",
    SkillRisk.HIGH: "red",
    SkillRisk.CRITICAL: "bold red",
}

NETWORK_NOTICE = (
    "This command clones a repository with git. It is the only part of DevForge that "
    "reaches the network, it runs under the command policy, and it never executes what "
    "it downloads."
)


def _context() -> AppContext:
    try:
        return AppContext.load()
    except DevForgeError as exc:
        render.error(str(exc))
        raise typer.Exit(code=1) from exc


def _entry(ctx: AppContext, name: str) -> SkillEntry:
    catalog = load_catalog(ctx.store.root)
    entry = catalog.skill(name)
    if entry is None:
        known = ", ".join(catalog.names) or "<empty catalogue>"
        render.error(f"unknown skill '{name}'. Catalogued: {known}")
        raise typer.Exit(code=1)
    return entry


def _signals_for(ctx: AppContext, entry: SkillEntry) -> RepoSignals:
    """Reuse the activity evidence already recorded in the source registry."""
    try:
        registry = load_registry(ctx.store.root)
    except DevForgeError:
        return RepoSignals()
    for source in registry.sources:
        if source.repository and source.repository == entry.repository:
            last = source.activity.last_push
            return RepoSignals(
                last_commit=_parse_date(last),
                open_issues=source.activity.open_issues,
                archived=source.activity.archived,
                maintainer_is_organisation=source.maintainer.type.value == "Organization",
            )
    return RepoSignals()


def _parse_date(value: str | None):
    if not value:
        return None
    from datetime import datetime

    try:
        return datetime.fromisoformat(value).replace(tzinfo=UTC)
    except ValueError:
        return None


def _risk_text(level: str) -> str:
    """Style a risk level, tolerating vocabularies this table does not colour.

    Catalogue entries carry the tool-layer risk words (read/write/execute), audits
    carry LOW/MEDIUM/HIGH/CRITICAL. An unknown level must render as plain text: an
    empty style produced `[]text[/]`, which is not valid markup and crashed the
    whole table.
    """
    style = RISK_STYLE.get(level)
    return f"[{style}]{level}[/]" if style else level


# --------------------------------------------------------------------------- search


@skill_app.command("search")
def search(
    query: Annotated[str, typer.Argument(help="Text to match against the catalogue.")] = "",
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Search catalogued skills. Reads local metadata only - no network."""
    ctx = _context()
    catalog = load_catalog(ctx.store.root)
    matches = catalog.search(query)

    if as_json:
        render.emit_json([entry.model_dump(mode="json") for entry in matches])
        return

    if not matches:
        render.info(f"no catalogued skill matches {query!r} ({len(catalog.skills)} catalogued)")
        return

    # "expected risk" is the catalogued expectation; an audit produces the real one.
    table = render.Table(
        "skill", "expected risk", "status", "quality", "license", "source", box=None
    )
    for entry in matches:
        table.add_row(
            entry.name,
            _risk_text(entry.risk_level.value.upper()),
            entry.security_status.value,
            entry.quality.grade if entry.quality.total else "-",
            entry.license or "[yellow]NONE[/yellow]",
            entry.repository.replace("https://github.com/", ""),
        )
    render.console.print(table)
    render.info(f"\n{len(matches)} of {len(catalog.skills)} catalogued skills")
    render.warn(
        "Catalogue entries record where a skill lives, not what it contains. "
        "Run `devforge skill audit <name>` before trusting one."
    )


# -------------------------------------------------------------------------- inspect


@skill_app.command("inspect")
def inspect(
    name: Annotated[str, typer.Argument(help="Catalogued skill name.")],
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Show catalogued metadata for a skill. Offline."""
    ctx = _context()
    entry = _entry(ctx, name)

    if as_json:
        render.emit_json(entry.model_dump(mode="json"))
        return

    render.console.print(
        render.Panel(
            f"[bold]{entry.name}[/bold] {entry.version}\n{entry.description}\n\n"
            f"author       {entry.author or 'unknown'}\n"
            f"repository   {entry.repository}\n"
            f"path         {entry.path}\n"
            f"commit       {entry.commit_sha or '[yellow]UNPINNED[/yellow]'}\n"
            f"content hash {entry.content_hash or '[yellow]not yet audited[/yellow]'}\n"
            f"license      {entry.license or '[yellow]UNKNOWN[/yellow]'}\n"
            f"risk         {entry.risk_level.value}\n"
            f"status       {entry.security_status.value}\n"
            f"last audited {entry.last_audited.isoformat() if entry.last_audited else 'never'}\n"
            f"runtimes     {', '.join(entry.supported_runtimes)}\n"
            f"tools        {', '.join(entry.required_tools) or 'none'}\n"
            f"permissions  {', '.join(entry.required_permissions) or 'none'}",
            title=entry.name,
            expand=False,
        )
    )
    if entry.capabilities:
        render.info(f"capabilities: {', '.join(entry.capabilities)}")
    if entry.dependencies:
        render.info(f"dependencies: {', '.join(entry.dependencies)}")
    if entry.quality.total:
        render.info(f"\nquality {entry.quality.grade} ({entry.quality.total}/90)")
        for note in entry.quality.notes:
            render.info(f"  {note}")
    if entry.notes:
        render.info(f"\n{entry.notes}")


# ---------------------------------------------------------------------------- audit


@skill_app.command("audit")
def audit(
    name: Annotated[str, typer.Argument(help="Catalogued skill name.")],
    commit: Annotated[
        str | None, typer.Option("--commit", help="Audit this commit instead of the pin.")
    ] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Fetch a skill at its pin and inspect it, without installing anything."""
    ctx = _context()
    entry = _entry(ctx, name)
    installer = SkillInstaller(ctx.store.root, policy=ctx.policy, logger=ctx.logger)

    if not as_json:
        render.info(NETWORK_NOTICE + "\n")

    try:
        plan = asyncio.run(installer.plan(entry, commit=commit, signals=_signals_for(ctx, entry)))
    except DevForgeError as exc:
        render.error(str(exc))
        raise typer.Exit(code=1) from exc

    try:
        report_path = installer._write_report(plan)
        assessment = plan.assessment

        if as_json:
            render.emit_json(
                {
                    "skill": entry.name,
                    "commit": plan.source.commit_sha,
                    "content_hash": plan.source.content_hash,
                    "risk_level": assessment.level,
                    "blocked": assessment.blocked,
                    "reasons": assessment.reasons,
                    "capabilities": assessment.capabilities,
                    "counts": assessment.counts(),
                    "required_permissions": plan.required_permissions,
                    "executable_files": plan.executable_files,
                    "license": plan.license_name,
                    "quality": plan.quality_grade,
                    "report": str(report_path),
                }
            )
        else:
            _print_plan(plan)
            render.info(f"\nreport written to {report_path}")
    finally:
        plan.source.cleanup()

    if plan.assessment.blocked:
        raise typer.Exit(code=1)


def _print_plan(plan) -> None:
    assessment = plan.assessment
    counts = assessment.counts()
    render.console.print(
        render.Panel(
            f"[bold]{plan.entry.name}[/bold]\n"
            f"commit       {plan.source.commit_sha}\n"
            f"content hash {plan.source.content_hash}\n"
            f"license      {plan.license_name or '[yellow]UNKNOWN[/yellow]'}\n"
            f"risk         {_risk_text(assessment.level)}\n"
            f"quality      {plan.quality_grade}\n"
            f"files        {assessment.files_scanned}\n"
            f"permissions  {', '.join(plan.required_permissions) or 'none'}",
            title="audit",
            expand=False,
        )
    )
    for reason in assessment.reasons:
        render.info(f"  - {reason}")
    if plan.executable_files:
        render.warn(
            f"{len(plan.executable_files)} executable file(s) ship with this skill and will be "
            f"quarantined on install: {plan.executable_files[:5]}"
        )
    if assessment.findings:
        table = render.Table("severity", "rule", "location", box=None)
        for finding in assessment.findings[:25]:
            location = finding.path + (f":{finding.line}" if finding.line else "")
            table.add_row(finding.severity.value, finding.rule, location)
        render.console.print(table)
        render.info(
            f"critical={counts['critical']} high={counts['high']} "
            f"medium={counts['medium']} low={counts['low']}"
        )


# -------------------------------------------------------------------------- install


@skill_app.command("install")
def install(
    name: Annotated[str, typer.Argument(help="Catalogued skill name.")],
    commit: Annotated[
        str | None,
        typer.Option("--commit", help="Install this commit instead of the catalogue pin."),
    ] = None,
    approve_by: Annotated[
        str | None,
        typer.Option("--approve-by", help="Record who approved a risk above the ceiling."),
    ] = None,
    with_scripts: Annotated[
        bool,
        typer.Option(
            "--with-scripts",
            help="Place executable files in the active directory instead of quarantine.",
        ),
    ] = False,
    ceiling: Annotated[
        str, typer.Option("--risk-ceiling", help="LOW, MEDIUM or HIGH.")
    ] = DEFAULT_RISK_CEILING,
) -> None:
    """Fetch, verify, inspect and install a skill, then write the lockfile."""
    ctx = _context()
    entry = _entry(ctx, name)
    installer = SkillInstaller(
        ctx.store.root, policy=ctx.policy, logger=ctx.logger, risk_ceiling=ceiling.upper()
    )

    lock = load_lockfile(ctx.store.root)
    existing = lock.entry(name)
    if existing and not commit:
        render.warn(
            f"'{name}' is already installed at {existing.commit_sha[:12]}. "
            "A pin is never moved implicitly - use `devforge skill update` to change it."
        )
        raise typer.Exit(code=0)

    render.info(NETWORK_NOTICE + "\n")
    try:
        plan = asyncio.run(installer.plan(entry, commit=commit, signals=_signals_for(ctx, entry)))
    except DevForgeError as exc:
        render.error(str(exc))
        raise typer.Exit(code=1) from exc

    try:
        _print_plan(plan)
        result = installer.install(
            plan, approved_by=approve_by or "", with_scripts=with_scripts, installed_by="cli"
        )
    except ApprovalRequiredError as exc:
        render.error(str(exc))
        raise typer.Exit(code=2) from exc
    except InstallError as exc:
        render.error(str(exc))
        raise typer.Exit(code=1) from exc
    finally:
        plan.source.cleanup()

    render.success(f"\ninstalled {result.entry.name} at {result.entry.commit_sha[:12]}")
    render.info(f"  location   {result.installed_path}")
    render.info(f"  report     {result.report_path}")
    render.info(f"  lockfile   {ctx.store.root / 'skills.lock'}")
    if result.quarantined:
        render.warn(
            f"{len(result.quarantined)} executable file(s) quarantined. DevForge never "
            "executes skill content; these are kept for review only."
        )


# --------------------------------------------------------------------------- update


@skill_app.command("update")
def update(
    name: Annotated[str, typer.Argument(help="Installed skill name.")],
    commit: Annotated[
        str | None, typer.Option("--commit", help="Update to this exact commit.")
    ] = None,
    to_head: Annotated[
        bool, typer.Option("--to-head", help="Resolve the remote HEAD and update to it.")
    ] = False,
    approve_by: Annotated[
        str | None, typer.Option("--approve-by", help="Record who approved the change.")
    ] = None,
    ceiling: Annotated[
        str, typer.Option("--risk-ceiling", help="LOW, MEDIUM or HIGH.")
    ] = DEFAULT_RISK_CEILING,
) -> None:
    """Move a pin deliberately. Never silent, always re-audited."""
    ctx = _context()
    entry = _entry(ctx, name)
    lock = load_lockfile(ctx.store.root)
    current = lock.entry(name)
    if current is None:
        render.error(f"'{name}' is not installed; use `devforge skill install` first")
        raise typer.Exit(code=1)

    if not commit and not to_head:
        render.error(
            "an update needs an explicit target: pass --commit SHA or --to-head. "
            "A pinned skill is never upgraded implicitly."
        )
        raise typer.Exit(code=1)

    installer = SkillInstaller(
        ctx.store.root, policy=ctx.policy, logger=ctx.logger, risk_ceiling=ceiling.upper()
    )
    render.info(NETWORK_NOTICE + "\n")

    try:
        target = commit or asyncio.run(installer.resolve_update_target(entry, to_head=True))
        if target.lower() == current.commit_sha.lower():
            render.info(f"'{name}' is already at {target[:12]}; nothing to do")
            raise typer.Exit(code=0)
        plan = asyncio.run(installer.plan(entry, commit=target, signals=_signals_for(ctx, entry)))
    except DevForgeError as exc:
        render.error(str(exc))
        raise typer.Exit(code=1) from exc

    try:
        _print_plan(plan)
        proposed = LockEntry(
            name=entry.name,
            source=entry.source,
            repository=entry.repository,
            commit_sha=plan.source.commit_sha,
            content_hash=plan.source.content_hash,
            license=plan.license_name,
            risk_level=plan.assessment.level,
        )
        changes = current.differs_from(proposed)
        render.info("\nchanges: " + ("; ".join(changes) if changes else "none"))

        result = installer.install(plan, approved_by=approve_by or "", installed_by="cli:update")
    except ApprovalRequiredError as exc:
        render.error(str(exc))
        raise typer.Exit(code=2) from exc
    except InstallError as exc:
        render.error(str(exc))
        raise typer.Exit(code=1) from exc
    finally:
        plan.source.cleanup()

    render.success(f"\nupdated {name}: {current.commit_sha[:12]} -> {result.entry.commit_sha[:12]}")


# --------------------------------------------------------------------------- remove


@skill_app.command("remove")
def remove(
    name: Annotated[str, typer.Argument(help="Installed skill name.")],
) -> None:
    """Remove an installed skill and its lockfile entry."""
    ctx = _context()
    installer = SkillInstaller(ctx.store.root, policy=ctx.policy, logger=ctx.logger)
    removed, path = installer.remove(name)

    if not removed:
        render.info(f"'{name}' is not installed")
        raise typer.Exit(code=0)
    render.success(f"removed {name} ({path})")
    render.info(
        "The security report is kept for the record; delete it deliberately if you want it gone."
    )


# ----------------------------------------------------------------------------- list


@skill_app.command("list")
def list_installed(
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
    verify: Annotated[
        bool, typer.Option("--verify", help="Re-hash installed trees and report drift.")
    ] = False,
) -> None:
    """List installed skills from the lockfile."""
    ctx = _context()
    lock = load_lockfile(ctx.store.root)

    problems: list[str] = []
    if verify:
        for entry in lock.skills:
            problems.extend(verify_installed(ctx.store.root, entry))

    if as_json:
        render.emit_json(
            {
                "skills": [entry.model_dump(mode="json") for entry in lock.skills],
                "problems": problems,
            }
        )
        if problems:
            raise typer.Exit(code=1)
        return

    if not lock.skills:
        render.info("no skills installed (skills.lock is empty or absent)")
        return

    table = render.Table(
        "skill", "commit", "risk", "license", "quarantined", "approved by", box=None
    )
    for entry in lock.skills:
        table.add_row(
            entry.name,
            entry.commit_sha[:12],
            _risk_text(entry.risk_level),
            entry.license or "[yellow]NONE[/yellow]",
            str(len(entry.quarantined_files)),
            entry.approved_by or "-",
        )
    render.console.print(table)
    render.info(f"\nlockfile: {ctx.store.root / 'skills.lock'}")
    for problem in problems:
        render.error(problem)
    if problems:
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------- paths


@skill_app.command("where")
def where(
    name: Annotated[str, typer.Argument(help="Installed skill name.")],
) -> None:
    """Print the install directory of a skill."""
    ctx = _context()
    path = skill_dir(ctx.store.root, name)
    if not path.exists():
        render.error(f"'{name}' is not installed")
        raise typer.Exit(code=1)
    render.info(str(path))
