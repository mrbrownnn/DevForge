"""CLI surface for the skill supply chain.

Read-only commands. `registry` inspects the catalogue of third-party sources;
`inspect-skill` statically analyses an untrusted skill directory. Neither fetches
anything and neither executes anything.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from devforge.cli import render
from devforge.core.errors import DevForgeError
from devforge.supplychain.inspect import inspect_skill
from devforge.supplychain.models import Severity, SkillRegistryFile
from devforge.supplychain.registry import load_registry, resolve_registry_path

registry_app = typer.Typer(
    help="Inspect the third-party skill source registry.", no_args_is_help=True
)

SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "dim",
}

UNTRUSTED_NOTICE = (
    "Every source is untrusted until a review is recorded at a pin. Nothing here is "
    "installed: DevForge ships no skill installer (docs/security/skill-supply-chain.md)."
)

INSPECTION_CAVEAT = (
    "A clean report is not proof of safety. Static inspection cannot decide intent, and "
    "natural-language injection is mitigated, never solved (docs/security/threat-model.md, T2)."
)


def _load() -> SkillRegistryFile:
    try:
        return load_registry(None)
    except DevForgeError as exc:
        render.error(str(exc))
        raise typer.Exit(code=1) from exc


def _worst_severity(counts: dict[str, int]) -> str:
    for level in ("critical", "high", "medium", "low"):
        if counts.get(level):
            style = "red" if level in {"critical", "high"} else "yellow"
            return f"[{style}]{level}[/]"
    return "-"


@registry_app.command("list")
def registry_list(
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """List third-party skill sources and the decision recorded for each."""
    registry = _load()
    if as_json:
        render.emit_json(registry.model_dump(mode="json"))
        return

    table = render.Table(
        "source", "disposition", "trust", "license", "pin", "worst concern", box=None
    )
    for source in registry.sources:
        disposition = "[red]rejected[/red]" if not source.usable else source.disposition.value
        table.add_row(
            source.id,
            disposition,
            source.trust_tier.value,
            source.license.spdx or "[yellow]NONE[/yellow]",
            source.pin.commit[:8],
            _worst_severity(source.concerns_by_severity),
        )
    render.console.print(table)
    render.info(
        f"\n{len(registry.sources)} sources | {len(registry.discovery_sources)} discovery lists "
        f"(not sources) | {len(registry.gaps)} recorded gaps"
    )
    render.warn(UNTRUSTED_NOTICE)


@registry_app.command("show")
def registry_show(
    source_id: Annotated[str, typer.Argument(help="Source id from `devforge registry list`.")],
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Show recorded evidence and the decision for one source."""
    registry = _load()
    source = registry.source(source_id)
    if source is None:
        known = ", ".join(s.id for s in registry.sources)
        render.error(f"unknown source {source_id!r}. Known: {known}")
        raise typer.Exit(code=1)

    if as_json:
        render.emit_json(source.model_dump(mode="json"))
        return

    render.console.print(
        render.Panel(
            f"[bold]{source.name}[/bold]\n{source.repository}\n\n"
            f"maintainer   {source.maintainer.name} ({source.maintainer.type.value})\n"
            f"license      {source.license.spdx or 'NONE'}\n"
            f"pin          {source.pin.commit}\n"
            f"verified     {source.pin.verified_at or 'never'}\n"
            f"install      {source.install_mechanism}\n"
            f"disposition  {source.disposition.value}\n"
            f"trust tier   {source.trust_tier.value}\n"
            f"review       {source.review.status.value}",
            title=source.id,
            expand=False,
        )
    )
    if source.skills:
        render.info(f"skills: {', '.join(source.skills)}\n")
    if source.security_concerns:
        table = render.Table("concern", "severity", "evidence", box=None)
        for concern in source.security_concerns:
            table.add_row(
                concern.id,
                f"[{SEVERITY_STYLE[concern.severity]}]{concern.severity.value}[/]",
                concern.evidence.strip(),
            )
        render.console.print(table)
    if source.rationale:
        render.info(f"\n{source.rationale.strip()}")


@registry_app.command("verify")
def registry_verify(
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Validate the registry: schema, pins, licenses and trust decisions."""
    path = resolve_registry_path(None)
    registry = _load()

    problems: list[str] = []
    for source in registry.sources:
        if source.trust_tier.value != "untrusted" and source.review.status.value == "not_reviewed":
            problems.append(f"{source.id}: trusted without a recorded review")
        if source.disposition.value == "vendor" and not source.license.vendorable:
            problems.append(f"{source.id}: vendored under a non-permissive license")
        if source.pin.verified_at is None:
            problems.append(f"{source.id}: pin carries no verification date")

    report = {
        "path": str(path),
        "sources": len(registry.sources),
        "rejected": [s.id for s in registry.rejected],
        "vendored": [s.id for s in registry.vendored],
        "problems": problems,
        "ok": not problems,
    }

    if as_json:
        render.emit_json(report)
    else:
        render.success(f"registry schema valid: {path}")
        render.info(
            f"  {len(registry.sources)} sources"
            f" | rejected: {', '.join(report['rejected']) or 'none'}"
            f" | vendored: {', '.join(report['vendored']) or 'none'}"
        )
        for problem in problems:
            render.error(problem)

    if problems:
        raise typer.Exit(code=1)


def inspect_skill_command(
    path: Annotated[Path, typer.Argument(help="Directory containing an untrusted skill.")],
    declared_scripts: Annotated[
        bool | None,
        typer.Option(
            "--declared-scripts/--declared-no-scripts",
            help="What the skill claims about shipping executable content.",
        ),
    ] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Statically inspect an untrusted skill directory. Nothing is executed."""
    report = inspect_skill(path, declared_scripts=declared_scripts)

    if as_json:
        render.emit_json(
            {
                "root": report.root,
                "files_scanned": report.files_scanned,
                "content_hash": report.content_hash,
                "counts": report.counts,
                "blocked": report.blocked,
                "findings": [
                    {
                        "rule": finding.rule,
                        "severity": finding.severity.value,
                        "path": finding.path,
                        "line": finding.line,
                        "detail": finding.detail,
                        "excerpt": finding.excerpt,
                    }
                    for finding in report.findings
                ],
            }
        )
    else:
        render.info(f"{report.root}\n{report.summary}\ncontent hash {report.content_hash}\n")
        if report.findings:
            table = render.Table("severity", "rule", "location", "detail", box=None)
            for finding in report.findings:
                location = finding.path + (f":{finding.line}" if finding.line else "")
                table.add_row(
                    f"[{SEVERITY_STYLE[finding.severity]}]{finding.severity.value}[/]",
                    finding.rule,
                    location,
                    finding.detail,
                )
            render.console.print(table)
        else:
            render.success("no findings")
        render.warn(INSPECTION_CAVEAT)

    if report.blocked:
        render.error("BLOCKED: a critical finding refuses installation")
        raise typer.Exit(code=1)
