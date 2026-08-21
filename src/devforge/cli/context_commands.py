"""`devforge index` and `devforge context` - build the map, inspect what an agent gets.

`context` exists so the pack is auditable *before* a run: a human can see which
files an agent will be pointed at, which it will not, and why. A retrieval layer
nobody can inspect is one nobody should trust.
"""

from __future__ import annotations

from typing import Annotated

import typer

from devforge.cli import render
from devforge.context.guard import IndexGuard, load_ignore_file
from devforge.context.indexer import build_index
from devforge.context.models import FileRole
from devforge.context.pack import (
    build_pack,
    estimate_tokens,
    full_repository_context,
    index_path,
    load_index,
    save_index,
    stale_files,
)
from devforge.core.errors import DevForgeError
from devforge.core.orchestrator.context import AppContext

ROLE_STYLE = {
    FileRole.SOURCE: "cyan",
    FileRole.TEST: "green",
    FileRole.CONFIG: "yellow",
    FileRole.DOCS: "blue",
    FileRole.SCHEMA: "magenta",
}


def _context() -> AppContext:
    try:
        return AppContext.load()
    except DevForgeError as exc:
        render.error(str(exc))
        raise typer.Exit(code=1) from exc


def index_command(
    rebuild: Annotated[
        bool, typer.Option("--rebuild", help="Re-parse every file instead of reusing hashes.")
    ] = False,
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Build or refresh the codebase index. Reads source; stores structure only."""
    ctx = _context()
    root = ctx.store.root

    previous = None
    if not rebuild:
        try:
            previous = load_index(root)
        except DevForgeError:
            previous = None

    guard = IndexGuard(root=root, extra_ignores=load_ignore_file(root))
    index = build_index(root, project_id=ctx.config.project_id, guard=guard, previous=previous)
    path = save_index(root, index)

    ctx.logger.info(
        "index.build",
        files_indexed=index.stats.files_indexed,
        symbols=index.stats.symbols,
        skipped=index.stats.files_skipped,
        excluded=index.stats.secrets_excluded,
        duration_ms=index.stats.duration_ms,
    )

    if as_json:
        render.emit_json(
            {
                "path": str(path),
                "files_indexed": index.stats.files_indexed,
                "files_skipped": index.stats.files_skipped,
                "symbols": index.stats.symbols,
                "duration_ms": index.stats.duration_ms,
                "excluded_for_secrets": index.stats.secrets_excluded,
                "excluded_paths": index.stats.excluded_paths,
                "dependencies": [dep.name for dep in index.dependencies],
            }
        )
        return

    stats = index.stats
    render.success(
        f"indexed {stats.files_indexed} files, {stats.symbols} symbols in {stats.duration_ms}ms"
    )
    table = render.Table("role", "files", box=None)
    for role in FileRole:
        count = len(index.by_role(role))
        if count:
            table.add_row(f"[{ROLE_STYLE.get(role, '')}]{role.value}[/]", str(count))
    render.console.print(table)
    render.info(f"\nindex: {path}")
    render.info(f"skipped {stats.files_skipped} files (build output, binaries, generated)")
    if stats.secrets_excluded:
        render.warn(
            f"{stats.secrets_excluded} file(s) withheld as credential material - "
            "never indexed, never retrievable:"
        )
        for entry in stats.excluded_paths[:5]:
            render.info(f"  {entry}")


def context_command(
    task: Annotated[str, typer.Argument(help="The task to retrieve context for.")],
    max_files: Annotated[int, typer.Option("--max-files", help="How many files to include.")] = 12,
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
    show_prompt: Annotated[
        bool, typer.Option("--prompt", help="Print the pack exactly as an agent receives it.")
    ] = False,
    compare: Annotated[
        bool, typer.Option("--compare", help="Measure this pack against full-repository context.")
    ] = False,
) -> None:
    """Show the context pack for a task, without running anything."""
    ctx = _context()
    try:
        index = load_index(ctx.store.root)
    except DevForgeError as exc:
        render.error(str(exc))
        raise typer.Exit(code=1) from exc

    pack = build_pack(task, store=ctx.store, index=index, max_files=max_files)

    if as_json:
        render.emit_json(pack.model_dump(mode="json"))
        return
    if show_prompt:
        render.console.print(pack.render())
        return

    render.console.print(
        render.Panel(
            f"[bold]{pack.task}[/bold]\n\n"
            f"files      {len(pack.relevant_files)} of {index.stats.files_indexed} indexed\n"
            f"symbols    {len(pack.relevant_symbols)}\n"
            f"tests      {len(pack.tests)}\n"
            f"tokens     ~{pack.estimated_tokens}",
            title="context pack",
            expand=False,
        )
    )

    if pack.retrieval_note:
        render.warn(pack.retrieval_note)

    if pack.relevant_files:
        table = render.Table("score", "role", "file", "why", box=None)
        for entry in pack.relevant_files:
            table.add_row(
                f"{entry.score:.1f}",
                f"[{ROLE_STYLE.get(entry.role, '')}]{entry.role.value}[/]",
                entry.path,
                "; ".join(entry.reasons)[:70],
            )
        render.console.print(table)

    if pack.relevant_symbols:
        render.info("\nsymbols:")
        for symbol in pack.relevant_symbols[:12]:
            render.info(f"  {symbol.qualified_name} ({symbol.kind.value}) {symbol.location}")

    if pack.tests:
        render.info("\ntests: " + ", ".join(entry.path for entry in pack.tests))
    if pack.excluded:
        render.info("\nwithheld by policy:")
        for entry in pack.excluded[:5]:
            render.info(f"  {entry}")

    if compare:
        _print_comparison(ctx, index, pack)


def _print_comparison(ctx: AppContext, index, pack) -> None:
    """The measurement the whole layer exists to justify."""
    import time

    started = time.monotonic()
    baseline = full_repository_context(ctx.store.root, index)
    baseline_ms = int((time.monotonic() - started) * 1000)

    baseline_tokens, method = estimate_tokens(baseline)
    pack_tokens, _ = estimate_tokens(pack.render())
    if baseline_tokens <= 0:
        render.warn("baseline is empty; nothing to compare")
        return

    reduction = 100 * (1 - pack_tokens / baseline_tokens)
    table = render.Table("context", "tokens", "files", "build ms", box=None)
    table.add_row(
        "full repository", f"{baseline_tokens:,}", str(index.stats.files_indexed), str(baseline_ms)
    )
    table.add_row("retrieved pack", f"{pack_tokens:,}", str(len(pack.relevant_files)), "-")
    render.console.print(table)
    render.success(f"{reduction:.1f}% fewer tokens ({method})")


def doctor_command(
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Report whether the index still matches the working tree."""
    ctx = _context()
    try:
        index = load_index(ctx.store.root)
    except DevForgeError as exc:
        render.error(str(exc))
        raise typer.Exit(code=1) from exc

    drifted = stale_files(ctx.store.root, index)
    payload = {
        "index": str(index_path(ctx.store.root)),
        "built_at": index.built_at.isoformat(),
        "files_indexed": index.stats.files_indexed,
        "stale": drifted[:50],
        "stale_count": len(drifted),
        "ok": not drifted,
    }
    if as_json:
        render.emit_json(payload)
    else:
        render.info(
            f"index built {index.built_at.isoformat()} over {index.stats.files_indexed} files"
        )
        if drifted:
            render.warn(
                f"{len(drifted)} indexed file(s) have changed or gone. Stale context is "
                "confident and wrong - run 'devforge index' again."
            )
            for entry in drifted[:10]:
                render.info(f"  {entry}")
        else:
            render.success("index matches the working tree")
    if drifted:
        raise typer.Exit(code=1)
