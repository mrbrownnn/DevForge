"""Installing DevForge's skills into a coding assistant's own configuration.

``devforge init --ai <assistant>`` writes the harness's skills where that assistant
reads them, so an assistant working in a DevForge project inherits the same
engineering guidance the harness gives its own agents.

Three flags exist for parity with the toolchains people already use, and two of them
behave differently here than they would elsewhere. That difference is reported
rather than papered over:

``--offline``
    Accepted and always true. DevForge imports no HTTP client - an architecture test
    enforces it - so every install is from bundled templates whether or not the flag
    is given. It is a compatibility no-op, and the command says so.
``--force``
    Replaces files that already exist. Without it an existing file is left alone and
    reported as skipped, because somebody's hand-written rules file is not DevForge's
    to overwrite.
``--global``
    Installs into the home directory instead of a project. Refused for any assistant
    whose profile declares no documented global location, rather than guessing one.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from devforge import __version__
from devforge.assistants.install import install
from devforge.assistants.models import ALL, AssistantProfile, AssistantRegistry, Confidence
from devforge.cli import render
from devforge.core.errors import DevForgeError
from devforge.core.registry.skills import SkillRegistry


def _fail(message: str) -> None:
    render.error(message)
    raise typer.Exit(code=1)


def _relative(path: Path, root: Path) -> str:
    """A path as the user would type it, falling back to absolute when it is not under root."""
    try:
        return path.relative_to(root).as_posix()
    except ValueError:  # pragma: no cover - a profile pointing elsewhere
        return str(path)


def install_for_assistant(
    assistant: str,
    *,
    root: Path,
    force: bool = False,
    global_install: bool = False,
    offline: bool = False,
    dry_run: bool = False,
) -> int:
    """Install one assistant, or every one. Returns the number of files written."""
    registry = AssistantRegistry.discover(None if global_install else root)

    try:
        profiles = registry.select(assistant)
    except DevForgeError as exc:
        _fail(str(exc))
        return 0

    if offline:
        render.info(
            "--offline: DevForge never reaches the network, so every install already "
            "uses bundled templates. The flag is accepted for compatibility."
        )

    skills = SkillRegistry.discover(None if global_install else root)
    if not skills.all():
        _fail("no skills were discovered, so there is nothing to install")

    destination = Path.home() if global_install else root
    written = 0
    inferred: list[AssistantProfile] = []

    for profile in profiles:
        if global_install and not profile.supports_global:
            render.warn(
                f"{profile.id}: no documented global location, skipped "
                "(install it into a project instead)"
            )
            continue

        try:
            result = install(
                profile,
                root=destination,
                skills=skills,
                force=force,
                global_install=global_install,
                dry_run=dry_run,
            )
        except DevForgeError as exc:
            render.warn(f"{profile.id}: {exc}")
            continue

        written += len(result.written)
        if profile.confidence is Confidence.INFERRED:
            inferred.append(profile)

        verb = "would write" if dry_run else "installed"
        render.success(f"{verb} {profile.name} - {result.summary()}")
        for item in result.written[:4]:
            render.info(f"    {_relative(item.path, destination)}")
        if len(result.written) > 4:
            render.info(f"    ... and {len(result.written) - 4} more")
        for item in result.skipped[:3]:
            render.info(f"    skipped {_relative(item.path, destination)} ({item.skipped_reason})")

    if inferred:
        # The honest part. A file written to a path the assistant does not read is
        # indistinguishable from DevForge having done nothing, and the user is the
        # only one who can confirm it.
        render.warn(
            "the layout for "
            + ", ".join(profile.id for profile in inferred)
            + " was inferred from convention, not confirmed against documentation. "
            "Check the assistant actually reads that path; correcting it means "
            "editing the profile YAML, not the code."
        )
        for profile in inferred:
            if profile.notes:
                render.info(f"  {profile.id}: {profile.notes.strip()}")

    return written


# --------------------------------------------------------------------------- commands


def assistants_command(
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Show target paths and notes.")
    ] = False,
) -> None:
    """List the coding assistants DevForge can install its skills into."""
    registry = AssistantRegistry.discover(None)

    render.info(f"{len(registry.profiles)} assistant profile(s), plus '{ALL}':\n")
    for profile in registry.profiles:
        flag = "" if profile.confidence is Confidence.ESTABLISHED else "  (layout inferred)"
        globally = "" if profile.supports_global else "  (no global install)"
        render.console.print(f"  {profile.id:<13} {profile.name}{flag}{globally}")
        if verbose:
            path = f"{profile.target.path} ({profile.target.format.value})"
            render.console.print(f"                {path}")
            if profile.notes:
                render.console.print(f"                {profile.notes.strip()}")

    render.info(
        "\n  devforge init --ai <id>        install into this project"
        "\n  devforge init --ai all         install for every assistant"
        "\n  devforge init --ai <id> --global   install into your home directory"
    )


def versions_command(
    as_json: Annotated[bool, typer.Option("--json", help="Emit as JSON.")] = False,
) -> None:
    """Show the installed version and the bundled assets it ships.

    Not a list of *available* versions: DevForge imports no HTTP client, so it
    cannot see a release index. What it can report honestly is what this install
    actually contains, which is the question people are usually asking.
    """
    from devforge.agents.spec import AgentRegistry
    from devforge.core.workflow.loader import WorkflowLoader

    payload = {
        "devforge": __version__,
        "workflows": sorted(WorkflowLoader.for_project(None).available()),
        "agents": sorted(AgentRegistry.discover(None).names()),
        "skills": sorted(SkillRegistry.discover(None).names()),
        "assistants": AssistantRegistry.discover(None).ids(),
    }

    if as_json:
        render.emit_json(payload)
        return

    render.info(f"devforge {payload['devforge']}\n")
    for label in ("workflows", "agents", "skills", "assistants"):
        items = payload[label]
        render.console.print(f"  {label:<11} {len(items)}: {', '.join(items)}")
    render.info(
        "\nDevForge makes no network calls, so this is what is installed here - not "
        "what is available upstream. Upgrade with your package manager:"
        "\n  pip install --upgrade devforge"
    )


def update_command(
    global_install: Annotated[
        bool,
        typer.Option("--global", help="Refresh globally installed assistant files."),
    ] = False,
    assistant: Annotated[
        str, typer.Option("--ai", help="Which assistant to refresh. Defaults to all.")
    ] = ALL,
) -> None:
    """Refresh generated assistant files from this installed package.

    Without ``--global`` this refuses rather than pretending: DevForge cannot fetch
    a release, so there is nothing for it to update itself from. Upgrading the CLI is
    a package-manager operation, and saying so is more useful than a command that
    appears to work and does nothing.
    """
    if not global_install:
        render.warn("devforge cannot update itself: it makes no network calls.")
        render.info(
            "  upgrade the package:   pip install --upgrade devforge\n"
            "  then refresh files:    devforge update --global\n"
            "  or, inside a project:  devforge init --ai <id> --force"
        )
        raise typer.Exit(code=1)

    written = install_for_assistant(
        assistant, root=Path.home(), force=True, global_install=True
    )
    render.success(f"refreshed {written} file(s) from devforge {__version__}")
