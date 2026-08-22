"""`devforge platform` - workers, submission, dispatch, status and audit.

The command set follows the lifecycle: register a worker, submit a task,
dispatch it, then read what the control plane recorded.

Exit codes: `0` when the task reached `verified`; `1` when the control plane
rejected it, the run failed, or the audit chain does not verify. A rejected task
is a failure of the *task*, and it exits non-zero because a caller in a script
needs to know that the thing it asked for did not happen.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from devforge.cli import render
from devforge.core.errors import DevForgeError
from devforge.core.state.store import ProjectStore
from devforge.platform.control import ControlPlane
from devforge.platform.models import Capability, TaskEnvelope, TaskState
from devforge.platform.transport import (
    InProcessTransport,
    SubprocessTransport,
    TransportError,
)
from devforge.platform.worker import Worker, default_capabilities

app = typer.Typer(
    help="Control plane and workers: submit a task, dispatch it, audit what happened.",
    no_args_is_help=True,
)
worker_app = typer.Typer(help="Register and inspect workers.", no_args_is_help=True)
app.add_typer(worker_app, name="worker")


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


def _capabilities(names: list[str] | None) -> list[Capability]:
    if not names:
        return default_capabilities()
    known = {capability.value: capability for capability in Capability}
    unknown = [name for name in names if name not in known]
    if unknown:
        _fail(f"unknown capabilit(ies) {unknown}; expected some of {sorted(known)}")
    return [known[name] for name in names]


# --------------------------------------------------------------------------- workers


@worker_app.command("register")
def register_worker(
    worker_id: Annotated[str, typer.Option("--id", help="Worker id.")] = "",
    description: Annotated[str, typer.Option("--description", help="What it is.")] = "",
    capability: Annotated[
        list[str] | None, typer.Option("--capability", "-c", help="Grant a capability.")
    ] = None,
    tool: Annotated[list[str] | None, typer.Option("--tool", help="Permit a tool.")] = None,
    runtime: Annotated[
        list[str] | None, typer.Option("--runtime", help="Permit a runtime.")
    ] = None,
    path: Annotated[Path | None, typer.Option("--path", help="Project root.")] = None,
) -> None:
    """Create a worker identity and print its key once."""
    root = _root(path)
    try:
        control = ControlPlane(root)
        identity, key = control.register_worker(
            worker_id=worker_id,
            description=description,
            capabilities=_capabilities(capability),
            tools=list(tool or []),
            runtimes=list(runtime or ["mock"]),
        )
    except DevForgeError as exc:
        _fail(str(exc))
        return

    render.success(f"registered {identity.worker_id}")
    render.info(f"  capabilities: {', '.join(c.value for c in identity.capabilities)}")
    render.info(f"  fingerprint:  {identity.key_fingerprint}")
    render.info(
        "\nThe signing key is shown once and is not recoverable from the registry:"
    )
    render.console.print(f"  [bold]{key}[/bold]")
    render.warn(
        "Treat it as a credential. It is stored under .devforge/platform/workers.key, "
        "which the filesystem policy, the security scanner and the commit guard all refuse."
    )


@worker_app.command("list")
def list_workers(
    path: Annotated[Path | None, typer.Option("--path", help="Project root.")] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Show registered workers and what each is permitted."""
    control = ControlPlane(_root(path))
    identities = control.registry.all()
    if as_json:
        render.emit_json([identity.model_dump(mode="json") for identity in identities])
        return
    render.render_workers(identities)


@worker_app.command("revoke")
def revoke_worker(
    worker_id: Annotated[str, typer.Argument(help="Worker to revoke.")],
    path: Annotated[Path | None, typer.Option("--path", help="Project root.")] = None,
) -> None:
    """Disable a worker and destroy its key."""
    root = _root(path)
    try:
        control = ControlPlane(root)
        identity = control.revoke_worker(worker_id)
    except DevForgeError as exc:
        _fail(str(exc))
        return
    render.success(f"revoked {identity.worker_id}; its key was destroyed")


# --------------------------------------------------------------------------- tasks


@app.command()
def submit(
    description: Annotated[str, typer.Option("--task", "-t", help="What to do.")],
    workflow: Annotated[str, typer.Option("--workflow", "-w", help="Workflow.")] = "feature",
    runtime: Annotated[str, typer.Option("--runtime", help="Agent runtime.")] = "mock",
    tool: Annotated[list[str] | None, typer.Option("--tool", help="Scope to a tool.")] = None,
    expect: Annotated[
        list[str] | None, typer.Option("--expect", help="Artifact the task must return.")
    ] = None,
    capability: Annotated[
        list[str] | None, typer.Option("--requires", help="Capability a worker must hold.")
    ] = None,
    path: Annotated[Path | None, typer.Option("--path", help="Project root.")] = None,
) -> None:
    """Put a task on the queue. Nothing runs until it is dispatched."""
    root = _root(path)
    try:
        envelope = TaskEnvelope(
            description=description,
            workflow=workflow,
            runtime=runtime,
            tools=list(tool or []),
            verify=list(expect or []),
            requires=_capabilities(capability) if capability else [Capability.AGENT],
        )
        record = ControlPlane(root).submit(envelope)
    except (DevForgeError, ValueError) as exc:
        _fail(str(exc))
        return
    render.success(f"queued {record.task_id}")
    render.info("  next: devforge platform dispatch --worker <id>")


@app.command()
def dispatch(
    worker_id: Annotated[str, typer.Option("--worker", help="Worker to lease to.")],
    local: Annotated[
        bool, typer.Option("--local", help="Run in this process instead of spawning one.")
    ] = False,
    path: Annotated[Path | None, typer.Option("--path", help="Project root.")] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Lease the next permitted task to a worker, run it, and verify the result.

    The worker runs in its own process by default. `--local` runs it here, which
    is for development: it exercises the same signing and authorisation path but
    gives up the process isolation that makes a worker containable.
    """
    root = _root(path)
    try:
        control = ControlPlane(root)
        leased = control.lease_next(worker_id)
    except DevForgeError as exc:
        _fail(str(exc))
        return

    if leased is None:
        render.info(f"nothing queued that '{worker_id}' is permitted to run")
        return

    record, lease = leased
    render.info(f"leased {record.task_id} to {worker_id} until {lease.expires_at:%H:%M:%S}")

    identity = control.registry.require(worker_id)
    transport = (
        InProcessTransport(
            registry=control.registry,
            worker=Worker(identity, root=root),
            control=control,
        )
        if local
        else SubprocessTransport(registry=control.registry, worker_id=worker_id, root=root)
    )

    try:
        result = transport.dispatch(record.envelope)
    except TransportError as exc:
        _fail(f"the worker channel failed: {exc}")
        return
    finally:
        transport.close()

    try:
        final = control.accept(result)
    except DevForgeError as exc:
        _fail(str(exc))
        return

    if as_json:
        render.emit_json(final.model_dump(mode="json"))
    else:
        render.render_platform_task(final)

    if final.state is TaskState.AWAITING_APPROVAL:
        # A pause, not a failure - the same distinction `devforge run` makes,
        # and the same exit code, so a script can tell them apart.
        render.info(
            f"\nthen: devforge platform approve {final.task_id} --gate <name>"
        )
        raise typer.Exit(code=2)
    if final.state in {TaskState.REJECTED, TaskState.FAILED}:
        raise typer.Exit(code=1)


@app.command()
def approve(
    task_id: Annotated[str, typer.Argument(help="Task waiting on a decision.")],
    gate: Annotated[str, typer.Option("--gate", help="Which gate to approve.")],
    by: Annotated[str, typer.Option("--by", help="Who decided.")] = "",
    reason: Annotated[str, typer.Option("--reason", help="Why.")] = "",
    deny: Annotated[bool, typer.Option("--deny", help="Refuse instead of approving.")] = False,
    path: Annotated[Path | None, typer.Option("--path", help="Project root.")] = None,
) -> None:
    """Decide a gate a worker stopped at, then let the task be dispatched again.

    The grant is recorded here and travels to the worker by name. A worker never
    decides an approval; it applies one a person already made.
    """
    root = _root(path)
    try:
        control = ControlPlane(root)
        record = (
            control.reject(task_id, gate, by=by, reason=reason)
            if deny
            else control.approve(task_id, gate, by=by, reason=reason)
        )
    except DevForgeError as exc:
        _fail(str(exc))
        return

    if deny:
        render.info(f"refused '{gate}' on {record.task_id}")
        raise typer.Exit(code=1)
    render.success(f"approved '{gate}' on {record.task_id}; it is queued again")
    render.info("  next: devforge platform dispatch --worker <id>")


@app.command()
def status(
    task_id: Annotated[str | None, typer.Argument(help="One task, or all of them.")] = None,
    path: Annotated[Path | None, typer.Option("--path", help="Project root.")] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Show the queue, or one task's record."""
    root = _root(path)
    control = ControlPlane(root)
    try:
        if task_id:
            record = control.queue.load(task_id)
            if as_json:
                render.emit_json(record.model_dump(mode="json"))
            else:
                render.render_platform_task(record)
            return
    except DevForgeError as exc:
        _fail(str(exc))
        return

    if as_json:
        render.emit_json(control.status())
        return
    render.render_platform_status(control.status(), control.queue.all())


@app.command()
def audit(
    task_id: Annotated[str | None, typer.Option("--task", help="Limit to one task.")] = None,
    verify_chain: Annotated[
        bool, typer.Option("--verify", help="Check the hash chain and exit non-zero if broken.")
    ] = False,
    path: Annotated[Path | None, typer.Option("--path", help="Project root.")] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Read the audit trail, and check that nothing in it has been altered."""
    root = _root(path)
    control = ControlPlane(root)
    try:
        events = control.audit.for_task(task_id) if task_id else control.audit.read()
        problems = control.audit.verify()
    except DevForgeError as exc:
        _fail(str(exc))
        return

    if as_json:
        render.emit_json(
            {
                "intact": not problems,
                "problems": problems,
                "events": [event.model_dump(mode="json") for event in events],
            }
        )
    else:
        render.render_audit_trail(events, problems)

    if verify_chain and problems:
        raise typer.Exit(code=1)


@app.command("protocol")
def show_protocol() -> None:
    """Print the protocol version and what the transport does not do."""
    render.console.print(json.dumps({"version": 1, "framing": "newline-delimited JSON"}, indent=1))
    render.info(
        "\nTransports: in-process and subprocess (stdio). There is no network "
        "transport: the architecture tests forbid an HTTP client in src/, and no "
        "measured workload here justifies adding one. See docs/platform.md."
    )
