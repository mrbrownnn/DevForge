"""Terminal rendering.

Presentation lives here so command functions stay about behaviour. Every command
also supports ``--json``; that path bypasses this module entirely so machine
consumers never have to parse decorated text.
"""

from __future__ import annotations

import json
import sys
from typing import Any

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from devforge.core.models import (
    ApprovalStatus,
    StepStatus,
    Task,
    TaskStatus,
    VerificationResult,
    VerificationStatus,
)
from devforge.core.workflow.spec import StepKind, WorkflowSpec

console = Console()
error_console = Console(stderr=True)

STATUS_STYLE = {
    TaskStatus.PENDING: "dim",
    TaskStatus.RUNNING: "cyan",
    TaskStatus.AWAITING_APPROVAL: "yellow",
    TaskStatus.COMPLETED: "green",
    TaskStatus.FAILED: "red",
    TaskStatus.CANCELLED: "dim",
}

STEP_STYLE = {
    StepStatus.PENDING: "dim",
    StepStatus.RUNNING: "cyan",
    StepStatus.PASSED: "green",
    StepStatus.FAILED: "red",
    StepStatus.SKIPPED: "dim",
    StepStatus.AWAITING_APPROVAL: "yellow",
    StepStatus.REJECTED: "red",
}

VERIFICATION_STYLE = {
    VerificationStatus.PASSED: "green",
    VerificationStatus.FAILED: "red",
    VerificationStatus.ERROR: "red",
    VerificationStatus.SKIPPED: "dim",
    VerificationStatus.UNAVAILABLE: "yellow",
}


def emit_json(payload: Any) -> None:
    """Write machine-readable JSON to stdout, independent of terminal encoding.

    Rich renders through the console's codec, so a single non-ASCII character in a
    third-party skill (a `!=` written as U+2260, say) raised UnicodeEncodeError on a
    cp1252 terminal and destroyed the output mid-stream. `--json` is consumed by
    programs; it escapes to ASCII and bypasses the pretty-printer entirely.
    """
    sys.stdout.write(json.dumps(payload, default=str, ensure_ascii=True) + "\n")
    sys.stdout.flush()


def error(message: str) -> None:
    error_console.print(f"[bold red]error[/bold red] {message}")


def warn(message: str) -> None:
    console.print(f"[yellow]warning[/yellow] {message}")


def success(message: str) -> None:
    console.print(f"[green]{message}[/green]")


def info(message: str) -> None:
    console.print(message)


def task_status_text(task: Task) -> Text:
    return Text(task.status.value, style=STATUS_STYLE.get(task.status, ""))


def render_workflow(spec: WorkflowSpec) -> None:
    console.print(
        Panel(
            # Descriptions come from YAML and task text from the command line. Rich
            # would read `devforge[browser]` as a style tag and silently swallow it,
            # so anything not written here is escaped.
            f"[bold]{escape(spec.name)}[/bold] v{escape(spec.version)}\n"
            f"{escape(spec.description.strip())}",
            title="workflow",
            expand=False,
        )
    )
    table = Table("#", "step", "kind", "agent", "skills", "tools", "verify", "attempts", box=None)
    for index, step in enumerate(spec.steps, start=1):
        table.add_row(
            str(index),
            step.id,
            _kind_text(step.kind, step.gate),
            step.agent or "-",
            ", ".join(step.skills) or "-",
            ", ".join(step.tools) or "-",
            ", ".join(step.verify) or "-",
            str(step.max_attempts) if step.verify else "-",
        )
    console.print(table)

    if spec.verifiers:
        verifiers = Table("verifier", "kind", "required", "command", box=None)
        for verifier in spec.verifiers:
            verifiers.add_row(
                verifier.id,
                verifier.kind,
                "yes" if verifier.required else "no",
                " ".join(verifier.argv) or "(no command)",
            )
        console.print(verifiers)


def _kind_text(kind: StepKind, gate: str | None) -> str:
    if kind is StepKind.APPROVAL:
        return f"[yellow]approval[/yellow] ({gate})"
    if kind is StepKind.VERIFY:
        return "[cyan]verify[/cyan]"
    return "agent"


def render_task_summary(task: Task) -> None:
    console.print(
        Panel(
            f"[bold]{escape(task.description)}[/bold]\n"
            f"task     {task.task_id}\n"
            f"workflow {task.workflow}\n"
            f"runtime  {task.runtime}\n"
            f"status   [{STATUS_STYLE.get(task.status, '')}]{task.status.value}[/]\n"
            f"step     {task.current_step or '-'}",
            title="run",
            expand=False,
        )
    )


def render_steps(task: Task) -> None:
    table = Table("step", "kind", "agent", "status", "attempts", "verification", box=None)
    for record in task.steps:
        last = record.attempts[-1] if record.attempts else None
        verification = (
            ", ".join(
                f"[{VERIFICATION_STYLE.get(v.status, '')}]{v.verifier}={v.status.value}[/]"
                for v in last.verification
            )
            if last and last.verification
            else "-"
        )
        table.add_row(
            record.step_id,
            record.kind,
            record.agent or "-",
            f"[{STEP_STYLE.get(record.status, '')}]{record.status.value}[/]",
            str(record.attempt_count),
            verification,
        )
    console.print(table)


def render_approvals(task: Task) -> None:
    pending = [a for a in task.approvals if a.status is ApprovalStatus.PENDING]
    if not task.approvals:
        return
    table = Table("gate", "step", "status", "decided by", "reason", box=None)
    for approval in task.approvals:
        style = {
            ApprovalStatus.PENDING: "yellow",
            ApprovalStatus.APPROVED: "green",
            ApprovalStatus.REJECTED: "red",
        }[approval.status]
        table.add_row(
            approval.gate,
            approval.step_id,
            f"[{style}]{approval.status.value}[/]",
            approval.decided_by or "-",
            approval.reason or "-",
        )
    console.print(table)
    for approval in pending:
        console.print(
            f"[yellow]awaiting approval[/yellow] gate '{approval.gate}': {approval.prompt}\n"
            f"  approve: devforge approve --gate {approval.gate}\n"
            f"  reject : devforge approve --gate {approval.gate} --reject"
        )


def render_errors(task: Task) -> None:
    if not task.errors:
        return
    table = Table("when", "step", "kind", "message", box=None)
    for failure in task.errors:
        table.add_row(
            failure.occurred_at.strftime("%H:%M:%S"),
            failure.step_id or "-",
            failure.kind,
            failure.message,
        )
    console.print(table)


def render_verification(results: list[VerificationResult], *, show_output: bool = False) -> None:
    if not results:
        console.print("[dim]no verification results[/dim]")
        return
    table = Table("verifier", "kind", "status", "exit", "ms", "attempt", "summary", box=None)
    for result in results:
        table.add_row(
            result.verifier,
            result.kind,
            f"[{VERIFICATION_STYLE.get(result.status, '')}]{result.status.value}[/]",
            "-" if result.exit_code is None else str(result.exit_code),
            str(result.duration_ms),
            str(result.attempt),
            result.summary,
        )
    console.print(table)
    if show_output:
        for result in results:
            if result.status.ok or not result.output_excerpt:
                continue
            console.print(
                Panel(
                    escape(result.output_excerpt),
                    title=f"{escape(result.verifier)} output",
                    style="red",
                )
            )
