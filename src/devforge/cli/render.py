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


BENCHMARK_STYLE = {
    "repaired": "green",
    "not_repaired": "red",
    "rejected_suspicious": "red",
    "not_reproduced": "yellow",
    "unavailable": "yellow",
}


def render_benchmark(report) -> None:
    """Show the per-case grid, then the rate, then what the rate is not.

    The caveat is printed every time rather than kept in the docs: a success rate
    is the single most quotable number this harness produces, and it travels
    without its context unless the context travels with it.
    """
    table = Table("case", "outcome", "reproduced", "patch", "suite after", "ms", box=None)
    for result in report.results:
        style = BENCHMARK_STYLE.get(result.outcome.value, "")
        table.add_row(
            escape(result.case_id),
            f"[{style}]{result.outcome.value}[/]",
            result.reproduced,
            result.patch_verdict,
            "[green]pass[/green]" if result.tests_pass_after else "[red]fail[/red]",
            str(result.duration_ms),
        )
    console.print(table)

    for result in report.results:
        for finding in result.findings:
            console.print(f"  [red]{escape(result.case_id)}[/red] {escape(finding)}")

    rate = f"{report.repaired}/{report.total} ({report.success_rate:.0%})"
    console.print(
        Panel(
            f"solver [bold]{escape(report.solver)}[/bold]\n"
            f"repair success rate [bold]{rate}[/bold]\n"
            f"{escape(str(report.by_outcome()))}\n\n"
            "A case counts as repaired only when the defect reproduced "
            "deterministically,\nthe patch is non-empty and clean, and the whole "
            "suite passes afterwards.\nThis score covers seeded defects in small "
            "projects; it does not predict\nbehaviour on real bugs in real codebases.",
            title="benchmark",
            expand=False,
        )
    )


SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}

CHECK_STYLE = {
    "pass": "green",
    "fail": "bold red",
    "warn": "yellow",
    "n/a": "dim",
    "unknown": "magenta",
}


def render_scan(report, *, show_suppressed: bool = False) -> None:
    if not report.findings:
        console.print(
            f"[green]no findings[/green] in {report.files_scanned} file(s) "
            f"({len(report.suppressed)} accepted by the baseline)"
        )
        console.print(
            "[dim]No pattern in the rule set matched. That is not the same as "
            "\"this code is safe\".[/dim]"
        )
    else:
        table = Table("severity", "rule", "location", "threat", "finding", box=None)
        for finding in report.sorted_findings():
            table.add_row(
                f"[{SEVERITY_STYLE.get(finding.severity.value, '')}]"
                f"{finding.severity.value}[/]",
                finding.id,
                escape(finding.location),
                finding.threat or "-",
                escape(finding.title),
            )
        console.print(table)
        for finding in report.sorted_findings():
            console.print(f"  [dim]{escape(finding.location)}:[/dim] {escape(finding.evidence)}")

    if show_suppressed and report.suppressed:
        console.print("\n[dim]accepted by security/baseline.yaml:[/dim]")
        for finding in report.suppressed:
            console.print(f"  [dim]{finding.id} {escape(finding.location)}[/dim]")

    if report.unreadable:
        console.print(f"[yellow]{len(report.unreadable)} path(s) could not be read[/yellow]")


def render_audit(report) -> None:
    from devforge.security.catalog import LAYERS

    names = {layer.number: layer.name for layer in LAYERS}
    table = Table("layer", "check", "status", "detail", box=None)
    for number, results in report.by_layer().items():
        for index, result in enumerate(results):
            table.add_row(
                f"{number} {names.get(number, '')}" if index == 0 else "",
                f"{result.id} {escape(result.title)}",
                f"[{CHECK_STYLE.get(result.status.value, '')}]{result.status.value}[/]",
                escape(result.detail[:90]),
            )
    console.print(table)

    for result in report.failed + report.warned:
        if result.remediation:
            console.print(
                f"  [yellow]{result.id}[/yellow] {escape(result.remediation)}"
            )
    if report.unknown:
        console.print(
            f"[magenta]{len(report.unknown)} check(s) could not be evaluated[/magenta] "
            "[dim]- unknown is never counted as passing[/dim]"
        )


def render_threats(layers, threats) -> None:
    table = Table("#", "layer", "status", "limits", box=None)
    for layer in layers:
        table.add_row(
            str(layer.number),
            escape(layer.name),
            layer.status.value,
            escape(layer.limits[:80] + ("..." if len(layer.limits) > 80 else "")),
        )
    console.print(table)

    threat_table = Table("id", "threat", "severity", "layers", "residual risk", box=None)
    for threat in threats:
        threat_table.add_row(
            threat.id,
            escape(threat.name),
            f"[{SEVERITY_STYLE.get(threat.severity.value, '')}]{threat.severity.value}[/]",
            ",".join(str(n) for n in threat.layers),
            escape(threat.residual[:70] + ("..." if len(threat.residual) > 70 else "")),
        )
    console.print(threat_table)


EVAL_STYLE = {
    "success": "green",
    "failed": "red",
    "regressed": "bold red",
    "rejected_suspicious": "bold red",
    "invalid": "magenta",
    "unavailable": "yellow",
}


def render_eval(report) -> None:
    """Per-case grid, then the metrics, then what none of it establishes.

    The caveat is printed on every run rather than left in the docs. A success
    rate is the most quotable number here and it travels without its denominator
    unless the denominator travels with it.
    """
    table = Table("case", "category", "outcome", "checks", "ms", "detail", box=None)
    for result in report.results:
        style = EVAL_STYLE.get(result.outcome.value, "")
        passed = sum(1 for check in result.checks if check.passed)
        table.add_row(
            escape(result.case_id),
            result.category.value,
            f"[{style}]{result.outcome.value}[/]",
            f"{passed}/{len(result.checks)}" if result.checks else "-",
            str(result.duration_ms),
            escape(result.detail[:70]),
        )
    console.print(table)

    for result in report.results:
        for finding in result.findings:
            console.print(f"  [red]{escape(result.case_id)}[/red] {escape(finding)}")

    metrics = Table("metric", "value", "basis", box=None)
    for metric in report.metrics.values:
        known = metric.known
        metrics.add_row(
            metric.label,
            f"[bold]{metric.format()}[/bold]" if known else "[dim]unknown[/dim]",
            escape(metric.basis if known else metric.unknown_reason),
        )
    console.print()
    console.print(metrics)

    if report.unhonoured:
        console.print()
        for item in report.unhonoured:
            console.print(f"  [yellow]not honoured[/yellow] {escape(item)}")

    console.print(
        Panel(
            f"configuration [bold]{escape(report.config.id)}[/bold] "
            f"({escape(report.config.driver)} driver, runtime "
            f"{escape(report.config.runtime)})\n"
            f"{len(report.succeeded)} of {len(report.attempted)} attempted case(s) "
            f"succeeded; {report.total - len(report.attempted)} not attempted\n\n"
            "These cases are small and have known answers. The number does not\n"
            "transfer to real defects in real codebases, and a difference between\n"
            "two configurations this size cannot be separated from variation.",
            title="evaluation",
            expand=False,
        )
    )


def render_eval_cases(cases, categories: list[str]) -> None:
    table = Table("case", "category", "workflow", "requires", "title", box=None)
    for case in cases:
        table.add_row(
            escape(case.id),
            case.category.value,
            case.workflow,
            ", ".join(case.requires) or "-",
            escape(case.title),
        )
    console.print(table)
    console.print(f"[dim]{len(cases)} case(s) across {len(categories)} category names[/dim]")


def render_eval_configs(configs) -> None:
    table = Table("id", "driver", "runtime", "model", "context", "description", box=None)
    for config in configs:
        table.add_row(
            escape(config.id),
            config.driver,
            config.runtime,
            config.model or "-",
            config.context_strategy,
            escape(config.description),
        )
    console.print(table)


def render_worktrees(entries: list[dict], active: str) -> None:
    table = Table("branch", "path", "", box=None)
    for entry in entries:
        branch = entry.get("branch") or "(detached)"
        marker = "[green]you are here[/green]" if branch == active else ""
        table.add_row(escape(branch), escape(entry.get("path", "")), marker)
    console.print(table)


GIT_EFFECT_STYLE = {"allow": "green", "require_approval": "yellow", "refuse": "bold red"}


def render_git_verdict(argv: list[str], verdict) -> None:
    style = GIT_EFFECT_STYLE.get(verdict.effect.value, "")
    console.print(f"[dim]git[/dim] {escape(' '.join(argv[1:]))}")
    console.print(f"  [{style}]{verdict.effect.value}[/] {escape(verdict.reason)}")
    if verdict.gate:
        console.print(f"  [dim]gate:[/dim] {escape(verdict.gate)}")


FLAG_STYLE = {
    "secret": "bold red",
    "credential_file": "bold red",
    "binary": "red",
    "oversized": "yellow",
    "unrelated": "yellow",
}


def render_commit_plan(plan) -> None:
    """The message, the files, then anything found in them.

    Flags print after the plan rather than instead of it: a person deciding
    whether a flag is a false positive needs to see what the commit actually is.
    """
    console.print(Panel(escape(plan.message().rstrip()), title="commit", expand=False))

    if plan.files:
        table = Table("file", box=None)
        for name in plan.files:
            table.add_row(escape(name))
        console.print(table)
    else:
        console.print("[dim]no files[/dim]")

    for flag in plan.flags:
        style = FLAG_STYLE.get(flag.kind.value, "")
        prefix = "blocks" if flag.blocking else "review"
        console.print(f"  [{style}]{prefix}[/] {escape(flag.describe())}")

    if plan.safe:
        console.print("[green]no blocking flags[/green]")
    else:
        console.print(
            f"[bold red]{len(plan.blocking_flags)} blocking flag(s)[/bold red] - "
            "this commit will not be recorded"
        )


CE_SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}

CE_STATE_STYLE = {
    "proposed": "cyan",
    "approved": "green",
    "rejected": "dim",
    "executing": "yellow",
    "verified": "bold green",
    "failed": "red",
}


def render_findings(report) -> None:
    """Findings by priority, then what could not be looked at.

    Unavailable detectors print even when there are no findings. "Nothing found"
    and "could not look" are different statements, and a reader who sees only the
    first will believe the second.
    """
    findings = report.by_priority()
    if findings:
        table = Table("id", "sev", "conf", "risk", "where", "what", box=None)
        for finding in findings:
            style = CE_SEVERITY_STYLE.get(finding.severity.value, "")
            where = finding.affected_files[0] if finding.affected_files else "-"
            table.add_row(
                escape(finding.finding_id),
                f"[{style}]{finding.severity.value}[/]",
                f"{finding.confidence:.0%}",
                finding.estimated_risk.value,
                escape(where[-42:]),
                escape(finding.title[:62]),
            )
        console.print(table)
    else:
        console.print("[green]no findings above the confidence threshold[/green]")

    for unavailable in report.unavailable:
        console.print(
            f"  [magenta]unavailable[/magenta] {unavailable.detector}: "
            f"{escape(unavailable.detail)}"
        )

    parts = [f"{len(findings)} finding(s)"]
    if report.withheld:
        parts.append(f"{report.withheld} withheld as low confidence")
    if report.suppressed:
        parts.append(f"{len(report.suppressed)} accepted previously")
    console.print(f"[dim]{'; '.join(parts)}[/dim]")
    console.print(
        "[dim]Static analysis. Confirm each finding before acting on it - a detector "
        "that was wrong is a normal outcome.[/dim]"
    )


def render_proposals(proposals, *, title: str, counts: dict | None = None) -> None:
    if not proposals:
        console.print(f"[dim]no {title} proposals[/dim]")
    else:
        table = Table("id", "state", "sev", "n", "workflow", "title", box=None)
        for proposal in proposals:
            state = CE_STATE_STYLE.get(proposal.state.value, "")
            severity = CE_SEVERITY_STYLE.get(proposal.severity.value, "")
            table.add_row(
                escape(proposal.proposal_id),
                f"[{state}]{proposal.state.value}[/]",
                f"[{severity}]{proposal.severity.value}[/]",
                str(len(proposal.findings)),
                proposal.workflow,
                escape(proposal.title[:58]),
            )
        console.print(table)
    if counts:
        console.print(f"[dim]{counts}[/dim]")


def render_continuous_verification(result) -> None:
    for key in result.resolved:
        console.print(f"  [green]resolved[/green] {escape(key)}")
    for key in result.remaining:
        console.print(f"  [red]still firing[/red] {escape(key)}")
    for key in result.unverifiable:
        console.print(f"  [magenta]unverifiable[/magenta] {escape(key)}")

    if result.complete:
        console.print("[green]every finding this proposal was about has stopped firing[/green]")
    else:
        console.print(
            "[red]not complete[/red] - a finding that still fires means the work is "
            "not done, whatever the workflow reported"
        )


PLATFORM_STATE_STYLE = {
    "queued": "cyan",
    "leased": "yellow",
    "awaiting_approval": "bold yellow",
    "executed": "yellow",
    "verified": "bold green",
    "rejected": "bold red",
    "failed": "red",
    "expired": "magenta",
}


def render_workers(identities) -> None:
    table = Table("worker", "enabled", "capabilities", "tools", "runtimes", "key", box=None)
    for identity in identities:
        table.add_row(
            escape(identity.worker_id),
            "[green]yes[/green]" if identity.enabled else "[red]revoked[/red]",
            ", ".join(c.value for c in identity.capabilities) or "-",
            ", ".join(identity.tools) or "-",
            ", ".join(identity.runtimes) or "-",
            identity.key_fingerprint or "-",
        )
    console.print(table)


def render_platform_task(record) -> None:
    """One task: what the worker claimed, and what the control plane confirmed.

    The two are shown side by side rather than merged. A worker's report is
    evidence about the worker, not about the work, and a reader who cannot see
    both cannot notice when they disagree.
    """
    style = PLATFORM_STATE_STYLE.get(record.state.value, "default")
    console.print(
        Panel(
            f"[{style}]{record.state.value}[/]  {escape(record.envelope.description[:70])}\n"
            f"{escape(record.reason)}",
            title=escape(record.task_id),
            expand=False,
        )
    )

    claimed = record.result.claims if record.result else []
    if claimed or record.verified:
        table = Table("verifier", "worker claimed", "control plane confirmed", box=None)
        names = sorted({c.verifier for c in claimed} | {c.verifier for c in record.verified})
        by_claim = {c.verifier: c for c in claimed}
        by_confirmed = {c.verifier: c for c in record.verified}
        for name in names:
            claim = by_claim.get(name)
            confirmed = by_confirmed.get(name)
            table.add_row(
                escape(name),
                escape(claim.status) if claim else "[dim]not reported[/dim]",
                escape(confirmed.status) if confirmed else "[dim]not checked[/dim]",
            )
        console.print(table)

    if record.artifact_paths:
        console.print(f"[dim]artifacts: {', '.join(record.artifact_paths)}[/dim]")
    if not record.envelope.verify:
        console.print(
            "[yellow]nothing was independently confirmed[/yellow] - this task declared "
            "no artifact to verify, so the control plane had nothing to check"
        )
    console.print(
        "[dim]Only the confirmed column is evidence. The claimed column is what the "
        "worker said about itself.[/dim]"
    )


def render_platform_status(status: dict, records) -> None:
    console.print(f"[dim]{status['root']}[/dim]")
    if records:
        table = Table("task", "state", "worker", "attempts", "description", box=None)
        for record in records:
            style = PLATFORM_STATE_STYLE.get(record.state.value, "default")
            table.add_row(
                escape(record.task_id),
                f"[{style}]{record.state.value}[/]",
                escape(record.lease.worker_id if record.lease else "-"),
                str(record.attempts),
                escape(record.envelope.description[:52]),
            )
        console.print(table)
    else:
        console.print("[dim]the queue is empty[/dim]")

    console.print(f"{status['counts']}  -  {len(status['workers'])} worker(s)")
    if status["audit_intact"]:
        console.print(
            f"[green]audit chain intact[/green] ({status['audit_entries']} entries)"
        )
    else:
        console.print("[bold red]audit chain is broken[/bold red] - run devforge platform audit")
    if status["unreadable_queue_files"]:
        console.print(
            f"[magenta]unreadable queue files:[/magenta] "
            f"{', '.join(status['unreadable_queue_files'])}"
        )


def render_audit_trail(events, problems: list[str]) -> None:
    table = Table("#", "at", "event", "task", "worker", box=None)
    for event in events:
        table.add_row(
            str(event.sequence),
            event.at.strftime("%H:%M:%S"),
            escape(event.event),
            escape(event.task_id or "-"),
            escape(event.worker_id or "-"),
        )
    console.print(table)

    if problems:
        console.print("[bold red]the chain does not verify[/bold red]")
        for problem in problems:
            console.print(f"  [red]{escape(problem)}[/red]")
    else:
        console.print(f"[green]chain intact[/green] over {len(events)} entries")
