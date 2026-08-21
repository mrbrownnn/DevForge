"""The debug tool: reproduce, collect evidence, review a patch, write the report.

This is the agent-facing surface of :mod:`devforge.debug`. It exists so a debugging
agent works from observation rather than from recall - the difference between "the
test fails because the slice is off by one, here is the traceback and the six lines
around it" and a plausible story about code nobody looked at.

Four actions, in the order a repair uses them:

``reproduce``
    Run the reproduction command several times and classify it as deterministic,
    flaky or not reproduced. Flaky is reported, never smoothed over.
``evidence``
    Gather traces, failing tests, logs, the diff, the implicated source and
    runtime state into one bundle - redacted, and with refusals listed.
``review_patch``
    Read the current diff for the ways a repair can cheat.
``report``
    Write the repair report the ``repair-report`` verifier requires.

One design decision is worth stating plainly: **the report's "changed files"
section comes from git, not from the agent.** An agent that mis-states what it
touched - through carelessness or otherwise - produces a report that disagrees
with the repository, and the point of the report is to be the thing a reviewer can
trust. So the tool asks git and writes down the answer.

Everything runs under the same policy as any other tool: argv only, no shell,
paths checked before they are read, output redacted before it is returned.
"""

from __future__ import annotations

from typing import Any

from devforge.core.models import ToolResult
from devforge.debug.evidence import EvidenceCollector
from devforge.debug.models import (
    Diagnosis,
    RepairOutcome,
    RepairReport,
    VerificationSummary,
)
from devforge.debug.patch_guard import review_patch
from devforge.debug.reproduce import reproduce
from devforge.tools.base import Tool, ToolContext
from devforge.tools.descriptor import (
    TOOL_OUTPUT_SCHEMA,
    RiskLevel,
    ToolDescriptor,
    ToolPermissions,
)
from devforge.tools.process import run_process

DEFAULT_REPORT_PATH = "REPAIR-REPORT.md"
MAX_DIFF_CHARS = 400_000

_STRING_LIST = {"type": "array", "items": {"type": "string"}}

_DIAGNOSIS_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "root_cause": {"type": "string"},
        "hypothesis": {"type": "string"},
        "suspect_files": _STRING_LIST,
        "confidence": {"type": "string"},
    },
    "additionalProperties": False,
}


class DebugTool(Tool):
    name = "debug"
    description = "Reproduce a defect, collect evidence, review the patch, report the repair."
    actions = ("reproduce", "evidence", "review_patch", "report")

    descriptor = ToolDescriptor(
        name="debug",
        version="1.0.0",
        description=(
            "Structured debugging: deterministic reproduction, redacted evidence "
            "collection, suspicious-patch review and the repair report."
        ),
        capabilities=[
            "reproduction",
            "evidence-collection",
            "patch-review",
            "repair-reporting",
        ],
        # No network and no delete. A debugger reads, runs the reproduction command
        # under the shell allowlist, and writes one report.
        permissions=ToolPermissions(
            filesystem_read=True,
            filesystem_write=True,
            process_execution=True,
            gates=["destructive_command"],
        ),
        risk=RiskLevel.EXECUTE,
        input_schema={
            "reproduce": {
                "type": "object",
                "properties": {
                    "argv": _STRING_LIST,
                    "runs": {"type": "integer"},
                    "timeout_s": {"type": "integer"},
                    "expect_failure": {"type": "boolean"},
                },
                "required": ["argv"],
                "additionalProperties": False,
            },
            "evidence": {
                "type": "object",
                "properties": {
                    "output": {"type": "string"},
                    "logs": _STRING_LIST,
                    "source": _STRING_LIST,
                    "include_diff": {"type": "boolean"},
                    "include_runtime_state": {"type": "boolean"},
                    "include_traceback_source": {"type": "boolean"},
                },
                "additionalProperties": False,
            },
            "review_patch": {
                "type": "object",
                "properties": {
                    "diff": {"type": "string"},
                    "base": {"type": "string"},
                },
                "additionalProperties": False,
            },
            "report": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "bug": {"type": "string"},
                    "diagnosis": _DIAGNOSIS_SCHEMA,
                    "tests": _STRING_LIST,
                    "notes": _STRING_LIST,
                    "verification": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string"},
                                "status": {"type": "string"},
                                "summary": {"type": "string"},
                                "required": {"type": "boolean"},
                            },
                            "required": ["name", "status"],
                            "additionalProperties": False,
                        },
                    },
                },
                "additionalProperties": False,
            },
        },
        output_schema=TOOL_OUTPUT_SCHEMA,
    )

    async def invoke(self, action: str, params: dict[str, Any], ctx: ToolContext) -> ToolResult:
        if action not in self.actions:
            return self.unknown_action(action)
        invalid = self.validate(action, params)
        if invalid is not None:
            return invalid

        if action == "reproduce":
            return await self._reproduce(params, ctx)
        if action == "evidence":
            return await self._evidence(params, ctx)
        if action == "review_patch":
            return await self._review(params, ctx)
        return await self._report(params, ctx)

    # -- actions ----------------------------------------------------------------

    async def _reproduce(self, params: dict[str, Any], ctx: ToolContext) -> ToolResult:
        argv = [str(item) for item in params.get("argv") or []]
        if not argv:
            return self.fail("reproduce", "action 'reproduce' requires a non-empty 'argv'")

        result = await reproduce(
            argv,
            workspace=ctx.workspace,
            policy=ctx.policy,
            runs=int(params.get("runs", 2)),
            timeout_s=int(params.get("timeout_s", 600)),
            logger=ctx.logger,
            expect_failure=bool(params.get("expect_failure", True)),
        )
        if result.outcome.value == "unavailable":
            # Policy said no. That is a denial, not a debugging outcome, and the
            # caller needs to see it as one.
            return self.fail("reproduce", result.summary, outcome=result.outcome.value)

        return self.ok(
            "reproduce",
            result.render(),
            outcome=result.outcome.value,
            deterministic=result.outcome.usable,
            attempts=len(result.attempts),
            summary=result.summary,
        )

    async def _evidence(self, params: dict[str, Any], ctx: ToolContext) -> ToolResult:
        collector = EvidenceCollector(
            workspace=ctx.workspace, policy=ctx.policy, logger=ctx.logger
        )
        output = str(params.get("output") or "")
        if output:
            collector.from_output(output)
            if params.get("include_traceback_source", True):
                collector.source_for_traceback(output)

        collector.logs([str(item) for item in params.get("logs") or []])
        collector.source_files([str(item) for item in params.get("source") or []])

        if params.get("include_diff", True):
            await collector.git_diff()
        if params.get("include_runtime_state", True):
            collector.runtime_state()

        bundle = collector.bundle
        return self.ok(
            "evidence",
            bundle.render(),
            items=len(bundle.items),
            kinds=[kind.value for kind in bundle.kinds()],
            refused=bundle.refused,
        )

    async def _review(self, params: dict[str, Any], ctx: ToolContext) -> ToolResult:
        supplied = str(params.get("diff") or "")
        if supplied:
            diff = supplied[:MAX_DIFF_CHARS]
        else:
            diff, problem = await _worktree_diff(ctx, str(params.get("base") or ""))
            if problem:
                return self.fail("review_patch", problem)

        review = review_patch(diff)
        return self.ok(
            "review_patch",
            review.render(),
            verdict=review.verdict().value,
            major=len(review.major),
            minor=len(review.minor),
            files_changed=review.files_changed,
            findings=[finding.model_dump(mode="json") for finding in review.findings],
        )

    async def _report(self, params: dict[str, Any], ctx: ToolContext) -> ToolResult:
        relative = str(params.get("path") or DEFAULT_REPORT_PATH)
        decision = ctx.policy.check_path(relative, mode="write")
        blocked = self.authorize("report", decision, ctx, gate_prompt=f"write {relative}")
        if blocked is not None:
            return blocked

        diff, problem = await _worktree_diff(ctx, "")
        review = review_patch(diff) if not problem else review_patch("")

        report = RepairReport(
            bug=str(params.get("bug") or ""),
            diagnosis=Diagnosis.model_validate(params.get("diagnosis") or {}),
            review=review,
            tests=[str(item) for item in params.get("tests") or []],
            verification=[
                VerificationSummary.model_validate(entry)
                for entry in params.get("verification") or []
            ],
            notes=[str(item) for item in params.get("notes") or []],
        )
        if problem:
            report.notes.append(f"changed files could not be read from git: {problem}")
        report.outcome = _outcome(report)

        path = ctx.policy.resolve_path(relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(report.render(), encoding="utf-8")

        missing = report.missing_parts()
        ctx.logger.info(
            "tool.debug",
            tool=self.name,
            action="report",
            path=relative,
            complete=not missing,
            outcome=report.outcome.value,
        )
        return self.ok(
            "report",
            f"wrote {relative} ({report.outcome.value})"
            + (f"; incomplete, missing: {', '.join(missing)}" if missing else ""),
            path=relative,
            complete=not missing,
            missing=missing,
            outcome=report.outcome.value,
            files_changed=review.files_changed,
        )


def _outcome(report: RepairReport) -> RepairOutcome:
    """Derived, never asserted by the caller.

    A tool that let an agent write ``outcome: repaired`` into its own report would
    be recording a claim, not a finding.
    """
    if report.review.verdict().value == "suspicious":
        return RepairOutcome.REJECTED_SUSPICIOUS
    required = [entry for entry in report.verification if entry.required]
    if required and all(entry.passed for entry in required) and report.review.files_changed:
        return RepairOutcome.REPAIRED
    return RepairOutcome.NOT_REPAIRED


async def _worktree_diff(ctx: ToolContext, base: str) -> tuple[str, str]:
    argv = ["git", "diff", "--no-color", base or "HEAD"]
    decision = ctx.policy.check_command(argv)
    if not decision.allowed:
        return "", f"{' '.join(argv)}: {decision.reason}"
    result = await run_process(
        argv,
        cwd=ctx.workspace,
        timeout_s=120,
        allow_env=ctx.policy.permissions.process.allow_env,
        max_output_chars=MAX_DIFF_CHARS,
    )
    if result.exit_code != 0 and not base:
        result = await run_process(
            ["git", "diff", "--no-color"],
            cwd=ctx.workspace,
            timeout_s=120,
            allow_env=ctx.policy.permissions.process.allow_env,
            max_output_chars=MAX_DIFF_CHARS,
        )
    if result.exit_code != 0:
        return "", f"`{' '.join(argv)}` failed: {(result.error or result.combined)[:300]}"
    return result.stdout, ""

