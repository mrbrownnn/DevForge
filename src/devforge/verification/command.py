"""Command verifier: run an argv, judge by exit code.

The command goes through the same permission policy as any tool, so a workflow
cannot smuggle an arbitrary command into the build by declaring it a "verifier".
A verifier the policy refuses is reported as ``ERROR`` - never as a pass.
"""

from __future__ import annotations

import shlex

from devforge.core.models import VerificationStatus
from devforge.core.workflow.spec import VerifierSpec
from devforge.tools.process import run_process
from devforge.verification.base import MAX_EXCERPT_CHARS, VerificationContext, Verifier


class CommandVerifier(Verifier):
    kind = "command"

    async def run(self, spec: VerifierSpec, ctx: VerificationContext):
        if not spec.argv:
            return self.result(
                spec,
                ctx,
                status=VerificationStatus.ERROR,
                summary="verifier declares no command to run",
                output_excerpt=f"verifier '{spec.id}' has an empty argv",
            )

        decision = ctx.policy.check_command(spec.argv)
        if not decision.allowed:
            return self.result(
                spec,
                ctx,
                status=VerificationStatus.ERROR,
                summary=f"blocked by permission policy: {decision.effect.value}",
                output_excerpt=decision.reason,
            )

        cwd = ctx.policy.resolve_path(spec.cwd) if spec.cwd else ctx.workspace
        ctx.logger.info(
            "verification.start",
            verifier=spec.id,
            kind=spec.kind,
            step=ctx.step_id,
            attempt=ctx.attempt,
            command=shlex.join(spec.argv),
        )
        process = await run_process(spec.argv, cwd=cwd, timeout_s=spec.timeout_s)

        if not process.started:
            status = VerificationStatus.ERROR
            summary = process.error
        elif process.timed_out:
            status = VerificationStatus.FAILED
            summary = f"timed out after {spec.timeout_s}s"
        elif process.exit_code in spec.success_exit_codes:
            status = VerificationStatus.PASSED
            summary = f"{spec.id} passed (exit {process.exit_code})"
        else:
            status = VerificationStatus.FAILED
            summary = f"{spec.id} failed (exit {process.exit_code})"

        result = self.result(
            spec,
            ctx,
            status=status,
            exit_code=process.exit_code,
            duration_ms=process.duration_ms,
            summary=summary,
            output_excerpt=process.excerpt(MAX_EXCERPT_CHARS),
        )
        ctx.logger.info(
            "verification.finish",
            verifier=spec.id,
            kind=spec.kind,
            step=ctx.step_id,
            attempt=ctx.attempt,
            status=status.value,
            exit_code=process.exit_code,
            duration_ms=process.duration_ms,
        )
        return result
