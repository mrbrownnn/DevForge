"""Command verifier: run an argv, judge by exit code.

The command goes through the same permission policy as any tool, so a workflow
cannot smuggle an arbitrary command into the build by declaring it a "verifier".
A verifier the policy refuses is reported as ``ERROR`` - never as a pass.
"""

from __future__ import annotations

from devforge.core.models import VerificationStatus
from devforge.core.workflow.spec import VerifierSpec
from devforge.tools.process import run_process
from devforge.verification.base import MAX_EXCERPT_CHARS, VerificationContext, Verifier

#: Exit codes whose meaning is worth spelling out in the failure summary. A verifier
#: that fails because there was nothing to check is a different problem from a
#: verifier that fails because the code is broken.
EXIT_CODE_HINTS = {
    5: "no tests were collected - this workflow expects a project with a test suite",
    127: "command not found - is the tool installed and on PATH?",
    126: "command found but not executable",
}


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
        process_policy = ctx.policy.permissions.process
        process = await run_process(
            spec.argv,
            cwd=cwd,
            timeout_s=spec.timeout_s,
            allow_env=process_policy.allow_env,
            max_output_chars=process_policy.max_output_chars,
        )

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
            hint = EXIT_CODE_HINTS.get(process.exit_code)
            if hint:
                summary = f"{summary}: {hint}"

        result = self.result(
            spec,
            ctx,
            status=status,
            exit_code=process.exit_code,
            duration_ms=process.duration_ms,
            summary=summary,
            output_excerpt=process.excerpt(MAX_EXCERPT_CHARS),
        )
        return result
