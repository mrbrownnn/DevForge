"""Artifact verifier: did the declared outputs actually appear?

The cheapest useful check in the harness, and the one that catches the most common
agent failure - reporting success without producing the file it was asked for.

It needs no external tooling, which makes it the one verifier that works in a fresh
project with no test suite, no linter and no build. Paths are resolved through the
permission policy, so a workflow cannot use a verifier to probe outside the
workspace.

Declared outputs come from the workflow step (``outputs:``), passed through the
verifier spec as ``expect``. A verifier with nothing to expect reports ``skipped``
rather than inventing a pass.
"""

from __future__ import annotations

from devforge.core.models import VerificationStatus
from devforge.core.workflow.spec import VerifierSpec
from devforge.verification.base import VerificationContext, Verifier


class ArtifactVerifier(Verifier):
    kind = "artifacts"

    async def run(self, spec: VerifierSpec, ctx: VerificationContext) -> object:
        expected = list(spec.expect)
        if not expected:
            return self.result(
                spec,
                ctx,
                status=VerificationStatus.SKIPPED,
                summary="no artifacts declared for this step",
            )

        missing: list[str] = []
        empty: list[str] = []
        denied: list[str] = []

        for relative in expected:
            decision = ctx.policy.check_path(relative, mode="read")
            if not decision.allowed:
                denied.append(f"{relative} ({decision.reason})")
                continue
            path = ctx.policy.resolve_path(relative)
            if not path.is_file():
                missing.append(relative)
            elif path.stat().st_size == 0:
                empty.append(relative)

        if denied:
            return self.result(
                spec,
                ctx,
                status=VerificationStatus.ERROR,
                summary="artifact path refused by policy",
                output_excerpt="\n".join(denied),
            )

        if missing or empty:
            lines = [f"missing: {path}" for path in missing]
            lines += [f"empty: {path}" for path in empty]
            return self.result(
                spec,
                ctx,
                status=VerificationStatus.FAILED,
                summary=(
                    f"{len(missing)} missing, {len(empty)} empty of {len(expected)} "
                    "declared artifact(s)"
                ),
                output_excerpt="\n".join(lines),
            )

        return self.result(
            spec,
            ctx,
            status=VerificationStatus.PASSED,
            summary=f"all {len(expected)} declared artifact(s) present and non-empty",
            output_excerpt="\n".join(f"present: {path}" for path in expected),
        )
