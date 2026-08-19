"""Visual verifier - DECLARED, NOT IMPLEMENTED.

Screenshot capture and perceptual diffing need a browser driver and an image
comparison backend. DevForge ships neither, so this verifier reports
``UNAVAILABLE`` and nothing else. It never reports ``PASSED``.

Because ``VerificationResult.blocking_failure`` treats a required-but-unavailable
verifier as a failure, a workflow that depends on visual verification (``clone``)
stops with an explicit reason instead of completing on an unchecked assumption.

To implement: provide a driver that renders both the reference and the candidate,
compare them with a documented metric and threshold, and register the result here.
"""

from __future__ import annotations

from devforge.core.models import VerificationStatus
from devforge.core.workflow.spec import VerifierSpec
from devforge.verification.base import VerificationContext, Verifier

REASON = (
    "visual verification is not implemented: DevForge ships no browser driver and no "
    "image diffing backend. Implement devforge.verification.visual (see docs/tools.md) "
    "before relying on this check."
)


class VisualVerifier(Verifier):
    kind = "visual"

    async def run(self, spec: VerifierSpec, ctx: VerificationContext):
        ctx.logger.warn(
            "verification.unavailable",
            verifier=spec.id,
            kind=spec.kind,
            step=ctx.step_id,
            reason=REASON,
        )
        return self.result(
            spec,
            ctx,
            status=VerificationStatus.UNAVAILABLE,
            summary="visual verification backend is not implemented",
            output_excerpt=REASON,
        )
