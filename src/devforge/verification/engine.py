"""Verification engine.

Resolves verifier ids to specs, runs the selected checks concurrently, and
aggregates them into a single verdict.

Aggregation rule: a set of results passes only when no *required* verifier
reports anything other than passed/skipped. An unavailable required verifier is
therefore a failure - the alternative would be silently treating "we could not
check" as "it is fine", which is exactly the failure mode this whole layer exists
to prevent.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from devforge.core.errors import VerificationError
from devforge.core.models import VerificationResult, VerificationStatus
from devforge.core.workflow.spec import VerifierSpec, WorkflowSpec
from devforge.verification.base import VerificationContext, Verifier, VerifierRegistry


@dataclass(frozen=True)
class VerificationReport:
    results: list[VerificationResult]

    @property
    def passed(self) -> bool:
        return not any(result.blocking_failure for result in self.results)

    @property
    def failures(self) -> list[VerificationResult]:
        return [result for result in self.results if result.blocking_failure]

    @property
    def summary(self) -> str:
        if not self.results:
            return "no verifiers configured"
        parts = [f"{result.verifier}={result.status.value}" for result in self.results]
        return ", ".join(parts)


class VerificationEngine:
    def __init__(self, registry: VerifierRegistry | None = None) -> None:
        self.registry = registry or VerifierRegistry.default()

    # -- resolution -------------------------------------------------------------

    @staticmethod
    def collect_specs(
        workflow: WorkflowSpec, project_verifiers: list[VerifierSpec] | None = None
    ) -> dict[str, VerifierSpec]:
        """Workflow definitions win over project-level ones with the same id."""
        specs: dict[str, VerifierSpec] = {v.id: v for v in (project_verifiers or [])}
        specs.update({v.id: v for v in workflow.verifiers})
        return specs

    @staticmethod
    def select(specs: dict[str, VerifierSpec], ids: list[str]) -> list[VerifierSpec]:
        missing = [vid for vid in ids if vid not in specs]
        if missing:
            raise VerificationError(
                f"undefined verifier(s) {missing}; defined: {sorted(specs) or '<none>'}"
            )
        return [specs[vid] for vid in ids]

    # -- execution --------------------------------------------------------------

    def verifier_for(self, spec: VerifierSpec) -> Verifier | None:
        return self.registry.try_get(spec.kind)

    async def run_one(self, spec: VerifierSpec, ctx: VerificationContext) -> VerificationResult:
        verifier = self.verifier_for(spec)
        if verifier is None:
            return VerificationResult(
                verifier=spec.id,
                kind=spec.kind,
                required=spec.required,
                step_id=ctx.step_id or None,
                attempt=ctx.attempt,
                status=VerificationStatus.UNAVAILABLE,
                summary=f"no verifier registered for kind '{spec.kind}'",
                output_excerpt=f"known kinds: {', '.join(self.registry.names())}",
            )
        try:
            return await verifier.run(spec, ctx)
        except Exception as exc:  # a broken verifier must not abort the whole run
            return VerificationResult(
                verifier=spec.id,
                kind=spec.kind,
                required=spec.required,
                step_id=ctx.step_id or None,
                attempt=ctx.attempt,
                status=VerificationStatus.ERROR,
                summary=f"verifier raised {type(exc).__name__}",
                output_excerpt=str(exc),
            )

    async def run(
        self, specs: list[VerifierSpec], ctx: VerificationContext
    ) -> VerificationReport:
        """Run all verifiers concurrently and aggregate. Order of results is stable."""
        if not specs:
            return VerificationReport(results=[])
        results = await asyncio.gather(*(self.run_one(spec, ctx) for spec in specs))
        return VerificationReport(results=list(results))
