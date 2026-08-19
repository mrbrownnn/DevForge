"""Verifier interface.

A verifier answers one question: *is the work actually correct according to this
check?* It is the only authority on that question - an agent claiming success is
evidence of nothing.

Verifiers are selected by ``kind``. Adding a new kind (e2e, mutation testing,
performance budget) means implementing this interface and registering it; the
orchestrator does not change.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from devforge.core.models import VerificationResult
from devforge.core.registry.base import Registry
from devforge.core.workflow.spec import VerifierSpec
from devforge.observability.logging import RunLogger, null_logger
from devforge.policy.engine import PolicyEngine

MAX_EXCERPT_CHARS = 4000


@dataclass
class VerificationContext:
    workspace: Path
    policy: PolicyEngine
    logger: RunLogger = field(default_factory=null_logger)
    step_id: str = ""
    attempt: int = 1
    task_id: str = ""


class Verifier(ABC):
    """Runs one check and reports a structured result."""

    kind: str = "abstract"

    @abstractmethod
    async def run(self, spec: VerifierSpec, ctx: VerificationContext) -> VerificationResult:
        """Execute the check. Must never raise for a failing check - report it."""

    @staticmethod
    def result(spec: VerifierSpec, ctx: VerificationContext, **fields) -> VerificationResult:
        return VerificationResult(
            verifier=spec.id,
            kind=spec.kind,
            required=spec.required,
            step_id=ctx.step_id or None,
            attempt=ctx.attempt,
            **fields,
        )


class VerifierRegistry(Registry[Verifier]):
    def __init__(self) -> None:
        super().__init__("verifier kind")

    @classmethod
    def default(cls) -> VerifierRegistry:
        from devforge.verification.artifacts import ArtifactVerifier
        from devforge.verification.command import CommandVerifier
        from devforge.verification.visual import VisualVerifier

        registry = cls()
        command = CommandVerifier()
        # Every command-shaped kind shares one implementation; the kind is kept
        # distinct so reports and future backends can differentiate them.
        for kind in ("command", "tests", "lint", "typecheck", "build", "e2e", "security"):
            registry.register(kind, command)
        registry.register("artifacts", ArtifactVerifier())
        registry.register("visual", VisualVerifier())
        return registry
