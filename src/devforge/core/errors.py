"""Exception hierarchy for DevForge.

Every error raised deliberately by DevForge derives from :class:`DevForgeError` so
callers (notably the CLI) can distinguish expected failures from bugs.
"""

from __future__ import annotations


class DevForgeError(Exception):
    """Base class for all DevForge errors."""


class ConfigError(DevForgeError):
    """Malformed or missing configuration (workflow, policy, agent, skill)."""


class WorkflowError(ConfigError):
    """A workflow definition could not be parsed or validated."""


class RegistryError(DevForgeError):
    """A registry lookup failed or a duplicate registration was attempted."""


class StateError(DevForgeError):
    """Project state could not be read, written, or was not initialised."""


class NotInitializedError(StateError):
    """The working directory has no ``.devforge`` project state."""


class RuntimeUnavailableError(DevForgeError):
    """An agent runtime was requested but is not usable in this environment."""


class RuntimeExecutionError(DevForgeError):
    """An agent runtime failed while executing an invocation."""


class PolicyViolation(DevForgeError):
    """An operation was refused by the permission policy."""


class ApprovalRequired(DevForgeError):
    """An operation needs human approval that has not been granted.

    Carries the gate identifier so the orchestrator can record the pending gate.
    """

    def __init__(self, gate: str, message: str = "") -> None:
        self.gate = gate
        super().__init__(message or f"approval required for gate '{gate}'")


class VerificationError(DevForgeError):
    """A verifier could not be executed (distinct from a verifier reporting failure)."""
