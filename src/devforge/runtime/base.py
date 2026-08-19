"""The agent runtime boundary.

``AgentRuntime`` is the *only* thing the orchestrator knows about agent execution.
It takes a runtime-agnostic :class:`AgentInvocation` and returns a structured
:class:`AgentResult`. Nothing above this line may import a concrete runtime, and
nothing in :mod:`devforge.core` mentions a vendor by name.

Adding a runtime means implementing this class and registering it - see
``docs/runtimes.md``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from devforge.core.models import AgentInvocation, AgentResult
from devforge.observability.logging import RunLogger, null_logger

if TYPE_CHECKING:  # pragma: no cover - typing only
    from devforge.tools.base import ToolRegistry


class ToolProvider(Protocol):
    """The slice of the tool registry a runtime is allowed to see."""

    def names(self) -> list[str]: ...


@dataclass(frozen=True)
class RuntimeAvailability:
    """Whether a runtime can actually run here, and why not if it cannot."""

    available: bool
    detail: str = ""
    version: str = ""


@dataclass
class RuntimeContext:
    """Everything a runtime may need besides the invocation itself."""

    workspace: Path
    tools: "ToolRegistry | None" = None
    logger: RunLogger = field(default_factory=null_logger)
    settings: dict = field(default_factory=dict)


class AgentRuntime(ABC):
    """Executes one agent invocation."""

    #: Stable identifier used in config, CLI flags and persisted task records.
    name: str = "abstract"

    @abstractmethod
    async def execute(
        self, invocation: AgentInvocation, context: RuntimeContext
    ) -> AgentResult:
        """Run the agent and return a structured result.

        Implementations must not raise for *agent* failure - they return an
        ``AgentResult`` with ``status=ERROR`` and a populated ``error`` field.
        They may raise :class:`~devforge.core.errors.RuntimeExecutionError` when
        the runtime itself is broken (binary missing, unparsable protocol).
        """

    def availability(self) -> RuntimeAvailability:
        """Cheap local check, used by ``devforge doctor`` and before a run starts."""
        return RuntimeAvailability(available=True)

    def describe(self) -> str:
        return self.__doc__.strip().splitlines()[0] if self.__doc__ else self.name

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<{type(self).__name__} name={self.name!r}>"
