"""Runtime capability declarations.

Runtimes are not interchangeable. One streams, another does not. One can spawn
subagents, another has no such concept. One enforces its own approval prompts,
another has none. Pretending otherwise produces workflows that silently do less
than they claim.

So a runtime declares what it can do, and the orchestrator can refuse a workflow
that needs something the selected runtime lacks - before any work starts, rather
than halfway through.

Capability names are deliberately coarse. A finer taxonomy would need evidence
from more than two adapters, and inventing one now would be guesswork.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class Capability(str, Enum):
    """What a runtime can do. Absent means "no", never "unknown"."""

    #: Can execute tools during a turn (file edits, shell, etc.).
    TOOLS = "tools"
    #: Emits incremental output rather than only a final result.
    STREAMING = "streaming"
    #: Returns machine-readable results rather than only prose.
    STRUCTURED_OUTPUT = "structured_output"
    #: Can delegate to nested agents within one invocation.
    SUBAGENTS = "subagents"
    #: Has its own permission/approval mechanism DevForge can drive.
    APPROVALS = "approvals"
    #: Can drive a browser.
    BROWSER = "browser"
    #: Can talk to MCP servers itself.
    MCP = "mcp"
    #: Work can be resumed across invocations (session ids).
    SESSIONS = "sessions"


class RuntimeCapabilities(BaseModel):
    """A declaration, not a promise the core verifies at runtime.

    An adapter that overstates itself will fail at execution and be reported as a
    runtime error - the same as any other broken adapter. The value of the
    declaration is that mismatches are caught *before* work begins.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    version: str = "unknown"
    capabilities: set[Capability] = Field(default_factory=set)
    #: Tool names this runtime can be asked to use, or empty for "none".
    tools: list[str] = Field(default_factory=list)
    #: Free-text notes about limits a caller should know (cost, isolation, quirks).
    notes: str = ""

    def has(self, capability: Capability) -> bool:
        return capability in self.capabilities

    def missing(self, required: set[Capability]) -> set[Capability]:
        return set(required) - self.capabilities

    def describe(self) -> dict[str, object]:
        return {
            "name": self.name,
            "version": self.version,
            "capabilities": sorted(c.value for c in self.capabilities),
            "tools": sorted(self.tools),
            "notes": self.notes,
        }
