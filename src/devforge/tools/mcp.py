"""MCP tool - DECLARED, NOT IMPLEMENTED.

Model Context Protocol servers are the intended path for third-party capabilities
(databases, issue trackers, design tools). DevForge defines the seam here but
implements no MCP client: there is no transport, no handshake and no server
registry in the MVP.

Actions report ``ToolStatus.UNAVAILABLE``. Nothing here pretends to talk to a
server. A real implementation needs: server configuration in the project config,
a stdio/HTTP client, tool discovery, and per-server policy - all of which is a
larger piece of work than the MVP justifies. See docs/tools.md.
"""

from __future__ import annotations

from typing import Any

from devforge.core.models import ToolResult
from devforge.tools.base import Tool, ToolAvailability, ToolContext

REASON = (
    "the MCP tool is an unimplemented adapter: DevForge has no MCP client. "
    "No server configuration, transport or tool discovery exists yet (see docs/tools.md)."
)


class McpTool(Tool):
    name = "mcp"
    description = "Call tools exposed by MCP servers (NOT IMPLEMENTED)."
    actions = ("list_servers", "list_tools", "call")

    def availability(self) -> ToolAvailability:
        return ToolAvailability(False, REASON)

    async def invoke(self, action: str, params: dict[str, Any], ctx: ToolContext) -> ToolResult:
        if action not in self.actions:
            return self.unknown_action(action)
        ctx.logger.warn("tool.unavailable", tool=self.name, action=action, reason=REASON)
        return self.unavailable(action, REASON)
