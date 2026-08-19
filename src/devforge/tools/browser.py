"""Browser tool - DECLARED, NOT IMPLEMENTED.

DevForge ships no browser automation. This adapter exists so the interface, the
action vocabulary and the ``clone`` workflow are real and executable, and so the
gap is visible at runtime instead of being discovered halfway through a run.

Every action returns ``ToolStatus.UNAVAILABLE`` with an explanation. It never
returns fabricated DOM, screenshots or measurements, and the orchestrator treats
an unavailable tool as a hard step failure.

To implement it, subclass this tool with a real driver (Playwright is the obvious
choice), register it in place of this one, and make ``availability()`` report the
driver state. See docs/tools.md.
"""

from __future__ import annotations

from typing import Any

from devforge.core.models import ToolResult
from devforge.tools.base import Tool, ToolAvailability, ToolContext

REASON = (
    "the browser tool is an unimplemented adapter: DevForge ships no browser driver. "
    "Install a driver and register a real implementation (see docs/tools.md)."
)


class BrowserTool(Tool):
    name = "browser"
    description = "Load pages, capture DOM, styles and screenshots (NOT IMPLEMENTED)."
    actions = ("open", "screenshot", "dom", "computed_styles", "assets", "close")

    def availability(self) -> ToolAvailability:
        return ToolAvailability(False, REASON)

    async def invoke(self, action: str, params: dict[str, Any], ctx: ToolContext) -> ToolResult:
        if action not in self.actions:
            return self.unknown_action(action)
        ctx.logger.warn("tool.unavailable", tool=self.name, action=action, reason=REASON)
        return self.unavailable(action, REASON)
