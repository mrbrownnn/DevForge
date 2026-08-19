"""The MCP tool: DevForge's bridge to configured MCP servers.

Replaces the Phase 0 placeholder that reported ``unavailable``. Every call now
runs the same gauntlet a native tool does, plus the checks an untrusted external
process needs.

Call path for ``mcp.call``::

    server configured?      -> no: denied
    server enabled?         -> no: denied
    transport supported?    -> no: unavailable (stdio only)
    tool named in allow_tools? -> no: denied  (deny-by-default)
    launch command allowed by the shell policy? -> no: denied
    server risk requires approval? -> yes: approval gate
    parameters valid against the discovered schema? -> no: error
    -> execute with a timeout, a sanitised environment and a size cap
    -> treat the response as untrusted content: bound, scan, fence
    -> emit an audit event either way

The server is started per call and stopped afterwards. That is slower than a
connection pool and much easier to reason about: no long-lived third-party
process outlives the operation that needed it.
"""

from __future__ import annotations

import time
from typing import Any

from devforge.core.models import ToolResult, ToolStatus
from devforge.mcp.client import McpClient, McpError, flatten_content
from devforge.mcp.registry import McpServerConfig, load_config
from devforge.tools.base import Tool, ToolAvailability, ToolContext
from devforge.tools.descriptor import (
    TOOL_OUTPUT_SCHEMA,
    RiskLevel,
    ToolDescriptor,
    ToolPermissions,
    validate_params,
)
from devforge.tools.untrusted import wrap

MCP_GATE = "mcp_server_call"


class McpTool(Tool):
    """Discover and call tools exposed by configured MCP servers."""

    name = "mcp"
    description = "Discover and call tools exposed by configured MCP servers."
    actions = ("list_servers", "list_tools", "call")

    descriptor = ToolDescriptor(
        name="mcp",
        version="1.0.0",
        description="Bridge to MCP servers configured in .devforge/mcp.yaml (stdio only).",
        capabilities=["server-discovery", "tool-discovery", "tool-invocation"],
        permissions=ToolPermissions(process_execution=True, gates=[MCP_GATE]),
        risk=RiskLevel.EXECUTE,
        input_schema={
            "list_servers": {"type": "object", "properties": {}, "additionalProperties": False},
            "list_tools": {
                "type": "object",
                "properties": {"server": {"type": "string"}},
                "required": ["server"],
                "additionalProperties": False,
            },
            "call": {
                "type": "object",
                "properties": {
                    "server": {"type": "string"},
                    "tool": {"type": "string"},
                    "arguments": {"type": "object"},
                    "timeout_s": {"type": "number"},
                },
                "required": ["server", "tool"],
                "additionalProperties": False,
            },
        },
        output_schema=TOOL_OUTPUT_SCHEMA,
    )

    def availability(self) -> ToolAvailability:
        # The bridge is implemented; whether any server is usable is per-project.
        return ToolAvailability(True, "stdio transport only; servers must be enabled explicitly")

    # -- dispatch ---------------------------------------------------------------

    async def invoke(self, action: str, params: dict[str, Any], ctx: ToolContext) -> ToolResult:
        if action not in self.actions:
            return self.unknown_action(action)

        problems = validate_params(self.descriptor.schema_for(action), params)
        if problems:
            return self.fail(action, "; ".join(problems))

        config = load_config(ctx.workspace)

        if action == "list_servers":
            return self._list_servers(config, ctx)
        if action == "list_tools":
            return await self._list_tools(config, params, ctx)
        return await self._call(config, params, ctx)

    # -- discovery --------------------------------------------------------------

    def _list_servers(self, config, ctx: ToolContext) -> ToolResult:
        rows = [
            {
                "name": server.name,
                "transport": server.transport.value,
                "enabled": server.enabled,
                "supported": server.supported,
                "trust": server.trust.value,
                "risk": server.risk.value,
                "allow_tools": server.allow_tools,
            }
            for server in config.servers
        ]
        ctx.logger.info("mcp.list_servers", tool=self.name, servers=len(rows))
        lines = [
            f"{row['name']}: {row['transport']}, "
            f"{'enabled' if row['enabled'] else 'disabled'}, trust={row['trust']}, "
            f"allowed tools={row['allow_tools'] or 'none'}"
            for row in rows
        ]
        return self.ok(
            "list_servers", "\n".join(lines) or "no MCP servers configured", servers=rows
        )

    async def _list_tools(self, config, params: dict[str, Any], ctx: ToolContext) -> ToolResult:
        server = config.server(params["server"])
        blocked = self._server_usable(server, params["server"], "list_tools", ctx)
        if blocked is not None:
            return blocked
        assert server is not None

        started = time.monotonic()
        try:
            async with McpClient(
                server.command,
                cwd=ctx.workspace,
                timeout_s=server.timeout_s,
                allow_env=server.allow_env,
            ) as client:
                discovered = await client.list_tools()
                server_info = client.server_info
        except McpError as exc:
            ctx.logger.error("mcp.discovery_failed", server=server.name, error=str(exc))
            return self.fail("list_tools", str(exc), server=server.name)

        tools = []
        for entry in discovered:
            tool_name = entry.get("name")
            if not isinstance(tool_name, str) or not tool_name:
                continue  # a server that cannot name its tools is not usable
            tools.append(
                {
                    "name": tool_name,
                    "description": str(entry.get("description", ""))[:500],
                    "approved": server.permits(tool_name),
                    "schema": entry.get("inputSchema")
                    if isinstance(entry.get("inputSchema"), dict)
                    else {},
                }
            )

        unapproved = [tool["name"] for tool in tools if not tool["approved"]]
        ctx.logger.info(
            "mcp.list_tools",
            server=server.name,
            discovered=len(tools),
            approved=len(tools) - len(unapproved),
            unapproved=unapproved or None,
            duration_ms=int((time.monotonic() - started) * 1000),
        )
        lines = [
            f"{'[approved]' if tool['approved'] else '[NOT approved]'} {tool['name']}: "
            f"{tool['description'][:120]}"
            for tool in tools
        ]
        return self.ok(
            "list_tools",
            "\n".join(lines) or "server exposes no tools",
            server=server.name,
            server_info=server_info,
            tools=tools,
            unapproved=unapproved,
        )

    # -- execution --------------------------------------------------------------

    async def _call(self, config, params: dict[str, Any], ctx: ToolContext) -> ToolResult:
        server_name = params["server"]
        tool_name = params["tool"]
        arguments = params.get("arguments") or {}
        if not isinstance(arguments, dict):
            return self.fail("call", "'arguments' must be an object")

        server = config.server(server_name)
        blocked = self._server_usable(server, server_name, "call", ctx)
        if blocked is not None:
            return blocked
        assert server is not None

        # Deny-by-default: a tool the project never named cannot be called, however
        # convincingly the server describes it.
        if not server.permits(tool_name):
            ctx.logger.warn(
                "mcp.denied",
                server=server.name,
                mcp_tool=tool_name,
                reason="tool not in allow_tools",
            )
            return ToolResult(
                tool=self.name,
                action="call",
                status=ToolStatus.DENIED,
                error=(
                    f"tool '{tool_name}' is not in allow_tools for server '{server.name}'. "
                    "Add it deliberately after reviewing what it does."
                ),
                data={"server": server.name, "mcp_tool": tool_name},
            )

        # An MCP server is a subprocess: its launch command passes the shell allowlist.
        decision = ctx.policy.check_command(server.command)
        gate_prompt = f"start MCP server '{server.name}' and call '{tool_name}'"
        refused = self.authorize("call", decision, ctx, gate_prompt=gate_prompt)
        if refused is not None:
            ctx.logger.warn(
                "mcp.denied", server=server.name, mcp_tool=tool_name, reason=decision.reason
            )
            return refused

        started = time.monotonic()
        timeout = float(params.get("timeout_s") or server.timeout_s)
        try:
            async with McpClient(
                server.command,
                cwd=ctx.workspace,
                timeout_s=timeout,
                allow_env=server.allow_env,
            ) as client:
                schema_problems = await self._validate_arguments(client, tool_name, arguments)
                if schema_problems:
                    return self.fail(
                        "call",
                        f"arguments rejected by the tool schema: {'; '.join(schema_problems)}",
                        server=server.name,
                        mcp_tool=tool_name,
                    )
                raw = await client.call_tool(tool_name, arguments)
        except McpError as exc:
            duration = int((time.monotonic() - started) * 1000)
            ctx.logger.error(
                "mcp.call_failed",
                server=server.name,
                mcp_tool=tool_name,
                error=str(exc),
                duration_ms=duration,
            )
            outcome = self.fail("call", str(exc), server=server.name, mcp_tool=tool_name)
            outcome.duration_ms = duration
            return outcome

        duration = int((time.monotonic() - started) * 1000)
        text = flatten_content(raw)
        untrusted = wrap(text, source=f"mcp:{server.name}/{tool_name}")

        ctx.logger.info(
            "mcp.call",
            server=server.name,
            mcp_tool=tool_name,
            status="error" if raw.get("isError") else "ok",
            duration_ms=duration,
            bytes=untrusted.original_length,
            truncated=untrusted.truncated,
            injection_findings=untrusted.rules or None,
            trust=server.trust.value,
        )

        if untrusted.suspicious:
            ctx.logger.warn(
                "mcp.untrusted_output",
                server=server.name,
                mcp_tool=tool_name,
                rules=untrusted.rules,
            )

        status = ToolStatus.ERROR if raw.get("isError") else ToolStatus.OK
        return ToolResult(
            tool=self.name,
            action="call",
            status=status,
            # Fenced, never raw: this text is destined for a model prompt.
            output=untrusted.fenced(),
            error="the MCP server reported an error" if status is ToolStatus.ERROR else "",
            data={
                "server": server.name,
                "mcp_tool": tool_name,
                "trust": server.trust.value,
                "injection_findings": untrusted.rules,
                "truncated": untrusted.truncated,
                "bytes": untrusted.original_length,
            },
            duration_ms=duration,
        )

    async def _validate_arguments(
        self, client: McpClient, tool_name: str, arguments: dict[str, Any]
    ) -> list[str]:
        """Check arguments against the schema the server publishes for that tool."""
        try:
            tools = await client.list_tools()
        except McpError:
            return []  # discovery failure is reported by the call itself
        for entry in tools:
            if entry.get("name") != tool_name:
                continue
            schema = entry.get("inputSchema")
            if isinstance(schema, dict):
                return validate_params(schema, arguments)
            return []
        return [f"server does not expose a tool named '{tool_name}'"]

    # -- shared guards ----------------------------------------------------------

    def _server_usable(
        self, server: McpServerConfig | None, name: str, action: str, ctx: ToolContext
    ) -> ToolResult | None:
        if server is None:
            return ToolResult(
                tool=self.name,
                action=action,
                status=ToolStatus.DENIED,
                error=f"no MCP server named '{name}' in .devforge/mcp.yaml",
            )
        if not server.enabled:
            return ToolResult(
                tool=self.name,
                action=action,
                status=ToolStatus.DENIED,
                error=f"MCP server '{name}' is configured but not enabled",
                data={"server": name},
            )
        if not server.supported:
            return self.unavailable(
                action,
                f"transport '{server.transport.value}' is not implemented; DevForge speaks "
                "stdio only (docs/security/mcp.md)",
            )
        return None
