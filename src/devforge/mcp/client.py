"""Minimal MCP client over stdio.

MCP is JSON-RPC 2.0 framed as newline-delimited JSON on a child process's stdin
and stdout. That is little enough that implementing it directly is cheaper and
more auditable than taking a dependency, and it keeps DevForge at four runtime
packages.

Scope, stated up front:

* **stdio transport only.** HTTP and SSE transports are not implemented. A server
  configured with one is refused, not silently downgraded.
* **Protocol subset:** ``initialize``, ``tools/list``, ``tools/call``. Resources,
  prompts, sampling and notifications are not implemented. Sampling in particular
  would let a server drive the model, which is a trust inversion this harness
  should not accept by default.

Security posture (see docs/security/mcp.md):

* the server process gets a sanitised environment, like any other child;
* every request has a timeout and the process is killed when it expires;
* responses are size-capped before parsing, so a hostile server cannot exhaust
  memory by streaming forever;
* nothing a server returns is trusted: names, schemas and text are all validated
  or treated as untrusted content by the caller.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from devforge.tools.environment import build_env

PROTOCOL_VERSION = "2024-11-05"
CLIENT_INFO = {"name": "devforge", "version": "0.1.0"}

#: A single JSON-RPC frame larger than this is refused unparsed.
MAX_FRAME_BYTES = 4_000_000
#: Total bytes read from one server before the connection is abandoned.
MAX_SESSION_BYTES = 32_000_000
#: How long to wait for a killed server to reap before abandoning it.
STOP_TIMEOUT_S = 5.0
#: How long to spend draining a killed server's pipes so it can actually die.
DRAIN_TIMEOUT_S = 2.0


class McpError(Exception):
    """The server failed, misbehaved, or spoke something other than MCP."""


@dataclass
class McpServerProcess:
    """A running MCP server subprocess and its JSON-RPC state."""

    argv: list[str]
    cwd: Path
    env: dict[str, str]
    timeout_s: float = 30.0
    process: asyncio.subprocess.Process | None = None
    _next_id: int = field(default=1, init=False)
    _bytes_read: int = field(default=0, init=False)

    async def start(self) -> None:
        try:
            self.process = await asyncio.create_subprocess_exec(
                *self.argv,
                cwd=str(self.cwd),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=self.env,
            )
        except (OSError, ValueError) as exc:
            raise McpError(f"could not start MCP server {self.argv[0]!r}: {exc}") from exc

    async def stop(self) -> None:
        """Terminate the server, without ever blocking on it.

        A server killed while blocked writing into a full stdout pipe will not reap
        promptly: the write never completes, so a plain ``wait()`` can hang forever.
        Since the whole point of the size and time caps is that a hostile server
        cannot stall the harness, cleanup has to be bounded too. Stdin is closed to
        release a child blocked on read, and the wait is time-boxed - an unreaped
        child is left to the OS rather than allowed to hold the run.
        """
        process, self.process = self.process, None
        if process is None:
            return

        if process.stdin is not None:
            with contextlib.suppress(OSError, RuntimeError):
                process.stdin.close()

        if process.returncode is None:
            with contextlib.suppress(ProcessLookupError, OSError, RuntimeError):
                process.kill()

        # Drain what the child already wrote: a process blocked on a full pipe cannot
        # die until someone reads it, so draining is what makes the kill take effect.
        for stream in (process.stdout, process.stderr):
            if stream is None:
                continue
            with contextlib.suppress(TimeoutError, ValueError, OSError, RuntimeError):
                await asyncio.wait_for(stream.read(-1), timeout=DRAIN_TIMEOUT_S)

        with contextlib.suppress(TimeoutError, ProcessLookupError, RuntimeError):
            await asyncio.wait_for(process.wait(), timeout=STOP_TIMEOUT_S)

    async def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Send one JSON-RPC request and wait for the matching response."""
        if self.process is None or self.process.stdin is None or self.process.stdout is None:
            raise McpError("MCP server is not running")

        request_id = self._next_id
        self._next_id += 1
        frame = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            frame["params"] = params

        payload = (json.dumps(frame) + "\n").encode("utf-8")
        try:
            self.process.stdin.write(payload)
            await self.process.stdin.drain()
        except (BrokenPipeError, ConnectionResetError) as exc:
            raise McpError(f"MCP server closed the connection during '{method}'") from exc

        return await self._read_response(request_id, method)

    async def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        if self.process is None or self.process.stdin is None:
            raise McpError("MCP server is not running")
        frame: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            frame["params"] = params
        self.process.stdin.write((json.dumps(frame) + "\n").encode("utf-8"))
        await self.process.stdin.drain()

    async def _read_response(self, request_id: int, method: str) -> dict[str, Any]:
        deadline = asyncio.get_running_loop().time() + self.timeout_s
        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise McpError(f"MCP server timed out after {self.timeout_s}s on '{method}'")
            try:
                line = await asyncio.wait_for(
                    self.process.stdout.readline(),  # type: ignore[union-attr]
                    timeout=remaining,
                )
            except TimeoutError as exc:
                raise McpError(
                    f"MCP server timed out after {self.timeout_s}s on '{method}'"
                ) from exc
            except ValueError as exc:  # readline hit its internal limit
                raise McpError(f"MCP server sent an oversized frame during '{method}'") from exc

            if not line:
                stderr = await self._drain_stderr()
                raise McpError(
                    f"MCP server exited during '{method}'" + (f": {stderr}" if stderr else "")
                )

            self._bytes_read += len(line)
            if len(line) > MAX_FRAME_BYTES:
                raise McpError(f"MCP frame exceeds {MAX_FRAME_BYTES} bytes; refusing to parse")
            if self._bytes_read > MAX_SESSION_BYTES:
                raise McpError("MCP server exceeded the session output budget")

            try:
                message = json.loads(line.decode("utf-8", errors="replace"))
            except json.JSONDecodeError:
                continue  # servers commonly emit stray logging on stdout; skip it

            if not isinstance(message, dict):
                continue
            if message.get("id") != request_id:
                continue  # a notification or a response we are not waiting for

            if "error" in message:
                error = message["error"] or {}
                raise McpError(
                    f"MCP server returned an error for '{method}': "
                    f"{error.get('code', '?')} {error.get('message', '')}".strip()
                )
            result = message.get("result")
            return result if isinstance(result, dict) else {}

    async def _drain_stderr(self) -> str:
        if self.process is None or self.process.stderr is None:
            return ""
        try:
            data = await asyncio.wait_for(self.process.stderr.read(4096), timeout=1.0)
        except (TimeoutError, OSError):
            return ""
        return data.decode("utf-8", errors="replace").strip()[:500]


class McpClient:
    """Connect, discover, call. One client per server, short-lived by design."""

    def __init__(
        self,
        argv: list[str],
        *,
        cwd: Path,
        timeout_s: float = 30.0,
        allow_env: list[str] | None = None,
        env: dict[str, str] | None = None,
    ) -> None:
        self.argv = argv
        self.cwd = Path(cwd)
        self.timeout_s = timeout_s
        self.env = env if env is not None else build_env(allow=allow_env or [])
        self.server = McpServerProcess(argv=argv, cwd=self.cwd, env=self.env, timeout_s=timeout_s)
        self.server_info: dict[str, Any] = {}

    async def __aenter__(self) -> McpClient:
        await self.connect()
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.close()

    async def connect(self) -> dict[str, Any]:
        await self.server.start()
        result = await self.server.request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": CLIENT_INFO,
            },
        )
        self.server_info = result.get("serverInfo") or {}
        await self.server.notify("notifications/initialized")
        return result

    async def list_tools(self) -> list[dict[str, Any]]:
        result = await self.server.request("tools/list")
        tools = result.get("tools")
        if not isinstance(tools, list):
            raise McpError("tools/list did not return a list of tools")
        return [tool for tool in tools if isinstance(tool, dict)]

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        return await self.server.request("tools/call", {"name": name, "arguments": arguments})

    async def close(self) -> None:
        await self.server.stop()


def flatten_content(result: dict[str, Any], *, limit: int = 100_000) -> str:
    """Turn an MCP tool result into text.

    Only ``text`` blocks are rendered. Images and binary blobs are named, not
    inlined: a base64 payload in an agent prompt is an opaque channel, and the
    inspector cannot review what it cannot read.
    """
    blocks = result.get("content")
    if not isinstance(blocks, list):
        return ""
    parts: list[str] = []
    for block in blocks:
        if not isinstance(block, dict):
            continue
        kind = block.get("type")
        if kind == "text":
            text = block.get("text")
            if isinstance(text, str):
                parts.append(text)
        else:
            parts.append(f"[non-text content omitted: {kind or 'unknown'}]")
    joined = "\n".join(parts)
    if len(joined) > limit:
        return joined[:limit] + f"\n[truncated at {limit} characters]"
    return joined
