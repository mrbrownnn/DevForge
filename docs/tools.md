# Tools

A tool is an executable capability: a stable name, a set of actions, and a uniform
`ToolResult` with status `ok | error | denied | unavailable`.

```python
class Tool(ABC):
    name: str
    description: str
    actions: tuple[str, ...]

    async def invoke(self, action: str, params: dict, ctx: ToolContext) -> ToolResult: ...
    def availability(self) -> ToolAvailability: ...
```

`ToolContext` carries the workspace, the policy engine, the run logger, and (when a run
is active) the task and its approval gate. Every tool consults the policy before acting;
the shared `Tool.authorize()` helper implements that consultation once so a new code
path cannot forget it.

## Implemented tools

### filesystem

Actions: `read`, `write`, `append`, `list`, `exists`, `mkdir`, `delete`.

Every path is fully resolved (symlinks included) and checked against the policy:
confined to the workspace, denied for `.env`, secrets, keys and `.git`, and with a
narrower allowlist for writes than for reads. `delete` is a separate mode that requires
approval by default. Directory deletion is limited to empty directories — recursive
removal is not offered.

### shell

Action: `run`. Takes `argv` (preferred) or `command`, which is split with `shlex.split`.

**No shell is spawned.** The argument vector goes straight to `exec`, so `&&`, `|`,
`;` and `$(...)` are literal arguments, not operators — and the policy engine rejects
them outright rather than letting them widen an allow rule. Commands are matched
against the allowlist in `policies/permissions.yaml`; destructive matches route to a
human approval gate. Every process has a timeout and is killed when it expires.

### git

Actions: `status`, `diff`, `log`, `show`, `branch`, `add`, `commit`, `current_branch`.

Each action builds its own argv and goes through the same policy check as any other
command, so `git push` is gated exactly as it would be from the shell tool. There is no
side door.

## Browser and MCP

Both are implemented as of Phase 2. Availability is still *discovered*, never assumed:
the browser tool reports `unavailable` with an installation hint when its driver is
missing, and never fabricates page content.

### browser

Actions: `fetch`, `text`, `html`, `title`, `screenshot`. Backed by Playwright, which is
an **optional** dependency:

```bash
pip install "devforge[browser]" && playwright install chromium
```

Every URL clears the network policy first (scheme, resolved address, host allowlist),
and network access is off by default. Page content returns fenced and scanned as
untrusted input. Screenshots are a filesystem write and are checked as one.

Not implemented: authenticated sessions, cookie persistence, downloads, and visual
diffing — so the `clone` workflow still cannot complete, it just gets further.

### mcp

Actions: `list_servers`, `list_tools`, `call`. A direct JSON-RPC client over **stdio**;
HTTP and SSE transports are refused rather than downgraded, and sampling is deliberately
not implemented because it would let a server drive the model.

Servers are disabled until enabled, tools are denied until named, the launch command
passes the shell allowlist, and responses are treated as untrusted content. Full model:
[security/mcp.md](security/mcp.md).

## Visual verification

`verification/visual.py` is the same kind of declared adapter on the verifier side. It
reports `unavailable` and never `passed`. Because a required verifier that is
unavailable counts as a blocking failure, a workflow depending on it stops with an
explicit reason instead of completing on an unchecked assumption.

## Adding a tool

```python
from devforge.tools.base import Tool, ToolContext, ToolAvailability

class HttpTool(Tool):
    name = "http"
    actions = ("get",)

    def availability(self) -> ToolAvailability:
        return ToolAvailability(True)

    async def invoke(self, action, params, ctx):
        if action != "get":
            return self.unknown_action(action)
        decision = ctx.policy.check_network(params["host"])
        blocked = self.authorize(action, decision, ctx)
        if blocked is not None:
            return blocked
        ...
        return self.ok(action, body)
```

Register it in `ToolRegistry.default()` or on a registry you build yourself, then name
it from a workflow step: `tools: [http]`.

## Tools and runtimes

A step declaring `tools: [filesystem]` scopes what the runtime may do. The Claude Code
adapter translates DevForge tool names into CLI tool permissions
(`filesystem` → `Read Write Edit Glob Grep`, `git` → `Bash(git *)`), so a step that did
not ask for `shell` cannot run shell commands.

Since Phase 2 a runtime may also receive a `ToolExecutor` on its `RuntimeContext`.
Calls made through it are scope-checked, schema-validated, policy-checked, risk-gated,
timed out and audited — one door, no way around it. The mock runtime uses it, which is
what makes the end-to-end security tests meaningful.

The limit, stated plainly: an external CLI runtime executes its own tools inside a turn
and cannot delegate them. Those calls are governed by that runtime's permission system,
constrained only by the `--allowedTools` DevForge derives from the step scope.

## Risk levels

Every tool declares one: `read`, `write`, `execute`, `destructive`. A `destructive` tool
routes through an approval gate in the executor even when policy would allow the call.
