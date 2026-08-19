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

## Declared but NOT implemented

These exist so the interface, the action vocabulary and the workflows that need them are
real and executable. They report `unavailable` at runtime and return no fabricated data.
A step that requires one fails immediately with the reason, before the agent is invoked.

### browser

Actions declared: `open`, `screenshot`, `dom`, `computed_styles`, `assets`, `close`.

DevForge ships no browser driver. To implement it:

1. Add a driver dependency (Playwright is the obvious choice).
2. Subclass or replace `devforge.tools.browser.BrowserTool`, implementing `invoke` for
   each action and making `availability()` report the real driver state.
3. Register it: `registry.register("browser", MyBrowserTool(), replace=True)`.
4. Decide the network policy — browsing is network access, and `network.enabled` is
   `false` by default.

The `clone` workflow becomes runnable at that point.

### mcp

Actions declared: `list_servers`, `list_tools`, `call`.

There is no MCP client: no transport, no handshake, no server registry, no per-server
policy. Implementing it means adding server configuration to the project config, a
stdio/HTTP client, tool discovery, and policy per server. That is a larger piece of work
than the MVP justifies, so the seam is declared and the gap is stated.

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

Note the current limit, stated plainly: tool calls made *inside* an agent turn are the
runtime, not DevForge, executing them. Routing those calls back through this tool layer
so each one is policy-checked is the first item on the roadmap.
