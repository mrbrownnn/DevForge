# Runtime adapters

The runtime is the only place DevForge talks to a model. Everything above it —
workflows, verification, policy, state, approvals — is runtime-agnostic.

```python
class AgentRuntime(ABC):
    name: str

    async def execute(self, invocation: AgentInvocation, context: RuntimeContext) -> AgentResult: ...
    def availability(self) -> RuntimeAvailability: ...
```

`AgentInvocation` is vendor-neutral: task and step ids, agent name and role, mode
(`initial` or `repair`), attempt number, system prompt, prompt, resolved skill names,
allowed tool names, workspace and timeout. `AgentResult` reports whether the *runtime*
succeeded — never whether the work is correct. That judgement belongs exclusively to the
verification layer.

Implementations must not raise for agent failure; they return `status=error` with the
message. They may raise `RuntimeExecutionError` when the runtime itself is broken.

## Shipped runtimes

### mock (default)

Deterministic, in-process, offline, free. Same inputs produce identical output, which is
what makes the end-to-end test meaningful instead of flaky. It can be scripted:

```python
MockAgentRuntime(script={
    "implementation": MockStep(writes={"src/auth.py": "..."}, fail_attempts=1),
})
```

`fail_attempts=n` makes the first *n* attempts fail, which exercises the retry path.
It records every invocation it received, so tests can assert on what the orchestrator
actually asked for — including whether a repair attempt carried the diagnostics.

### claude-code

Shells out to the local `claude` CLI in non-interactive mode:

```
claude -p <prompt> --output-format json
       [--append-system-prompt <system>]
       [--allowedTools Read Write Edit ...]
       [--model <model>] [--permission-mode <mode>]
```

- Requires the Claude Code CLI on `PATH`; `availability()` checks that and runs
  `--version`.
- Parses the JSON envelope into an `AgentResult`, carrying `session_id`, `num_turns` and
  `total_cost_usd` into `metadata`. Non-JSON output degrades gracefully rather than
  crashing the run.
- Timeouts kill the process and return an error result.
- DevForge tool names map to CLI tool permissions, so a step gets least privilege:
  `filesystem` → `Read Write Edit Glob Grep`, `shell` → `Bash`, `git` → `Bash(git *)`.

**Cost.** Every execution is a real, billed model call. This runtime is never the
default: `devforge init` sets `mock`, and using Claude Code requires
`--runtime claude-code` or a change to `.devforge/config.yaml`.

**Permissions.** `permission_mode` is unset by default, so the CLI applies its own
rules. Setting `bypassPermissions` is possible and is unsafe — see docs/security.md.

## Adding a runtime

```python
from devforge.runtime.base import AgentRuntime, RuntimeAvailability, RuntimeContext
from devforge.core.models import AgentResult, AgentResultStatus

class MyRuntime(AgentRuntime):
    name = "my-runtime"

    def availability(self) -> RuntimeAvailability:
        return RuntimeAvailability(available=True, detail="ready")

    async def execute(self, invocation, context) -> AgentResult:
        text = await call_my_backend(
            system=invocation.system_prompt,
            prompt=invocation.prompt,
            cwd=context.workspace,
            tools=invocation.tools,
        )
        return AgentResult(
            invocation_id=invocation.invocation_id,
            runtime=self.name,
            status=AgentResultStatus.OK,
            summary=text.splitlines()[0][:200],
            output=text,
        )
```

Register it:

```python
registry = RuntimeRegistry.default()
registry.register(MyRuntime.name, MyRuntime)
```

Then `devforge run --runtime my-runtime`, and `devforge runtimes` /
`devforge doctor` will report its availability.

### Checklist for a new adapter

- [ ] `availability()` is cheap and never raises.
- [ ] Agent failure is a result, not an exception.
- [ ] The timeout in `invocation.timeout_s` is honoured and the process is killed.
- [ ] `invocation.tools` constrains what the runtime is permitted to do.
- [ ] Nothing vendor-specific leaks into `AgentResult` beyond `metadata`.
- [ ] Repair mode is handled: `invocation.mode` and the diagnostics already in the
      prompt are the contract for a second attempt.

## External CLI runtimes

DevForge executes agents by spawning a command-line tool, never by calling an HTTP
API - it imports no HTTP client, and `tests/test_architecture.py` enforces that. So
"adding a provider" means describing its CLI, not adding an API key.

Most providers need no Python at all. `ExternalCliRuntime` is one adapter driven by a
profile in `builtin/runtimes/*.yaml`:

```yaml
id: codex-cli
name: Codex CLI
binary: codex
confidence: verified
subcommand: exec
prompt_style: positional     # positional | flag | stdin
model_flag: --model
output:
  format: text               # text | json
```

Drop a file in `.devforge/runtimes/` to override a bundled profile for one project.
A profile never shadows a hand-written adapter: a real adapter knows things a profile
cannot express, and silently replacing it would be a downgrade.

### What ships

| runtime | binary | invocation shape |
| --- | --- | --- |
| `claude-code` | `claude` | hand-written adapter |
| `codex-cli` | `codex` | **verified** against `codex exec --help` |
| `opencode-cli` | `opencode` | **verified** against `opencode run --help` |
| `gemini-cli` | `gemini` | documented, not checked here |
| `cursor-agent` | `cursor-agent` | **inferred** |
| `copilot-cli` | `copilot` | **inferred** |

`verified` means the argument vector was checked against a real installation's own
`--help`, with the version recorded in the profile. It does **not** mean a full agent
run was performed - that bills a model and edits files, so it is the user's call.

`devforge runtimes` shows which binaries are actually present. An unverified profile
says so in its availability detail, because a wrong flag produces an error message
from someone else's binary and reads as DevForge being broken.

### Editors have no runtime

Windsurf, Antigravity, Kiro, Qoder, Trae and Roo Code are editors or editor
extensions, not headless CLIs. There is nothing to spawn, so they ship an assistant
profile (`devforge init --ai <id>`, see [assistants.md](assistants.md)) and no
runtime. Shipping a runtime that could never start would be worse than not shipping
one.
