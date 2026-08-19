# DevForge

**An extensible AI software-engineering harness.**

DevForge orchestrates AI coding agents, skills, tools, workflows, verification loops,
project state and human approval gates into one reusable engineering system.

It is not an LLM wrapper. The model runtime sits behind an adapter interface, and the
harness around it — workflows, verification, policy, state, approvals — is where the
value is. Swap the runtime and everything else keeps working.

```
User → CLI → Orchestrator → Workflow → Steps → Agents → Skills + Tools
                                 ↓
                          Verification  →  fail → repair → verify again
                                 ↓
                          Human approval
                                 ↓
                               Done
```

---

## Why it exists

Agents claim success they have not earned. A harness that takes those claims at face
value produces confident, broken changes.

DevForge is built on three commitments:

1. **Never trust the agent's report.** A step passes only when its verifiers pass.
   Failed verification feeds the diagnostics back to the agent as a repair briefing,
   bounded by `max_attempts`, then stops loudly.
2. **Humans hold the dangerous decisions.** Architecture, destructive commands and
   final sign-off are approval gates that persist across processes.
3. **Nothing pretends to work.** Capabilities DevForge does not have (browser
   automation, MCP, visual diffing) are declared adapters that report `unavailable`
   at runtime. They never return fabricated data, and a workflow that needs them
   halts with an explicit reason.

---

## Installation

Requires Python 3.11+.

```bash
git clone https://github.com/mrbrownnn/DevForge.git
cd DevForge
pip install -e ".[dev]"
devforge --version
```

## Quick start

```bash
cd /path/to/your/project
devforge init                       # creates .devforge/
devforge doctor                     # what is available, what is not
devforge plan --workflow feature    # what would happen, nothing executed

devforge run --workflow feature --task "Add authentication using JWT"
# ... pauses at the architecture approval gate (exit code 2)

devforge approve --gate architecture --by you --reason "design ok"
devforge run --resume task_ab12cd34
devforge status
devforge review
```

The default runtime is `mock` — deterministic, offline, free. Use a real runtime
explicitly:

```bash
devforge run --workflow feature --task "..." --runtime claude-code
```

---

## Architecture

```
src/devforge/
├── core/
│   ├── models.py          Task, StepRecord, AgentInvocation/Result, VerificationResult, Approval
│   ├── orchestrator/      the step loop, the verify→repair retry, run wiring
│   ├── workflow/          WorkflowSpec + YAML loader
│   ├── state/             .devforge file store (atomic writes, run index)
│   └── registry/          generic Registry + skill discovery
├── runtime/               AgentRuntime interface, MockAgentRuntime, ClaudeCodeRuntime
├── agents/                AgentSpec model + prompt composition
├── tools/                 Tool interface: filesystem, shell, git (real); browser, mcp (declared)
├── verification/          Verifier interface, command verifier, visual (declared)
├── policy/                permission + approval policy engine
├── approval/              persistent human gates
├── observability/         structured JSON event logging
├── cli/                   typer commands + rich rendering
└── builtin/               shipped workflows, skills, agents, policies, templates
```

**Layout note.** Built-in assets live inside the package (`devforge/builtin/…`) rather
than at the repository root, so they are importable and installable. Every one of them
can be overridden per project — resolution order is
`./.devforge/<kind>/` → `./<kind>/` → built-in. Create `./workflows/feature.yaml` in
your project and it wins over the shipped one.

Full details: [docs/architecture.md](docs/architecture.md).

---

## Core concepts

| Concept | What it is | Where |
| --- | --- | --- |
| **Task** | One execution of a workflow. The task id is the run id. | `core/models.py` |
| **Workflow** | Declarative YAML: ordered steps of kind `agent`, `verify` or `approval`. | [docs/workflows.md](docs/workflows.md) |
| **Agent** | A YAML spec: role, prompt templates, default skills and tools. | `builtin/agents/` |
| **Skill** | Reusable instructions as Markdown + frontmatter, composed into prompts. | [docs/skills.md](docs/skills.md) |
| **Tool** | An executable capability with actions and a uniform result. | [docs/tools.md](docs/tools.md) |
| **Runtime** | The adapter that actually executes an agent. | [docs/runtimes.md](docs/runtimes.md) |
| **Verifier** | The only authority on whether work is correct. | [docs/workflows.md](docs/workflows.md) |
| **Policy** | Permission allowlists and approval gates. | [docs/security.md](docs/security.md) |

---

## CLI

| Command | Purpose |
| --- | --- |
| `devforge init [path]` | Create `.devforge/` project state |
| `devforge plan -w feature` | Show what a workflow would do; run nothing |
| `devforge run -w feature -t "..."` | Execute a workflow (`--resume`, `--interactive`, `--events`) |
| `devforge status [task]` | Run state; `--all` lists runs, `--json` for machines |
| `devforge review [task]` | Agent output, artifacts and verification per step |
| `devforge verify` | Run verifiers against the working tree, outside a run |
| `devforge approve --gate G` | Approve or `--reject` a pending gate |
| `devforge skills` | List discoverable skills |
| `devforge workflows` | List available workflows |
| `devforge runtimes` | List agent runtimes and their availability |
| `devforge doctor` | Environment check: what works, what is unavailable |

Exit codes: `0` success, `1` failure, `2` paused awaiting approval. Every command
supports `--json`.

---

## Workflow format

```yaml
name: feature
verifiers:
  - id: tests
    kind: tests
    argv: [python, -m, pytest, -q]   # argv, never a shell string
    required: true
steps:
  - id: implementation
    agent: coder
    skills: [backend]
    tools: [filesystem, shell, git]
    verify: [tests]
    max_attempts: 3
  - id: approve-final
    kind: approval
    gate: final_review
```

Shipped workflows: `feature`, `bugfix`, `refactor`, `clone`
(`clone` is an executable extension point — see Limitations).

---

## Verification loop

```
agent runs
   ↓
verifiers run (concurrently)
   ↓
all required passed? ── yes ──▶ next step
   │ no
   ▼
diagnostics bundle (failing verifier ids, exit codes, output tails)
   ↓
agent re-invoked in repair mode with that bundle
   ↓
verify again … up to max_attempts, then fail loudly
```

A required verifier that is *unavailable* counts as a failure. "We could not check"
never becomes "it is fine".

---

## Security model

DevForge is **secure by default but it is not a sandbox.**

What the policy layer does:

- Deny-by-default allowlist for shell commands, matched on the argv DevForge execs.
- No shell is ever spawned — `&&`, `|`, `$(…)` are rejected, not interpreted.
- Filesystem paths fully resolved (symlinks included) and confined to the workspace,
  with deny rules for `.env`, secrets, keys and `.git`.
- Destructive operations (`git push`, deletes, installs) route to human approval gates.
- Network access off by default for DevForge's own tools.

What it does **not** do: allowed commands run as you, with your privileges. An
adversarial agent can escape an allowlist trivially (write a script, ask an allowed
interpreter to run it). This layer protects against accidents and drift, not against a
hostile agent. Real isolation needs an OS boundary — container, VM, seccomp — which is
deliberately out of MVP scope. See [docs/security.md](docs/security.md).

---

## Current limitations

Stated plainly, because a harness that hides its gaps is worse than useless:

- **No sandbox.** As above.
- **Browser automation is not implemented.** `tools/browser.py` is a declared adapter
  that reports `unavailable`. The `clone` workflow therefore halts at its first step.
- **MCP is not implemented.** `tools/mcp.py` declares the seam; there is no client,
  transport or server registry.
- **Visual verification is not implemented.** `verification/visual.py` reports
  `unavailable` and never `passed`.
- **One real runtime adapter.** Claude Code. Codex/OpenCode adapters are interface
  work, not present.
- **Agents do not drive DevForge tools yet.** The tool layer is real, policy-checked
  and tested, and it scopes what a runtime may do (Claude Code tool permissions are
  derived from a step's `tools:`). Tool *calls* originating from inside an agent turn
  are the runtime's own; DevForge does not yet proxy them.
- **State is files, single machine, no concurrency control.** Two simultaneous runs in
  one project can interleave writes to `state.json`.
- **Memory is markdown, not retrieval.** No embeddings, no vector store, by design.

## Roadmap

1. Proxy agent tool calls through the DevForge tool layer, so every call is policy-checked.
2. Playwright-backed browser tool + perceptual visual verifier → makes `clone` real.
3. MCP client with per-server policy.
4. Second runtime adapter, to prove the abstraction under load.
5. Parallel/DAG steps instead of a strict sequence.
6. Optional OS-level sandboxing for shell and verifier execution.

## Development

```bash
python -m pytest -q      # 172 tests, no network, no paid API calls
ruff check . && ruff format --check .
```

See [docs/contributing.md](docs/contributing.md).

## License

MIT.
