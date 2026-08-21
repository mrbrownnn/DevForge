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

# a complete run in any project, including an empty one
devforge run --workflow demo --task "Add authentication" --interactive

# the real thing: runs your tests, linters and build
devforge run --workflow feature --task "Add authentication using JWT"
# ... pauses at the architecture approval gate (exit code 2)

devforge approve --gate architecture --by you --reason "design ok"
devforge run --resume task_ab12cd34
devforge status
devforge review
```

`demo` completes end to end anywhere: its verifiers check that the files each step
declared actually exist, which needs no test suite. `feature` runs `pytest`, `ruff` and
your build, so in a project without tests it will **fail at the unit-tests step** — that
is the verification loop working, not a bug. The failure says so: *"no tests were
collected - this workflow expects a project with a test suite"*.

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
├── tools/                 Tool interface + executor: filesystem, shell, git, browser
├── mcp/                   MCP client, server registry and tool bridge (stdio)
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
| `devforge index` | Build the codebase index (structure only, no file contents) |
| `devforge context "task"` | Show the context pack an agent would receive (`--compare` measures it) |
| `devforge context-doctor` | Report whether the index still matches the working tree |
| `devforge registry list` | Third-party skill sources, pins and dispositions |
| `devforge registry show <id>` | Recorded evidence and decision for one source |
| `devforge registry verify` | Validate the registry: pins, licenses, trust decisions |
| `devforge inspect-skill <dir>` | Statically inspect a local skill directory; nothing is executed |
| `devforge skill search <query>` | Search the catalogue of third-party skills (offline) |
| `devforge skill audit <name>` | Fetch at the pin and inspect; installs nothing |
| `devforge skill install <name>` | Fetch, verify, gate, install, lock |
| `devforge skill update <name>` | Move a pin deliberately and re-audit |
| `devforge skill remove <name>` | Remove an installed skill and its lock entry |
| `devforge skill list` | List installed skills (`--verify` re-hashes them) |

Exit codes: `0` success, `1` failure, `2` paused awaiting approval.

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

Shipped workflows: `demo`, `feature`, `bugfix`, `refactor`, `clone`
(`clone` is an executable extension point — see Limitations).

---

## Context engineering

Agents get a **retrieved context pack**, not the repository. `devforge index` builds a
structural map - files, symbols, imports, roles - storing no file contents, only where
to look. Retrieval is lexical and structural: no vector database, no embedding model,
and every result carries the reason it was chosen.

```bash
devforge index
devforge context "Change JWT authentication" --compare
```

Measured on a 64-file fixture with real `tiktoken` counts: **4,369 tokens of
full-repository context versus 515 for the pack - an 88% reduction at precision 1.00,
recall 0.75.** When nothing matches well the pack says so rather than listing the
least-irrelevant files, because an agent treats anything listed as relevant.

Secrets are never indexed: `.env`, key material and `**/secrets/**` are refused by
path, and files that *are* credential material are refused by content. Files that
merely discuss credentials are indexed - the distinction matters, and getting it wrong
once hid this project's own redaction code from retrieval.

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
- Workflow YAML is data: a verifier it declares still goes through that allowlist, so a
  workflow cannot run `curl` or `bash -c` that policy would otherwise refuse.
- Secrets are redacted from events **and** persisted state at the write boundary
  (known credential shapes, secret-named keys, private keys, URL credentials).
- Third-party skills are inspected at consumption; a critical finding fails the step.
- Child processes get a **constructed** environment - ambient credentials are never
  handed to a subprocess.
- URL fetches clear an SSRF check (scheme, resolved address, host allowlist) and network
  access is off by default.
- Output from outside the workspace is bounded, scanned for injection, and fenced as
  data before it can reach a prompt.
- Inline code (`python -c`, `node -e`) is approval-gated regardless of the allowlist: no
  glob can constrain what inline code does.
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

## Third-party skills are untrusted code

DevForge treats every external skill as untrusted **code and instructions**. A survey of
six well-known sources found 70 Python scripts, 41 shell scripts, 155 `.mjs` files,
auto-executing session hooks and six opaque `.zip` archives — plus an instruction telling
the agent to run a script before reading it.

**There is an installer, and it never executes what it installs.** A skill is
instructions; DevForge has no code path that runs a file a skill shipped. Executable
content is quarantined for review, listed in the report and recorded in the lockfile.
That is what lets you install a skill without handing it the machine.

```bash
devforge skill search testing
devforge skill audit test-driven-development     # fetch at the pin, inspect, install nothing
devforge skill install test-driven-development   # only after you have read the report
```

The pipeline: refuse if unpinned → clone at the exact commit → verify HEAD matches the
pin → hash the tree → inspect → classify risk → refuse CRITICAL, gate anything above
the ceiling → install with executables quarantined → write the report → write
`skills.lock`. Pins never move on their own: `update` needs an explicit target and
re-runs every check.

Supporting machinery:

- `registry/skills.yaml` — sources pinned by canonical URL **plus commit SHA** (names are
  not identity: one skill name resolves to four repositories in the wild)
- trust tiers, `untrusted` by default; a pin change revokes trust
- a static inspector that flags pipe-to-shell, credential access, install commands,
  archives, hooks and execute-before-read instructions
- a quality score over nine dimensions, none of them popularity
- `skills.lock`, `THIRD_PARTY_NOTICES.md` and per-skill reports in `security-reports/`

```bash
devforge registry list
devforge inspect-skill ./some-untrusted-skill
```

Research: [docs/skill-ecosystem.md](docs/skill-ecosystem.md) ·
Installing: [docs/security/skills.md](docs/security/skills.md) ·
Design: [docs/security/skill-supply-chain.md](docs/security/skill-supply-chain.md) ·
Threats: [docs/security/threat-model.md](docs/security/threat-model.md)

## Current limitations

Stated plainly, because a harness that hides its gaps is worse than useless:

- **No sandbox.** As above.
- **Browser automation** works through Playwright, an optional extra
  (`pip install "devforge[browser]"`). Without the driver the tool reports `unavailable`
  rather than fabricating page content.
- **MCP** works over stdio only. HTTP/SSE transports are refused rather than downgraded,
  and sampling is deliberately unimplemented - it would let a server drive the model.
  See [docs/security/mcp.md](docs/security/mcp.md).
- **Visual verification is not implemented.** `verification/visual.py` reports
  `unavailable` and never `passed`.
- **One real runtime adapter.** Claude Code. Codex/OpenCode adapters are interface
  work, not present.
- **Agent tool calls are proxied only for runtimes that delegate.** A runtime given a
  `ToolExecutor` has every call scope-checked, schema-validated, policy-checked,
  risk-gated, timed out and audited. An external CLI runtime executes its own tools
  inside a turn and cannot delegate; those calls are constrained only by the tool
  permissions DevForge derives for it.
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
python -m pytest -q      # 406 tests, no network, no paid API calls
ruff check . && ruff format --check .
```

See [docs/contributing.md](docs/contributing.md).

## License

MIT.
