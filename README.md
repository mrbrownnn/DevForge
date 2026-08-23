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
3. **Nothing pretends to work.** Capabilities that depend on something absent - a
   browser driver, an image decoder, an MCP server - report `unavailable` at runtime
   rather than returning fabricated data, and a workflow that needs them halts with an
   explicit reason. Visual verification reports `UNVERIFIED` as a real verdict and
   never claims pixel-perfect reproduction.

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
├── browser/               isolated Playwright session + page capture
├── visual/                structural diff, pixel corroboration, loopback static server
├── verification/          Verifier interface, command verifier, visual verifier
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
| **Patch guard** | Reads a repair's diff for the ways it can cheat. | [docs/debugging.md](docs/debugging.md) |
| **Security Center** | Threat model, posture audit, workspace scan, SBOM. | [docs/security/security-center.md](docs/security/security-center.md) |
| **Evaluation** | Benchmark cases with known answers, twelve metrics, a calibrated grader. | [docs/evaluation.md](docs/evaluation.md) |
| **Git-native flow** | Isolated worktrees, screened commits, PR artifacts, refused history rewrites. | [docs/git.md](docs/git.md) |
| **Continuous engineering** | Ten detectors, findings with confidence, approval before any work. | [docs/continuous.md](docs/continuous.md) |
| **Execution platform** | Control plane and untrusted workers, signed protocol, independent re-verification. | [docs/platform.md](docs/platform.md) |
| **Skill Radar** | Ecosystem sweep, scored on quality and fit with stars capped, security gating. | [docs/skill-radar.md](docs/skill-radar.md) |

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
| `devforge bench` | Repair success rate against the seeded-defect benchmark (`--solver reference\|cheat\|none`) |
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
| `devforge security scan` | Scan a workspace for secrets, injection-shaped text and dangerous code |
| `devforge security audit` | Check whether the declared security controls are actually in place |
| `devforge security sbom` | CycloneDX inventory: packages, skills, MCP servers, runtime binaries |
| `devforge security threats` | The threat model and the defence-in-depth layers |
| `devforge security report` | Full report: audit, scan, inventory and residual risk |
| `devforge eval run` | Measure one configuration against the benchmark cases |
| `devforge eval compare` | Two reports side by side; names differences, never a winner |
| `devforge eval report` | Render a saved evaluation report as Markdown |
| `devforge eval cases` | The benchmark cases that apply here |
| `devforge eval configs` | The evaluation configurations that apply here |
| `devforge falsify` | Search adversarially for counterexamples against the current patch |
| `devforge falsify report` | Show a persisted falsification report |
| `devforge falsify explain <id>` | Explain one finding, with `--regression` to print a test |
| `devforge falsify list` | Persisted falsification runs, newest first |
| `devforge falsify corpus` | Counterexamples preserved across runs |
| `devforge git worktree` | Create, list and remove isolated worktrees |
| `devforge git commit` | Plan a commit, screen its contents, then record it |
| `devforge git pr` | Write the pull-request artifact (does not push) |
| `devforge git guard` | Say what would happen to a git command, without running it |
| `devforge continuous detect` | Scan for engineering work nobody has filed yet |
| `devforge continuous propose` | Record findings as proposals in the backlog |
| `devforge continuous backlog` | Proposals and what happened to them |
| `devforge continuous approve` | Agree that a proposal is worth doing |
| `devforge continuous execute` | Prepare an approved proposal in an isolated worktree |
| `devforge continuous verify` | Re-detect and check the findings stopped firing |
| `devforge platform worker` | Register, list and revoke execution workers |
| `devforge platform submit` | Queue a task for a worker |
| `devforge platform dispatch` | Lease, execute and independently verify a task |
| `devforge platform approve` | Decide a gate a worker paused at |
| `devforge platform status` | The queue, workers and audit health |
| `devforge platform audit` | Read the hash-chained audit trail and check it |
| `devforge skill radar` | Sweep watched sources: NEW, UPDATE, WARNING, DEPRECATE |
| `devforge skill outdated` | Installed skills a sweep found a newer version of |
| `devforge skill audit-all` | Re-inspect every installed skill and detect content drift |
| `devforge skill recommend` | Candidates worth a person's review, best first |

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

Shipped workflows: `demo`, `feature`, `multi-agent-feature`, `bugfix`, `refactor`, `clone`
(`clone` is an executable extension point — see Limitations).

---

## Multi-agent orchestration

A multi-agent run is an explicit **task graph**, not a swarm. Agents never talk to each
other: each declares the artifacts it produces and consumes, and the supervisor passes
file references between them.

```bash
devforge run --workflow multi-agent-feature --task "Add rate limiting" --interactive
```

`architect → coder → (tester ‖ security ‖ docs) → reviewer`. The three middle agents run
concurrently because the graph says they are independent; review waits for all three.
Each agent gets least privilege - the documentation agent has no shell and cannot write
source; only the coder writes source. A failure preserves artifacts, blocks downstream
nodes rather than running them on missing inputs, and leaves siblings' work intact.

Details: [docs/multi-agent.md](docs/multi-agent.md).

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

## Falsification

Verification is confirmation-shaped: it runs the checks the workflow already named, so
it can ask *do these checks pass?* and never *are these checks sufficient?* Falsification
fills that gap by searching for evidence **against** a change.

```
implement -> verify -> falsify -+-> survives -> confidence (with stated limits)
                                +-> broken   -> repair -> verify -> falsify -> ...
```

```yaml
- id: falsify
  kind: falsify
  strategies: [mutation, property, adversarial, differential, metamorphic]
  targets: [behavior, boundary_conditions, error_handling]
  budget:
    max_duration_s: 600
    max_mutants: 50
    flakiness_probes: 2
  on_incomplete: fail
  on_unavailable: continue

- id: repair
  agent: coder
  condition: falsification_failed(falsify)
```

Five strategies ship: mutation testing over the patch, property-based testing,
an adversarial test agent, differential testing, and metamorphic testing. Every run
happens in an isolated git worktree; the user's working tree is never mutated.

**Falsification does not prove correctness.** Surviving it means no counterexample was
found within the configured search space, with the budget that was actually spent. A
mutation score is a statement about the *test suite* - reported as "94% of valid
generated mutants were detected", never as "94% correct". `UNAVAILABLE` and
`INCOMPLETE` are never treated as success, and there is no `SUCCESS` state in the
vocabulary at all. See [docs/falsification/](docs/falsification/limitations.md).

Falsification is opt-in: the `feature` workflow is unchanged, and a workflow without a
`falsify` step behaves exactly as before.

## Current limitations

Stated plainly, because a harness that hides its gaps is worse than useless:

- **No sandbox.** As above.
- **Browser automation** works through Playwright, an optional extra
  (`pip install "devforge[browser]"`). Without the driver the tool reports `unavailable`
  rather than fabricating page content.
- **MCP** works over stdio only. HTTP/SSE transports are refused rather than downgraded,
  and sampling is deliberately not implemented - it would let a server drive the model.
  See [docs/security/mcp.md](docs/security/mcp.md).
- **Visual verification compares structure, not pixels.** The verdict comes from
  matched elements and their computed styles; the pixel ratio is corroboration and
  needs the `visual` extra (Pillow + numpy) to be computed at all. A passing report
  never claims pixel-perfect reproduction, and states what it could not check. See
  [docs/browser.md](docs/browser.md).
- **Falsification searches; it does not prove.** Mutation is scoped to the lines the
  patch touched, so a pre-existing defect in unchanged code will not be found.
  Property invariants and metamorphic relations are declared, never inferred. Six of
  the ten attack targets ship with no strategy attacking them and honestly report 0%
  coverage. Property testing needs Hypothesis
  (`pip install "devforge[falsification]"`) and reports `unavailable` without it,
  never a survival. See [docs/falsification/limitations.md](docs/falsification/limitations.md).
- **The clone workflow needs configuring.** The built-in ships without a reference URL,
  because the target is task-specific; copy it to `workflows/clone.yaml` and set one.
- **The patch guard catches known cheating patterns, not all of them.** It reads the
  diff for removed assertions, added skip markers, disabled auth, bypassed validation,
  swallowed exceptions and security settings turned off. An agent can still weaken a
  check in a way no pattern anticipates - by rewriting a helper an assertion calls, say.
  It raises the cost of the obvious cheats and claims nothing more.
- **The security scanner is pattern matching.** `devforge security scan` finds
  known-dangerous constructs. It has no taint analysis and no vulnerability
  database, and a clean scan means no pattern matched - not that the code is safe.
  The configuration audit is stronger, because it checks facts rather than
  heuristics, but it only checks the controls someone wrote a check for. See
  [docs/security/security-center.md](docs/security/security-center.md).
- **The repair benchmark scores one solver on eight seeded defects.** `devforge bench`
  measures a repair success rate against small, self-contained Python bugs with known
  fixes. It is not a prediction about real defects in real codebases. See
  [docs/debugging.md](docs/debugging.md).
- **The evaluation measures small cases with known answers.** `devforge eval` scores a
  configuration on ten self-contained cases across eight categories. Real defects in
  real codebases are neither small nor answered in advance, so the number does not
  transfer to them - and with ten cases, one case is worth ten percent, which is far
  too coarse to separate a real improvement from run-to-run variation. `eval compare`
  therefore reports directions and refuses to declare a winner. See
  [docs/evaluation.md](docs/evaluation.md).
- **DevForge never pushes and never opens a pull request.** `devforge git pr` writes
  an artifact to a file; a person pushes the branch. Force push, branch deletion and
  history rewriting are refused outright rather than gated, and the commit content
  guard is pattern matching - it finds credential-shaped strings and known credential
  filenames, not a secret that reads like prose. See [docs/git.md](docs/git.md).
- **Continuous engineering proposes; it never acts.** `devforge continuous` detects
  findings and records proposals, and `execute` only creates a worktree and writes the
  issue - no source file is modified without an approved proposal and a workflow run.
  Every detector is static: nothing is executed or profiled, so a finding is a
  hypothesis to confirm rather than a defect that was proven. See
  [docs/continuous.md](docs/continuous.md).
- **Workers are separate processes, not separate machines.** The platform splits a
  control plane from workers over a signed stdio protocol, and there is deliberately
  no network transport: an architecture test forbids importing an HTTP client, and the
  measured workload (9.7 ms to submit, 23 ms to scan a 200-task queue) does not justify
  a broker, a database or a scheduler service. The file-backed queue is safe for one
  control plane, not two. See [docs/platform.md](docs/platform.md).
- **The Skill Radar does not crawl.** It has no HTTP client, so discovery is bounded
  by configured sources, operator-supplied feeds and propagation from what is already
  known - and every report lists what it could not consult. A score reads a
  repository's shape, not what its instructions will make a model do, so `INSTALL`
  means "worth a person's review", never "safe". Nothing is installed automatically.
  See [docs/skill-radar.md](docs/skill-radar.md).
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
2. Perceptual (not just per-pixel) image comparison, so a shifted-but-correct layout
   stops registering as a difference.
3. Second runtime adapter, to prove the abstraction under load.
4. Optional OS-level sandboxing for shell and verifier execution.
5. Authenticated browser sessions, under an explicit credential policy.

## Development

```bash
python -m pytest -q      # 460 tests, no network, no paid API calls
ruff check . && ruff format --check .
```

See [docs/contributing.md](docs/contributing.md).

## License

MIT.
