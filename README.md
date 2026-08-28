<div align="center">

# 🔨 DevForge

### AI coding agents say "Done ✅". DevForge is the part that checks.

[![CI](https://github.com/mrbrownnn/DevForge/actions/workflows/ci.yml/badge.svg)](https://github.com/mrbrownnn/DevForge/actions/workflows/ci.yml)
[![Release](https://github.com/mrbrownnn/DevForge/actions/workflows/release.yml/badge.svg)](https://github.com/mrbrownnn/DevForge/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-black.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%20|%203.12%20|%203.13-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/tests-1%2C000%2B%20passing-brightgreen.svg)](#development)

**[Quick start](#quick-start-2-minutes)** · **[How it works](#how-it-works)** ·
**[What it can't do](#current-limitations)** · **[Docs](docs/)**

</div>

---

## The problem

You ask an AI agent to add authentication. Two minutes later:

> ✅ **Done!** Added JWT authentication with full test coverage.

You run the tests. Three fail. One of them the agent wrote itself — and marked
`@skip`.

The agent isn't lying on purpose. It has no way to know. It produced text that
*looks* like a finished task, and nothing ever checked. Every "done" you have ever
gotten from an AI agent was a **claim**, not a **result**.

DevForge is the layer that turns claims into results.

```
Without DevForge                  With DevForge

  you                               you
   |                                 |
  agent                            DevForge ---> agent
   |                                 |             |
  "Done!"                          runs your tests, linters, build
   |                                 |
  you find out                     still failing? ---> hand the exact
  three days later                   |                 errors back, retry
                                   passing?
                                     |
                                   you approve
                                     |
                                   actually done
```

An agent's report is never accepted as evidence. A step passes only when **your**
test suite says so.

---

## Installation

Requires Python 3.11+. No API key is needed to try it: the default runtime is
`mock`, which is offline and deterministic.

```bash
git clone https://github.com/mrbrownnn/DevForge.git
cd DevForge
pip install -e ".[dev]"
```

Optional extras, each of which turns a documented `unavailable` into a working
feature rather than into a guess:

```bash
pip install -e ".[browser]"        # Playwright browser tools
pip install -e ".[falsification]"  # Hypothesis property testing
pip install -e ".[visual]"         # Pillow + numpy pixel corroboration
```

---

## Quick start (2 minutes)


Then go to any project you like — even an empty folder:

```bash
cd /path/to/your/project
devforge init      # creates .devforge/
devforge doctor    # tells you what works here and what doesn't
```

Run the built-in demo workflow. It works anywhere and costs nothing: the default
runtime is `mock` — offline, deterministic, no API calls, no bill.

```bash
devforge run --workflow demo --task "Add a health check endpoint"
```

```
demo workflow - 5 steps - runtime mock
task task_f9de5b6c: Add a health check endpoint

 step          kind      agent      status             attempts  verification
 requirements  agent     planner    passed             1         requirements-written=passed
 planning      agent     architect  passed             1         plan-written=passed
 approve-plan  approval  -          awaiting_approval  0         -

awaiting approval gate 'architecture': A human approves the plan before
anything else happens.
  approve: devforge approve --gate architecture
  reject : devforge approve --gate architecture --reject

paused waiting for approval at gate 'architecture'.
```

It stopped and waited for you. That is the point. Approve it and continue:

```bash
devforge approve --gate architecture --by me --reason "plan looks good"
devforge run --resume task_f9de5b6c
```

```
 step          kind      agent      status  attempts  verification
 requirements  agent     planner    passed  1         requirements-written=passed
 planning      agent     architect  passed  1         plan-written=passed
 approve-plan  approval  -          passed  0         -
 review        agent     reviewer   passed  1         -
 verification  verify    -          passed  1         deliverables-present=passed

run completed: task_f9de5b6c
```

The pause survived the process exiting. Approvals live in files, so a run can wait
for you overnight and pick up exactly where it stopped.

### Now the real thing

```bash
devforge run --workflow feature --task "Add rate limiting to the API"
```

`feature` runs **your** `pytest`, **your** `ruff`, **your** build. In a project
without tests it will **fail at the unit-tests step** — and that is the system
working, not a bug. The failure says so out loud:

> *no tests were collected — this workflow expects a project with a test suite*

To use a real AI agent instead of the mock, name it explicitly:

```bash
devforge run --workflow feature --task "..." --runtime claude-code
```

---

## How it works

Three rules the whole system is built around.

### 1. Never trust the agent's report

A step passes only when its verifiers pass. If they don't, the failure output is
bundled up and handed back to the agent as a repair briefing — actual exit codes
and error text, not a vague "please fix it".

```
agent writes code
      |
your verifiers run (concurrently)
      |
all passed? ---- yes ----> next step
      | no
      v
diagnostics bundle: which verifier failed, exit code, output tail
      |
agent re-invoked in repair mode with that bundle
      |
verify again ... up to max_attempts, then stop loudly
```

A verifier that *cannot run* counts as a failure. **"We could not check" never
becomes "it is fine."**

### 2. Humans hold the dangerous decisions

Architecture choices, destructive commands and final sign-off are approval gates.
The run pauses (exit code `2`), writes its state to disk, and waits — across
processes, across reboots.

### 3. Nothing pretends to work

Anything that depends on something missing — a browser driver, an image library,
an MCP server — reports `unavailable` at runtime instead of returning made-up
data, and a workflow that needs it halts with the reason. Visual checks report
`UNVERIFIED` as a real verdict.

---

## What you actually get

| | |
|---|---|
| 🔁 **Verification loop** | Agent works → your tests run → failures go back to the agent → repeat, bounded. |
| ✋ **Approval gates** | Runs pause for a human and survive process exit. Exit code `2` means "waiting for you". |
| 🧩 **8 built-in workflows** | `demo`, `feature`, `bugfix`, `refactor`, `multi-agent-feature`, `falsify`, `git-feature`, `clone` — plain YAML you can copy and edit. |
| 🤖 **7 runtimes** | Claude Code, Codex, Copilot, Cursor, Gemini, OpenCode, plus a free offline `mock`. Run `devforge runtimes`. |
| 👥 **Multi-agent graphs** | Not a swarm — an explicit dependency graph. Independent agents run in parallel; each gets least privilege. |
| 🎯 **Context engineering** | Agents get a retrieved context pack, not your whole repo. Measured on a 64-file fixture: **88% fewer tokens**, precision 1.00. |
| 🔬 **Falsification** | Actively hunts for evidence a change is *broken*: mutation, property, adversarial, differential and metamorphic testing. |
| 🔒 **Untrusted-by-default skills** | There is an installer, and **it never executes what it installs**. |
| 🛡️ **Security Center** | Threat model, posture audit, secret scanning, SBOM. |
| 🌱 **Works with your assistant** | Installs its skills into 13 coding assistants — Cursor, Claude Code, Copilot, Windsurf, Gemini, Codex and more. |

Exit codes: `0` success, `1` failure, `2` paused for approval. Most commands
support `--json`.

---

## CLI

Every command, with the one thing it is for. Details and flags:
**[docs/cli.md](docs/cli.md)**.

| Command | What it does |
|---|---|
| `devforge init` | Create the `.devforge` state directory, and optionally wire up an assistant |
| `devforge doctor` | Check the project and environment, and report what is unavailable |
| `devforge plan` | Show what a workflow would do, without running anything |
| `devforge run` | Execute a workflow, or resume one that is waiting |
| `devforge status` | Show the state of a run |
| `devforge review` | Show what the agents produced and how it verified |
| `devforge verify` | Run verifiers against the working tree, outside any run |
| `devforge approve` | Approve or reject a pending gate |
| `devforge workflows` | List available workflows |
| `devforge runtimes` | List agent runtimes and whether they are usable here |
| `devforge skills` | List discoverable skills |
| `devforge inspect-skill` | Statically inspect an untrusted skill directory — nothing is executed |
| `devforge index` | Build or refresh the codebase index; stores structure, not source |
| `devforge context` | Show the context pack for a task, without running anything |
| `devforge context-doctor` | Report whether the index still matches the working tree |
| `devforge assistants` | List the coding assistants DevForge can install its skills into |
| `devforge update` | Refresh generated assistant files from this installed package |
| `devforge versions` | Show the installed version and the bundled assets it ships |
| `devforge bench` | Measure repair success rate against the seeded-defect benchmark |

Command groups, each with its own subcommands:

| Group | What it covers |
|---|---|
| `devforge falsify` | Search adversarially for counterexamples — mutation, property, adversarial, differential, metamorphic |
| `devforge security` | Security scanning, configuration audit and reporting |
| `devforge skill` | Discover, install and audit third-party skills |
| `devforge registry` | Inspect the third-party skill source registry |
| `devforge git` | Git-native engineering: worktrees, screened commits, PR artifacts |
| `devforge eval` | Measure DevForge against benchmark cases with known answers |
| `devforge platform` | Control plane and workers: submit a task, dispatch it, audit what happened |
| `devforge continuous` | Find engineering work nobody has filed yet, and propose it |

---

## Use it with the assistant you already have

You do not have to adopt the whole harness. DevForge's skills are just Markdown,
and it can install them into the tool you already use:

```bash
devforge assistants                 # 13 supported, plus 'all'
devforge init --ai cursor           # into this project
devforge init --ai claude --global  # into your home directory
devforge init --ai all              # every one of them
```

Each assistant is a YAML profile, so adding one is a file rather than a code
change. Five of the thirteen layouts follow convention but were never confirmed
against documentation — the installer marks those **inferred** when it writes them.

---

## Workflow format

A workflow is a YAML file. That is the whole extension model.

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

Drop `workflows/feature.yaml` in your project and it overrides the built-in one.
The same applies to agents, skills and policies — resolution order is
`./.devforge/<kind>/` → `./<kind>/` → built-in.

---

## Architecture

```
User → CLI → Orchestrator → Workflow → Steps → Agents → Skills + Tools
                                 ↓
                          Verification  →  fail → repair → verify again
                                 ↓
                          Human approval
                                 ↓
                               Done
```

DevForge is **not an LLM wrapper**. The model sits behind an adapter interface;
the harness around it — workflows, verification, policy, state, approvals — is
where the value is. Swap the runtime and everything else keeps working.

<details>
<summary><b>Core concepts and package layout</b></summary>

<br>

| Concept | What it is |
| --- | --- |
| **Task** | One execution of a workflow. The task id is the run id. |
| **Workflow** | Declarative YAML: ordered steps of kind `agent`, `verify` or `approval`. |
| **Agent** | A YAML spec: role, prompt templates, default skills and tools. |
| **Skill** | Reusable instructions as Markdown + frontmatter, composed into prompts. |
| **Tool** | An executable capability with actions and a uniform result. |
| **Runtime** | The adapter that actually executes an agent. |
| **Verifier** | The only authority on whether work is correct. |
| **Policy** | Permission allowlists and approval gates. |
| **Patch guard** | Reads a repair's diff for the ways it can cheat. |

```
src/devforge/
├── core/           models, orchestrator, workflow loader, state store, registry
├── runtime/        AgentRuntime interface + adapters (mock, Claude Code, CLI profiles)
├── agents/         AgentSpec model + prompt composition
├── tools/          filesystem, shell, git, browser
├── mcp/            MCP client, server registry, tool bridge (stdio)
├── browser/        isolated Playwright session + page capture
├── visual/         structural diff, pixel corroboration
├── verification/   Verifier interface, command and visual verifiers
├── policy/         permission + approval policy engine
├── approval/       persistent human gates
├── falsification/  five adversarial strategies
├── security/       scanner, posture audit, SBOM, threat model
├── observability/  structured JSON event logging
├── cli/            typer commands + rich rendering
└── builtin/        shipped workflows, skills, agents, policies, templates
```

Built-in assets live inside the package rather than at the repository root, so
they are importable and installable — and every one of them can be overridden per
project.

Details: **[docs/architecture.md](docs/architecture.md)**

</details>

---

## Security model

DevForge is **secure by default, but it is not a sandbox.**

<details>
<summary><b>What the policy layer does</b></summary>

<br>

- Deny-by-default allowlist for shell commands, matched on the argv DevForge execs.
- Workflow YAML is treated as data: a verifier it declares still goes through that
  allowlist, so a workflow cannot smuggle in `curl` or `bash -c`.
- Secrets are redacted from events **and** persisted state at the write boundary.
- Third-party skills are inspected at consumption; a critical finding fails the step.
- Child processes get a **constructed** environment — ambient credentials never
  reach a subprocess.
- URL fetches clear an SSRF check (scheme, resolved address, host allowlist), and
  network access is off by default.
- Output from outside the workspace is bounded, scanned for injection, and fenced
  as data before it can reach a prompt.
- Inline code (`python -c`, `node -e`) is approval-gated no matter what the
  allowlist says — no glob can constrain what inline code does.
- No shell is ever spawned: `&&`, `|`, `$(…)` are rejected, not interpreted.
- Filesystem paths are fully resolved (symlinks included) and confined to the
  workspace, with deny rules for `.env`, secrets, keys and `.git`.
- Destructive operations (`git push`, deletes, installs) route to approval gates.

</details>

**What it does not do:** allowed commands run as you, with your privileges. An
adversarial agent can escape an allowlist trivially — write a script, ask an
allowed interpreter to run it. This layer protects against **accidents and drift,
not a hostile agent**. Real isolation needs an OS boundary (container, VM,
seccomp), which is deliberately out of scope for now.
See **[docs/security.md](docs/security.md)**.

### Third-party skills are untrusted code

A survey of six well-known skill sources found 70 Python scripts, 41 shell
scripts, 155 `.mjs` files, auto-executing session hooks, six opaque `.zip`
archives — plus an instruction telling the agent to run a script *before reading
it*.

So: **there is an installer, and it never executes what it installs.** A skill is
instructions; DevForge has no code path that runs a file a skill shipped.
Executable content is quarantined for review, listed in the report and recorded in
the lockfile.

```bash
devforge skill search testing
devforge skill audit test-driven-development     # fetch, inspect, install nothing
devforge skill install test-driven-development   # only after you have read the report
```

Refuse if unpinned → clone at the exact commit → verify HEAD matches the pin →
hash the tree → inspect → classify risk → refuse CRITICAL → install with
executables quarantined → write `skills.lock`. Pins never move on their own.

Research: [docs/skill-ecosystem.md](docs/skill-ecosystem.md) ·
Installing: [docs/security/skills.md](docs/security/skills.md) ·
Threats: [docs/security/threat-model.md](docs/security/threat-model.md)

---

## Current limitations

Stated plainly, because a harness that hides its gaps is worse than useless.

- **No sandbox.** As above. OS-level isolation is not implemented.
- **State is files, single machine, no concurrency control.** Two simultaneous runs
  in one project can interleave writes to `state.json`.
- **No cost or token accounting in the run path.** Real runtimes are billed calls,
  and DevForge does not yet meter them or enforce a budget.
- **Runs do not stream.** Adapters wait for the whole result, so a long step looks
  like a frozen terminal.
- **Falsification searches; it does not prove.** Surviving means no counterexample
  was found *within the budget that was actually spent*. A mutation score is a
  statement about the **test suite**, never "94% correct". Six of the ten attack
  targets ship with no strategy attacking them and honestly report 0% coverage.
  [Details](docs/falsification/limitations.md)
- **Visual verification compares structure, not pixels.** The pixel ratio is
  corroboration only and needs the `visual` extra to be computed at all. A passing
  report never claims pixel-perfect reproduction. [Details](docs/browser.md)
- **The patch guard catches known cheating patterns, not all of them.** It reads
  the diff for removed assertions, added skip markers, disabled auth, bypassed
  validation and swallowed exceptions. An agent can still weaken a check in a way
  no pattern anticipates. [Details](docs/debugging.md)
- **The security scanner is pattern matching.** No taint analysis, no vulnerability
  database. A clean scan means no pattern matched — not that the code is safe.
  [Details](docs/security/security-center.md)
- **Benchmarks are small and self-contained.** `devforge bench` scores one solver on
  eight seeded defects; `devforge eval` scores ten cases across eight categories.
  With ten cases one case is worth ten percent — far too coarse to separate a real
  improvement from run-to-run variation, which is why `eval compare` reports
  directions and refuses to name a winner. [Details](docs/evaluation.md)
- **DevForge never pushes and never opens a pull request.** `devforge git pr` writes
  an artifact to a file; a person pushes the branch. Force push, branch deletion and
  history rewriting are refused outright. [Details](docs/git.md)
- **Continuous engineering proposes; it never acts.** Every detector is static, so a
  finding is a hypothesis to confirm rather than a proven defect.
  [Details](docs/continuous.md)
- **Workers are separate processes, not separate machines.** No network transport,
  by design. The file-backed queue is safe for one control plane, not two.
  [Details](docs/platform.md)
- **The Skill Radar does not crawl.** It has no HTTP client, so discovery is bounded
  by configured sources. `INSTALL` means "worth a person's review", never "safe".
  [Details](docs/skill-radar.md)
- **MCP works over stdio only.** HTTP/SSE transports are refused rather than
  downgraded, and sampling is deliberately not implemented — it would let a server
  drive the model. [Details](docs/security/mcp.md)
- **Agent tool calls are proxied only for runtimes that delegate.** An external CLI
  runtime executes its own tools inside a turn and cannot delegate them.
- **Memory is markdown, not retrieval.** No embeddings, no vector store, by design.
- **The `clone` workflow needs configuring.** It ships without a reference URL
  because the target is task-specific.

## Roadmap

1. Cost and token accounting, with an enforceable budget cap.
2. Streaming output, so a long-running step is legible while it runs.
3. Proxy agent tool calls through the DevForge tool layer, so every call is
   policy-checked.
4. Locking for the state store, so concurrent runs are safe.
5. Optional OS-level sandboxing for shell and verifier execution.
6. Perceptual (not per-pixel) image comparison, so a shifted-but-correct layout
   stops registering as a difference.

---

## Development

```bash
pip install -e ".[dev]"
python -m pytest -q     # 1,103 tests, no network, no paid API calls
ruff check .
```

The optional extras are listed under [Installation](#installation).

CI runs the suite on Linux, macOS and Windows across Python 3.11-3.13, with the
extras and again on a bare install, then builds the wheel and drives the whole CLI
surface from it on each OS - and runs DevForge's own security scanner against
DevForge. See **[what CI runs](docs/contributing.md#what-ci-runs)**.

Contributions welcome — see **[docs/contributing.md](docs/contributing.md)** and
the design rules in **[docs/principles.md](docs/principles.md)**.

## Why it exists

Agents claim success they have not earned. A harness that takes those claims at
face value produces confident, broken changes. DevForge exists to keep the claim
and the result two different things.

## License

MIT — see [LICENSE](LICENSE).

<div align="center">
<br>
<sub>If DevForge ever catches something an agent told you was finished, ⭐ the repo.</sub>
</div>
