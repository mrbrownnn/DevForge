# Architecture

## Layering

```
cli ──────────────► orchestrator ──────► runtime (interface)
                          │                  ├── mock
                          │                  └── claude-code
                          ├───────► verification (interface)
                          ├───────► tools (interface)
                          ├───────► policy + approvals
                          └───────► state store
```

Dependency direction is inward. `core/` imports interfaces only; concrete runtimes,
tools and verifiers are resolved through registries and injected at construction time
by `core/orchestrator/context.py`. The word "claude" appears in exactly one module,
`runtime/claude_code.py`.

## The object graph

`AppContext.load()` builds everything once:

| Component | Responsibility |
| --- | --- |
| `ProjectStore` | `.devforge/` reads and writes, atomic, run index |
| `PolicyEngine` | may this command run, may this path be touched, which gate applies |
| `WorkflowLoader` | resolve and validate workflow YAML |
| `SkillRegistry` / `AgentRegistry` | discover Markdown skills and YAML agent specs |
| `ToolRegistry` | name to Tool, plus availability reporting |
| `RuntimeRegistry` | name to runtime factory (lazily constructed) |
| `VerificationEngine` | resolve verifier ids, run them concurrently, aggregate |
| `RunLogger` | structured events to JSONL and optionally stderr |

There is no global mutable state and no singleton. Tests build the same graph with
substituted parts.

## The step loop

`Orchestrator.run(task, workflow)` walks steps in order. A step already `passed` or
`skipped` is skipped, which is what makes `--resume` correct rather than a re-run.

**Agent step**

1. Refuse early if any tool the step declares is unavailable — the agent is never
   invoked without the capabilities it was promised.
2. Compose the invocation: agent spec + resolved skills (with transitive dependencies)
   + project memory + step instructions.
3. Execute through `AgentRuntime`.
4. Run the verifiers named by the step.
5. Pass → next step. Fail → build a diagnostics bundle from the failing verifiers and
   re-invoke the agent in `repair` mode. Repeat up to `max_attempts`.

**Verify step** — verifiers only, single attempt: with no agent in the loop, re-running
identical commands cannot change the outcome.

**Approval step** — request the gate. Approved → continue. Rejected → the run fails.
Pending → the task becomes `awaiting_approval`, state is saved and control returns.

State is persisted after every attempt and every step transition.

## Data model

One task is one run. `.devforge/runs/<task_id>/` holds `task.json`, `events.jsonl` and
`artifacts/`. The `Task` record carries the full history: steps, per-attempt agent
results, every verification result verbatim, artifacts, errors and approvals. Nothing
is summarised away, so `devforge review` can reconstruct exactly what happened.

## Design decisions and their reasons

**Agents are YAML, not classes.** Six subclasses differing only by a prompt string
would be an abstraction with no content. An `AgentSpec` plus a prompt composer gives
the same behaviour and makes adding an agent a one-file change.

**Skills are Markdown with frontmatter.** Prompt text belongs in files a human edits,
not in Python string literals. Dependencies are declared and resolved transitively,
with cycle detection.

**Verifiers are declared in YAML by argv.** Adding a check never requires code. Because
verifiers execute through the policy engine, a workflow cannot use them as a back door
to run arbitrary commands.

**Approvals persist instead of blocking.** A gate that blocks a thread dies with the
terminal. A gate that writes a record survives, which is the only way a human decision
can arrive an hour later from a different process.

**Files, not a database.** State is small, human-readable and diffable. A database
would add operational weight the MVP cannot justify. The `ProjectStore` interface is
the seam if that changes.

**Async only where it pays.** Subprocess I/O — runtimes, tools, verifiers — is async,
and the verifiers in one set run concurrently. The CLI is synchronous, with a single
`asyncio.run` at the edge.

## Extension points

| To add | Implement | Register |
| --- | --- | --- |
| A runtime | `runtime.base.AgentRuntime` | `RuntimeRegistry` |
| A tool | `tools.base.Tool` | `ToolRegistry` |
| A verifier kind | `verification.base.Verifier` | `VerifierRegistry` |
| An agent | a YAML file | `agents/` in your project |
| A skill | a Markdown file | `skills/` in your project |
| A workflow | a YAML file | `workflows/` in your project |

---

# Phase 0 addendum: assessment, target architecture, dependencies

## Repository assessment (2026-08-19)

The MVP is built and green. Measured, not estimated:

| Metric | Value |
| --- | --- |
| Tracked files | 95 |
| Python (src + tests) | ~7,100 lines |
| Commits | 27, Conventional Commits |
| Tests | 171 passing, 1 skipped, no network, no paid calls |
| Lint | `ruff check` clean, `ruff format --check` clean |
| Runtime adapters | 2 (`mock`, `claude-code`) |
| Tools | 5 (3 implemented, 2 declared-unavailable) |
| Built-in assets | 4 workflows, 8 skills, 6 agents, 2 policies |

**Strengths to preserve.** Dependency inversion holds — `core/` imports interfaces only,
and no vendor name appears outside `runtime/claude_code.py`. Verification is declarative
and the repair loop is bounded. Approvals persist across processes. Unimplemented
capabilities report `unavailable` instead of faking results.

**Weaknesses this phase addresses.** There was no notion of a *third-party* skill at all:
`SkillRegistry` discovers local Markdown and trusts it completely, which is defensible
for first-party content and unacceptable for anything fetched. There was no provenance,
no pinning, no inspection, and no trust model. That gap is what Phase 0 fills.

**Weaknesses this phase does not address** (carried forward, tracked in the threat model):
agent tool calls are not yet proxied through the DevForge tool layer (T10); the audit log
is unsigned and rewritable (T8); an agent can still weaken its own verifiers (T9); event
payloads are not redacted (T12).

## Target architecture

One new layer, placed at the untrusted edge:

```
                    ┌──────────────────────────────────┐
   third party ───► │  supplychain                     │
   skill source     │  registry · provenance · pins    │
                    │  inspector · trust tiers         │
                    └───────────────┬──────────────────┘
                                    │ only reviewed content crosses
                    ┌───────────────▼──────────────────┐
                    │  SkillRegistry (existing)        │
                    └───────────────┬──────────────────┘
   cli ──► orchestrator ────────────┴──► runtime | tools | verification
                    │
                    └──► policy · approvals · state · observability
```

Deliberate properties:

- **The new layer depends on nothing above it.** `supplychain` imports `core.errors`,
  `core.registry` and pydantic. The orchestrator does not import `supplychain` at all in
  Phase 0 — enforcement at consumption time is Phase 1, and until it exists the layer
  makes no claim to be enforcing anything.
- **It reuses the existing seams.** Approval gates, the event logger and the policy
  engine already exist; the skill gate is another gate, not a parallel mechanism.
- **It is inert by default.** No installer, no fetching, no execution. The registry is
  data; the inspector is a pure function over a directory.

## Dependency analysis

Runtime dependencies remain **four**, unchanged by this phase:

| Package | Why | Replaceable? | Risk |
| --- | --- | --- | --- |
| `pydantic` >=2.7 | Schema validation at every boundary; `extra="forbid"` catches config typos | Yes, at real cost | Low — widely used, active |
| `typer` >=0.12 | CLI with type-driven parsing | Yes (argparse) | Low — thin layer over click |
| `PyYAML` >=6.0 | Workflows, policies, registry. **`safe_load` only** | Yes (ruamel) | Medium — `yaml.load` is unsafe by design; enforced by a static check |
| `rich` >=13 | Terminal rendering, isolated in `cli/render.py` | Yes, trivially | Low |

Dev-only: `pytest`, `pytest-asyncio`, `ruff`.

**Rejected for this phase**, with reasons:

| Candidate | Rejected because |
| --- | --- |
| `requests` / `httpx` | DevForge makes no network calls. Adding an HTTP client before there is an installer would create the capability the threat model exists to deny. |
| `GitPython` | The git tool shells out through the policy layer; a library would bypass that check. |
| `sigstore` / `in-toto` | Real answers to T8, but they presuppose a publishing pipeline that does not exist yet. Phase 2. |
| `semgrep` / `bandit` | The inspector is intentionally a small deterministic pattern set with no third-party analysis engine in the trust path. Revisit if findings prove too shallow. |
| `jsonschema` | Pydantic already validates the registry. Two schema systems is one too many. |

**Supply chain of DevForge itself:** four direct dependencies, all from major maintainers,
all pinned by lower bound and resolved by the user's own installer. DevForge does not
vendor, download, or execute anything at install time beyond standard `pip`.

## When these decisions should be revisited

Each rejection in [principles.md](principles.md) has a trigger:

| Decision | Revisit when |
| --- | --- |
| Files instead of a database | Concurrent runs in one project become normal, or the run index exceeds ~10k entries |
| No vector store | Project memory outgrows what a human maintains by hand (>50 documents) |
| No queue / scheduler | Runs need to outlive the invoking process, or to be distributed |
| No installer | A human review pipeline exists *and* the tier model is enforced at consumption |
| No OS sandbox | DevForge runs anything other than a trusted local user session — this is the first thing to build for a hosted control plane |
| Sequential steps | A workflow has genuinely independent branches worth parallelising |

Until a trigger fires, the simpler design is the correct one.
