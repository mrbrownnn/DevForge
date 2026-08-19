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
