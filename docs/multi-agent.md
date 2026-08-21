# Controlled multi-agent orchestration

A multi-agent run in DevForge is a **directed acyclic graph declared in YAML**, not a
swarm. The topology is fixed before anything starts, agents never talk to each other,
and each one gets only the permissions its role needs.

## Why not a swarm

Agents that call each other freely produce an unbounded channel with no schema and no
audit trail. A transcript claiming *"I implemented the endpoint"* cannot be checked; an
`implementation.patch` on disk can. So:

- **The graph is declared, not discovered.** Nothing spawns an agent at runtime.
- **Communication is artifacts.** A node declares what it `produces` and `consumes`;
  the supervisor passes file references and previews, never conversation.
- **Claiming is not producing.** A node that promised an artifact and did not write it
  fails, whatever its agent reported.

## The shipped workflow

`multi-agent-feature`:

```
architect
    |
  coder
    |________________________
    |          |             |
 tester    security        docs      <- one level, executed concurrently
    |__________|_____________|
               |
           reviewer
               |
         approve-final
```

Levels come from the dependency graph, not from a hand-written schedule. Everything in
one level is independent by construction, which is what makes running them together
safe rather than hopeful.

```bash
devforge run --workflow multi-agent-feature --task "Add rate limiting" --interactive
```

## Artifact contracts

| Agent | Produces | Consumes |
| --- | --- | --- |
| architect | `docs/architecture-proposal.md` | — |
| coder | `docs/implementation.patch` | architecture proposal |
| tester | `docs/test-results.json` | patch |
| security | `docs/security-report.json` | patch |
| docs | `docs/api-docs.md` | proposal, patch |
| reviewer | `docs/review.json` | all three reports |

The graph is validated at load: cycles, unknown dependencies, two nodes producing the
same artifact, and consuming an artifact nothing produces are all refused before a run
starts. A graph must not promise a channel it cannot deliver.

## Execution modes

**Sequential** — a workflow with no `depends_on` becomes a chain, so every workflow
written before this existed keeps working unchanged.

**Parallel** — independent nodes in one level run concurrently via `asyncio.gather`.

**Conditional** — `when:` takes a closed vocabulary: `always`, `success(node)`,
`failed(node)`, `skipped(node)`, `artifact_exists(name)`. Deliberately **not** an
expression language: `eval` on a string from a workflow file would make that file
executable, and workflow files arrive from the same places skills do. An unmet
condition is a **skip**, not a failure.

**Retry** — unchanged from the step machinery: `max_attempts` per node, with the
verifier diagnostics fed back as a repair briefing.

## Least privilege

Each agent declares what it may touch, and the supervisor narrows the project policy to
it. The overlay only ever *removes* access: an agent asking for `/etc/**` gets nothing
new, because the project policy still refuses it and both must agree.

| Agent | Writes | Shell |
| --- | --- | --- |
| architect, planner | `docs/**`, `*.md` | none |
| **docs** | `docs/**`, `*.md` | **none** |
| security | `docs/**`, `*.json` | read-only git, linters |
| reviewer | `docs/**`, `*.json` | read-only git |
| tester | `tests/**` | test runners |
| coder | `src/**`, `lib/**`, `app/**`, `tests/**` | development allowlist |

A documentation agent that can run shell commands can do anything; a security auditor
that can write source can edit away the finding it just reported. Only the coder writes
source, and only the coder and tester run commands.

## Failure

When a node fails:

1. **Artifacts are preserved** to `.devforge/runs/<task>/preserved/` before anything
   else. A run that dies after the architect wrote a proposal keeps that proposal.
2. **The failure is recorded** on the task, with the node that caused it.
3. **Downstream nodes are blocked**, not run. A node whose input never arrived would be
   inventing a result.
4. **Siblings are untouched.** If the security auditor crashes, the tester's and docs
   agent's work stays on disk and their nodes stay `passed`.

Nothing already written is discarded. That is what makes a re-run cheaper than a
restart.

## What is deliberately absent

- **No dynamic spawning.** An agent cannot decide to add a node.
- **No agent-to-agent messaging.** The artifact store is the only channel.
- **No negotiation or voting.** The reviewer reads reports; it does not debate them.
- **No expression evaluation in workflow files.**

Anything above would need a compelling reason and a new threat-model entry, not just
capability.
