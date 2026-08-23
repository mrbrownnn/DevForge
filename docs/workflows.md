# Workflows

A workflow is declarative YAML. Resolution order:
`./.devforge/workflows/<name>.yaml` → `./workflows/<name>.yaml` → built-in.

## Schema

```yaml
name: feature              # defaults to the filename
version: 1.0.0
description: ...
tags: [default]

verifiers:                 # available to the steps of this workflow
  - id: tests
    kind: tests            # command | tests | lint | typecheck | build | e2e | security
                           #   | artifacts (checks declared files exist, runs nothing)
                           #   | visual (declared, NOT implemented)
    description: ...
    argv: [python, -m, pytest, -q]
    cwd: null              # defaults to the workspace root
    timeout_s: 900
    required: true         # false = failure is recorded but does not block
    success_exit_codes: [0]

steps:
  - id: implementation     # unique within the workflow
    name: Implementation   # defaults to a title-cased id
    kind: agent            # agent | verify | approval
    description: ...
    agent: coder           # required for kind: agent
    skills: [backend]      # overrides the default skills of the agent
    tools: [filesystem, shell, git]
    prompt: ...            # appended to the composed prompt
    outputs: [auth.py]     # declared, for the prompt and for review
    verify: [tests]        # verifier ids
    max_attempts: 3        # bound on the agent + verify repair loop
    gate: architecture     # required for kind: approval
    on_failure: fail       # fail (default) | continue
```

Unknown keys are rejected at load time, with the file path and the offending field in
the message.

## Step kinds

**agent** — invoke an agent, then run `verify`. On failure the agent is re-invoked in
repair mode with the output of the failing verifiers, up to `max_attempts`.

**verify** — verifiers only. Always one attempt: nothing would change on a second run.

**approval** — pause for a human at `gate`. Gates should be declared in
`policies/approvals.yaml`; an undeclared gate is treated as blocking (fail closed).

## The `artifacts` verifier

The only verifier kind that needs no external tooling, which is what lets a workflow
complete in a project with no test suite:

```yaml
verifiers:
  - id: plan-written
    kind: artifacts
    expect: [docs/plan.md]      # never `argv` - it executes nothing
```

It fails when a declared file is missing or empty, which catches the most common agent
failure: reporting success without producing the deliverable. Paths go through the
permission policy, so a verifier cannot probe outside the workspace.

## Verification semantics

- The verifiers of a step run **concurrently**.
- The step passes when no *required* verifier reports anything but `passed`/`skipped`.
- `unavailable` on a required verifier is a **failure**, never a pass.
- Every result is persisted with exit code, duration and a tail of the output.

## Built-in workflows

| Workflow | Steps | Notes |
| --- | --- | --- |
| `demo` | requirements → planning → **approval** → review → verification | Completes in any project; verifies declared artifacts exist |
| `feature` | requirements → planning → **approval** → implementation → unit tests → verification → review → **approval** | The default |
| `bugfix` | reproduce → evidence → analyse → **approval** → patch + regression test → report → verification | The patch itself is reviewed, not just the suite |
| `refactor` | analyse → **baseline verify** → plan → **approval** → refactor → tests → verification | Baseline first, or there is no safety net |
| `clone` | recon → design analysis → **approval** → implementation → visual refinement → visual verification → **approval** | Needs `devforge[browser]` and a `reference` URL; see [browser.md](browser.md) |

## Writing your own

```bash
mkdir -p workflows
```

`workflows/hotfix.yaml`:

```yaml
name: hotfix
verifiers:
  - id: tests
    kind: tests
    argv: [python, -m, pytest, -q, tests/unit]
steps:
  - id: fix
    agent: coder
    tools: [filesystem, shell]
    verify: [tests]
    max_attempts: 2
  - id: sign-off
    kind: approval
    gate: final_review
```

Then:

```bash
devforge plan --workflow hotfix
```

`devforge plan` validates the file, lists unknown agents and skills, warns about
unavailable tools and shows the approval gates — before anything executes.

## Resuming

A run that stops at a gate leaves the task `awaiting_approval` and exits with code 2.

```bash
devforge approve --gate architecture --by you
devforge run --resume task_ab12cd34
```

Steps already marked `passed` are skipped, so no agent work and no billed call is
repeated.

## `kind: falsify`

A fourth step kind. Where a `verify` step gathers evidence *for* a change, a `falsify`
step searches for evidence *against* it: mutants the tests fail to detect, inputs that
violate a declared invariant, tests an adversarial agent writes to break it.

```yaml
- id: falsify
  kind: falsify
  strategies: [mutation, property, adversarial]
  targets: [behavior, boundary_conditions, error_handling]
  scope: diff
  budget:
    max_duration_s: 600
    max_mutants: 50
    max_agent_invocations: 5
    flakiness_probes: 2
  on_incomplete: fail        # an unfinished search is not a pass
  on_unavailable: continue   # a missing dependency is recorded, not fatal
```

Two conditions are available to downstream steps, and they are not interchangeable
with `success`/`failed`: a falsify step that finds a counterexample worked correctly.

```yaml
- id: repair
  agent: coder
  condition: falsification_failed(falsify)
```

`falsification_survived(node)` is the complement. `condition:` and `when:` are the same
guard - two spellings, mirrored, exactly as `outputs`/`produces` are.

The built-in `falsify` workflow demonstrates the full loop, including a `re-falsify`
step that measures post-repair survival. See
[docs/falsification/architecture.md](falsification/architecture.md).
