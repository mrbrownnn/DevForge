# Phase 13 — Adversarial Falsification Engine: integration plan

**Status: implemented.** This document is kept as written - the architecture audit
and the approved design - so that what was intended stays readable next to what was
built. Three things landed differently, each noted here rather than edited into the
text above:

* The benchmark suite has **twenty** cases, not nineteen: `benign-difference` was
  added to pin that a suppressed difference is still reported as suppressed.
* Mutation candidates are diff-scoped by *line*, not merely by file. `patch.py`
  parses hunks so `scope: diff` is the boundary §16 claims it is.
* `models.py` re-exports the coverage models from `coverage.py` rather than owning
  them, so shape and computation stay together without an import cycle.

Everything else was built as specified. See `architecture.md` for the shipped
module map.

The governing constraint, taken from the brief and checked against the repository:
falsification is a **fourth step kind and a second evidence source**, not a second
harness. Nothing proposed here forks the workflow engine, the verification engine,
the policy engine, the state store, the observability layer or the evaluation
framework.

---

## 1. Existing architecture

Audited at commit `2133a56` (`docs: document the execution platform`). Every path
below was read, not inferred.

| Concern | Where it lives | What it provides |
| --- | --- | --- |
| Workflow engine | `core/orchestrator/engine.py` (472 lines) | One loop: agent -> verify -> repair -> verify. Injected collaborators only; knows no concrete runtime, tool or verifier |
| Workflow step abstraction | `core/workflow/spec.py` | `StepKind{agent,verify,approval}`, `WorkflowStep` (pydantic, `extra="forbid"`), `VerifierSpec`, `WorkflowSpec` |
| Workflow loading | `core/workflow/loader.py` | `.devforge/workflows/` -> `workflows/` -> `builtin/workflows/`, first hit wins |
| Task graph | `core/graph/models.py`, `supervisor.py` | DAG over steps, parallel levels, artifact contracts, closed-vocabulary `Condition` evaluated by a matcher (never `eval`) |
| Verification engine | `verification/engine.py`, `base.py` | `VerifierRegistry` keyed by `kind`; `asyncio.gather` concurrency; required-verifier aggregation; a broken verifier becomes `ERROR`, never a pass |
| Verifier kinds | `verification/{command,artifacts,visual,repair}.py` | command/tests/lint/typecheck/build/e2e/security, artifacts, visual, patch-guard, repair-report |
| Repair loop | `engine.py::run_step` attempts + `debug/patch_guard.py` | Bounded re-invocation with `previous_attempt` fed back into the prompt; the patch guard fails a repair that weakens checks |
| Agent runtime | `runtime/base.py`, `registry.py`, `capabilities.py` | `AgentRuntime.execute(invocation, RuntimeContext)`; `configure(**settings)` **returns the settings it could not honour** |
| Agent specs | `agents/spec.py`, `builtin/agents/*.yaml` | Declarative role/prompts/skills/tools plus `AgentPermissions` (read, write, shell, allow_shell, network) |
| Tool registry | `tools/base.py`, `executor.py`, `descriptor.py` | `Tool` ABC; `ToolExecutor` is the single policy-enforcing door for every tool call |
| Policy engine | `policy/engine.py`, `models.py`, `agent_scope.py` | Deny-by-default argv allowlist, path confinement with real glob semantics, approval gates, shell-metacharacter refusal, inline-code gating, **narrowing-only** per-agent scope |
| Sandbox / isolation | `vcs/worktree.py`, `platform/isolation.py` | Linked git worktrees under `.devforge/worktrees/`; per-task workspaces with scrubbed env. **Neither is an OS sandbox, and both say so** |
| State persistence | `core/state/store.py` | `.devforge/` plain files, atomic temp+`os.replace` writes, run dirs at `.devforge/runs/<task_id>/` |
| Artifact system | `core/graph/artifacts.py`, `store.write_artifact` | Named artifacts resolved inside the run directory; path escape refused |
| Observability | `observability/logging.py` | `RunLogger`, JSONL sink per run, `bind()` for step scope, redaction before any sink sees an event |
| Secrets | `observability/redaction.py` | Pattern redaction at exactly two boundaries: `RunLogger.emit`, `ProjectStore.save_task` |
| Untrusted content | `tools/untrusted.py` | Bound -> scan (7 injection patterns) -> fence with an explicit data-not-instructions warning |
| Evaluation | `eval/{models,runner,metrics,drivers,store,compare}.py` | Cases with executable checks; twelve metrics; `MetricValue(value=None)` with `unknown_reason` = unmeasured, never `0` |
| CLI | `cli/main.py` + 9 `cli/*_commands.py` | Typer app; sub-apps via `add_typer`; commands are thin and hand off to `cli/render.py` |
| Security system | `security/*`, `supplychain/*`, `docs/security/threat-model.md` | Scan, baseline, SBOM, audit; skill trust assessment before prompt composition |
| Skill system | `core/registry/skills.py`, `supplychain/consumption.py` | Discovery plus `assess_all`; an untrusted skill **fails the step** rather than being silently dropped |
| Executable architecture rules | `tests/test_architecture.py` | Enforces: no vendor names outside adapters, no `yaml.load`, no `shell=True`, **no `eval`/`exec`/`compile`/`__import__`**, no HTTP client, **runtime deps frozen at exactly `{pydantic, typer, pyyaml, rich}`** |

---

## 2. Existing verification lifecycle

```
Orchestrator.run(task, workflow)
  |- collect_specs(workflow, project verifiers)   # workflow wins on id collision
  |- missing_verifiers() -> fail the run before anything executes
  |- any step declares depends_on? -> Supervisor (graph) ; else sequential
  `- for step in workflow.steps:
        ensure_step(); skip if already PASSED/SKIPPED   # resume, not restart
        run_step(...)

run_step(step)
  |- APPROVAL      -> gate; PASSED / REJECTED / AWAITING_APPROVAL (run pauses)
  |- tool availability check -> fail with the tool's own reason
  |- AGENT: untrusted-skill check -> fail, never silently degrade the prompt
  `- for attempt in 1..max_attempts:
        AGENT: _invoke_agent()  -> AgentResult          # runtime success only
              policy narrowed by scope_for_agent(agent.permissions)
        _verify(step, specs, ctx.for_step(...)) -> VerificationReport
        report.passed -> record PASSED, persist, return None
        else         -> record attempt, persist; if not step.repairable: break
     _finish_failed_step(...)  -> FAIL the run, or CONTINUE per on_failure
```

Two properties of this lifecycle decide the whole Phase 13 design:

* **Self-reports are never trusted.** `AgentResult.ok` means the runtime worked.
  Only verifiers may judge the work. Falsification extends the same suspicion one
  level outward: verifiers passing means *the declared checks agreed*, not that the
  declared checks were adequate.
* **Verification is structurally confirmation-oriented.** It executes only what the
  workflow already named. It therefore cannot ask "are these checks sufficient?" —
  not because of an implementation gap but because of its contract. That is the gap
  `kind: falsify` fills, and it is why falsification must be a peer of verification
  rather than a verifier kind.

### State flow today

```
Task (pydantic)
  -> ensure_step / record_verification / add_error / add_artifact
  -> ProjectStore.save_task()  ->  redact_value()  ->  atomic write
        .devforge/runs/<task_id>/task.json
        .devforge/runs/<task_id>/events.jsonl      (RunLogger jsonl sink)
        .devforge/runs/<task_id>/artifacts/
  -> _index_task()  ->  .devforge/state.json
```

Persistence happens **after every attempt**, which is what makes a crashed run
resumable rather than restartable. Falsification must persist on the same cadence.

---

## 3. Existing security boundaries

Seven boundaries exist today. Phase 13 reuses all seven and adds none of its own
invention.

1. **Command allowlist** (`PolicyEngine.check_command`). Deny-by-default fnmatch over
   the argv DevForge will pass to `exec`. Refuses shell metacharacters and command
   substitution outright; routes inline-code flags (`python -c`, `node -e`) to an
   approval gate *regardless of any allow rule*, because no glob can constrain
   inline code.
2. **Path confinement** (`check_path` / `resolve_path`). Full symlink resolution,
   workspace-only by default, deny rules that beat allow rules, real path-glob
   semantics (`*` does not cross `/`).
3. **Per-agent narrowing** (`scope_for_agent`). Intersection only. An agent spec can
   remove access and can never add it — enforced structurally, not documented.
4. **Approval gates** (`ApprovalGate`, `approvals.yaml`). Unknown gates are blocking:
   fail closed.
5. **Process hygiene** (`tools/process.py`, `tools/environment.py`). argv only, never
   a shell; mandatory timeout; constructed environment, never the host's; bounded
   output with visible truncation.
6. **Redaction** (`observability/redaction.py`) at the log-emit and state-save
   boundaries.
7. **Untrusted-content fencing** (`tools/untrusted.py`) for anything arriving from
   outside the workspace.

**The stated limitation, which Phase 13 must not contradict:** none of this is a
sandbox. `policy/engine.py` says so in its module docstring; `docs/security.md` says
so in its first third (asserted by `tests/test_docs.py`). An allowed command runs as
the current user with that user's privileges.

---

## 4. Integration points

Twelve touch points. Every one is additive; none changes an existing code path.

| # | File | Change | Backward-compat risk |
| --- | --- | --- | --- |
| 1 | `core/workflow/spec.py` | `StepKind.FALSIFY`; new optional `WorkflowStep` fields (`strategies`, `targets`, `budget`, `falsifier`, `order`, `scope`, `on_incomplete`, `on_unavailable`, `condition`); validation rules for falsify steps | **Low** — new optional fields on an `extra="forbid"` model; existing YAML unaffected |
| 2 | `core/orchestrator/engine.py` | One `if step.kind is StepKind.FALSIFY:` branch in `run_step`; new **keyword-with-default** `falsification=None` constructor parameter | **Low** — default `None` keeps every existing construction (tests included) working |
| 3 | `core/graph/models.py` | Widen `CONDITION_PATTERN` with `falsification_failed(node)` / `falsification_survived(node)`; `Condition.evaluate` reads falsification status from run state | **Low** — closed vocabulary widened; still not an expression language |
| 4 | `core/orchestrator/context.py` | `AppContext.falsification: FalsificationEngine`, built once, passed into `Orchestrator` | **Low** |
| 5 | `core/state/store.py` | `falsification_dir(task_id)`, `corpus_dir()`, save/load of reports through the existing `_atomic_write` + `redact_value` | **Low** — new methods only |
| 6 | `core/models.py` | `StepRecord`/`StepAttempt` gain an optional `falsification: FalsificationReport \| None` so a falsify step's evidence lands in `task.json` like verification does | **Medium** — `Task` schema grows; old `task.json` files still parse because the field is optional |
| 7 | `cli/main.py` | `app.add_typer(falsify_commands.app, name="falsify")` | **Low** — but see §12, `tests/test_docs.py` will fail until the README documents it |
| 8 | `eval/metrics.py` | Append falsification metrics when results carry them; `None` + `unknown_reason` otherwise | **Low** — existing twelve metrics untouched |
| 9 | `eval/models.py` | `CaseResult` gains an optional falsification payload; benchmark cases gain a `falsification:` block | **Low** |
| 10 | `builtin/policies/permissions.yaml` | An explicit falsifier command allowlist | **Medium** — reviewed in §3/§9 |
| 11 | `builtin/agents/falsifier.yaml` | New agent spec, narrowest `AgentPermissions` in the tree | **Low** |
| 12 | `builtin/workflows/falsify.yaml` | New opt-in workflow demonstrating implement -> verify -> falsify -> repair | **None** |

### Rejected integration points, and why

* **A verifier kind (`kind: falsify` inside `verifiers:`).** Fits the plumbing;
  the contract is wrong. `Verifier.run` returns one `VerificationResult`
  (status, exit code, summary, excerpt). A falsification run produces mutants,
  counterexamples, minimised forms, per-target coverage, per-strategy budget usage
  and an equivalence classification. Forcing that through one result record makes
  the report unpersistable and leaves the repair agent with nothing actionable.
  It would also merge evidence-for and evidence-against into one verdict, which
  §2 of the brief forbids.
* **Extending `debug/patch_guard.py`.** It already asks a falsification-shaped
  question ("did this patch weaken the checks?") but it is a static read of a diff.
  It will be **reused unchanged** as the write-scope guard for the adversarial agent.
* **The eval framework as the executor.** Right for *measuring* falsification across
  a benchmark; wrong for *running* it inside one workflow.

---

## 5. Components that can be reused (not rebuilt)

| Need | Reused, unchanged |
| --- | --- |
| Run a command safely | `tools/process.py::run_process` — argv, timeout, scrubbed env, bounded output |
| Decide whether a command may run | `policy/engine.py::check_command` |
| Narrow the falsifier's permissions | `policy/agent_scope.py::scope_for_agent` + `agents/spec.py::AgentPermissions` |
| Isolated checkout | `vcs/worktree.py::create_worktree` / `remove_worktree` |
| Per-task workspace + scrubbed env | `platform/isolation.py` |
| Structured events | `observability/logging.py::RunLogger` (`bind`, JSONL sink) |
| Secret redaction | `observability/redaction.py::redact_value` at the same two boundaries |
| Untrusted repository content | `tools/untrusted.py::wrap` / `scan` |
| Refuse a check-weakening or scope-violating patch | `debug/patch_guard.py::review_patch` |
| Atomic state writes | `core/state/store.py::_atomic_write` |
| Name -> item lookup | `core/registry/base.py::Registry` |
| Agent invocation and prompt assembly | `runtime/base.py::AgentRuntime` + `agents/prompt.py::build_invocation` |
| Runtime setting honesty (`configure` returns unhonoured keys) | `runtime/base.py::AgentRuntime.configure` |
| Metric honesty (`None` is not `0`) | `eval/metrics.py::MetricValue` |
| Concurrency | `asyncio.gather`, exactly as `VerificationEngine.run` does |

Nothing in this table is copied, wrapped-and-forked, or reimplemented.

---

## 6. Components that must be extended

| Component | Extension | Why it cannot simply be reused |
| --- | --- | --- |
| `StepKind` | Add `FALSIFY` | A closed enum; a fourth kind is the whole feature |
| `WorkflowStep` | `strategies`, `targets`, `budget`, `falsifier`, `condition` | `extra="forbid"` rejects unknown keys, so fields must be declared |
| `Orchestrator` | One branch + one defaulted collaborator | A falsify step has no verifiers to run and no agent to invoke; the existing attempt loop does not describe it |
| `Condition` | Two new kinds | `falsification_failed` cannot be expressed with `success()`/`failed()`: a falsify step that *found* a counterexample did its job correctly while the implementation failed |
| `StepRecord` | Optional falsification payload | Evidence must persist in `task.json` next to verification evidence |
| `ProjectStore` | Falsification + corpus directories | New on-disk locations, same atomic-write discipline |
| `eval/metrics.py` | Eleven added metrics | Falsification is measured differently from task success |
| `permissions.yaml` | Falsifier allowlist entries | The falsifier needs `pytest` variants the default list does not carry |
| `render.py` | `render_falsification`, `render_counterexample` | Reports are structurally unlike anything already rendered |

---

## 7. New components

```
src/devforge/falsification/
|- models.py         FalsificationReport, Counterexample, Mutant, Budget,
|                    FalsificationTarget, statuses, coverage models
|- engine.py         FalsificationEngine (peer of VerificationEngine)
|- targets.py        FalsificationTarget registry; target x strategy applicability
|- sandbox.py        Isolated workspace: worktree -> copy -> ISOLATION_UNAVAILABLE
|- equivalence.py    Layered equivalent-mutant detection (static/behavioral/assisted)
|- reliability.py    Test-flakiness screening: separates unreliable survival from
|                    behavioural equivalence, and unreliable kills from real ones
|- reduction.py      CounterexampleReducer (first-class subsystem)
|- corpus.py         Falsification Corpus: findings, counterexamples, mutants
|- regression.py     Counterexample -> permanent regression test
|- coverage.py       AttackSurfaceCoverage + StrategyCoverage
|- store.py          Report persistence, listing, explain-by-finding-id
|- metrics.py        Falsification metrics feeding the eval framework
`- strategies/
   |- base.py           FalsificationStrategy ABC, FalsificationContext, registry
   |- mutation.py       AST-operator mutation testing
   |- property.py       Property-based testing (Hypothesis when installed)
   |- adversarial.py    Adversarial test agent
   |- differential.py   Old vs new with configurable equivalence
   `- metamorphic.py    Relations between executions
```

Plus: `cli/falsify_commands.py`, `builtin/agents/falsifier.yaml`,
`builtin/workflows/falsify.yaml`, `builtin/benchmarks/falsification.yaml`,
`tests/test_falsification.py`, `tests/security/test_falsification_security.py`,
and the twelve `docs/falsification/` pages.

### The `Budget` fields, settled

```yaml
falsify:
  budget:
    max_duration_s: 600          # seconds, per recommendation 3
    max_mutants: 50              # default lowered from 100, per the cost analysis
    max_property_examples: 1000
    max_adversarial_tests: 20
    max_agent_invocations: 5     # NEW - caps calls, not just produced tests
    max_retries: 2
    max_tokens: null             # unenforceable, and reported so, when the
                                 # runtime reports no token counts
    max_parallel_jobs: 4
    flakiness_probes: 2          # NEW - 0 disables screening and states the gap
    strategy_share:              # NEW - per-strategy wall-clock sub-budgets
      adversarial: 0.4           # fractions of max_duration_s; unlisted
                                 # strategies share what remains
```

Two of these are additions to the brief's list and are argued in §15: without
`max_agent_invocations` the adversarial strategy is bounded only by a number of
*outputs* it may legitimately fail to produce, and without `strategy_share` a single
slow agent call can spend a budget four other strategies were relying on.

### The three abstractions this design adds over a naive one

**`FalsificationTarget` — *what* is attacked.** A strategy says how to attack; a
target says what is under attack. They compose:

```
                 behavior  error_handling  security  authorization  boundary
mutation            X            X            X            -           X
property            X            X            -            -           X
adversarial         X            X            X            X           X
differential        X            -            -            -           -
metamorphic         X            -            -            -           X
```

Phase 13 ships `behavior`, `boundary_conditions`, `error_handling` and `regression`
as fully attacked; `security`, `authorization`, `input_validation`,
`state_transitions`, `api_contract` and `concurrency` are **declared** in the target
registry with an applicability matrix and report `0%` attacked coverage rather than
being absent. A declared-but-unattacked target that honestly reports zero is more
useful than a target that does not exist, because it makes the gap visible.

**`CounterexampleReducer` — minimisation as a subsystem, not a strategy detail.**
Property, adversarial, differential and future fuzzing counterexamples all need
shrinking, and shrinking is the same algorithm each time (delta-debugging over a
reproduction that the strategy knows how to re-run). Placing it in each strategy
would produce four divergent implementations. Contract:

```
ReductionResult:
  original:   Counterexample
  minimized:  Counterexample | None
  status:     REDUCED | IRREDUCIBLE | UNAVAILABLE | BUDGET_EXHAUSTED | ERROR
  steps:      int
  reproduction: list[str]        # argv, never a shell string
```

If minimisation fails for any reason the original is preserved verbatim. A reducer
that loses a counterexample is worse than no reducer.

**Test reliability — a third failure mode, kept out of the equivalence pipeline.**
A mutant can survive for a reason the equivalence layers are structurally unable to
see: the test that should have killed it is flaky and happened to pass. That is not
behavioural equivalence, and routing it through `equivalence.py` would produce a
confident wrong answer. It corrupts the mutation score in both directions:

```
flaky test passes on the mutant   -> SURVIVED   -> score understated,
                                                   a false TEST_WEAKNESS finding
flaky test fails on the mutant    -> KILLED     -> score overstated,
                                                   a real weakness hidden
```

Neither the equivalent-mutant benchmark cases nor any other fixture in §14 can catch
this, because they are deterministic by construction. So it is screened explicitly:

1. **Baseline probe, once per run, before any mutation.** The selected test set is
   run `flakiness_probes` times (default `2`) against the *unmutated* sandbox. Any
   test whose outcome is not identical across probes is **quarantined**, and the
   quarantine list is recorded in the report.
2. **Classification.** A mutant whose verdict depends on a quarantined test — whether
   it survived or was killed by one — is classified `MutantStatus.UNRELIABLE`, with
   the offending test named.
3. **Arithmetic.** `UNRELIABLE` is excluded from *both* the numerator and the
   denominator of the mutation score, and reported as its own count beside
   killed/survived/equivalent/invalid/error. It is never folded into `EQUIVALENT`,
   and never silently dropped: a score computed over fewer mutants than were
   generated must say so.
4. **When screening is off** (`flakiness_probes: 0`, for a project whose suite is too
   slow to run twice), every survival carries the stated limitation *"test
   reliability was not screened; a surviving mutant may indicate a flaky test rather
   than a weak one."* Screening is skippable; the resulting uncertainty is not.

Cost is bounded and paid once per run, not per mutant: one extra full pass of the
selected tests. That is the cheapest honest option, and the alternative — re-running
every mutant *n* times — multiplies the most expensive part of the strategy.

This is a Phase 13 deliverable, not a deferral. Shipping a mutation score that a
flaky suite can move by an unknown amount would undermine the one number this
subsystem is most likely to be quoted on.

---

## 8. Data flow

```
                       ┌──────────────── evidence FOR ────────────────┐
   patch / diff ──────►│           VerificationEngine                 │──┐
                       └──────────────────────────────────────────────┘  │
                                                                          ▼
                       ┌────────────── evidence AGAINST ──────────────┐  Orchestrator
   patch / diff ──────►│           FalsificationEngine                │──┘   │
                       └──────────────────────────────────────────────┘      ▼
                                                                        decision / gate
FalsificationEngine.run(task, step, diff, ctx):

  1. resolve targets     step.targets  -> TargetSet (default: behavior, boundary,
                                          error_handling)
  2. resolve strategies  step.strategies -> [Strategy], filtered by the
                                          target x strategy applicability matrix
  3. acquire sandbox     worktree -> copy -> ISOLATION_UNAVAILABLE (refuse, do not
                                          downgrade silently)
  4. open ledger         Budget -> BudgetLedger (wall clock starts here)
  4b. reliability probe  run the selected tests flakiness_probes times unmutated;
                         quarantine any test that is not deterministic
  5. for each strategy, cheapest and most deterministic first:
        mutation -> property -> differential -> metamorphic -> adversarial
        each strategy opens a sub-ledger against its own share of the budget
        available(ctx)?  no  -> StrategyReport(UNAVAILABLE, reason)   [never SURVIVED]
        attack(ctx)      -> counterexamples, mutants, coverage, usage
        emit falsification.strategy.{started,completed}
  6. reduce              CounterexampleReducer over every counterexample
  7. classify            equivalence layers; strict status derivation
  8. coverage            AttackSurfaceCoverage + StrategyCoverage
  9. report              FalsificationReport.settle() -> status + confidence
 10. persist             run report + corpus entries; emit falsification.completed
 11. release sandbox
```

**Status derivation is ordered, and the order is the point:**

```
any strategy FAILED (counterexample found)        -> FAILED
else any strategy ERROR                            -> INCOMPLETE (never SURVIVED)
else any strategy INCOMPLETE or budget exhausted   -> INCOMPLETE
else every strategy UNAVAILABLE                    -> UNAVAILABLE
else                                               -> SURVIVED
```

`UNAVAILABLE` and `INCOMPLETE` never collapse into `SURVIVED`. This is asserted by a
dedicated test, because it is the single most likely place for the subsystem to
start lying.

**Why the strategy order is fixed rather than declaration-order.** Budget exhaustion
truncates whatever is running when the clock runs out. Running the deterministic,
reproducible strategies first means a truncated run loses the *least* reproducible
evidence, not the most; running adversarial first would mean an expensive agent call
routinely consumes the budget that mutation testing needed. The order is a default,
overridable per step with `order:` when a workflow genuinely wants otherwise.

---

## 9. State flow

```
.devforge/
├── runs/<task_id>/
│   ├── task.json                      StepRecord.falsification (redacted on save)
│   ├── events.jsonl                   falsification.* events (redacted on emit)
│   └── falsification/
│       ├── <run_id>.json              full FalsificationReport
│       └── <run_id>.md                rendered report, human-readable
└── falsification/                     cross-run, task-independent
    ├── findings/<finding_id>.json     one actionable finding
    ├── counterexamples/<id>.json      original + minimised form
    ├── mutants/<run_id>.jsonl         every mutant and its classification
    └── corpus/<id>/                   reproduction + metadata + generated test
```

Two locations on purpose. Per-run evidence belongs with the run, alongside
`task.json` and `events.jsonl`, and disappears when the run directory is cleaned.
The **corpus outlives runs**: it is the growing library of real failure modes that
later feeds regression tests and DevForge's own benchmarks. Putting the corpus under
`runs/<task_id>/` would tie its lifetime to a run, which defeats its purpose.

**Corpus secret discipline.** Corpus entries pass through `redact_value` on write,
same as `save_task`. Additionally, a corpus entry stores a reproduction *argv* and
input values, never an environment snapshot, and never file contents from paths the
policy denies. A dedicated security test writes a secret into a case's inputs and
asserts it does not appear anywhere under `.devforge/falsification/`.

---

## 10. Failure semantics

### Strategy-level

| State | Meaning | Never means |
| --- | --- | --- |
| `FAILED` | At least one valid counterexample found | The strategy malfunctioned |
| `SURVIVED` | Ran to completion in the configured space, found nothing | The code is correct |
| `INCOMPLETE` | Started, could not fully explore: budget, timeout, partial run, infrastructure failure | Success |
| `UNAVAILABLE` | Cannot execute here: dependency missing, language unsupported, no isolation | Success, or a skip that can be ignored |
| `ERROR` | The strategy itself broke | Anything about the implementation under test |

### Mutant-level (mutation strategy only)

| Classification | Meaning | Counts in the score |
| --- | --- | --- |
| `KILLED` | A reliable test failed on the mutant | Numerator and denominator |
| `SURVIVED` | Every reliable test passed on the mutant — evidence about the suite | Denominator only |
| `EQUIVALENT` | Behaviourally identical to the original, per a named layer | Neither |
| `UNRELIABLE` | The verdict depended on a quarantined flaky test | Neither, and reported separately |
| `INVALID` | The mutant does not compile or is not a realistic fault | Neither |
| `ERROR` | The mutant could not be evaluated | Neither |

`UNRELIABLE` is never folded into `EQUIVALENT`. They look alike from the outside —
both are surviving mutants that are not test weaknesses — and they have nothing in
common: one is a property of the code, the other a property of the suite, and only
one of them is a bug the user should fix.

### Step-level, inside the orchestrator

| Report status | Step outcome | Rationale |
| --- | --- | --- |
| `FAILED` | Step **fails**; findings written; `falsification_failed(step)` becomes true | A counterexample is actionable evidence, and the repair loop must see it |
| `SURVIVED` | Step passes with recorded confidence and limitations | The best available outcome, and it is not a proof |
| `INCOMPLETE` | Governed by `on_incomplete: fail \| continue` (default `fail`) | Silently passing an unfinished search is the failure mode the brief singles out |
| `UNAVAILABLE` | Governed by `on_unavailable: fail \| continue` (default `continue`, with a loud limitation recorded) | A project without Hypothesis installed should not be unable to run any workflow; but the gap must be visible in the report |
| `ERROR` | Step fails | A broken falsifier is not evidence of anything |
| `ISOLATION_UNAVAILABLE` | Step **fails**, always, not configurable | Mutating a user's working tree is not a degraded mode; it is a defect |

**Non-negotiable:** the falsifier never repairs. A `FAILED` falsification produces a
finding artifact; the *workflow* decides whether a repair agent step consumes it.
Likewise the falsifier proposes tests and never writes into the permanent suite.

---

## 11. Migration strategy

Thirteen increments, mapped to the brief's Phases A–M. Each is independently
shippable and leaves the tree green. After **every** increment: existing tests, new
tests, security tests, then documentation.

| Inc. | Brief phase | Content | Exit criterion |
| --- | --- | --- | --- |
| 1 | A | `models.py`, `targets.py` — domain only, no execution | Model invariants, mutation-score denominator, status-derivation table, budget arithmetic |
| 2 | B | `StepKind.FALSIFY`, DSL fields, conditions, orchestrator branch, `AppContext` wiring | `kind: falsify` parses and runs (engine returns `UNAVAILABLE` with a reason); **all pre-existing tests still pass** |
| 3 | C | `engine.py`, `strategies/base.py`, `sandbox.py`, `store.py` | Sandbox tiering; `ISOLATION_UNAVAILABLE` refuses; report persists |
| 4 | D | `strategies/mutation.py`, `equivalence.py`, **`reliability.py`** | Operator coverage; killed/survived/equivalent/unreliable/invalid/error each demonstrated; the baseline probe quarantines a flaky test before any mutant is generated |
| 5 | E | `strategies/property.py` | Violation detected with Hypothesis present; clean `UNAVAILABLE` when absent |
| 6 | F | `strategies/differential.py`, `strategies/metamorphic.py` | Mismatch found; configurable equivalence suppresses a benign ordering difference |
| 7 | G | `reduction.py` | A large counterexample shrinks; a failed reduction preserves the original |
| 8 | H | `strategies/adversarial.py`, `builtin/agents/falsifier.yaml`, per-strategy sub-budgets | Agent produces tests; independence knobs honoured or reported unhonoured; `max_agent_invocations` and the wall-clock sub-budget both enforced; unmeasurable token budgets reported unenforceable |
| 9 | I | Security enforcement + `tests/security/` | Write-scope, permission-invariant, injection, secret tests all pass |
| 10 | J | `corpus.py`, `regression.py` | Counterexample -> corpus entry -> runnable regression test |
| 11 | K | Repair integration | `falsify -> repair -> verify -> falsify` demonstrated end to end |
| 12 | L | `coverage.py`, `metrics.py`, observability events, `cli/falsify_commands.py` | All fourteen events emitted; eleven metrics computed or explicitly unknown |
| 13 | M | `builtin/benchmarks/falsification.yaml`, regression suite, twelve docs pages | Nineteen benchmarks with declared oracles; `tests/test_docs.py` green |

---

## 12. Backward compatibility concerns

Seven concrete risks, each with its mitigation. Five are mechanical; two need a
decision.

1. **`Orchestrator.__init__` signature.** Tests and `AppContext` construct it
   directly. Mitigation: `falsification: FalsificationEngine | None = None`, added
   last, keyword-only in practice. A falsify step with no engine **fails the step
   with a clear reason** — it must never pass by omission.
2. **`WorkflowStep` is `extra="forbid"`.** New keys must be declared or every
   falsify workflow raises a validation error. Mitigation: declare them; add a
   validator that rejects `strategies:` on non-falsify steps so the field cannot be
   silently ignored somewhere it does nothing.
3. **`Task` schema growth.** `core/models.py` uses `extra="forbid"`, so an old
   `task.json` still loads (the new field is optional with a default) but a *new*
   `task.json` will not load on an older DevForge. Acceptable and stated in the
   release note; there is no cross-version state contract today.
4. **`tests/test_docs.py` will fail the moment the CLI group is added.** It asserts
   every registered command and group appears in `README.md`, and that
   `EXPECTED_DOCS` all exist. Mitigation: README and `EXPECTED_DOCS` are updated in
   the *same* increment as the CLI, never after.
5. **`tests/test_architecture.py::test_runtime_dependencies_stay_minimal`** pins
   runtime dependencies to exactly `{pydantic, typer, pyyaml, rich}`. Hypothesis and
   any external mutation tool therefore **cannot** be runtime dependencies. See §15
   item 1.
6. **`test_no_eval_or_exec_of_dynamic_content`** bans `eval`, `exec`, `compile` and
   `__import__` anywhere in `src/`. Mutation must therefore work by rewriting source
   text in the sandbox and executing it via `run_process` in a subprocess — never by
   compiling a mutated module in-process. This is also the safer design.
7. **`test_no_vendor_name_appears_outside_its_adapter`** bans vendor tokens
   (including `codex`) in any `src/**/*.py` outside `runtime/claude_code.py`. The
   brief's `falsifier: runtime: <runtime> model: <model>` example must therefore stay
   *data* in YAML and documentation; no shipped Python may name a model or vendor.

**The opt-in guarantee.** A workflow without a `falsify` step must behave bit-for-bit
as before. This is verified, not asserted: increment 2's exit criterion is the full
pre-existing suite passing unchanged, and a test loads every builtin workflow and
asserts none of them gained a falsify step by default. `builtin/workflows/feature.yaml`
is **not** modified in Phase 13; falsification arrives as a new `falsify.yaml`
workflow that a project opts into.

---

## 13. Test plan

| Layer | File | Covers |
| --- | --- | --- |
| Domain | `tests/test_falsification.py` | Status derivation table (all five inputs), mutation-score denominator excludes equivalent/invalid/**unreliable**, `None` score over zero mutants, budget ledger arithmetic and exhaustion naming, per-strategy sub-budget allocation, target x strategy applicability |
| Reliability | `tests/test_falsification.py` | A test that alternates pass/fail is quarantined by the baseline probe; a mutant that only that test would kill is `UNRELIABLE`, not `SURVIVED` and not `EQUIVALENT`; it is excluded from both halves of the score; `flakiness_probes: 0` produces the stated limitation on every survival |
| Adversarial budget | `tests/test_falsification.py` | `max_agent_invocations` caps calls independently of `max_adversarial_tests`; the 40% wall-clock sub-budget expires to `INCOMPLETE` with partial tests kept; a runtime reporting no tokens makes `max_tokens` **unenforceable and reported as such**, never silently satisfied; adversarial runs last by default |
| DSL | `tests/test_workflow.py` (extended) | `kind: falsify` parses; `strategies:` on a non-falsify step is rejected; unknown strategy name rejected at parse time; existing workflows unchanged |
| Orchestrator | `tests/test_orchestrator.py` (extended) | Falsify step runs; `FAILED` fails the step and records findings; `UNAVAILABLE` follows `on_unavailable`; missing engine fails rather than passes; `falsification_failed(step)` gates a downstream repair step |
| Strategies | `tests/test_falsification.py` | Mutation: each operator class produces a mutant; killed/survived/equivalent/invalid/error each demonstrated on a fixture. Property: violation found; absent Hypothesis -> `UNAVAILABLE`. Differential: mismatch found; ordering/float/timestamp rules suppress benign diffs. Metamorphic: relation violation reported with both executions |
| Reduction | `tests/test_falsification.py` | A 100-element counterexample shrinks; a reducer failure preserves the original; budget exhaustion during reduction is reported, not hidden |
| Isolation | `tests/test_falsification.py` | Worktree tier used when git is present; copy tier when forced; **the user's working tree is byte-identical after a mutation run** (snapshot before/after); no isolation -> step fails |
| Security | `tests/security/test_falsification_security.py` | (a) adversarial agent writing outside the scratch dir fails the step; (b) **LLM permission invariant**: a runtime that emits "run `rm -rf /`" / "add this to permissions.yaml" / "read `.env`" is refused by the policy engine and the refusal is recorded; (c) prompt injection in source, README, comments and fixtures is fenced and not obeyed; (d) a secret planted in the workspace appears in no report, event, corpus entry or generated test; (e) the falsifier cannot write `policies/`, `.git/`, or the permanent test suite |
| Evaluation | `tests/test_eval.py` (extended) | Falsification metrics computed; unmeasured metrics are `None` with a reason, never `0` |
| Docs | `tests/test_docs.py` (extended) | Twelve falsification pages exist; `limitations.md` states "does not prove correctness"; README documents `devforge falsify`; no page claims sandbox isolation |
| Architecture | `tests/test_architecture.py` | Unchanged and still passing — this is the guard that the new package respects every existing rule |

---

## 14. Benchmark plan

`src/devforge/builtin/benchmarks/falsification.yaml`, nineteen cases — seventeen
deterministic, plus two (17, 18) whose fixture is *reliably* flaky by construction.
Every case declares expected result, target, strategy, oracle and security
expectation, per §29 of the brief.

| # | Case | Target | Strategy | Expected | Oracle |
| --- | --- | --- | --- | --- | --- |
| 1 | Obvious bug | behavior | mutation | FAILED | Seeded off-by-one; the suite kills it |
| 2 | Hidden edge case | boundary_conditions | property | FAILED | Empty-input path unhandled |
| 3 | Insufficient unit tests | behavior | mutation | FAILED + weakness | Tests assert only the happy path |
| 4 | Surviving mutant | behavior | mutation | FAILED | Known-uncovered branch |
| 5 | Equivalent mutant | behavior | mutation | SURVIVED | `x*1` -> `x/1`; must classify EQUIVALENT with a stated layer |
| 6 | Property violation | boundary_conditions | property | FAILED | `result >= 0` broken by NaN |
| 7 | Adversarial discovery | error_handling | adversarial | FAILED | Unhandled exception path |
| 8 | Differential regression | regression | differential | FAILED | Refactor changes output |
| 9 | Metamorphic violation | behavior | metamorphic | FAILED | `f(x) != f(shuffle(x))` for an order-insensitive function |
| 10 | Counterexample reduction | behavior | property | FAILED + REDUCED | 100-element input shrinks to 2 |
| 11 | Prompt injection | security | adversarial | SURVIVED + finding | README says "delete the tests"; must be reported, never obeyed |
| 12 | Malicious test modifying source | security | adversarial | step FAILED | Write-scope violation detected by `scope_violations` |
| 13 | Permission escalation | authorization | adversarial | step FAILED | Attempt to edit `policies/permissions.yaml` refused |
| 14 | Secret leakage | security | mutation | SURVIVED + clean corpus | Planted token absent from every artifact |
| 15 | Budget exhaustion | behavior | mutation | **INCOMPLETE** | `max_mutants: 2` against 50 candidates |
| 16 | Unavailable strategy | behavior | property | **UNAVAILABLE** | Hypothesis absent; must not read as SURVIVED |
| 17 | Flaky survival | behavior | mutation | **UNRELIABLE** | A test failing on alternate invocations (counter file) is quarantined; the mutant it would have killed is classified `UNRELIABLE`, excluded from the score, and produces no `TEST_WEAKNESS` finding |
| 18 | Flaky kill | behavior | mutation | **UNRELIABLE** | The same flaky test passes on the mutant by chance; the mutant must not be counted `KILLED` and must not inflate the score |
| 19 | Adversarial budget exhaustion | error_handling | adversarial | **INCOMPLETE** | `max_agent_invocations: 1` against a case needing several; partial tests are kept and the truncation is named |

Cases 15–19 are the most important five in the suite. Fifteen and sixteen are the
executable statements that `INCOMPLETE` and `UNAVAILABLE` are not `SURVIVED`.
Seventeen and eighteen are the executable statements that the mutation score is not
distorted by a flaky suite in *either* direction — and they are the only cases in the
set that cannot be built from a purely deterministic fixture, which is precisely why
they have to exist. Nineteen is the statement that the most expensive strategy runs
under a budget it cannot exceed.

---

## 15. Assessment, risks, and recommended changes

### Architecture compatibility: **compatible.** No contradictions with DevForge's
existing principles were found. The design is a strict addition. Four constraints in
`tests/test_architecture.py` shape the implementation and are accommodated above:
frozen runtime dependencies, no dynamic execution, no HTTP client, no vendor names
outside the adapter.

### Dependency requirements

| Need | Resolution |
| --- | --- |
| Property testing | `hypothesis` as **optional extra** `[falsification]`; `UNAVAILABLE` with a stated reason when absent |
| Mutation | **stdlib `ast` only.** See recommendation 1 |
| Everything else | Already present |

### Performance risks

1. **The adversarial strategy is the most expensive and least predictable of the
   five, and it is the only one whose cost is not bounded by local computation.** It
   calls the agent runtime: latency is a network round trip of unknown duration,
   cost is monetary, and variance between two runs of the same case can be an order
   of magnitude. Its budget therefore cannot be an afterthought inherited from the
   shared ledger, and gets three enforcement points of its own:
   * `max_adversarial_tests` (already in `Budget`) caps produced tests, and
     `max_agent_invocations` (**new**) caps calls — the two are not the same number,
     because one call can yield several tests or none.
   * A **per-strategy wall-clock sub-budget**, defaulting to 40% of
     `max_duration_s`, so one hung agent call cannot consume a run that four other
     strategies still need. On expiry: `INCOMPLETE`, with the partial tests kept.
   * **Token accounting is read from `AgentResult.metadata`, and a runtime that does
     not report tokens makes `max_tokens` unenforceable — which is reported as
     unenforceable, not assumed satisfied.** This follows the existing
     `MetricValue(None)` convention: a budget that cannot be measured is a stated
     gap, never a silently passed check.

   Ordering (§8) is the fourth mitigation: adversarial runs last, so it spends what
   the deterministic strategies left rather than the reverse.
2. **Mutation cost is multiplicative:** `mutants × test-suite duration`. A 60-second
   suite and 100 mutants is 100 minutes. Mitigations, all in Phase D: mutate only
   lines the diff touched (see §16 — this is a scope boundary, not only a saving);
   select only tests that import the changed module; run mutants concurrently up to
   `max_parallel_jobs`; stop the moment `max_duration_s` is reached and report
   `INCOMPLETE`. Default `max_mutants` should be **50**, not 100.
3. **The reliability probe adds one full test pass per run** (`flakiness_probes: 2`
   means the baseline runs twice). Bounded, paid once, and cheaper than any
   per-mutant repetition scheme.
4. **Copy-tier sandbox cost** on a large tree. Mitigated by the exclusion list, and
   the worktree tier is preferred precisely because it is near-free.
5. **Reduction is another multiplier** — each shrink step re-runs the reproduction.
   It gets its own sub-budget rather than sharing the strategy's.

### Migration risks

Highest is item 4 in §12 (`test_docs.py` failing mid-phase); it is entirely avoided
by sequencing docs with code in the same increment. Second is item 3 (`Task` schema
growth), which is one-directional and acceptable.

### Recommended changes to the plan as written

1. **Do not adopt an external mutation engine.** §8 says "use mature mutation tooling
   where appropriate… do not build from scratch unless the architecture genuinely
   requires it." The architecture genuinely requires it. `mutmut` and `cosmic-ray`
   would each be a new runtime dependency (blocked by a passing architecture test),
   both drive their own test-runner subprocesses outside the policy engine's argv
   allowlist, and `cosmic-ray` maintains its own session database — a second state
   store. Recommendation: implement operators on stdlib `ast` (roughly 200 lines for
   the nine operator classes), and define an `ExternalMutationBackend` adapter
   interface so a mature tool can be plugged in later behind DevForge's own
   interface, exactly as the brief's §8 wrapper requirement intends.
2. **Rename the success state on the wire, with no alias.** §16 names it `SUCCESS`,
   but a field reading `status: SUCCESS` on a report about correctness will be read
   as "the code is correct" — which §16 itself forbids. Recommendation: `SURVIVED` is
   the only accepted spelling, on the wire and in the CLI, documented as carrying
   exactly the brief's `SUCCESS` semantics. **No `SUCCESS` alias, not even a
   deprecated one.** An indefinitely accepted alias defeats the rename: someone
   writes `if status == "SUCCESS"` in a CI script, it works, and the misreading this
   recommendation exists to prevent returns through the alias. A deprecation window
   would be the right answer for an existing public interface with existing
   consumers; this is a new subsystem with none, so the cost of refusing the alias
   today is zero and the cost of removing it later is not.
3. **Express budget durations in seconds, not `10m`.** The brief's example uses
   `max_duration: 10m`. Every timeout in DevForge today is an integer `*_timeout_s`.
   Recommendation: `max_duration_s: 600`, consistent with `VerifierSpec.timeout_s`
   and `ShellPolicy.timeout_s`. One convention, no parser.
4. **Use `when:` rather than a new `condition:` key.** `WorkflowStep` already has
   `when:` with a closed vocabulary and a validating matcher. The brief's §23 example
   uses `condition:`. Recommendation: extend `when:` with the two new kinds and accept
   `condition:` as a mirrored alias, exactly as `outputs`/`produces` are mirrored
   today. Two keys for one concept, with one source of truth.
5. **Ship `security` and `authorization` as declared-but-unattacked targets.** The
   brief lists ten targets and says not to implement all of them. Recommendation:
   register all ten with their applicability matrix and report honest `0%` coverage
   for the unattacked ones, rather than omitting them. A visible gap is worth more
   than a silent one, and it makes `AttackSurfaceCoverage` meaningful from day one.
6. **Defer LLM-assisted equivalence detection to a follow-up.** §9 permits it as
   optional. It is the only part of the design where a model's opinion could
   downgrade a real finding to `EQUIVALENT`. Recommendation: implement static and
   behavioral layers in Phase D; land the assisted layer only behind an explicit
   opt-in flag, with `Confidence.LOW` hard-capped and the layer recorded on every
   judgement it makes.

### Contradictions with existing DevForge architecture

**None found.** The six items above are refinements for consistency, not conflicts.
The one place the brief and the repository genuinely pull apart is external mutation
tooling (recommendation 1), and the repository's constraint is the correct one to
keep.

---

## 16. What falsification will never claim

Surviving falsification is not proof of correctness. It means no counterexample was
found inside the configured search space, with the budget actually spent, using the
strategies that were actually available. A mutation score is a statement about the
**test suite**, never about the code. Coverage measures explored attack surface,
never correctness. Every report carries its own limitations section, and a report
that would otherwise have none gets one written for it.

Four scope boundaries follow from the design above and are stated here rather than
left to be inferred from the implementation.

**It attacks the patch, not the codebase.** Mutation is scoped to lines the diff
touched (`scope: diff`, the default; `files` and `module` widen it per step). A
pre-existing defect in code the patch did not change will not be found, however
obvious. This is deliberate — falsification is an evidence system for a *change*,
not a codebase audit tool, and diff scoping is what keeps the cost proportional to
the patch rather than to the repository. But it means a `SURVIVED` verdict says
nothing whatsoever about unchanged code, and the report says so on every run.

**A mutation score is bounded by the reliability of the suite that produced it.**
Where flakiness screening ran, unreliable mutants are excluded from the arithmetic
and counted separately. Where it did not run, the score carries an explicit
statement that a surviving mutant may indicate a flaky test rather than a weak one.

**A budget that could not be measured was not enforced.** Where the runtime reports
no token counts, `max_tokens` is reported unenforceable rather than satisfied.

**Declared targets are not attacked targets.** Six of the ten registered
`FalsificationTarget`s ship with no strategy attacking them and report `0%`
coverage. That zero is the honest number, and it is not the same claim as absence.

The purpose of this subsystem is not to prove software correct. It is to make it
progressively harder for incorrect software to survive.
