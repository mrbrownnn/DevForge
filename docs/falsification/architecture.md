# Falsification architecture

Verification asks *do the declared checks pass?* Falsification asks *can I find a
counterexample?* They are independent evidence sources reporting to the same
orchestrator, and neither of them is correctness.

```
patch --+--> VerificationEngine --> evidence FOR ----+
        |                                            +--> orchestrator --> decision
        +--> FalsificationEngine -> evidence AGAINST +
```

## Why a step kind and not a verifier

A `Verifier` returns one `VerificationResult`: status, exit code, summary, excerpt.
A falsification run produces mutants, counterexamples, minimised forms, per-target
coverage, per-strategy budget usage and an equivalence classification. None of that
survives a single result record, and forcing it through one would leave the repair
loop with nothing actionable. So `falsify` is a fourth `StepKind`, and
`FalsificationEngine` sits beside `VerificationEngine` at the same level.

## The run

```
resolve targets      validated against the target registry
resolve strategies   filtered by the target x strategy applicability matrix
acquire sandbox      worktree -> copy -> refuse
reliability probe    quarantine flaky tests before anything is judged
for each strategy    cheapest and most deterministic first, each under a sub-budget
coverage             per target and per strategy
settle               derive status and confidence, write the limitations
persist              run report, then the cross-run corpus
release sandbox
```

Two ordering decisions are load-bearing.

**Strategies run cheapest-first.** Budget exhaustion truncates whatever is running,
so this order means a truncated run loses the least reproducible evidence rather
than the most. An expensive agent call should never consume the budget mutation
testing needed.

**The reliability probe runs before any mutation.** A verdict from a suite whose
flakiness nobody has measured is not a verdict.

## Module map

| Module | Responsibility |
| --- | --- |
| `models.py` | Reports, mutants, counterexamples, budgets, coverage, statuses |
| `engine.py` | Selection, sequencing, budget enforcement, coverage, settlement |
| `targets.py` | The ten targets and the applicability matrix |
| `sandbox.py` | Isolation tiers and the write-scope guard |
| `reliability.py` | Flaky-test screening and quarantine |
| `equivalence.py` | Layered equivalent-mutant detection |
| `reduction.py` | Counterexample minimisation |
| `mutation_operators.py` | Nine AST operators, stdlib only |
| `patch.py` | Reading the diff and the lines it touches |
| `testrun.py` | The single policy-checked door to the test runner |
| `coverage.py` | Attack-surface and strategy coverage, shape and computation |
| `store.py` | Per-run report persistence |
| `corpus.py` | The cross-run corpus of findings and counterexamples |
| `metrics.py` | Falsification metrics for the evaluation framework |
| `regression.py` | Counterexample to permanent regression test |
| `strategies/` | The five attack strategies plus the interface |

## What the orchestrator does with the report

The engine returns a report. The orchestrator decides what it means, because "a
counterexample exists" and "this step fails" are different judgements and only the
second belongs to the workflow. See `limitations.md` for the mapping, and for what a
survival does not license.

## Observability

Fourteen events, emitted through the existing `RunLogger` - there is no second
logging system:

```
falsification.started            falsification.strategy.started
falsification.strategy.completed falsification.completed
mutation.generated               mutation.killed
mutation.survived                mutation.equivalent
property.started                 property.counterexample
adversarial.test.generated       adversarial.counterexample
differential.mismatch            counterexample.reduced
```

Plus ones specific to this subsystem's own honesty: `mutation.unreliable`,
`falsification.reliability.probe`, `falsification.reliability.quarantine`,
`falsification.scope_violation`, `falsification.injection_detected`,
`falsification.budget_exhausted`, `metamorphic.violation`.

## Benchmarks

`builtin/benchmarks/falsification.yaml` holds twenty cases, each declaring an
expected result, a target, a strategy, an oracle and a security expectation.
`tests/test_falsification_benchmarks.py` executes the oracles rather than asserting
about them.

The five that matter most are `budget-exhaustion`, `unavailable-strategy`,
`flaky-survival`, `flaky-kill` and `adversarial-budget`. The first two are the
executable statements that `INCOMPLETE` and `UNAVAILABLE` are not `SURVIVED`; the
next two are the only cases in the set that cannot be built from a deterministic
fixture, which is exactly why they exist.
