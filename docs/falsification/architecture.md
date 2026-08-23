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
| `store.py` | Per-run reports and the cross-run corpus |
| `regression.py` | Counterexample to permanent regression test |
| `strategies/` | The five attack strategies plus the interface |

## What the orchestrator does with the report

The engine returns a report. The orchestrator decides what it means, because "a
counterexample exists" and "this step fails" are different judgements and only the
second belongs to the workflow. See `limitations.md` for the mapping, and for what a
survival does not license.
