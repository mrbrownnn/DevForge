# Metrics

Every number here measures a search. None of them measures correctness.

## Mutation score

```
                     killed mutants
    ---------------------------------------------------
    valid, non-equivalent, reliably-judged mutants
```

Excluded from **both** halves: `EQUIVALENT`, `UNRELIABLE`, `INVALID`, `ERROR`.

Reported as: *"94% of valid generated mutants were detected by the test suite."*
Never as *"94% correct"*. A score over zero mutants is `None` - the absence of a
measurement, never `1.0`.

## Attack surface coverage

Per target: attacked strategies over applicable strategies.

```
behavior             100%
boundary_conditions  100%
error_handling       100%
regression           n/a
security             n/a
authorization        n/a
```

Six targets ship with no strategy that can attack them and report `n/a` or 0%. That
zero is the honest number, and it is not the same claim as absence of defects.
Coverage measures explored attack surface, never correctness.

## Strategy coverage

Requested, executed, and unavailable-with-a-reason. A strategy that could not run is
always accompanied by why.

## Confidence

`NONE`, `LOW`, `MODERATE`, `HIGH`. It answers *how hard did we look?* - never *how
likely is the code correct?* A falsified run is always `NONE`: a counterexample
exists. Confidence is capped at `LOW` when the budget was exhausted, when mutants
survived, or when the suite's reliability was never screened.

## Why flakiness screening changes the arithmetic

A flaky test distorts the score in both directions:

```
flaky test passes on the mutant -> SURVIVED -> score understated,
                                               a false TEST_WEAKNESS finding
flaky test fails on the mutant  -> KILLED   -> score overstated,
                                               a real weakness hidden
```

No deterministic fixture can catch either case, which is why it is screened explicitly
rather than left to the benchmark suite. Where screening is disabled
(`flakiness_probes: 0`), every survival carries the stated limitation.

## Post-repair falsification survival

The lifecycle metric that matters most:

```
initial patch -> falsify -> repair -> falsify again
```

Whether a repair actually removed the counterexample or merely moved it. The built-in
`falsify` workflow runs exactly this loop with its `re-falsify` step.
