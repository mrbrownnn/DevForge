# Differential testing

For refactors, rewrites, migrations and optimisations, where the specification is
*whatever the previous version did*.

```
input --+-- old --> A
        +-- new --> B      A != B  ->  DIFFERENTIAL_MISMATCH
```

## Configuration

```yaml
falsify:
  differential:
    command: [python, scripts/run.py]
    baseline_ref: HEAD~1        # or baseline_dir: ../previous
    cases:
      - {id: small, args: ["--input", "small.json"]}
      - {id: large, args: ["--input", "large.json"]}
    equivalence:
      float_tolerance: 1.0e-9
      ignore_ordering: true
      ignore_timestamps: true
      ignore_generated_ids: true
      ignore_fields: [request_id, duration_ms]
```

## Not every difference is a defect

Timestamps differ. Generated identifiers differ. Ordering differs. Floating-point
arithmetic differs in the last place. Treating all of those as regressions is what
makes naive differential testing useless on real systems.

So equivalence is configurable - and **every rule that fires is recorded**. A
suppressed difference is reported as suppressed, never silently dropped, because a
rule quietly hiding a real regression is worse than no rule at all. The report says
how many differences the rules absorbed.

## Baselines and isolation

`baseline_ref` needs version-control history, which only the worktree sandbox
carries. Under the copy sandbox the strategy reports `UNAVAILABLE` and says to
configure `baseline_dir` instead, rather than comparing against nothing.
