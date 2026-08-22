# evals/

Evaluation *configurations* — the things being measured, as opposed to the cases
they are measured on, which live in `benchmarks/`.

A configuration names a driver and, when that driver is DevForge itself, the five
axes a comparison can vary:

```yaml
configs:
  - id: mock-minimal-skills
    driver: harness
    runtime: mock          # which agent runtime
    model: null            # which model, when the runtime takes one
    skills: [testing]      # which skills each step may use
    workflow: null         # override the workflow each case names
    context_strategy: none # 'none' or 'indexed'
```

Ids collide by design: a file here redefining `mock-baseline` replaces the shipped
one. `devforge eval configs` lists what actually applies.

## Comparing

```bash
devforge eval run mock-baseline
devforge eval run mock-indexed
devforge eval compare mock-baseline mock-indexed
```

Vary **one** axis per comparison. When two differ, the comparison prints how many
changed and says the difference cannot be attributed to either — it will not guess
which one mattered.

Nothing here declares a winner. `better` and `worse` mark the direction a number
moved; deciding which configuration to adopt means reading the cost, the latency
and the failures together, and that judgement is yours. The one exception is
regression: a case that passed and now fails is a reproducible fact, which is why
`--fail-on-regression` is the only condition that fails a build.

## Regression checking a DevForge change

```bash
devforge eval run mock-baseline --baseline mock-baseline
```

Runs the suite and compares it against the most recent saved report for the same
configuration. Same axes on both sides, so any difference is either a change you
made or run-to-run variation — and with ten cases, one case is worth ten percent,
which the report says every time it prints a rate.
