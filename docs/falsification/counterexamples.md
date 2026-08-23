# Counterexamples and reduction

A counterexample of 200 elements and one of 2 prove the same thing, and only one of
them can be read. Minimisation is what turns a finding into something actionable in
the time a person actually has.

## The reducer is a subsystem, not a strategy detail

Property, adversarial, differential and future fuzzing counterexamples all need the
same algorithm - delta debugging over a reproduction the strategy knows how to re-run.
Four copies would drift into four behaviours.

```
ReductionStatus: REDUCED | IRREDUCIBLE | UNAVAILABLE | BUDGET_EXHAUSTED | ERROR
```

## It never loses a counterexample

Every failure mode preserves the original: an unshrinkable input, an exhausted budget,
a predicate that raises. `Reduction` always carries `original`, and
`Counterexample.minimal_input` falls back to it. A reducer that discards evidence
because it could not simplify it is worse than no reducer.

## What a counterexample carries

`strategy`, `target`, `input`, `minimal_input`, `expected`, `actual`, `reproduction`
(an argv, never a shell string), `file`, `symbol`, `severity`, `evidence`,
`reduction`.

## The corpus

Every counterexample is filed under `.devforge/falsification/` so it outlives the run
directory:

```
.devforge/falsification/
    findings/<finding_id>.json
    counterexamples/<finding_id>.json
    mutants/<run_id>.jsonl
    corpus/<finding_id>/
```

The corpus stores an argv, the input, the expected and actual behaviour, the file and
the symbol. It never stores an environment snapshot and never file contents from a
denied path - a corpus that accumulates secrets over months is a worse liability than
the bugs it records. Everything passes `redact_value` on write.

## Regression tests

```
counterexample -> reproduction -> regression test -> repair -> permanent suite
```

`devforge falsify explain <finding-id> --regression` prints a test reproducing the
finding. It produces test *source*; it does not install it. Where the counterexample
records what happened but not what should have happened - which is most of the time,
because the reason the bug exists is that nobody stated the expectation - the
generated test carries an explicit failing assertion rather than a plausible-looking
one. A regression test that passes without checking anything is worse than no test.
