# Property-based testing

Where mutation asks whether the tests notice a fault, this asks whether the code
holds a stated invariant across inputs nobody thought to write down.

```
declared property -> generated inputs -> execute -> shrink -> counterexample
```

## Declaring a property

```yaml
- id: falsify
  kind: falsify
  strategies: [property]
  falsify:
    property:
      properties:
        - id: non-negative-total
          module: billing
          call: total
          args: [ints, small_ints]
          invariant: result >= 0
          examples: 200
          severity: high
```

Invariants are **declared, never inferred**. A guessed invariant that does not hold
produces counterexamples against a claim the author never made, and a report full of
those is one nobody reads.

## Argument shapes

`ints`, `small_ints`, `floats`, `any_floats`, `text`, `ascii_text`, `lists_of_ints`,
`lists_of_text`, `booleans`, `dicts`. Named shapes rather than expressions, so a
workflow file stays data - the same reasoning that keeps `eval` out of conditions.
`module` and `call` must be plain dotted identifiers; anything else is refused before
a line of code is generated.

## Hypothesis is optional

It cannot be a runtime dependency, so when it is absent the strategy reports
`UNAVAILABLE` with the reason and the run records the gap. It never degrades to a
weaker search and calls the result a survival.

```
pip install "devforge[falsification]"
```

## Isolation

Generated property modules are written into the sandbox scratch directory and
executed there. Nothing is written to the project's permanent test suite.
