# Metamorphic testing

Often nobody can say what the right answer *is*, but everybody can say how two
answers must relate.

```
f(x) == f(shuffle(x))
len(f(x + [e])) >= len(f(x))
e in f(x + [e])
```

That relation is the oracle. It holds without anyone writing down an expected value,
which makes this the strategy for code whose correct output is expensive or
impossible to state directly.

## Configuration

```yaml
falsify:
  metamorphic:
    relations:
      - id: order-insensitive
        module: search
        call: rank
        input: [3, 1, 2]
        transformation: shuffle
        relation: equal
      - id: growth
        module: search
        call: rank
        input: [1, 2]
        append: 3
        transformation: append
        relation: monotonic
```

**Transformations**: `shuffle`, `reverse`, `duplicate`, `append`, `negate`, `scale`,
`identity`.

**Relations**: `equal`, `not_equal`, `same_length`, `subset`, `monotonic`,
`contains_appended`.

Both are named shapes rather than expressions, for the same reason as everywhere else
in this subsystem: a workflow file is data, and data that becomes code is an injection
surface.

## Output

A violation reports the transformation, the original result, the transformed result,
the expected relation and the actual one - enough for someone to see which of the two
executions was wrong.
