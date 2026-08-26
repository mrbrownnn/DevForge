# Mutation testing

**The question is about the test suite, not the code.** A mutant that survives means
a realistic fault could be introduced at that line without any test noticing. That
is a gap in the checks. It is not, by itself, a defect in the implementation.

```
diff -> candidates -> mutate in the sandbox -> run tests
     -> killed / survived -> classify survivors -> report
```

## Operators

Nine, all AST-based and Python-specific:

| Operator | Example |
| --- | --- |
| `arithmetic_replacement` | `a * b` -> `a // b` |
| `comparison_replacement` | `a == b` -> `a != b` |
| `boundary_mutation` | `a > b` -> `a >= b` |
| `boolean_replacement` | `a and b` -> `a or b` |
| `conditional_negation` | `if x:` -> `if not (x):` |
| `return_value_mutation` | `return x * y` -> `return None` |
| `constant_replacement` | `0.5` -> `1.5` |
| `branch_mutation` | `if cond:` -> `if True:` |
| `exception_path_mutation` | `raise ValueError(...)` -> `pass` |

## Why not mutmut or cosmic-ray

Both are mature and both were rejected, for reasons specific to this codebase: each
would be a new runtime dependency in a tree whose dependency list is pinned by a
passing architecture test; both drive their own test-runner subprocesses outside the
policy engine's argv allowlist; and one maintains its own session database, which
would be a second state store. The operators are therefore in-tree, and
`MutationStrategy` is written so an external backend can be plugged in behind
DevForge's own interface later.

Nothing here calls `compile` or `exec`. Mutants are written as source text and run in
a subprocess - required by `tests/test_architecture.py`, and the safer design
regardless.

## Classification

| Status | Meaning | In the score |
| --- | --- | --- |
| `KILLED` | A reliable test failed on the mutant | numerator and denominator |
| `SURVIVED` | Every reliable test passed | denominator only |
| `EQUIVALENT` | Behaviourally identical, per a named layer | neither |
| `UNRELIABLE` | The verdict depended on a quarantined flaky test | neither |
| `INVALID` | Does not compile, or is not a realistic fault | neither |
| `ERROR` | Could not be evaluated | neither |

## Equivalent mutants

Three layers, tried in order, each recording which one decided and how sure it was:
`static` (AST reasoning about identity operations and unreachable code), `behavioral`
(identical observable output), `assisted` (a model's opinion, off by default and
capped at `LOW` confidence).

A mutant no layer can classify **stays `SURVIVED`**. Promotion to `EQUIVALENT` on
uncertainty is how a real weakness disappears from a report, and it is the most
dangerous shortcut available here.

The static identity rule is deliberately narrow. `x * 1` and `x // 1` agree for
integers and for nothing else - `2.5 * 1` is `2.5` where `2.5 // 1` is `2.0`, and
`"ab" // 1` raises - so the rule fires only where the left operand is *statically*
an integer (`len(...)`, an int literal, integer arithmetic over those). `/` is never
an identity: it returns a float where `*` returns an int, and overflows on integers
that `*` handles. The rule also has to be looking at the operator that was actually
mutated, not merely one on the same line.

## Concurrency

`max_parallel_jobs` mutants are evaluated at once, each in its **own copy of the
sandbox**. A mutant is judged by running the whole suite, so two mutants in one
directory are judged by one run: whichever fault it reports gets recorded against
both, and a mutant in an untested file is credited as killed by a fault injected
somewhere else. Copies cost one per worker, not one per mutant. When fewer can be
created the pool runs narrower and the report says so.

## Scope

Mutation is confined to the lines the patch touched (`scope: diff`, the default).
`files` widens it to whole changed files; `module` to their modules. This is a scope
boundary, not only a cost control - see `limitations.md`.

## Reliability

Before any mutant is generated, the suite runs `flakiness_probes` times (default 2)
against unmutated code. Tests that disagree between identical runs are quarantined,
and any mutant whose verdict rests on one becomes `UNRELIABLE`. See `metrics.md` for
why this matters in both directions.
