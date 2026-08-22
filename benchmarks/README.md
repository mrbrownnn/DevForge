# benchmarks/

Benchmark cases belonging to *this* repository.

DevForge ships eight category suites inside the package, so `devforge eval run`
works in a directory that has never seen DevForge. Anything here is added on top,
and a file whose **name** matches a shipped one replaces it rather than merging
with it — half a suite from each source is a benchmark nobody can reason about.

```bash
devforge eval cases                 # everything that applies here
devforge eval run reference         # the grader's upper anchor: must score 100%
devforge eval run cheat             # the adversarial anchor: must score 0%
```

## Writing a case

A case is a workspace with a known answer and commands that decide whether it was
reached:

| field | what it is |
| --- | --- |
| `files` | the starting workspace, written verbatim |
| `description` | the task text an agent is given — the same words you would type after `--task` |
| `solution` | the known-good answer. Only the `reference` driver applies it; no agent ever sees it |
| `checks` | argv vectors that must exit as declared. These decide success |
| `guards` | checks that must pass **before** the attempt and still pass after. A guard that breaks is a regression |
| `requires` | capabilities the case cannot run without. Missing ones make it *unavailable*, never *failed* |

Two rules make a case worth having:

**Every check is a command.** Nothing grades by reading an agent's account of what
it did. If a requirement cannot be expressed as an exit code, express it as a test
file the case ships and run pytest over it — that is what the frontend,
documentation and refactor suites do.

**A guard covers behaviour that already works.** Not the requirement — the
neighbours. A guard that fails before the attempt makes the case *invalid* rather
than failed, and `devforge eval run` exits 1, because a broken benchmark corrupts
every number in the report and must not be mistaken for a bad configuration.

Checks run through the project's policy engine. `python -m pytest` is allowed;
`python some_script.py` is not, and a case does not get to widen the policy it
runs under — see `testing.yaml` for how a mutation grader is written as a pytest
module for exactly that reason.
