# Evaluation and benchmarking

Every other part of DevForge makes it do something. This part asks whether that
worked, on cases with known answers, and writes the answer down where it can be
compared against another configuration or against yesterday.

```bash
devforge eval cases                          # what will be run
devforge eval configs                        # what can run it
devforge eval run mock-baseline              # measure a configuration
devforge eval run mock-baseline --baseline mock-baseline   # regression check
devforge eval compare mock-baseline mock-indexed
devforge eval report                         # render the newest as Markdown
```

Exit codes: `0` when the run completed and nothing regressed; `1` on a regression
against the named baseline, on a broken benchmark, or on a calibration anchor that
scored what it must not. **A low success rate is not an error.** It is a
measurement, and a command that fails the build for it teaches people to stop
running it.

## The grader is calibrated, and that is the load-bearing part

A benchmark's grader is the component nobody checks and everybody trusts. Three of
the shipped configurations are not agents at all — they exist to hold it to
account:

| configuration | what it does | required score |
| --- | --- | --- |
| `reference` | applies each case's known-good solution | **100%** |
| `cheat` | deletes assertions until the checks stop objecting | **0%** |
| `none` | changes nothing | **0%** |

`tests/test_eval.py` asserts all three, and `devforge eval run` fails when an
anchor scores wrong, because a grader that is off makes every other number in the
report unreadable rather than merely wrong.

The `cheat` anchor is the interesting one. It **succeeds** at making the checks
pass — the report shows cases with every check green — and scores zero anyway,
because the patch guard reads the diff before success is considered. A benchmark
without that ordering scores an agent higher the more dishonest it is, and would
have recorded those same runs as wins.

## What a case is

A workspace, a task description, and commands that decide whether the task was
done. Nothing grades by reading an agent's account of its own work.

```yaml
- id: feature-slugify
  category: feature
  description: Implement slugify() in app/text.py so that…   # the agent's task
  files: {…}          # the starting workspace
  solution: {…}       # the known answer; only `reference` applies it
  guards:             # must pass BEFORE the attempt and still pass after
    - {id: existing-behaviour, argv: [python, -m, pytest, -q, tests/test_existing.py]}
  checks:             # decide success
    - {id: suite, argv: [python, -m, pytest, -q]}
```

Three outcomes are deliberately not failures:

* **`unavailable`** — a required capability is absent (the website case needs a
  browser). Excluded from every denominator and listed with the reason. Scoring it
  zero would blame the configuration for the environment.
* **`invalid`** — a guard was already failing before anything was attempted. The
  benchmark is broken, not the configuration, and the command exits 1.
* **`rejected_suspicious`** — the patch guard found a cheating pattern. A refusal,
  not a miss.

Checks run through the project's **policy engine**. `python -m pytest` is allowed;
`python some_script.py` is not. A benchmark case is data, and data does not get to
widen the policy it runs under — the mutation grader in `testing.yaml` is written
as a pytest module for exactly this reason.

## Categories

Eight, one suite file each, all shipped inside the package so `devforge eval run`
works in a directory that has never seen DevForge.

| category | what it measures | how it is graded |
| --- | --- | --- |
| feature | building something that is not there | a failing test the case ships |
| bugfix | repairing a defect | the failing test, plus a guard on the neighbours |
| refactor | changing shape without changing behaviour | behaviour guard **and** an AST check that the duplication is gone |
| testing | writing tests that catch real defects | mutation: three deliberate defects, all must be caught |
| frontend | producing markup with the required structure | parsed with `html.parser`, not pattern-matched |
| website | reproducing a page | element skeleton and visible text; needs a browser |
| security | removing a vulnerability | the attack must stop working **and** the construct must be gone |
| documentation | documenting the public surface | the page is checked against the module with `ast` |

Two of these deserve a note. A refactor graded only on "the tests still pass" is
also satisfied by doing nothing, which is why the structural check exists. And a
testing case graded on "a test file appeared" measures nothing at all, which is
why that one mutates the source and requires the suite to notice.

## The twelve metrics

All twelve the brief names are produced on every run. What varies is whether they
can be measured:

| metric | notes |
| --- | --- |
| task success rate | successes over *attempted* cases |
| first-pass success | succeeded with no step retried |
| repair success | of the cases that needed a retry, how many recovered |
| verification pass rate | over verifier results, from the task record |
| regression rate | a guard that passed before the attempt and failed after |
| average iterations | attempts per step; 1.0 means nothing was retried |
| token usage | only when the runtime reports counts |
| cost | only when the runtime reports cost |
| latency | wall clock per case, grading included |
| human intervention rate | approval gates reached |
| security violations | denied tool calls and suspicious-patch findings |
| tool failures | tool calls that errored |

**`unknown` is never `0`.** Zero is a measurement; a runtime that reports no token
counts has produced no measurement, and a report that renders that as `0 tokens`
has invented one. The mock runtime reports neither tokens nor cost, so those two
read `unknown` with the reason attached, and a comparison leaves them unknown on
both sides rather than manufacturing an improvement.

Two figures come from answering approval gates automatically. An evaluation cannot
wait for a human, and stopping at the first gate would measure nothing — so gates
are answered yes and **counted**, and the count is reported as the human
intervention rate. An unattended number never implies an unattended process.

## Comparing configurations

Five axes: runtime, model, skill set, workflow, context strategy. All five are
recorded verbatim in every report, so a comparison says exactly what differed
rather than inferring it.

The interventions are real. Restricting the skill set actually narrows every
step's skill list before the run; `context_strategy: indexed` actually builds the
retrieval index. A configuration that merely *labelled* itself would produce two
identical runs and attribute the difference to the label.

```bash
devforge eval run mock-baseline
devforge eval run mock-indexed
devforge eval compare mock-baseline mock-indexed
```

**No conclusion is computed.** `better` and `worse` mark the direction a number
moved, nothing more. There is no composite score, no significance test — with ten
cases there is no significance to test — and no recommendation. When more than one
axis differs, the comparison says so and states that the difference cannot be
attributed to either.

Asking a runtime for a model it does not take is reported as *not honoured* rather
than dropped. Otherwise two identical runs get labelled a model comparison.

## Regression checking a DevForge change

```bash
devforge eval run mock-baseline --baseline mock-baseline
```

Same configuration on both sides, compared against its most recent saved report.
A case that passed and now fails exits 1. That is the one thing here allowed to
fail a build, because it is a reproducible fact about a specific case rather than
an inference about quality.

The mock runtime is the right thing to regression-check the harness with: free,
deterministic, and reachable in CI. It does not solve cases — it exercises the
pipeline, which is what a harness change can break.

## What none of this establishes

**The cases are small and have known answers.** Real defects in real codebases are
neither. A success rate here does not transfer to them, and the report says so
every time it prints one.

**A difference between two configurations is not established by one run.** Ten
cases means one case is worth ten percent. Nothing separates a genuine improvement
from run-to-run variation at that size, and no amount of formatting will.

**Code quality is not measured.** Whether a change is maintainable, or whether a
reviewer would accept it, is not something an exit code knows. What is measured is
whether the declared checks passed.

**A runtime that runs its own tools is partly invisible.** An external CLI runtime
executes tools inside its turn, so DevForge's policy engine never sees those calls.
The tool-failure and security-violation figures for such a configuration are lower
bounds, not totals — the configuration's own notes say so, and they are printed
with the report.
