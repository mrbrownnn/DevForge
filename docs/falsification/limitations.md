# Limitations

**Falsification does not prove correctness.** It is a systematic adversarial search
for counterexamples within a defined search space and budget. Surviving it means no
counterexample was found with the strategies that were available and the budget that
was actually spent. That is all it means.

Every report carries its own limitations section, and a report that would otherwise
have none gets one written for it. There is no configuration in which this subsystem
reports a clean survival with nothing qualifying it.

## Status semantics

| Status | Meaning | Never means |
| --- | --- | --- |
| `FAILED` | At least one valid counterexample was found | The subsystem malfunctioned |
| `SURVIVED` | Ran to completion in the configured space, found nothing | The code is correct |
| `INCOMPLETE` | Started, could not fully explore: budget, timeout, partial run | Success |
| `UNAVAILABLE` | Could not execute: dependency missing, no isolation | Success, or a skip to ignore |
| `ERROR` | The subsystem itself broke | Anything about the code under test |

**`UNAVAILABLE` and `INCOMPLETE` never collapse into `SURVIVED`.** There is no
`SUCCESS` state anywhere in the vocabulary and no alias for one: a field reading
`status: SUCCESS` on a report about correctness gets read as "the code is correct",
and no amount of documentation undoes that.

In the orchestrator, `INCOMPLETE` fails the step by default (`on_incomplete: fail`)
because silently passing an unfinished search is the exact failure mode this exists to
prevent. `UNAVAILABLE` continues by default with the gap recorded, so a project
without Hypothesis installed can still run its workflows.

## The four scope boundaries

**It attacks the patch, not the codebase.** Mutation is scoped to lines the diff
touched. A pre-existing defect in unchanged code will not be found, however obvious.
This is deliberate - falsification is an evidence system for a *change*, not a
codebase audit tool - but a `SURVIVED` verdict says nothing about unchanged code.

**A mutation score is bounded by the reliability of the suite that produced it.**
Where flakiness screening ran, unreliable mutants are excluded and counted separately.
Where it did not, the score carries an explicit statement that a surviving mutant may
indicate a flaky test rather than a weak one.

**A budget that could not be measured was not enforced.** Where the runtime reports no
token counts, `max_tokens` is reported unenforceable rather than satisfied.

**Declared targets are not attacked targets.** Six of the ten registered targets ship
with no strategy attacking them and report 0% coverage. That zero is honest, and it is
not the same claim as absence.

## Other known limits

* **Python only** for mutation, property and metamorphic generation. Other languages
  report `UNAVAILABLE`.
* **Invariants and relations are declared, never inferred.** A guessed property
  produces counterexamples against a claim nobody made.
* **Related-test attribution is textual.** The `relevant_tests` list on a weakness is
  a heuristic, not coverage attribution.
* **The copy sandbox has no version-control history**, so `baseline_ref` differential
  runs are unavailable under it.
* **Equivalence detection is incomplete** by nature - the general problem is
  undecidable. Anything the layers cannot decide stays `SURVIVED` rather than being
  promoted, which errs toward reporting a weakness that is not one.
* **The assisted equivalence layer is off by default.** It is the only place where a
  model's opinion could downgrade a genuine finding, so it requires an explicit opt-in
  and is hard-capped at `LOW` confidence.

## The purpose

Not to prove software correct. To make it progressively harder for incorrect software
to survive.
