---
name: requirements
version: 2.0.0
description: Turn a vague request into explicit, verifiable requirements.
capabilities: [requirements-analysis, scope-definition, acceptance-criteria]
dependencies: []
compatible_runtimes: ["*"]
---

# Requirements

A requirement that cannot be checked is a wish. Write each one so a verifier - a test,
a command, or a human reading a screen - can decide pass or fail without asking you
what you meant.

## Method

1. Restate the request in your own words, in one sentence. If the restatement changes
   its meaning, the request was ambiguous: record the ambiguity rather than guessing
   silently. Guessing is the single largest source of rework.
2. Separate the request from its justification. "Add a cache" is a proposed solution;
   "the dashboard must load in under 400ms" is the requirement. Work at the level of
   the requirement, and note the proposed solution as an input to design, not as scope.
3. Split into functional requirements (observable behaviour) and constraints
   (performance, security, compatibility, budget, deadline).
4. For each functional requirement, write the acceptance check next to it, before
   moving on. If you cannot write the check, the requirement is not yet a requirement.
5. State what is explicitly out of scope. This is the sentence that stops scope creep
   three days later.
6. List open questions, split into blocking (work cannot start) and non-blocking
   (work can start under a stated assumption). Assumptions get written down as
   assumptions, not silently promoted to facts.

## Writing an acceptance check

A good check names the observation, not the implementation:

- Bad: "the `UserCache` class is used." Implementation, and it can pass while broken.
- Good: "a second request for the same user within 60s issues no database query."

Choose the cheapest verifier that can actually decide: a unit test beats an
integration test beats a manual screen check. Pick a manual check only when nothing
automatable can observe the behaviour, and say so explicitly.

## Quantifying a constraint

"Should be fast", "must be secure", "handle a lot of traffic" are unmeasurable and
therefore unverifiable. Convert each to a number and a condition, or drop it:

- fast -> p95 latency under Xms at Y concurrent requests
- a lot of traffic -> N requests/second sustained, M peak
- secure -> names the threat: "an authenticated user cannot read another tenant's rows"

If you do not know the number, that is a blocking open question, not a licence to
invent one.

## Output shape

- **R1..Rn** functional requirements, each with its acceptance check.
- **C1..Cn** constraints, each with a number or a named condition.
- **Out of scope** - what this change deliberately does not do.
- **Assumptions** - what you decided in the absence of an answer.
- **Open questions** - blocking / non-blocking.

## Anti-patterns

- Inventing requirements the user never asked for, then implementing them.
- "Should be fast" - unmeasurable. Give a number or drop it.
- Hiding a design decision inside a requirement ("use Redis for the session store").
- Folding the acceptance check into the requirement text so vaguely that any outcome
  satisfies it ("works correctly").
- Marking a question non-blocking because you would rather start coding.

## Done when

Every functional requirement has a check a machine or a named human can run; every
constraint has a number; scope, assumptions and open questions are written down; and
no blocking question is still open.
