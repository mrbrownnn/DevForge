---
name: requirements
version: 1.0.0
description: Turn a vague request into explicit, verifiable requirements.
capabilities: [requirements-analysis, scope-definition]
dependencies: []
compatible_runtimes: ["*"]
---

# Requirements

A requirement that cannot be checked is a wish. Write each one so a verifier - a test,
a command, or a human reading a screen - can decide pass or fail.

## Method

1. Restate the request in your own words. If your restatement changes its meaning, the
   request was ambiguous: record the ambiguity instead of guessing silently.
2. Split into functional requirements (observable behaviour) and constraints
   (performance, security, compatibility, budget).
3. For each functional requirement write the acceptance check next to it.
4. State what is explicitly out of scope. This is what stops scope creep later.
5. List blocking open questions separately from non-blocking ones.

## Output shape

- R1..Rn functional requirements, each with an acceptance check.
- C1..Cn constraints.
- Out of scope.
- Open questions (blocking / non-blocking).

## Anti-patterns

- Inventing requirements the user never asked for.
- "Should be fast" - unmeasurable. Give a number or drop it.
- Hiding a design decision inside a requirement.
