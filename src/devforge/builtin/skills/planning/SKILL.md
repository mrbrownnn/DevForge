---
name: planning
version: 2.0.0
description: Break approved requirements into an ordered, verifiable implementation plan.
capabilities: [task-decomposition, sequencing, risk-analysis, verification-design]
dependencies: [requirements]
compatible_runtimes: ["*"]
---

# Planning

A plan is a sequence of steps, each of which leaves the repository in a state you can
verify. If a step cannot be verified, it is too big or too vague - split it or sharpen
it until it can be.

## Method

1. Map each requirement to the steps that satisfy it. A requirement with no step is
   unplanned work; a step serving no requirement is scope you invented.
2. Order by risk, not by comfort. The riskiest assumption - the unfamiliar API, the
   schema migration, the third-party rate limit - is tested in the first step that can
   test it. Discovering it last means replanning everything.
3. For each step write four fields: **files touched**, **the change**, **how it is
   verified**, **how it is reverted**. A step missing the third field is not a step.
4. Size a step so it stays revertible: one concern, one commit, a green suite at the
   end. If reverting it would require untangling it from a later step, it is two steps
   in the wrong order.
5. Mark the steps that need human approval before execution: schema changes, data
   migrations, anything outward-facing, anything deleting data, anything touching
   credentials or CI configuration.
6. State assumptions explicitly next to the step that depends on them. Assumptions are
   where plans fail, and an assumption written down is one that can be checked cheaply
   before it costs a day.

## Sequencing rules

- Interfaces and data shapes before the code on either side of them.
- Read paths before write paths; the write path is where mistakes are expensive.
- A migration lands and is verified in its own step, never bundled with the feature
  that needs it.
- Behaviour-preserving refactors go in their own steps, before or after the change,
  never inside it - a mixed diff cannot be reviewed.
- Anything reversible before anything irreversible.

## Sizing heuristic

If a step's description needs the word "and" to join two unrelated verbs, it is two
steps. If its verification is "the whole suite passes", it is too coarse: name the
test that would not pass without this step.

## Anti-patterns

- A single "implement the feature" step.
- Planning refactors the requirements do not need, on the way past.
- Leaving verification to the end, so nothing is known until everything is done.
- Steps whose only ordering rationale is the order you thought of them.
- A plan that assumes every step succeeds. Name what you do when the risky one fails.

## Done when

Every requirement maps to at least one step; every step names files, change,
verification and revert; risky steps come first; approval gates are marked; and the
plan says what happens if the riskiest step fails.
