---
name: architecture
version: 2.0.0
description: Design components, interfaces and data flow for a change.
capabilities: [system-design, interface-design, trade-off-analysis, boundary-design]
dependencies: [planning]
compatible_runtimes: ["*"]
---

# Architecture

Design the smallest structure that satisfies the requirements and does not have to be
undone by the next change. Every structure you add is a constraint on everyone who
touches this code later; add it only when the requirements pay for it.

## Method

1. Read what already exists before proposing anything new. Reuse beats invention, and
   the existing shape is evidence about constraints you have not been told about.
2. Define interfaces first: inputs, outputs, **errors**, and who owns the data. The
   error cases are the half that gets skipped and the half that decides whether the
   design survives contact with production.
3. Push dependencies inwards: policy and decisions at the core, I/O at the edges. The
   test for this is whether the core logic can be exercised without a network, a clock,
   or a filesystem.
4. Draw the data flow end to end and mark every boundary where data is validated,
   transformed, or persisted. Data that crosses a boundary in two different shapes is
   a bug that has not happened yet.
5. Name the extension points, and be explicit about what is deliberately not built.
   "We do not support multi-region" is a design decision worth recording.
6. Record trade-offs: the alternatives you rejected, and the condition under which the
   rejected one would have been right. That condition is what a future reader needs.

## Choosing a boundary

Put a boundary where the two sides change for different reasons, or are owned by
different people, or need different failure semantics. Do not put one where the only
argument is symmetry or tidiness.

Cost of a boundary: an interface to keep in sync, a serialisation format, a failure
mode, and a place for state to diverge. Charge every proposed boundary that cost and
see whether it still pays.

## State and failure

- Name where each piece of state lives, and who is allowed to write it. Two writers to
  one piece of state is the design decision, not an implementation detail.
- For every remote call: what happens on timeout, on partial success, on retry. If the
  answer is "retry", say whether the operation is idempotent.
- Say what is consistent and what is eventually consistent, in the design, not in a
  comment discovered later.

## Anti-patterns

- Abstractions with exactly one implementation and no second one in sight.
- Distributed infrastructure for a problem that fits in one process.
- A layer whose only job is to forward calls.
- A "flexible" configuration surface built for requirements nobody has stated.
- Designing for a scale that is two orders of magnitude beyond the stated constraint.
- Deciding the database before the data shape.

## Done when

Interfaces name their errors; the core is testable without I/O; every boundary has a
reason and a stated cost; state ownership and failure semantics are written down; and
the rejected alternatives are recorded with the condition that would have chosen them.
