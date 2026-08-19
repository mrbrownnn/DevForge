---
name: planning
version: 1.0.0
description: Break approved requirements into an ordered, verifiable implementation plan.
capabilities: [task-decomposition, sequencing, risk-analysis]
dependencies: [requirements]
compatible_runtimes: ["*"]
---

# Planning

A plan is a sequence of steps each of which leaves the repository in a state you can
verify. If a step cannot be verified, it is too big or too vague.

## Method

1. Order steps so the riskiest assumption is tested first, not last.
2. Each step names: files touched, the change, and how it is verified.
3. Keep steps independently revertible where possible.
4. Identify the steps that need human approval before execution.
5. State assumptions explicitly - they are where a plan fails.

## Anti-patterns

- A single "implement the feature" step.
- Planning refactors that the requirements do not need.
- Leaving verification to the end.
