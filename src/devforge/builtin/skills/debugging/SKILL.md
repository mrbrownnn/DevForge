---
name: debugging
version: 1.0.0
description: Find the root cause of a failure from evidence.
capabilities: [root-cause-analysis, reproduction, diagnostics]
dependencies: []
compatible_runtimes: ["*"]
---

# Debugging

## Method

1. Reproduce first. A bug you cannot reproduce, you cannot claim to have fixed.
2. Read the actual error text and the failing frame before forming a theory.
3. Form one hypothesis, design the cheapest experiment that falsifies it, run it.
4. Bisect: shrink the input, the code path, or the history until the cause is isolated.
5. Fix the cause, then prove it with a test that failed before the fix.

## Anti-patterns

- Changing several things at once and declaring victory when the symptom moves.
- Adding a retry or a sleep around a race you have not understood.
- Widening an exception handler until the error stops surfacing.
