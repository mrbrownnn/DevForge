---
name: testing
version: 1.0.0
description: Write tests that would fail without the change.
capabilities: [unit-testing, regression-testing, test-design]
dependencies: []
compatible_runtimes: ["*"]
---

# Testing

The only useful test is one that fails when the behaviour it describes is broken.

## Method

1. Before writing the assertion, name the bug the test would catch.
2. Cover the happy path, boundaries, and the documented failure modes.
3. For a bugfix, write the regression test first and watch it fail.
4. Keep tests deterministic: no real clock, no network, no ordering assumptions.
5. Test behaviour through public interfaces, not private internals.

## Anti-patterns

- Asserting that a mock was called instead of asserting an outcome.
- Loosening an assertion to make a suite green.
- Marking a genuinely failing test as skipped or expected-to-fail.
