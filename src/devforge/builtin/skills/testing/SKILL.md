---
name: testing
version: 2.0.0
description: Write tests that would fail without the change.
capabilities: [unit-testing, regression-testing, test-design, determinism]
dependencies: []
compatible_runtimes: ["*"]
---

# Testing

The only useful test is one that fails when the behaviour it describes is broken. A
suite that has never failed has never been shown to test anything.

## Method

1. Before writing the assertion, name the bug the test would catch, in one sentence.
   If you cannot name it, the test is decorative.
2. Prove the test can fail. For a bugfix, write the regression test first and watch it
   fail for the right reason. For new code, break the implementation once, confirm the
   test goes red, and put it back. A test never observed failing is unverified.
3. Cover the happy path, the boundaries, and the documented failure modes. Boundaries
   are where bugs live: empty, one, many, maximum, one past maximum, null, duplicate,
   and the wrong type.
4. Keep tests deterministic: no real clock, no real network, no sleeping, no dependence
   on test ordering or on data left behind by another test. A flaky test is a broken
   test, and quarantining it is not fixing it.
5. Test behaviour through public interfaces, not private internals. A test coupled to
   internals fails on every refactor and passes through every real regression.
6. One reason to fail per test. When a test with six assertions goes red, the failure
   message should still tell you which behaviour broke.

## Choosing the level

Pick the cheapest level that can actually observe the behaviour:

- **Unit** for logic, branching and edge cases. Fast, precise, most of the suite.
- **Integration** for the wiring - the query really runs, the route really mounts, the
  serialisation really round-trips. Where mocked unit tests lie most convincingly.
- **End-to-end** for the few paths whose failure means nobody can use the product.
  Expensive and flaky in proportion to their length; keep them few and keep them real.

A mock of the component under test proves nothing. Mock at the boundary you do not own
(the network, the payment provider, the clock) and let everything inside it be real.

## Making a test readable

Arrange, act, assert - in that order, with the interesting input visible in the test
body rather than hidden in a fixture three files away. The name states the behaviour
and the condition: `rejects_a_second_charge_with_the_same_idempotency_key`, not
`test_charge_2`.

Assert on the outcome the user of the code cares about. Comparing whole structures
gives a better failure message than checking one field at a time.

## Anti-patterns

- Asserting that a mock was called instead of asserting an outcome.
- Loosening an assertion to make a suite green.
- Marking a genuinely failing test as skipped or expected-to-fail.
- Writing the test after the code by copying what the code currently returns - that is
  a snapshot of the bug, not a check on the behaviour.
- A `sleep` to fix a timing failure. Wait on the condition, or make it synchronous.
- Chasing a coverage number with tests that execute lines without asserting anything.

## Done when

Each new behaviour has a test that has been observed to fail without the change; edge
cases and documented failure modes are covered; the suite passes repeatedly and in a
different order; nothing is skipped or expected-to-fail; and no test asserts on a
private internal.
