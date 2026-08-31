---
name: debugging
version: 2.0.0
description: Find the root cause of a failure from evidence.
capabilities: [root-cause-analysis, reproduction, diagnostics, bisection]
dependencies: []
compatible_runtimes: ["*"]
---

# Debugging

Debugging is evidence work, not guessing work. Every step either narrows where the
cause can be or it was not a step.

## Method

1. Reproduce first. A bug you cannot reproduce, you cannot claim to have fixed - you
   can only claim the symptom stopped appearing. Write down the exact command, input
   and environment that produce it.
2. Read the actual error text and the failing frame before forming a theory. Read the
   whole stack, including the parts you assume are irrelevant, and read the first error
   rather than the last - later errors are usually consequences.
3. Establish the last known-good state: a commit, a version, an input size, a config.
   The cause lives in the difference between that state and this one.
4. Form one hypothesis at a time, stated so it can be wrong ("the retry re-sends the
   request before the connection is closed"). Design the cheapest experiment that would
   falsify it, and run that. Confirmation is not evidence; failed falsification is.
5. Bisect along whichever axis is cheapest: the input (shrink it until removing one
   more thing hides the bug), the code path (disable half), or the history
   (`git bisect`). Each bisection halves the search space; guessing does not.
6. Fix the cause, not the symptom, then prove it with a test that failed before the fix
   and passes after - and that fails again if you revert the fix.
7. Ask why the existing tests did not catch it. The answer is a second, permanent fix.

## Narrowing by class of bug

- **Works alone, fails in the suite**: shared state, ordering, or a leaked fixture.
- **Works locally, fails in CI**: environment, versions, timezone, locale, file system
  case sensitivity, parallelism, or a missing file that is gitignored locally.
- **Intermittent**: concurrency, timing, network, or unordered iteration. Run it in a
  loop until it fails, and capture the state at the moment of failure.
- **Recently started**: bisect the history. Do this before reading any code.
- **Only with real data**: shrink the real input to the smallest failing case, then
  make it a fixture.

## Instrumenting

Print the value and its type at the boundary where you believe the data is still
correct, and again where you believe it is wrong. The bug is between the last correct
observation and the first incorrect one. Log identifiers, not entire objects, and
remove the instrumentation before the change ships - or promote it to a real log line
if it earned its place.

## Anti-patterns

- Changing several things at once and declaring victory when the symptom moves.
- Adding a retry or a sleep around a race you have not understood.
- Widening an exception handler until the error stops surfacing.
- Rewriting the failing component instead of finding the fault - the bug usually
  survives the rewrite, now with a new home.
- Trusting a comment, a variable name, or a log message over observed behaviour.
- Closing it as "could not reproduce" without recording what you tried.

## Done when

The failure reproduces on demand; the causal chain from cause to symptom is stated in
one or two sentences; a test fails before the fix and passes after; and you can say why
the suite missed it.
