---
name: frontend
version: 2.0.0
description: Implement user interfaces and client-side state.
capabilities: [ui-implementation, state-management, accessibility, performance]
dependencies: []
compatible_runtimes: ["*"]
---

# Frontend Implementation

A UI ships all four of its states or it has not shipped. The states nobody demonstrates
- empty, slow, broken - are the ones real users hit first.

## Method

1. Follow the existing component, styling and file conventions of the project.
   Consistency beats personal preference; a codebase with two idioms costs more than
   either idiom costs alone.
2. Model loading, empty, error and success explicitly, and build all four. An error
   state that only prints "Something went wrong" is a placeholder, not a state: say
   what failed and what the user can do next.
3. Keep state as local as it can be; lift it only when two components genuinely share
   it. Distinguish server state (cached remote data, needs invalidation) from UI state
   (open/closed, focused) - conflating them is the usual cause of stale screens.
4. Accessibility is part of done: semantic elements over styled `div`s, a label for
   every input, a visible focus ring, keyboard reachability for every action, and
   contrast that meets the project's standard.
5. No layout that only works at one viewport width. Check the narrowest supported width
   and the point where content, not the device, breaks the layout.
6. Guard the render path: a list that can grow needs virtualisation or a limit, and an
   expensive computation in a render body runs on every keystroke.

## Data and effects

- Fetching belongs in a hook, a loader, or a container - not in a component that also
  renders complex markup. The rendering component takes data as input and is testable
  without a network.
- Every request has a failure branch that reaches the UI, and a cancellation path for
  when the user navigates away.
- Do not derive state you can compute during render; two sources of truth drift.
- Debounce user-driven requests, and make the last response win - out-of-order
  responses overwriting newer data is a race, not a rare glitch.

## Forms

- Validate on the client for speed and on the server for correctness. The client check
  is a convenience, never the guarantee.
- Disable the submit control while a submission is in flight, or make the submission
  idempotent. Double-submit is the default user behaviour, not an edge case.
- Preserve what the user typed when a submission fails.

## Anti-patterns

- Fetching data in a component that also renders complex markup.
- Loosely typed props (`any`, untyped objects) used to silence the type checker.
- Hardcoded colours, spacing or fonts where the design system defines tokens.
- `div` with a click handler where a `button` belongs - it loses keyboard, focus and
  screen-reader behaviour that you then reimplement badly.
- A spinner as the entire loading state for a screen that could show its layout.
- Suppressing a dependency-array or reactivity warning instead of understanding it.

## Done when

All four states render; every interactive element is reachable and operable by
keyboard with a visible focus indicator; inputs are labelled; the layout holds at the
narrowest supported width; failures surface a message the user can act on; and no
design token has been hardcoded around.
