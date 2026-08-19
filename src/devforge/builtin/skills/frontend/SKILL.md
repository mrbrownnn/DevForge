---
name: frontend
version: 1.0.0
description: Implement user interfaces and client-side state.
capabilities: [ui-implementation, state-management, accessibility]
dependencies: []
compatible_runtimes: ["*"]
---

# Frontend Implementation

## Method

1. Follow the existing component and styling conventions of the project - consistency
   beats personal preference.
2. Model loading, empty, error and success states explicitly; every one of them ships.
3. Keep state as local as it can be; lift it only when two components genuinely share it.
4. Accessibility is part of done: semantic elements, labels, focus order, contrast.
5. No layout that only works at one viewport width.

## Anti-patterns

- Fetching data in a component that also renders complex markup.
- Loosely typed props used to silence the type checker.
- Hardcoded colours where the design system defines tokens.
