---
name: architecture
version: 1.0.0
description: Design components, interfaces and data flow for a change.
capabilities: [system-design, interface-design, trade-off-analysis]
dependencies: [planning]
compatible_runtimes: ["*"]
---

# Architecture

Design the smallest structure that satisfies the requirements and does not have to be
undone by the next change.

## Method

1. Read what already exists before proposing anything new. Reuse beats invention.
2. Define interfaces first: inputs, outputs, errors, and who owns the data.
3. Push dependencies inwards: policy at the core, I/O at the edges.
4. Name the extension points, and be explicit about what is deliberately not built.
5. Record trade-offs, including the alternatives you rejected and why.

## Anti-patterns

- Abstractions with exactly one implementation and no second one in sight.
- Distributed infrastructure for a problem that fits in one process.
- A layer whose only job is to forward calls.
