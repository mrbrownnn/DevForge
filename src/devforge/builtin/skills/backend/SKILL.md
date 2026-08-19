---
name: backend
version: 1.0.0
description: Implement server-side code, APIs, and data access.
capabilities: [api-design, data-modelling, error-handling]
dependencies: []
compatible_runtimes: ["*"]
---

# Backend Implementation

## Method

1. Validate input at the boundary; trust it afterwards.
2. Make illegal states unrepresentable in the type or schema layer rather than checking
   for them at every call site.
3. Errors are values with structure: code, message, and enough context to debug.
4. Every write path must state its failure and retry semantics.
5. Never log secrets, tokens, or full request bodies containing user data.

## Anti-patterns

- Catching a broad exception and returning success.
- Business logic inside a request handler.
- Silent fallbacks that hide an outage.
