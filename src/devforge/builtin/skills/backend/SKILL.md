---
name: backend
version: 2.0.0
description: Implement server-side code, APIs, and data access.
capabilities: [api-design, data-modelling, error-handling, concurrency, observability]
dependencies: []
compatible_runtimes: ["*"]
---

# Backend Implementation

Server-side code is judged on what it does when things go wrong, because the happy path
is the easy half and it is not the half that pages someone at 3am.

## Method

1. Validate input at the boundary; trust it afterwards. One validation layer, at the
   edge, producing a typed value. Re-checking the same field in four places means no
   layer owns the invariant.
2. Make illegal states unrepresentable in the type or schema layer rather than checking
   for them at every call site. A `NOT NULL` and a union type prevent more bugs than a
   guard clause, because they cannot be forgotten at the fifth call site.
3. Errors are values with structure: a stable code, a human message, and enough context
   to debug. Callers switch on the code, never on the message text.
4. Every write path states its failure and retry semantics: is it idempotent, what does
   a partial failure leave behind, and what does the caller do on timeout.
5. Never log secrets, tokens, credentials, or full request bodies containing user data.
   Log identifiers and let the operator join to the data if authorised.
6. Instrument at the boundary: one structured log line or span per request with route,
   outcome, duration and a correlation id. Debuggability is a feature, and it is
   cheapest to add while writing the code.

## Data access

- Own the transaction boundary explicitly: one unit of work per request, committed in
  one place. Nested implicit transactions are how partial writes happen.
- Every query that can return many rows takes a limit. "It is only ever a few" is a
  statement about today's data.
- Migrations are forward-only and deployable independently of the code that needs them:
  add the column, deploy, backfill, then start reading it.
- Know which queries hit an index and which do not, on the tables that grow.

## Concurrency and time

- Read-modify-write across a network is a race unless it is guarded by a lock, a
  compare-and-set, or a database constraint. Pick one and name it.
- Take the current time from an injected clock, never from a direct call buried in
  business logic - otherwise the behaviour cannot be tested.
- Background work that can run twice must be safe to run twice. It will run twice.

## API surface

- Additive changes only, unless a version is bumped: adding a required field, removing
  a field, or narrowing a type is a breaking change for someone.
- Pagination, on any collection endpoint, from the first version.
- Return the error the caller can act on. `400` with a field name beats `500` with a
  stack trace, and both beat `200` with an error inside the body.

## Anti-patterns

- Catching a broad exception and returning success.
- Business logic inside a request handler.
- Silent fallbacks that hide an outage - a cached stale value returned as if fresh.
- N+1 queries introduced by a convenient ORM relation in a loop.
- Retrying a non-idempotent operation.
- Configuration read at the point of use instead of at startup, so a bad value fails
  in production traffic rather than at boot.

## Done when

Input is validated once at the edge; errors are structured and coded; every write path
documents idempotency and failure; no secret reaches a log; collection endpoints
paginate; and the change is observable in logs or traces without adding print
statements later.
