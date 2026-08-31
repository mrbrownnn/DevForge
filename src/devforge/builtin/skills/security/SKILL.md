---
name: security
version: 2.0.0
description: Find reachable vulnerabilities in a change.
capabilities: [threat-modelling, code-review, dependency-review, secrets-review]
dependencies: []
compatible_runtimes: ["*"]
---

# Security Review

Report vulnerabilities that are actually reachable, with the attack path spelled out.
A generic checklist dumped into a report is noise, and noise is what teaches people to
ignore security reports.

## Method

1. Establish the trust boundary for this change: which inputs come from someone who is
   not trusted, and where do they enter. Everything downstream of that entry point is
   the review surface; everything else is not.
2. Follow the untrusted value forward until it reaches a sink - a query, a shell, a
   path, a template, a deserialiser, a redirect, a log. A vulnerability is a path from
   a source to a sink without an effective control in between.
3. For each candidate finding, construct the concrete attack: who the attacker is, what
   they send, what they get. If you cannot construct it, say so and rank it lower
   rather than reporting it as though you could.
4. Check the controls that already exist before assuming they are absent, and check
   that they apply to the new path - an auth decorator on the old handler does nothing
   for the new one.

## Checklist

1. **Injection sinks**: SQL, shell, template, path traversal, deserialisation, LDAP,
   header injection. Parameterisation and escaping are the controls; string
   concatenation into any of these is the finding.
2. **AuthN and AuthZ**: is every new endpoint or action covered by an existing check?
   Authorisation is per-object, not just per-route: can user A pass user B's id?
3. **Secrets**: nothing hardcoded, nothing logged, nothing committed, nothing in an
   error message or a stack trace returned to a caller.
4. **Path handling**: resolve symlinks and `..`, then confirm the result is still
   inside the allowed root. Check after resolution, never before.
5. **Dependencies added by this change**: maintained, pinned, and actually needed? A
   new transitive dependency tree is new attack surface with new maintainers.
6. **Error messages and logs**: no internal detail, no stack trace, no SQL, no
   file path leaked to an untrusted caller.
7. **Crypto and randomness**: a library, not a construction. A CSPRNG for anything a
   user must not predict - tokens, session ids, password resets, nonces.
8. **Server-side request forgery**: any URL supplied by a user and then fetched by the
   server, including redirects followed on the way.
9. **Resource limits**: unbounded reads, unbounded allocation, unbounded regex
   backtracking, no timeout on an outbound call.
10. **Multi-tenancy**: every query that returns tenant data filters by tenant, at a
    layer that cannot be bypassed by forgetting a `where` clause.

## Reporting

For each finding: **location** (file and line), **concrete attack path**, **impact**,
and the **minimal fix**. Rank by reachability and impact, not by category name.

Distinguish what you verified from what you inferred, and say which controls you
checked and found effective. Say plainly when you find nothing, rather than padding the
report with theoretical issues - an honest empty report is a useful signal and a padded
one destroys the value of every future report.

## Anti-patterns

- Reporting a category ("possible SQL injection") without the path that reaches it.
- Flagging code that is unreachable from any untrusted input.
- Rating everything high, so nothing is.
- Treating a linter's output as a review.
- Recommending a rewrite where a parameterised query would do.

## Done when

The trust boundary and untrusted inputs are named; each untrusted input is traced to
its sinks; every finding carries a concrete attack path and a minimal fix; controls
that were checked and found effective are recorded; and the report says clearly what
was not examined.
