"""The execution platform: a control plane, and workers that are not trusted.

Everything before this phase runs in one process. This package splits it in two:

**The control plane** owns what must not be forgeable - the queue, workflow
state, policy, approvals, the audit trail and the artifacts of record. It runs
where the operator runs it.

**A worker** owns what must not be trusted - executing agents, tools, browser
sessions and verifiers. It holds its own identity, declares its own
capabilities, and is assumed to be compromised.

That assumption is the design. A worker's report of its own success is a
*claim*; the control plane re-verifies against the artifacts it received before
recording anything as verified. A worker's request for work is authenticated
and authorised on every message. A worker's returned paths are validated
against the task it was actually leased.

What is deliberately **not** here
---------------------------------

There is no network transport, no database, no broker and no scheduler service.
Workers are separate operating-system processes speaking a signed protocol over
stdio.

That is a measured decision, not an omission. ``docs/platform.md`` records the
workload this project actually has, and it does not justify any of them. It also
records the harder constraint: ``tests/test_architecture.py`` forbids importing
an HTTP client anywhere in ``src/``, because the threat model relies on DevForge
having no outbound network capability at all. Adding a listener would trade a
documented, tested property for a capability nothing needs yet.

The transport is an interface with two implementations, so replacing stdio with
a network is a new module rather than a rewrite - and the security properties
that matter (identity, signing, replay defence, authorisation, isolation,
re-verification) live above it and would carry over unchanged.
"""
