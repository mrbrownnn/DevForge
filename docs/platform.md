# The execution platform

Everything before this phase runs in one process. This splits it in two: a
**control plane** that owns what must not be forgeable, and **workers** that own
what must not be trusted.

```bash
devforge platform worker register --id w1        # identity + a key, shown once
devforge platform submit -t "Add JWT auth" -w feature --expect docs/plan.md
devforge platform dispatch --worker w1           # lease, execute, verify
devforge platform approve <task> --gate architecture --by you
devforge platform status
devforge platform audit --verify
```

Exit codes: `0` verified or executed, `1` rejected or failed, `2` waiting on a
human — the same code `devforge run` uses for a pause, so a script can tell "not
yet" from "no".

## The premise: a worker can be compromised

That assumption decides the whole design, and it has one consequence that matters
more than the rest.

**A worker's report of its own success is a claim.** The control plane records
it, stores the artifacts it was given, and then **re-runs verification itself**
against those artifacts. A task reaches `verified` because the control plane
checked, never because a worker said so.

This is the cheapest attack in the design — lying costs nothing and is invisible
to a control plane that takes results at face value — so it has its own test. A
worker that reports success, claims every verifier passed, and returns no
artifact is `rejected`, and the audit trail records that the two accounts
**disagree**.

`devforge platform status <task>` prints both columns side by side. The
`confirmed` column is evidence; the `claimed` column is what the worker said
about itself.

**`verified` requires that something was verified.** A task that declared no
artifact settles as `executed`, with the reason spelled out: "no verifier was
declared, so the control plane confirmed nothing independently". Putting the
strongest word in the vocabulary on the weakest evidence there is would undo the
point of having the word.

## Identity, authentication, authorisation

**Identity.** A worker registers once and gets an id and a signing key. The key
is printed once and is not recoverable — a key that can be read back is a key
that leaks through every later convenience. It is stored in
`.devforge/platform/workers.key`, and that name is deliberate: `*.key` already
matches the filesystem policy's deny rules, the security scanner's credential
patterns, and the commit content guard. Three controls written before this phase
refuse the file, and a test asserts all three still do.

**Authentication.** Every message carries an HMAC over its canonical form
together with the sender, a nonce and a timestamp. A signature valid for one
payload is not valid for another payload, another worker, or another moment.
Replays are refused by nonce; captured messages expire on a two-minute skew
window. A refused message is written to the audit trail before the exception
propagates, because an exception is not a record.

**Authorisation.** Capabilities (`agent`, `tools`, `browser`, `verify`, `shell`,
`network`), permitted tools and permitted runtimes, checked **on both sides**.
The control plane will not lease work to a worker that lacks a capability; the
worker refuses the same envelope again on receipt. The duplication is the point —
one check protects the operator from work going to the wrong machine, the other
protects the machine from a control plane that has been persuaded to ask for
something the operator never permitted there.

## Isolation

| kind | what it is |
| --- | --- |
| task | each task gets its own directory, recreated empty, with a policy engine bound to it |
| artifact | artifacts cross as a **name and content**, never a path; every name resolves inside exactly one task's directory or is refused |
| secret | the envelope carries no credentials, and the schema is tested for it; the task environment is the scrubbed allowlist and does not include the worker's own key |
| network | default deny, declared per envelope, and gated behind a capability the worker must hold |

**None of this is a sandbox.** A worker runs as the user who started it, with
that user's privileges. Isolation here separates *tasks from each other* and
bounds what the protocol can express; it does not contain a hostile process.
Running an untrusted worker means running it in a container or a VM.

## Approvals stay with the control plane

A worker has nobody to ask. When a run reaches a gate nobody granted, it
**pauses** — the task becomes `awaiting_approval`, and the reason names the gate.

A human decides through the control plane. The grant travels to the worker by
name in the envelope, and the worker writes it onto the task as a decision
already made, attributed to the control plane. A worker never decides an
approval; it applies one.

## The transport, and the network that is not here

Two transports ship: **in-process** (development and tests) and **subprocess**
(a worker in its own OS process, newline-delimited JSON over stdio). The
in-process one still signs and verifies every message — a local transport that
skipped authentication would leave that code untested until the day it mattered.

**There is no network transport**, for two reasons that both point the same way.

`tests/test_architecture.py::test_no_http_client_is_imported` forbids importing
an HTTP client anywhere in `src/`, because the threat model rests on DevForge
having no outbound network capability at all. A listener would trade a
documented, tested property for a capability nothing here needs. A second test in
`tests/test_platform.py` asserts the same rule specifically for this package, so
adding one is a deliberate change to a stated principle rather than an import
somebody slipped in.

And the measured workload does not ask for it. Everything above the transport —
identity, signing, replay defence, authorisation, isolation, independent
re-verification — is transport-agnostic and would carry over unchanged.

## Measured workload

Measured on the development machine, mock runtime, one control plane:

| operation | cost |
| --- | --- |
| submit a task | **9.7 ms** |
| lease a task | **62 ms** |
| scan a 200-task queue | **23 ms** |
| append an audit entry (chain of 252) | **8.8 ms** |
| end-to-end dispatch, subprocess transport | **0.8 s** |

Read against what this project actually generates: a benchmark run is ten cases,
a continuous-engineering pass proposes at most ten items, and a developer submits
tasks at human speed. The queue holds tens of items and is scanned in
milliseconds; the dominant cost is the work itself, by three orders of magnitude.

So: **no PostgreSQL, no Redis, no Temporal, no broker, no Kubernetes.** Each
would add a service to run, secure, back up and upgrade, in exchange for
throughput nothing here needs. The brief asked for infrastructure to be justified
by measured workload; this is the measurement, and it does not justify any.

**Where that stops being true.** The file-backed queue has no cross-process lock,
so two control planes leasing at once can hand one task to two workers. One
control plane is safe; two are not. That is the point at which a real database
earns its place, and it is the first thing to change if this ever needs to scale
out.

## The audit trail

Append-only JSONL, hash-chained: each entry carries the digest of the one before
it. Editing an entry breaks its own digest and every link after it; removing one
breaks the chain at that point. `devforge platform audit --verify` reports every
break and exits non-zero.

Details are redacted before they are written, through the same boundary every
other persisted record uses. A durable, widely-read file is one of the worst
places for a credential to land.

**What it is:** tamper-*evident*. **What it is not:** tamper-proof. It is a local
file owned by the same user as the control plane, and somebody with that user's
privileges can delete it or rewrite the chain from scratch. What they cannot do
is quietly change one entry — which is the realistic failure, a mistake being
tidied away rather than a determined attacker rebuilding history. An off-host log
or a signature over the head would raise that bar; neither is implemented.

## Residual risks

- **HMAC authenticates, it does not encrypt.** Over a stdio pipe between two
  processes under one operator that is fine. A network transport would need
  confidentiality, and nothing here provides it.
- **The key is shared, not asymmetric.** Both sides hold the same secret, so a
  signature proves the message came from something holding the key — not which
  of the two sides sent it. Distinguishing them needs public-key signatures.
- **Worker keys are protected by file permissions**, best-effort. `chmod` is
  applied where the platform implements it; Windows does not, so there the key's
  protection is whatever the containing directory's ACL provides.
- **Control-plane-side verification checks artifacts, not behaviour.** It
  confirms that declared artifacts arrived intact. It does not re-run the
  project's test suite against the worker's tree, because the control plane holds
  files rather than that tree.
- **A worker still executes the work.** Everything here constrains what a
  compromised worker can *report* and *reach through the protocol*. It does not
  constrain what that process does on its own machine.
