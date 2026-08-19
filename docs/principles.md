# Principles

Nine commitments. Each one is falsifiable: it names what would count as a violation, so
a pull request can be measured against it instead of argued about.

---

## 1. Runtime agnostic

The orchestrator depends on `AgentRuntime` and nothing else. No vendor name appears
outside a runtime adapter.

**Violated when:** any module under `core/` imports a concrete runtime, or branches on a
runtime name. Checked by `tests/test_architecture.py::test_core_has_no_vendor_imports`.

## 2. Model agnostic

DevForge does not know what a model is. It composes prompts and reads structured
results. Model selection, token budgets and pricing belong to the adapter.

**Violated when:** a model id, context window, or token count appears in `core/`.

## 3. Tool agnostic

Capabilities arrive through the `Tool` interface and a registry. Adding a tool never
changes the orchestrator.

**Violated when:** the orchestrator special-cases a tool by name — with one deliberate
exception, the availability check, which treats all tools identically.

## 4. Workflow driven

Behaviour is declared in YAML, not encoded in Python. A new workflow, agent, skill or
verifier is a file.

**Violated when:** supporting a new workflow shape requires editing the step loop.

## 5. Skill driven

Instructions live in Markdown that a human can read and edit. Prompt text is never a
string literal inside a code path.

**Violated when:** an agent instruction is written in Python rather than a skill or
agent spec.

## 6. Observable

Every meaningful action emits a structured event carrying task, step, agent, tool,
duration, status and error. The run log is sufficient to reconstruct what happened
without re-running anything.

**Violated when:** a decision is taken that leaves no event — silent retries, silent
skips, silent denials.

## 7. Secure by default

Deny first. Permissions are allowlists; approvals fail closed; unknown gates block;
third-party content is untrusted until reviewed at a pinned commit.

**Violated when:** a default widens access — an auto-approved gate, an allowlist entry
of `*`, a trust tier granted implicitly.

## 8. Locally runnable

`git clone && pip install -e . && pytest` works offline on one machine. The full test
suite makes no network call and no paid API call.

**Violated when:** a test needs a network, a service, or a credential.

## 9. Extensible

Every layer has one seam: implement an interface, register it. Extension does not
require modification.

**Violated when:** adding a capability means editing a `match` statement in the core.

---

## The one that outranks the others: honesty

**Nothing may pretend to work.**

A capability DevForge does not have reports `unavailable` and returns no data. A check
that could not run is a failure, never a pass. An agent claiming success is evidence of
nothing until a verifier agrees.

This is the principle the rest exist to protect. A harness that overstates itself is
worse than no harness, because it converts a visible gap into an invisible one.

Concretely, today: `tools/browser.py`, `tools/mcp.py` and `verification/visual.py` are
declared adapters that report `unavailable`; the `clone` workflow therefore halts at its
first step, loudly, rather than producing a plausible-looking result.

---

## Explicitly out of scope

Not "later" — **not now, and here is why**:

| Rejected | Why |
| --- | --- |
| Kubernetes | One process on one machine. There is nothing to schedule. |
| Kafka | Event volume is tens per run. A JSONL file is the right medium. |
| Redis | No cross-process shared state beyond files that are already atomic. |
| Vector database | Project memory is four Markdown files a human maintains. Retrieval solves a problem we do not have. |
| Microservices | The whole system is 7k lines. Service boundaries would be pure overhead. |
| Temporal / workflow engines | The step loop is 200 lines and resumes from persisted state. |
| Dynamic skill installation | Deliberately unimplemented — see docs/security/skill-supply-chain.md. |

Each may become justified. The trigger conditions are stated in
[docs/architecture.md](architecture.md#when-these-decisions-should-be-revisited).

## Precedence when principles conflict

```
honesty > security > correctness > extensibility > features > performance
```

If observability and security conflict (an event would log a secret), security wins and
the event records a redaction marker — never silence.
