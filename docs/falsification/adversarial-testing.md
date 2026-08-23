# The adversarial test agent

The coding agent is asked to make the implementation work. The falsifier is asked to
find the smallest reproducible input that makes it fail. That inversion is the point,
and it is why the falsifier is a separate agent with its own prompt and its own
permission scope rather than the coder wearing a different hat.

## What it may do

| | |
| --- | --- |
| **Read** | source, the diff, existing tests, requirements, architecture notes, documentation, previous verification results |
| **Write** | the sandbox scratch directory, and nothing else |
| **Never** | modify production source or the permanent suite, weaken an assertion, disable a control, change configuration to hide a failure, repair anything |

## The write scope is a control, not a request

After the agent runs, the filesystem is compared against a content-hash snapshot
taken before. Any write outside the scratch directory fails the strategy and discards
its findings. An instruction in a prompt can be ignored; a snapshot comparison cannot
be argued with.

This is why `test_a_scope_violating_agent_is_stopped_even_when_the_prompt_was_injected`
exists: it assumes the injection worked and asserts the control still holds.

## It never repairs

A counterexample is evidence handed to the workflow. Changing production code belongs
to a repair step. Keeping the roles apart is what stops a falsifier from "fixing" the
thing that made its own test fail.

## Independence

The architecture never assumes `coder == falsifier`. A step may configure a different
runtime, model, temperature or context policy:

```yaml
- id: falsify
  kind: falsify
  falsifier:
    runtime: <runtime name>
    model: <model id>
    context_policy: adversarial
    temperature: 1.0
```

A different model is **not** required for the MVP. A setting the runtime cannot
honour is reported as unhonoured rather than silently dropped - `AgentRuntime.configure`
returns exactly that list.

## Budgets

This is the most expensive and least predictable strategy: its cost is a network
round trip of unknown duration. Three separate bounds apply - `max_agent_invocations`
(calls, which is a different number from produced tests), a wall-clock share
defaulting to 40% of `max_duration_s`, and `max_tokens` where the runtime reports
token counts. Where it does not, the token budget is reported **unenforceable**, never
assumed satisfied.

An agent that produced no test at all yields `INCOMPLETE`, never `SURVIVED`: nothing
was searched.
