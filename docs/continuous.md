# Continuous engineering

Everything else in DevForge waits to be asked. This part looks at a repository and
proposes what is worth doing.

```bash
devforge continuous detect              # what is here; changes nothing
devforge continuous propose             # record proposals in the backlog
devforge continuous backlog             # what is open
devforge continuous approve <id>        # a human agrees
devforge continuous execute <id>        # isolated worktree + the issue to work from
devforge continuous verify <id> --path <worktree>
```

Exit codes: `0` normally; `1` when a decision is missing — an unapproved proposal
handed to `execute`, or a verification that found the finding still firing.
**Finding things is never an error.** A backlog is a measurement of a repository,
and a command that fails a build for having one teaches people to stop running it.

## Two rules the design is built around

**Nothing here modifies code.** `detect` and `propose` are read-only. `execute`
creates a git worktree and writes the proposal into it as an issue — that is all
it does to a filesystem. The work itself runs through the ordinary workflow, with
the ordinary verifiers and the ordinary approval gates. A tool that tidies your
repository while you are not looking is not a colleague.

**Nothing here files noise.** A low-confidence finding costs more than it saves:
it trains people to ignore the list, and a list that gets ignored may as well not
exist. Four mechanisms enforce that, and all four are tested:

| mechanism | what it prevents |
| --- | --- |
| confidence threshold (0.6) | guesses filed as work. Withheld findings are counted, not hidden |
| flood collapse (>25 per detector) | a detector that fires a hundred times files one policy question, not a hundred tasks |
| per-category cap (3 per run) | the most talkative detector filling the list |
| directory grouping | five modules in one package needing tests is one afternoon, not five tasks |

Security is **exempt from the confidence threshold**. The cost of checking a false
positive there is a minute; the cost of missing a real one is not symmetric with
it, and pretending otherwise turns a threshold into a way of not looking.

## A finding

The seven fields the brief names, each answering a question a reader actually has:

```
finding_id          which rule fired, so it can be accepted by name
severity            how bad it is if real
confidence          how likely it is to be real
evidence            what was observed, so the claim can be checked
affected_files      where to look
recommended_action  what to do, in one sentence
estimated_risk      what doing it might break
```

Severity and confidence are **separate axes**. Conflating them is what makes an
automated backlog unusable: a possible SQL injection and a certain trailing
whitespace are not comparable on one number, and averaging them produces an
ordering nobody agrees with.

`estimated_risk` is about the *fix*, not the problem. Deleting apparently dead
code is a small change with a large blast radius if the analysis was wrong, and a
backlog that does not say so invites exactly that mistake.

## Priority

```
priority = severity × 10  +  (15 if security)  +  confidence × 5  −  risk
```

The security term is a term of its own rather than a weighting, so the guarantee
holds by construction: **a high-severity security finding always outranks a
critical cosmetic one.** `tests/test_continuous.py` asserts both directions.

## The ten detectors

| category | what it looks at | confidence | notes |
| --- | --- | --- | --- |
| security | `devforge security scan` | 0.6–0.85 | a bridge, not a second scanner — one rule set, so the two can never disagree |
| dependency | `pyproject.toml` vs installed metadata | 0.9–0.95 | unpinned, missing, below the declared minimum |
| flaky_test | recorded run history | 0.85 | verifiers that passed and failed in an **agent-free** `verify` step |
| dead_code | module-level defs nothing references | 0.5–0.68 | names in strings count as references |
| duplication | 8 identical meaningful lines | 0.85 | across files only |
| architecture | import cycles, long modules, branchy functions | 0.9 | cycles through third-party packages are not reported |
| tech_debt | `TODO`/`FIXME`/`HACK`/`XXX` | 0.9–0.95 | five or more in one file collapse into one finding |
| missing_tests | public definitions no test names | 0.75 | unavailable when a project has no tests at all |
| performance | shapes: concat in a loop, `re.compile` in a loop, list membership | 0.7–0.85 | never a measurement |
| doc_drift | broken Markdown links, documented functions that do not exist | 0.7–0.85 | |

**Every detector reports its status.** `unavailable` carries a reason and never
counts as "nothing found" — the flaky-test detector says so when there is no run
history rather than guessing from test contents, and a detector that raises is
reported as unavailable with the exception rather than taking the scan with it.

Credential files are **never read**, by any detector, for any reason. The reader
skips them by name and records why.

Two detectors are worth reading closely.

**Flakiness cannot be read off source.** It is a claim about behaviour over time,
so this detector reads run history and looks for a verifier that both passed and
failed inside a `verify` step — a step with no agent, so the two runs differ only
in when they happened. Guessing which tests "look flaky" would produce a list of
tests that use timers, which is a different thing.

**Dependencies are analysed offline.** "Outdated" usually means "behind the latest
release", and knowing that needs a package index: a network call, a new trust
relationship and a new egress path, which is the operator's decision and not a
default. So the detector reports what is knowable without one and *states the gap*
rather than implying it covers the whole question.

## Accepting a finding

`.devforge/continuous/accepted.yaml`, the same shape as the security baseline and
for the same reasons — a written reason and an expiry date, so a decision nobody
has re-confirmed becomes visible again instead of becoming permanent.

```yaml
accepted:
  - finding_id: CE-DEBT-001
    location: src/app.py
    reason: Tracked in ISSUE-42; the marker is the tracking.
    expires: 2027-01-31
    accepted_by: someone
```

A rejected **proposal** is different from an accepted **finding**: rejecting a
proposal records a decision that survives re-detection, so the backlog does not
ask the same question every day.

## Verification is a re-detection

```bash
devforge continuous verify <id> --path .devforge/worktrees/<branch>
```

A proposal is verified when the findings that motivated it **stop firing** — not
when a workflow reports success, and not when an agent says it is done. It is the
only check in the pipeline that cannot be satisfied by claiming it.

A finding whose detector could not run in that tree is reported as
`unverifiable`, never as resolved.

## Limits

**Every detector is static.** Nothing is executed, nothing is profiled, and no
detector can see what the program does at runtime. That is why the confidences
differ so widely: a `FIXME` marker is a fact about a file, a function nobody names
might be an entry point reached by a decorator or a string.

**A finding is a hypothesis.** The output says so on every run, and the issue
`execute` writes tells the agent the same thing: confirm each finding before
acting on it, and a detector that was wrong is a normal outcome rather than a
reason to change the code anyway.

**Detection was tuned against this repository.** The doc-drift detector originally
flagged backticked paths in prose and produced ninety-four findings here, not one
of which was real; the rule was deleted rather than baselined. Expect to make the
same kind of adjustment on a codebase with different conventions — and to make it
in the detector, not in a list of exceptions.

**The categories are not exhaustive.** Ten kinds of work are looked for. Nothing
here finds a logic error, a bad abstraction, a race, or a feature that should not
have been built.
