# Git-native engineering

DevForge writes to repositories that people are working in. This page is about
the rules that makes that safe to do.

```
issue → plan → branch → worktree → implementation → tests → review
      → security → commit → pull request
```

The `git-feature` workflow runs that flow end to end. The commands below are the
same machinery, available one piece at a time.

```bash
devforge git worktree create --issue ISSUE-12.md   # branch and isolated checkout
devforge git worktree list
devforge git commit -m "add the thing" --type feat # plans, screens, then commits
devforge git pr --base main                        # writes the artifact
devforge git guard git push --force origin main    # asks what would happen
```

## Two rules, enforced rather than described

**The user's checked-out branch is not DevForge's to move.** Autonomous work
happens in a git worktree - a second checkout, on its own branch, under
`.devforge/worktrees/`. The agent-facing `vcs` tool refuses to commit unless it
is running inside a linked worktree, and the test that proves it asserts that the
change is *still uncommitted* afterwards. Creating a worktree on a branch that is
checked out anywhere is refused with the reason, not with a porcelain error.

The human CLI has no such restriction. A person who types `devforge git commit`
has chosen where they are standing.

**History is not editable without a person.** Force push, branch deletion and
every form of rewriting are **refused**, not queued for approval:

| operation | why it is not merely gated |
| --- | --- |
| `push --force`, `push -f`, `push --force-with-lease` | discards commits other people may have pulled; a lease makes it safer for them, not reversible for you |
| `push --delete`, `branch -d`, `branch -D` | removes a branch, locally or remotely |
| `rebase`, `commit --amend`, `reset --hard` | replaces commits that other work may already refer to |
| `filter-branch`, `filter-repo`, `reflog expire`, `update-ref -d`, `gc --prune=now` | rewrites or discards the record that makes recovery possible |

Each names its own approval gate - `force_push`, `branch_delete`,
`history_rewrite` - and the gates are separate on purpose. Approving one branch
deletion is not approving a rebase, and a single "git is fine" gate would make it
one.

`devforge git guard <command>` prints the verdict without running anything, so
the refusal is inspectable rather than a surprise mid-run.

This sits on top of the shell allowlist, which already denies `git push --force`.
Two layers, in different places, checking different things: the policy engine
judges a *command*, this judges an *outcome*.

## What never reaches a commit

Screening runs between staging and committing, which is the last moment it can
fail closed. A commit that has already happened is in the reflog whatever you do
next.

| flag | blocks? | what it is |
| --- | --- | --- |
| `credential_file` | yes | `.env`, `id_rsa`, `*.pem`, `credentials.json`. **Not opened** - confirming what is already known would pull the credential into memory and possibly into a prompt |
| `secret` | yes | credential-shaped content. The matched value is never repeated in the message |
| `binary` | yes | executable or opaque content nobody explained. Images, fonts and PDFs are expected and pass |
| `oversized` | no | over 2 MB; worth a human glance whatever it is |
| `unrelated` | no | outside the scope the plan declared |

The last two do not block on purpose. Scope is a heuristic, and real work
routinely touches something the plan did not anticipate; a guard that blocks on
that gets bypassed until it blocks on nothing. `.env.example` and `key.sample`
pass for the same reason - blocking documentation is how a guard stops guarding.

There is **no approval path for committing a secret** through the tool. Offering
one teaches people to use it. A human who has looked and decided a flag is wrong
can pass `--i-have-reviewed-the-flags` to the CLI, which prints every flag first.

`.devforge/` is excluded from an automatically-derived file list: it is run
state, not anybody's change.

## Commits

Conventional Commits, from a closed vocabulary, because a history is only
greppable if the words in it are the same words every time. The scope is inferred
only when it is unambiguous - the deepest directory every path shares, minus
layout prefixes like `src/` - because a wrong scope makes `git log --grep` lie.

**No tool or model attribution is added.** A commit records what changed and why;
who typed it is a question about the repository's contributors, and inventing an
answer in every commit is not this layer's decision to make.

## The pull request is a file

DevForge does not open pull requests. `devforge git pr` writes
`.devforge/artifacts/PR-<branch>.md` and the matching JSON, and a person pushes.

Opening a pull request notifies people, starts CI, and in many repositories
begins an auto-merge path. Those consequences reach beyond the machine.
Preparing the proposal is the part that benefits from automation; publishing it
is the part that benefits from a person reading it first.

The artifact has the five sections the flow requires, and two of them are filled
from evidence rather than from an account of the work:

* **summary** - from the issue, or given;
* **changes** - from `git diff --name-status base...HEAD`, not from what the
  agent said it touched;
* **tests** and **security results** - from recorded verification results, split
  by verifier kind;
* **known limitations** - given, plus what the run itself demonstrates: a
  verifier that could not run, an advisory check that failed, a step that needed
  several attempts, an approval still pending. None of those is something an
  agent reliably volunteers, and all of them are things a reviewer wants.

A missing section is *stated*, never left blank: "no test results were recorded,
which is not the same as passing". An artifact with no stated limitations says so
too, because a change with none has usually not been asked for any. Incomplete
artifacts exit 1.

## The workflow

`devforge run --workflow git-feature` runs the whole flow. Two orderings in it
are load-bearing:

`security` runs **before** `commit-screen`, so a finding is caught while it is
still a file on disk. Screening after the commit would be a review, not a guard.

`review` runs the patch guard **before** anything writes a summary, so a change
that removed assertions is caught before a document claims it works.

Each step is granted only the tools it needs. `implementation` gets the
filesystem and the shell; `commit-screen` gets `vcs`; `intake` gets neither.

## Limits

**The content guard is pattern matching.** It finds credential-shaped strings,
known credential filenames and binary content. It does not find a secret that
looks like prose, a credential split across lines, or a backdoor written in
readable Python. The patch guard and human review are the other two layers, and
none of the three is sufficient alone.

**A refusal is not a sandbox.** Nothing here stops a shell command from running
`git push --force` directly - the shell allowlist denies that pattern, and an
allowlist is not a sandbox either. What these guards do is make the dangerous
path require a deliberate act rather than an accidental one.

**Scope detection is a heuristic**, and it is deliberately quiet: it answers
nothing rather than guessing when paths span trees.

**Worktrees are per repository, not per machine.** Two DevForge runs in the same
repository on the same branch name collide, and the second one is refused. That
is the correct outcome, but it means running many tasks in parallel needs
distinct branch names, which the issue-derived naming gives you.
