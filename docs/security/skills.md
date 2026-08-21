# Installing third-party skills

Phase 0 shipped no installer, deliberately: an attack that needs code execution at
install time has no entry point if there is no install path. Phase 3 adds one. This
document is the argument that it is still safe, and where it is not.

## The property everything rests on

> **DevForge never executes an installed skill.**

There is no install hook, no postinstall, no interpreter invocation, no code path
anywhere that runs a file a skill shipped. A skill is *instructions* - text composed
into a prompt. That is what lets a user install one without handing it the machine,
and it is why the pipeline below can be honest about the limits of static inspection:
the mitigation that matters does not depend on the inspection being right.

Executable content is **quarantined**: copied to `quarantine/` inside the skill
directory for review, kept out of the active tree, listed in the report and recorded
in the lockfile. `--with-scripts` moves them into the active tree for a human to use;
DevForge still never runs them.

## The pipeline

```
devforge skill install <name>
  1  resolve the catalogue entry
  2  refuse if unpinned            - a name is not an identity
  3  git clone at the exact commit - policy-checked, sanitised environment
  4  verify HEAD == the pin        - a moved tag or branch fails here
  5  hash the tree that arrived
  6  compare to the catalogue hash - reviewed tree must equal served tree
  7  inspect: scripts, installers, network, secrets, encoded payloads, hooks
  8  classify risk; derive permissions from content, not from claims
  9  CRITICAL -> refuse; above the ceiling -> require --approve-by
 10  install into .devforge/installed-skills/<name>/, quarantining executables
 11  write the security report
 12  write skills.lock
```

Fetching uses `git`, not an HTTP client. DevForge imports no HTTP library and a test
enforces that. Git gives commit pinning natively, keeps TLS and archive handling out
of our address space, and routes through the same command policy as anything else -
`git clone` is **refused by the default policy** and must be permitted deliberately.

## Risk levels

| Level | Rule | Result |
| --- | --- | --- |
| `LOW` | Static instructions only | installs |
| `MEDIUM` | Local scripts, file writes, environment reads | needs `--approve-by` |
| `HIGH` | Network **and** execution, package installation, obfuscation, hooks | needs `--approve-by` |
| `CRITICAL` | Credential access, or piping content into an interpreter | **refused outright** |

The default ceiling is `LOW`: anything more capable than instructions is a decision
someone has to sign for, and the signature is recorded in `skills.lock`.

## Pins never move on their own

`install` on an already-installed skill refuses and points at `update`. `update`
requires an explicit `--commit` or `--to-head`, reports what changed (commit, content
hash, risk level, licence) and re-runs the whole pipeline against the new tree. A
skill that turns hostile between commits is caught at the new commit, and a refused
update leaves the old pin in place.

`devforge skill list --verify` re-hashes installed trees and reports drift - the case
the lockfile exists to catch: content changing under a pin that still reads fine.

## Installation is not activation

Installed skills land in `.devforge/installed-skills/`, which is discovered **last**,
after the project's own `.devforge/skills/` and `./skills/`. A project can always
override a skill it installed rather than being stuck with it. Consumption-time trust
enforcement (Phase 1) still applies: a skill with a critical finding fails the step
rather than being silently dropped.

## Licences

`detect_license` reads the LICENSE file and matches only identifiers whose text is
unmistakable; anything else is `None`, because "unknown" is useful and a wrong SPDX id
is not. The detected licence goes into the lockfile and the report.

DevForge **vendors nothing**. Skills are fetched at a pin into the consuming project;
this repository contains no third-party skill content. `THIRD_PARTY_NOTICES.md`
records the terms of every source the catalogue points at, including the share-alike
ones that are usable as installed instructions but must not be copied into DevForge's
own documentation.

## Quality scoring

Nine dimensions, ten points each, none of them popularity: maintenance, activity,
documentation, tests, licence, portability, security posture, dependency risk,
capability coverage. Every dimension records *why* it scored what it did, and a
dimension with no evidence scores a neutral 5 and says so rather than inventing a
number.

The argument against stars is in the data: the most-starred source in the Phase 0
survey ships auto-executing session hooks; the least-starred ships CODEOWNERS, a
pre-commit config and a security policy.

## What this does not protect against

- **Signature verification is not implemented.** A commit SHA proves the tree matches
  what the host served for that identifier; it does not prove who wrote it. A
  compromised maintainer account produces a valid pin.
- **Static inspection cannot decide intent.** A hostile instruction phrased in prose
  no pattern matches will score LOW. That is why nothing is executed.
- **The catalogue is curated by hand.** An entry means someone verified where the
  skill lives, not that anyone read it. `security_status: unaudited` is the default
  and means exactly that.
- **`--with-scripts` is a real decision.** It puts executables in the active tree
  where a human might run them. DevForge still will not, but a person might.
- **No sandbox.** Unchanged from every other phase: `git` runs as you.

## Operating advice

1. `devforge skill search <query>` - offline, reads the catalogue.
2. `devforge skill audit <name>` - fetches and inspects, installs nothing. Read the
   report.
3. `devforge skill install <name>` - only after the audit says something you accept.
4. Commit `skills.lock`. It is the record of what was installed, at what commit, at
   what content hash, at what risk, approved by whom.
5. Re-audit before every `update`. The pipeline does it anyway; read the diff it
   prints.
