# Skill supply-chain security

**Premise: a third-party skill is untrusted code.**

Not "untrusted content that might contain code" — untrusted code. The survey behind
[skill-ecosystem.md](../skill-ecosystem.md) found, across six well-known sources: 70
Python scripts, 41 shell scripts, 155 `.mjs` files, session-start hooks that execute
automatically, bundled CLIs, and six opaque `.zip` archives. It also found an instruction
in a first-party repository telling the agent to run a script *before* reading it.

A skill can therefore carry shell commands, scripts, installers, network access, file
writes, and — most importantly — **instructions to an agent that holds tool
permissions**. The instruction channel needs the same suspicion as the code channel.

---

## The model in one line

**Identity is a URL plus a commit SHA. Trust is a tier a human grants. Consumption is
gated by that tier. Everything is recorded.**

---

## 1. Provenance

A source is identified by fields that cannot be spoofed by naming:

| Field | Purpose | Verified how |
| --- | --- | --- |
| `repository` | Canonical URL — the only identity that counts | Recorded, compared exactly |
| `maintainer.type` | Organization vs User — different compromise profiles | GitHub API |
| `pin.commit` | Full 40-hex SHA. **Immutable content identity** | GitHub API |
| `pin.verified_at` | When a human last confirmed the pin | Recorded |
| `content_hash` | SHA-256 over the fetched tree, computed locally | Computed at fetch |
| `license.spdx` | Redistribution terms | GitHub API + file check |
| `install_mechanism` | How upstream expects to be installed | Repository inspection |

**Names are never identity.** `ui-ux-pro-max-skill` resolves to at least four
repositories; `trailofbits/skills` has at least three mirrors carrying its license text.
A resolver keyed on names picks by luck.

**Why both SHA and content hash?** The SHA is upstream's claim about content; the content
hash is ours, computed over what we actually received. They answer different questions —
"did we ask for the right thing" and "did we get what we asked for". The second one
survives a compromised transport or a rewritten tag.

**Tags and branches are never pins.** Both are mutable. `main` today is not `main`
tomorrow, and a tag can be moved.

---

## 2. Trust tiers

Tiers are DevForge policy about what a source may *do here*. They are not a rating of the
upstream project — Anthropic's skills sit at `untrusted` today because nobody has
recorded a review, not because they are suspect.

| Tier | Scripts | Network | Install cmds | Approval | Entry condition |
| --- | --- | --- | --- | --- | --- |
| `untrusted` | ✗ | ✗ | ✗ | required | **Default for everything new** |
| `reviewed` | ✗ | ✗ | ✗ | required | A human read the instruction content and recorded it |
| `audited` | ✓ | ✗ | ✗ | required | Content reviewed **and** executable surface audited at the pin |
| `first_party` | ✓ | ✗ | ✗ | not required | Ships inside DevForge |

Rules:

- Promotion is **manual, per source, per pin**. It is a registry edit by a human.
- Any pin change **demotes to `untrusted`**. Trust attaches to reviewed bytes, not to a
  repository name. This is the property that makes ADV2 (compromised maintainer pushing
  to an already-trusted repo) expensive rather than free.
- No tier grants network access. Nothing in a skill needs to phone home.
- No tier grants install commands. DevForge does not install packages, ever.

---

## 3. Permission declaration

A skill declares what it needs; the tier decides whether it may have it. A declaration is
a *claim*, useful for review and for detecting mismatch — never a grant.

```yaml
permissions:
  filesystem: { read: [src/**], write: [tests/**] }
  shell: { commands: ["pytest*"] }
  network: false
  scripts: false
```

The inspector compares the declaration to observed content. **Undeclared capability is a
finding**: a skill that declares `scripts: false` and ships `install.sh` is either
careless or lying, and both warrant refusal.

---

## 4. Install-time inspection

Static, local, deterministic, no execution. Implemented in
`devforge/supplychain/inspect.py`; every check below is exercised by
`tests/test_supplychain.py`.

**Structural**

| Check | Severity | Rationale |
| --- | --- | --- |
| Archive present (`.zip`, `.tar*`, `.gz`, `.whl`) | high | Defeats diff review; content can diverge from the reviewed source |
| Hook manifest (`hooks.json`, `session-start`, `.claude-plugin/plugin.json`) | high | Executes with no per-invocation decision point |
| Executable scripts (`.py`, `.sh`, `.js`, `.mjs`, `.ts`, `.cmd`, `.ps1`) | medium | Code, not instructions |
| Binary or non-UTF-8 files | medium | Unreviewable |
| Missing `SKILL.md` frontmatter | low | Not a well-formed skill |

**Content patterns**

| Pattern | Severity | Example |
| --- | --- | --- |
| Pipe-to-shell | critical | `curl … \| sh`, `wget … \| bash`, `iwr … \| iex` |
| Credential path reference | critical | `.env`, `~/.ssh`, `id_rsa`, `.aws/credentials`, `.npmrc` |
| Install command | high | `pip install`, `npm install`, `uv add`, `cargo install` |
| Execute-before-read instruction | high | "do not read the source", "run it first" |
| Exfiltration shape | high | `curl -d`, `POST` to a literal external URL |
| Encoded payload | high | `base64 -d`, `eval(atob(`, long opaque blobs |
| Destructive command | high | `rm -rf`, `git push --force`, `DROP TABLE` |
| Instruction-override phrasing | medium | "ignore previous instructions", "you are now" |
| Network fetch | medium | `curl`, `fetch(`, `requests.get` |
| Undeclared capability | medium | Declaration contradicts observed content |

Findings are **advisory to a human**, not an automatic verdict — except `critical`, which
refuses outright. A pattern list cannot decide intent, and pretending otherwise would be
the same over-claim this project exists to avoid.

---

## 5. Approval

Every skill installation is an approval gate. There is no `auto_approve` path for skill
installation, and the gate prompt shows: source, pin, license, tier, finding counts by
severity, and every `critical`/`high` finding in full.

Re-approval is required when the pin changes, the declaration changes, or a new finding
appears. **Approving a skill approves one exact tree, once.**

---

## 6. Audit log

Structured events on the existing observability path
(`.devforge/runs/<task_id>/events.jsonl`):

```json
{"event":"skill.inspect","source":"anthropics-skills","pin":"0a64e39…",
 "content_hash":"sha256:…","findings":{"critical":0,"high":2,"medium":5},"decision":"pending"}
{"event":"skill.approve","source":"anthropics-skills","pin":"0a64e39…","by":"thanh"}
{"event":"skill.load","source":"anthropics-skills","skill":"webapp-testing","tier":"reviewed"}
{"event":"skill.reject","source":"vercel-agent-skills","reason":"archive_present","severity":"high"}
```

**Limitation, stated plainly:** the log is a plain local file with no signing and no
append-only guarantee. Anything running as the user can rewrite it (threat T8). An
append-only hash-chained journal is Phase 2.

---

## 7. What is deliberately NOT implemented

**There is no installer.** No code path fetches a skill, and none runs one. This is the
strongest control available and it costs nothing — an attack that needs code execution at
install time has no reachable entry point.

Consequently there is **no dynamic installation, no marketplace client, no
`skills.sh` integration, no `.claude-plugin` support, and no automatic updates.**
Adoption today means: a human reads the source, decides, and either references it in
documentation or copies specific content in under an explicit license.

The registry, inspector and tier model exist so that when an installer is eventually
built, the controls precede it rather than being retrofitted.

---

## 8. Vendor / reference / reject

**Vendor** (copy in at a pin) requires *all* of: permissive license (MIT/Apache-2.0/BSD),
no executable content or an audited one, a recorded review, attribution in
`THIRD_PARTY_NOTICES.md`, and the pin in `registry/skills.yaml`.
*Today: nothing is vendored.*

**Reference** (document, fetch on demand) — the default. Costs nothing, creates no
license obligation, adds no attack surface.
*Today: five of six sources.*

**Reject** — recorded with a reason, because "we looked and said no" is more useful than
silence. *Today: `vercel-labs/agent-skills` — opaque archives, a credential-handling
skill, a deployment skill, an off-GitHub installer, no license.*

---

## 9. Operational flow

```
   candidate source
        │
   ┌────▼─────┐  URL + SHA, never a name
   │ identify │  → typosquat and mirror substitution fail here
   └────┬─────┘
   ┌────▼─────┐  license, maintainer type, activity, HEAD
   │ evidence │  → recorded in registry/skills.yaml
   └────┬─────┘
   ┌────▼─────┐  static, local, no execution
   │ inspect  │  → critical finding = refuse
   └────┬─────┘
   ┌────▼─────┐  human sees source, pin, license, findings
   │ approve  │  → no auto-approve path exists
   └────┬─────┘
   ┌────▼─────┐  untrusted → reviewed → audited
   │  tier    │  → pin change demotes to untrusted
   └────┬─────┘
   ┌────▼─────┐  instructions only, unless tier allows more
   │ consume  │  → every step emits an event
   └──────────┘
```

## 10. Checklist for adding a source

- [ ] Canonical URL confirmed — owner account checked, not just the name
- [ ] HEAD commit SHA recorded with the date
- [ ] License determined; per-skill licenses checked if there is no root LICENSE
- [ ] Executable surface inventoried (`git/trees?recursive=1`)
- [ ] Install mechanism identified
- [ ] Inspector run; findings recorded
- [ ] Disposition and rationale written down
- [ ] Trust tier set (`untrusted` unless a review is recorded)
- [ ] Entry added to `registry/skills.yaml`; `devforge registry verify` passes
