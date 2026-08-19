# Skill ecosystem research

**Survey date:** 2026-08-19
**Method:** GitHub REST API — `repos`, `contents`, `git/trees?recursive=1`, `search/repositories`.
Star counts, licenses, HEAD commits and file inventories were read from the API, not from
READMEs or third-party lists.
**Machine-readable form:** [`registry/skills.yaml`](../registry/skills.yaml)

## What was not done

Stated first, so nothing here is over-read:

- **No CVE or advisory lookup.** "No known issues" below means the repository issue
  metadata we read showed nothing relevant — not that anything was audited.
- **No dynamic analysis.** Nothing was cloned, installed, or executed.
- **No line-by-line review.** File inventories are extension counts, not code review.
- **Point-in-time.** Star counts and issue counts drift; the commit SHA is the durable field.

Every claim below is either linked to an API observation or explicitly marked unverified.

---

## Summary

| Source | Stars | License | Last push | Disposition | Deciding factor |
| --- | --- | --- | --- | --- | --- |
| [anthropics/skills](https://github.com/anthropics/skills) | 170,394 | none at root; Apache-2.0 per skill | 2026-08-18 | **reference** | Root license ambiguity + 70 Python scripts |
| [obra/superpowers](https://github.com/obra/superpowers) | 273,950 | MIT | 2026-08-13 | **reference** | Session-start hooks execute automatically |
| [trailofbits/skills](https://github.com/trailofbits/skills) | 6,663 | CC-BY-SA-4.0 | 2026-08-19 | **reference** | Share-alike would propagate to our docs |
| [addyosmani/agent-skills](https://github.com/addyosmani/agent-skills) | 88,495 | MIT | 2026-08-14 | **reference** | Best taxonomy fit; surface not yet inventoried |
| [nextlevelbuilder/ui-ux-pro-max-skill](https://github.com/nextlevelbuilder/ui-ux-pro-max-skill) | 118,086 | MIT | 2026-08-18 | **reference** | Heavy clone proliferation; pin by URL+SHA |
| [vercel-labs/agent-skills](https://github.com/vercel-labs/agent-skills) | 30,202 | **none** | 2026-08-18 | **rejected** | Opaque .zip bundles + credential skill + no license |

**Nothing is vendored. Nothing is auto-installed. Every source starts `untrusted`.**

---

## anthropics/skills

**Anthropic (Organization) · 170,394 ★ · 20,273 forks · 1,120 open issues · created 2025-09-22**
**Pin:** `0a64e398ec6bb34a494f0c347e8ccae53a862f8e` (2026-08-18)

19 skills: `academy-guide`, `algorithmic-art`, `brand-guidelines`, `canvas-design`,
`claude-api`, `discernment-nudge`, `doc-coauthoring`, `docx`, `frontend-design`,
`internal-comms`, `mcp-builder`, `pdf`, `pptx`, `skill-creator`, `slack-gif-creator`,
`theme-factory`, `web-artifacts-builder`, `webapp-testing`, `xlsx`.

This single repository answers two of the categories the brief asked about:
`webapp-testing` is the Playwright/browser skill, and `mcp-builder` is the MCP skill.
Both come from the vendor that defined the skill format, which is as good as provenance
gets in this ecosystem.

**Licensing is subtler than it looks.** There is no `LICENSE` file at the repository
root — the GitHub API reports no license, and the root holds only `.gitignore`,
`README.md` and `THIRD_PARTY_NOTICES.md`. Individual skills ship their own:
`skills/webapp-testing/LICENSE.txt` is Apache-2.0, and the SKILL.md frontmatter says
`license: Complete terms in LICENSE.txt`. So licensing must be resolved **per skill**,
which the registry schema supports (`license.per_skill_license`).

**Inventory:** 508 files — 70 `.py`, 2 `.sh`, 1 `.js`, no archives.

**The finding that shaped our threat model.** `skills/webapp-testing/SKILL.md` says:

> Always run scripts with `--help` first to see usage. **DO NOT read the source until you
> try running the script first** and find that a customized solution is absolutely necessary.

Read charitably this is about token economy, and from this publisher the code is very
likely fine. But as a *pattern* it is an instruction, embedded in fetched content, telling
an agent to execute code before inspecting it. That is the exact inversion of the
inspection model, and DevForge's inspector flags this class of instruction
(`execute-before-read`) regardless of who publishes it. Trusting the publisher is a
decision a human records in the registry, not something the content gets to assert.

**Concerns:** execute-before-read instruction (high) · 70-script surface (medium) ·
root license ambiguity (medium).
**Disposition: reference.** Best-in-class for format and for the browser/MCP categories.
Using its scripts requires an audit and promotion to the `audited` tier.

---

## obra/superpowers

**obra / Jesse Vincent (User) · 273,950 ★ · 24,522 forks · 288 open issues**
**Pin:** `b36e0829c6d0140e93cfef2ca599b1b07d4a7797` (2026-08-12) · **MIT**

The most-starred source surveyed, and the closest philosophical relative of DevForge.
14 skills, several of which are effectively the same thesis: `test-driven-development`,
`verification-before-completion`, `systematic-debugging`, `requesting-code-review`,
`receiving-code-review`, `writing-plans`, `executing-plans`, `brainstorming`,
`subagent-driven-development`, `dispatching-parallel-agents`, `using-git-worktrees`,
`finishing-a-development-branch`, `writing-skills`, `using-superpowers`.

`verification-before-completion` states the same rule DevForge enforces mechanically:
do not declare work done on an agent's say-so. Worth reading as prior art on *phrasing*;
DevForge's contribution is that a verifier, not a paragraph, decides.

**Broadest agent support found:** plugin directories for Claude Code, Codex, Cursor,
Devin, Hermes, Kimi, OpenCode, plus `GEMINI.md` and `gemini-extension.json`. This is the
one source with real evidence of cross-runtime portability, which matters for a
runtime-agnostic harness.

**Inventory:** 255 files — 41 `.sh`, 10 `.js`, 6 `.py`, 2 `.mjs`, 2 `.ts`, 1 `.cmd`.
The largest shell surface of any source reviewed.

**The blocking concern is hooks.** `hooks/hooks.json`, `hooks/hooks-cursor.json`,
`hooks/run-hook.cmd` and `hooks/session-start` run automatically when an agent session
starts. Automatic execution at session start is code execution with no per-invocation
decision point — there is no gate to place. DevForge therefore consumes **instruction
text only** and never installs a plugin wholesale. MIT would permit vendoring the
Markdown with attribution; the hooks are simply out of scope.

**Concerns:** session-start hook execution (high) · 41 shell scripts (medium) ·
single-maintainer bus factor and account-compromise blast radius (medium).
**Disposition: reference.**

---

## trailofbits/skills

**Trail of Bits (Organization) · 6,663 ★ · 27 open issues**
**Pin:** `07bce8a2c8ccc56c5b44b7067a04b8bf46128f05` (2026-08-19) · **CC-BY-SA-4.0**

41 plugins. The security-relevant set: `supply-chain-risk-auditor`, `static-analysis`,
`semgrep-rule-creator`, `semgrep-rule-variant-creator`, `variant-analysis`,
`vulnerability-triage-brocards`, `differential-review`, `insecure-defaults`,
`agentic-actions-auditor`, `zeroize-audit`, `yara-authoring`, `c-review`, `rust-review`.
Testing: `mutation-testing`, `property-based-testing`, `spec-to-code-compliance`.
Repository hygiene is visible in the layout — `CODEOWNERS`, `.pre-commit-config.yaml`,
`ruff.toml`, `Makefile`.

Lowest star count here and the highest institutional credibility: a security firm
publishing under its own organization account, with an actively maintained curated
marketplace alongside (`trailofbits/skills-curated`, 488 ★, pinned in the registry).
Popularity is not a security signal, which is the point.

`supply-chain-risk-auditor` and `agentic-actions-auditor` are direct prior art for what
DevForge is building in `devforge.supplychain`. Reading them is on the Phase 1 list.

**License is the deciding factor.** CC-BY-SA-4.0 is share-alike over *content*. Copying
this text into DevForge would impose CC-BY-SA obligations on derived documentation in an
MIT project. Reference, never vendor — a legal constraint, not a quality judgement.

**Mirror proliferation is documented, not hypothetical.** Search surfaces
`botnotstrawberry/trailofbits-skills`, `RUSHYOP/mirror-trailofbits-skills` and
`chenxihuang1028-a11y/variant-analysis` ("redistributed from Trail of Bits"), all
carrying the CC-BY-SA license string. A name- or license-based resolver would happily
install any of them.

**Concerns:** share-alike license (medium) · external tool invocation, contained by the
shell allowlist (low) · mirror proliferation (medium).
**Disposition: reference.**

---

## addyosmani/agent-skills

**addyosmani / Addy Osmani (User) · 88,495 ★ · MIT**
**Pin:** `df1edb2e05487d0aa6d93c747141e0aed1187f25` (2026-08-14)

24 skills, and the closest taxonomy match to DevForge's own: `api-and-interface-design`,
`browser-testing-with-devtools`, `ci-cd-and-automation`, `code-review-and-quality`,
`code-simplification`, `context-engineering`, `debugging-and-error-recovery`,
`deprecation-and-migration`, `documentation-and-adrs`, `doubt-driven-development`,
`frontend-ui-engineering`, `git-workflow-and-versioning`, `idea-refine`,
`incremental-implementation`, `interview-me`, `observability-and-instrumentation`,
`performance-optimization`, `planning-and-task-breakdown`, `security-and-hardening`,
`shipping-and-launch`, `source-driven-development`, `spec-driven-development`,
`test-driven-development`, `using-agent-skills`.

This is the **only credible source found for the DevOps/CI-CD category**
(`ci-cd-and-automation`, `observability-and-instrumentation`, `shipping-and-launch`).

**Concerns:** single maintainer with very high reach — an account compromise would have
an unusually wide blast radius (medium) · executable surface not yet inventoried, so
"predominantly markdown" is an impression, not a verified fact (low).
**Disposition: reference**, pending an inventory pass before anything beyond reading.

---

## nextlevelbuilder/ui-ux-pro-max-skill

**NextLevelBuilder (Organization) · 118,086 ★ · MIT · v2.13.0**
**Pin:** `8a1a6d857332da32252d77365da90c3f6293b47b` (2026-08-18)

One large skill: by its own `skill.json`, 84 UI styles, 192 color palettes, 74 font
pairings, 98 UX guidelines and 25 chart types across 22 stacks. Ships `.claude-plugin/`,
`cli/`, `scripts/`, `src/`, `stack/` and points at an external homepage (`uupm.cc`).

**The best available illustration of name-based resolution failing.** Search returns
`bbylw/ui-ux-pro-max-skill-cn` (1,314 ★), `ganavisk/nextlevelbuilder-ui-ux-pro-max-skill-Public`
(143 ★), `dualseason/ui-ux-pro-max-skill` (30 ★) and aggregator repos claiming to bundle
"7000+ skills". Some are honest translations. Any of them could not be. A resolver keyed
on `ui-ux-pro-max` picks by luck; DevForge resolves by canonical URL **plus commit SHA**,
which is a coincidence-free identifier.

**Concerns:** clone/typosquat proliferation (high) · bundled CLI is executable code
(medium) · content served from an external homepage sits outside the pin (low).
**Disposition: reference.**

---

## vercel-labs/agent-skills — REJECTED

**Vercel Labs (Organization) · 30,202 ★ · 172 open issues · no LICENSE file**
**Pin:** `b8caa260a420a73042e35521de4b5c8baf6446cc` (2026-08-12)

Skills: `composition-patterns`, `deploy-to-vercel`, `react-best-practices`,
`react-native-skills`, `react-view-transitions`, `vercel-cli-with-tokens`,
`vercel-optimize`, `web-design-guidelines`, `writing-guidelines`.

**Inventory:** 475 files — 155 `.mjs`, 8 `.ts`, 2 `.sh`, and **6 `.zip` archives**.

Rejected on risk profile, not quality. Five factors compound:

1. **Opaque archives.** Six `.zip` bundles are committed next to their unpacked
   directories. An archive defeats diff review — the reviewed source and the shipped
   artefact can diverge silently, and a content hash over the zip tells you it changed
   without telling you how. The DevForge inspector rejects archives categorically.
2. **A credential-handling skill.** `vercel-cli-with-tokens` is about API tokens by
   name and purpose. Anything that touches credentials is high risk by construction.
3. **Real-world side effects.** `deploy-to-vercel` performs outward-facing actions.
4. **Off-GitHub installer.** Installation flows through `skills.sh` (per
   `skills.sh.json`), a service outside the GitHub provenance path.
5. **No license.** Redistribution terms are undetermined; vendoring would be unsound.

Individually each is manageable. Together they are the exact profile the supply-chain
model exists to refuse. Revisit if a license appears, the archives are dropped, and the
credential skill is quarantined.

---

## Aggregator lists

`ComposioHQ/awesome-claude-skills` (72,785 ★), `travisvn/awesome-claude-skills`
(14,714 ★), `BehiSecc/awesome-claude-skills` (10,013 ★), `karanb192/awesome-claude-skills`
(491 ★, MIT, claims "50+ verified").

Useful for **discovery only**. Inclusion in a list is a popularity signal, never a
security signal, and most carry no license of their own. `trailofbits/skills-curated` is
the only one with a stated vetting process — still an input to review, not a substitute.

They are recorded in `registry/skills.yaml` under `discovery_sources`, structurally
separated from `sources`, so nothing can accidentally resolve a skill from a list.

---

## Gaps — recorded, not filled

**Kubernetes / cloud operations.** No reputable dedicated source surfaced. Closest is
`ci-cd-and-automation` in `addyosmani/agent-skills`. Adopting a weak repository to fill
the slot would be worse than the gap.

**Agent evaluation harnesses.** No established skill-level evaluation or benchmarking
source found. Testing *content* exists (superpowers TDD, Trail of Bits mutation and
property-based testing); evaluating the *agent* is unserved. DevForge's verification
layer covers this need internally for now.

---

## Cross-cutting observations

**1. Popularity and trustworthiness are uncorrelated.** The most-starred source ships
auto-executing hooks. The least-starred is from a security firm with CODEOWNERS and
pre-commit hygiene.

**2. Licensing is unresolved across the ecosystem.** Two of six sources have no root
license; one licenses per skill; one is share-alike. Any tool that installs skills
without recording license terms is creating obligations its users cannot see.

**3. Skills are code, whatever the format claims.** Across the six sources: 70 Python
scripts, 41 shell scripts, 155 `.mjs` files, auto-executing session hooks, bundled CLIs
and six opaque archives. "It is just Markdown" is false in every case reviewed.

**4. Instructions are an attack surface in their own right.** Even the vendor's own
repository contains an instruction that tells an agent to execute before reading. Skill
*text* is untrusted input, not just skill *code*.

**5. Install mechanisms bypass provenance.** Three distinct mechanisms observed
(`.claude-plugin/marketplace.json`, `skills.sh`, plain `git clone`), and none of them
pins a commit by default.

---

## What DevForge does with this

| Observation | Mechanism |
| --- | --- |
| Clones and mirrors are everywhere | Resolve by canonical URL **plus commit SHA**, never by name |
| Skills contain executable code | `untrusted` tier forbids scripts; promotion requires an audit |
| Instructions can be adversarial | Inspector flags `execute-before-read`, `curl-pipe-shell`, credential access |
| Archives defeat review | Inspector rejects archives outright |
| Licenses are missing or share-alike | License recorded per source; missing license blocks vendoring |
| Aggregator lists are not vetting | `discovery_sources` structurally separate from `sources` |

Full design: [security/skill-supply-chain.md](security/skill-supply-chain.md).
Threats and assumptions: [security/threat-model.md](security/threat-model.md).

## Re-survey cadence

Quarterly, or on any of: a pinned source changing license; a new disposition request; a
published advisory affecting a listed source. Each re-survey updates the pin and the
`verified_at` field. **A stale pin is not a vulnerability — an unpinned source is.**
