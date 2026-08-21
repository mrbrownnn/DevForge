# Third-party notices

## What this file records

DevForge **vendors no third-party code**. This repository contains no skill content
from any source listed below. Skills are fetched at a pinned commit into the
*consuming* project, hashed, inspected and installed there — see
[docs/security/skills.md](docs/security/skills.md).

This file therefore records two things:

1. **The terms of every source `registry/catalog.yaml` points at**, so anyone
   installing from the catalogue knows what they are agreeing to.
2. **Which of those terms would prevent copying content into DevForge itself.**

Licences were read from each repository's LICENSE file at the pinned commit, not
inferred from a repository's metadata badge. Where a repository has no root LICENSE,
that is recorded as such rather than guessed.

Verified 2026-08-19 against the pinned commits below.

---

## Runtime dependencies of DevForge itself

| Package | Licence | Role |
| --- | --- | --- |
| [pydantic](https://github.com/pydantic/pydantic) | MIT | Schema validation at every boundary |
| [typer](https://github.com/fastapi/typer) | MIT | CLI |
| [PyYAML](https://github.com/yaml/pyyaml) | MIT | Workflows, policies, registries (`safe_load` only) |
| [rich](https://github.com/Textualize/rich) | MIT | Terminal rendering |

Optional extra:

| Package | Licence | Role |
| --- | --- | --- |
| [playwright](https://github.com/microsoft/playwright-python) | Apache-2.0 | Browser tool (`devforge[browser]`) |

Development only: pytest (MIT), pytest-asyncio (Apache-2.0), ruff (MIT).

---

## Skill sources in the catalogue

### anthropics/skills

- **Repository:** https://github.com/anthropics/skills
- **Pin:** `0a64e398ec6bb34a494f0c347e8ccae53a862f8e`
- **Licence:** no root LICENSE file. Individual skills ship their own —
  `skills/webapp-testing/LICENSE.txt` is **Apache-2.0**, and the SKILL.md frontmatter
  points at it.
- **Consequence:** licensing must be resolved **per skill**, not per repository. The
  catalogue records the per-skill licence, and `detect_license` re-reads it from the
  fetched tree at install time rather than trusting the catalogue.
- **Catalogued skills:** `webapp-testing`, `mcp-builder`, `skill-creator`

### obra/superpowers

- **Repository:** https://github.com/obra/superpowers
- **Pin:** `b36e0829c6d0140e93cfef2ca599b1b07d4a7797`
- **Licence:** **MIT**
- **Consequence:** permissive; vendoring would be legally simple. DevForge still does
  not vendor it — the repository ships session-start hooks, and DevForge installs
  skill content only.
- **Catalogued skills:** `test-driven-development`, `systematic-debugging`,
  `verification-before-completion`

### trailofbits/skills

- **Repository:** https://github.com/trailofbits/skills
- **Pin:** `07bce8a2c8ccc56c5b44b7067a04b8bf46128f05`
- **Licence:** **CC-BY-SA-4.0**
- **Consequence — the one that constrains DevForge:** share-alike applies to
  *content*. Copying this text into DevForge's own documentation would impose
  CC-BY-SA obligations on the derived work, which is why nothing from this source
  appears in `docs/`. Installing it into a consuming project is a different act and
  is fine; the licence travels with the installed tree and is recorded in
  `skills.lock`.
- **Attribution:** Trail of Bits, https://github.com/trailofbits/skills
- **Catalogued skills:** `supply-chain-risk-auditor`, `semgrep-rule-creator`,
  `mutation-testing`

### addyosmani/agent-skills

- **Repository:** https://github.com/addyosmani/agent-skills
- **Pin:** `df1edb2e05487d0aa6d93c747141e0aed1187f25`
- **Licence:** **MIT**
- **Catalogued skills:** `api-and-interface-design`, `ci-cd-and-automation`,
  `observability-and-instrumentation`

### nextlevelbuilder/ui-ux-pro-max-skill

- **Repository:** https://github.com/nextlevelbuilder/ui-ux-pro-max-skill
- **Pin:** `8a1a6d857332da32252d77365da90c3f6293b47b`
- **Licence:** **MIT** (declared in `skill.json`, v2.13.0)
- **Note:** at least four repositories answer to this skill's name. The canonical URL
  plus the commit pin is the only thing that distinguishes the real one; a
  name-keyed resolver would pick by luck.
- **Catalogued skills:** `ui-ux-pro-max`

### vercel-labs/agent-skills — REJECTED

- **Repository:** https://github.com/vercel-labs/agent-skills
- **Pin:** `b8caa260a420a73042e35521de4b5c8baf6446cc`
- **Licence:** **none** — no LICENSE file at the pinned commit. Redistribution terms
  are undetermined.
- **Catalogued as a refusal**, so the decision is visible rather than silent:
  six opaque `.zip` bundles committed alongside their unpacked directories, an
  off-GitHub installer, a deployment skill with real side effects, and a skill that
  handles API tokens by name. Installation is refused by
  `security_status: rejected`.

---

## Discovery aids (not sources)

Aggregator lists are recorded in `registry/skills.yaml` under `discovery_sources` and
are **not** installable. Most carry no licence of their own. Inclusion in such a list
is a popularity signal, never a security signal:

- ComposioHQ/awesome-claude-skills, travisvn/awesome-claude-skills,
  BehiSecc/awesome-claude-skills — no licence recorded
- trailofbits/skills-curated (CC-BY-SA-4.0, pin
  `6d05be4889017b06fb15069f371afd220daffb62`) — the only one with a stated vetting
  process, and still an input to review rather than a substitute for it

---

## If you vendor something later

`SkillEntry.license_permits_redistribution` and the registry's
`VENDORABLE_LICENSES` gate that decision in code: MIT, Apache-2.0, BSD-2/3-Clause and
ISC only. Share-alike and unlicensed sources fail the check, and
`SourceEntry` refuses a `vendor` disposition without both a permissive licence and a
recorded review. Add the notice here in the same change.
