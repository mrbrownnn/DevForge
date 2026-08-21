# Skill security report: supply-chain-risk-auditor

- **Risk level:** HIGH
- **Repository:** https://github.com/trailofbits/skills
- **Commit:** `07bce8a2c8ccc56c5b44b7067a04b8bf46128f05`
- **Content hash:** `sha256:3cfb606fb9a3776e36885d8614ed7992fa409382a858232b918ee0e7fbaf0666`
- **License:** CC-BY-SA-4.0
- **Files scanned:** 13
- **Assessed:** 2026-08-21T06:16:34.023548+00:00
- **Quality:** B (62/90); weakest: security_posture

## Verdict

- credential access appears only in shipped scripts, which are quarantined and never executed by DevForge - treated as capability, not direction
- can execute code that was not in the reviewed tree: ['credential-env-read', 'install-command']

## Capabilities demonstrated by the content

- local script execution
- network access
- package installation
- reads credentials from the environment

## Findings

critical=1 high=3 medium=11 low=0

| severity | rule | location | detail |
| --- | --- | --- | --- |
| critical | credential-access | `scripts/sources.py:485` | instructs the agent to access credentials |
| high | install-command | `SKILL.md:62` | installs packages; no trust tier grants install commands |
| high | install-command | `scripts/collect.py:872` | installs packages; no trust tier grants install commands |
| high | install-command | `scripts/test_render.py:351` | installs packages; no trust tier grants install commands |
| medium | executable-script | `scripts/collect.py` | executable code, not instruction content; forbidden below the audited tier |
| medium | executable-script | `scripts/model.py` | executable code, not instruction content; forbidden below the audited tier |
| medium | executable-script | `scripts/render.py` | executable code, not instruction content; forbidden below the audited tier |
| medium | executable-script | `scripts/sources.py` | executable code, not instruction content; forbidden below the audited tier |
| medium | network-fetch | `scripts/sources.py:35` | reaches the network; no trust tier grants network access |
| medium | network-fetch | `scripts/sources.py:103` | reaches the network; no trust tier grants network access |
| medium | network-fetch | `scripts/sources.py:173` | reaches the network; no trust tier grants network access |
| medium | executable-script | `scripts/test_collect.py` | executable code, not instruction content; forbidden below the audited tier |
| medium | executable-script | `scripts/test_model.py` | executable code, not instruction content; forbidden below the audited tier |
| medium | executable-script | `scripts/test_render.py` | executable code, not instruction content; forbidden below the audited tier |
| medium | executable-script | `scripts/test_sources.py` | executable code, not instruction content; forbidden below the audited tier |

## What this report is not

A clean report is not proof of safety. Static inspection cannot decide intent,
and natural-language instructions can be hostile without matching any pattern.
DevForge never executes skill content, which is the control that does not depend
on this report being right.
