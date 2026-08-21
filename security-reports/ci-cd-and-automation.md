# Skill security report: ci-cd-and-automation

- **Risk level:** HIGH
- **Repository:** https://github.com/addyosmani/agent-skills
- **Commit:** `df1edb2e05487d0aa6d93c747141e0aed1187f25`
- **Content hash:** `sha256:706d42c02e056cfd0509172fa294ecbdec8509aac9dc25862310800892709d9d`
- **License:** MIT
- **Files scanned:** 1
- **Assessed:** 2026-08-21T06:12:15.316400+00:00
- **Quality:** B (62/90); weakest: tests, security_posture

## Verdict

- can execute code that was not in the reviewed tree: ['install-command']

## Capabilities demonstrated by the content

- mentions a credential location
- package installation

## Findings

critical=0 high=6 medium=3 low=0

| severity | rule | location | detail |
| --- | --- | --- | --- |
| high | install-command | `SKILL.md:82` | installs packages; no trust tier grants install commands |
| high | install-command | `SKILL.md:126` | installs packages; no trust tier grants install commands |
| high | install-command | `SKILL.md:150` | installs packages; no trust tier grants install commands |
| high | install-command | `SKILL.md:338` | installs packages; no trust tier grants install commands |
| high | install-command | `SKILL.md:347` | installs packages; no trust tier grants install commands |
| high | install-command | `SKILL.md:356` | installs packages; no trust tier grants install commands |
| medium | credential-reference | `SKILL.md:274` | mentions a credential location; worth reading in context, not a refusal by itself |
| medium | credential-reference | `SKILL.md:275` | mentions a credential location; worth reading in context, not a refusal by itself |
| medium | credential-reference | `SKILL.md:276` | mentions a credential location; worth reading in context, not a refusal by itself |

## What this report is not

A clean report is not proof of safety. Static inspection cannot decide intent,
and natural-language instructions can be hostile without matching any pattern.
DevForge never executes skill content, which is the control that does not depend
on this report being right.
