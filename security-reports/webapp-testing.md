# Skill security report: webapp-testing

- **Risk level:** HIGH
- **Repository:** https://github.com/anthropics/skills
- **Commit:** `0a64e398ec6bb34a494f0c347e8ccae53a862f8e`
- **Content hash:** `sha256:ef3e69aa73063ebdc9a0d664d3eda416d5895bd1495290bb85d1ecb820408c3e`
- **License:** Apache-2.0
- **Files scanned:** 6
- **Assessed:** 2026-08-21T06:14:11.303003+00:00
- **Quality:** C (54/90); weakest: tests, security_posture, dependency_risk

## Verdict

- can execute code that was not in the reviewed tree: ['execute-before-read']

## Capabilities demonstrated by the content

- execute-before-review instruction
- local script execution

## Findings

critical=0 high=1 medium=4 low=0

| severity | rule | location | detail |
| --- | --- | --- | --- |
| high | execute-before-read | `SKILL.md:14` | instructs the agent to execute code before inspecting it |
| medium | executable-script | `examples/console_logging.py` | executable code, not instruction content; forbidden below the audited tier |
| medium | executable-script | `examples/element_discovery.py` | executable code, not instruction content; forbidden below the audited tier |
| medium | executable-script | `examples/static_html_automation.py` | executable code, not instruction content; forbidden below the audited tier |
| medium | executable-script | `scripts/with_server.py` | executable code, not instruction content; forbidden below the audited tier |

## What this report is not

A clean report is not proof of safety. Static inspection cannot decide intent,
and natural-language instructions can be hostile without matching any pattern.
DevForge never executes skill content, which is the control that does not depend
on this report being right.
