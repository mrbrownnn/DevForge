# Skill security report: skill-creator

- **Risk level:** MEDIUM
- **Repository:** https://github.com/anthropics/skills
- **Commit:** `0a64e398ec6bb34a494f0c347e8ccae53a862f8e`
- **Content hash:** `sha256:9c34dd6bc9789d84af6c183fccb0c21af173eaabb0be6afa97ea03d0b754325c`
- **License:** Apache-2.0
- **Files scanned:** 18
- **Assessed:** 2026-08-21T06:15:10.466862+00:00
- **Quality:** B (62/90); weakest: tests, security_posture

## Verdict

- ships capability beyond instructions: ['credential-reference', 'executable-script']

## Capabilities demonstrated by the content

- local script execution
- mentions a credential location

## Findings

critical=0 high=0 medium=11 low=0

| severity | rule | location | detail |
| --- | --- | --- | --- |
| medium | executable-script | `eval-viewer/generate_review.py` | executable code, not instruction content; forbidden below the audited tier |
| medium | executable-script | `scripts/__init__.py` | executable code, not instruction content; forbidden below the audited tier |
| medium | executable-script | `scripts/aggregate_benchmark.py` | executable code, not instruction content; forbidden below the audited tier |
| medium | executable-script | `scripts/generate_report.py` | executable code, not instruction content; forbidden below the audited tier |
| medium | executable-script | `scripts/improve_description.py` | executable code, not instruction content; forbidden below the audited tier |
| medium | credential-reference | `scripts/improve_description.py:6` | mentions a credential location; worth reading in context, not a refusal by itself |
| medium | executable-script | `scripts/package_skill.py` | executable code, not instruction content; forbidden below the audited tier |
| medium | executable-script | `scripts/quick_validate.py` | executable code, not instruction content; forbidden below the audited tier |
| medium | executable-script | `scripts/run_eval.py` | executable code, not instruction content; forbidden below the audited tier |
| medium | executable-script | `scripts/run_loop.py` | executable code, not instruction content; forbidden below the audited tier |
| medium | executable-script | `scripts/utils.py` | executable code, not instruction content; forbidden below the audited tier |

## What this report is not

A clean report is not proof of safety. Static inspection cannot decide intent,
and natural-language instructions can be hostile without matching any pattern.
DevForge never executes skill content, which is the control that does not depend
on this report being right.
