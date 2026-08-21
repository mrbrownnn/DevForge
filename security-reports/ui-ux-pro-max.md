# Skill security report: ui-ux-pro-max

- **Risk level:** MEDIUM
- **Repository:** https://github.com/nextlevelbuilder/ui-ux-pro-max-skill
- **Commit:** `8a1a6d857332da32252d77365da90c3f6293b47b`
- **Content hash:** `sha256:1a3c885fdec745c84502abc4e5fe0829c91776b7459e3b363c94c7f26415cf11`
- **License:** MIT
- **Files scanned:** 70
- **Assessed:** 2026-08-21T06:13:36.395527+00:00
- **Quality:** A (72/90); weakest: security_posture

## Verdict

- ships capability beyond instructions: ['approval-bypass', 'executable-script']

## Capabilities demonstrated by the content

- local script execution
- safety-control bypass

## Findings

critical=0 high=0 medium=21 low=0

| severity | rule | location | detail |
| --- | --- | --- | --- |
| medium | approval-bypass | `SKILL.md:100` | asks for a safety control to be disabled |
| medium | approval-bypass | `SKILL.md:102` | asks for a safety control to be disabled |
| medium | approval-bypass | `SKILL.md:104` | asks for a safety control to be disabled |
| medium | executable-script | `scripts/core.py` | executable code, not instruction content; forbidden below the audited tier |
| medium | executable-script | `scripts/design_system.py` | executable code, not instruction content; forbidden below the audited tier |
| medium | approval-bypass | `scripts/design_system.py:1047` | asks for a safety control to be disabled |
| medium | executable-script | `scripts/reasoning_contract.py` | executable code, not instruction content; forbidden below the audited tier |
| medium | executable-script | `scripts/search.py` | executable code, not instruction content; forbidden below the audited tier |
| medium | approval-bypass | `scripts/search.py:24` | asks for a safety control to be disabled |
| medium | approval-bypass | `scripts/search.py:113` | asks for a safety control to be disabled |
| medium | executable-script | `scripts/tests/test_catalog_refresh.py` | executable code, not instruction content; forbidden below the audited tier |
| medium | executable-script | `scripts/tests/test_core.py` | executable code, not instruction content; forbidden below the audited tier |
| medium | executable-script | `scripts/tests/test_core_data_quality.py` | executable code, not instruction content; forbidden below the audited tier |
| medium | executable-script | `scripts/tests/test_data_contracts.py` | executable code, not instruction content; forbidden below the audited tier |
| medium | executable-script | `scripts/tests/test_design_system_mode.py` | executable code, not instruction content; forbidden below the audited tier |
| medium | executable-script | `scripts/tests/test_native_desktop_stack_freshness.py` | executable code, not instruction content; forbidden below the audited tier |
| medium | executable-script | `scripts/tests/test_relevance_evaluator.py` | executable code, not instruction content; forbidden below the audited tier |
| medium | executable-script | `scripts/tests/test_style_taxonomy.py` | executable code, not instruction content; forbidden below the audited tier |
| medium | executable-script | `scripts/tests/test_text_layout_resilience.py` | executable code, not instruction content; forbidden below the audited tier |
| medium | executable-script | `scripts/tests/test_web_stack_freshness.py` | executable code, not instruction content; forbidden below the audited tier |
| medium | executable-script | `scripts/validate_data.py` | executable code, not instruction content; forbidden below the audited tier |

## What this report is not

A clean report is not proof of safety. Static inspection cannot decide intent,
and natural-language instructions can be hostile without matching any pattern.
DevForge never executes skill content, which is the control that does not depend
on this report being right.
