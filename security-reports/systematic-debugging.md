# Skill security report: systematic-debugging

- **Risk level:** MEDIUM
- **Repository:** https://github.com/obra/superpowers
- **Commit:** `b36e0829c6d0140e93cfef2ca599b1b07d4a7797`
- **Content hash:** `sha256:5fb75988dc5a451de5706c345ae32cb3b520a9df9dbd33d09aab5c3a2cf691b9`
- **License:** MIT
- **Files scanned:** 11
- **Assessed:** 2026-08-21T06:15:39.827439+00:00
- **Quality:** B (71/90); weakest: security_posture

## Verdict

- ships capability beyond instructions: ['credential-reference', 'executable-script']

## Capabilities demonstrated by the content

- local script execution
- mentions a credential location

## Findings

critical=0 high=0 medium=4 low=0

| severity | rule | location | detail |
| --- | --- | --- | --- |
| medium | executable-script | `condition-based-waiting-example.ts` | executable code, not instruction content; forbidden below the audited tier |
| medium | credential-reference | `defense-in-depth.md:58` | mentions a credential location; worth reading in context, not a refusal by itself |
| medium | executable-script | `find-polluter.sh` | executable code, not instruction content; forbidden below the audited tier |
| medium | credential-reference | `root-cause-tracing.md:77` | mentions a credential location; worth reading in context, not a refusal by itself |

## What this report is not

A clean report is not proof of safety. Static inspection cannot decide intent,
and natural-language instructions can be hostile without matching any pattern.
DevForge never executes skill content, which is the control that does not depend
on this report being right.
