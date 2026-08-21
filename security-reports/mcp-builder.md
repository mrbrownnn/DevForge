# Skill security report: mcp-builder

- **Risk level:** HIGH
- **Repository:** https://github.com/anthropics/skills
- **Commit:** `0a64e398ec6bb34a494f0c347e8ccae53a862f8e`
- **Content hash:** `sha256:3edfbf3bc794bd4a979e8293507290c6d61dfc0263da4fa9e73ffca649f89712`
- **License:** Apache-2.0
- **Files scanned:** 10
- **Assessed:** 2026-08-21T06:14:45.751413+00:00
- **Quality:** B (58/90); weakest: tests, security_posture

## Verdict

- can execute code that was not in the reviewed tree: ['credential-env-read', 'install-command']

## Capabilities demonstrated by the content

- local script execution
- mentions a credential location
- network access
- package installation
- reads credentials from the environment

## Findings

critical=0 high=5 medium=13 low=0

| severity | rule | location | detail |
| --- | --- | --- | --- |
| high | install-command | `reference/evaluation.md:387` | installs packages; no trust tier grants install commands |
| high | install-command | `reference/evaluation.md:392` | installs packages; no trust tier grants install commands |
| high | install-command | `reference/evaluation.md:556` | installs packages; no trust tier grants install commands |
| high | credential-env-read | `reference/node_mcp_server.md:707` | reads a credential out of the environment |
| high | credential-env-read | `reference/node_mcp_server.md:719` | reads a credential out of the environment |
| medium | credential-reference | `reference/evaluation.md:398` | mentions a credential location; worth reading in context, not a refusal by itself |
| medium | credential-reference | `reference/evaluation.md:557` | mentions a credential location; worth reading in context, not a refusal by itself |
| medium | credential-reference | `reference/evaluation.md:567` | mentions a credential location; worth reading in context, not a refusal by itself |
| medium | credential-reference | `reference/node_mcp_server.md:707` | mentions a credential location; worth reading in context, not a refusal by itself |
| medium | credential-reference | `reference/node_mcp_server.md:719` | mentions a credential location; worth reading in context, not a refusal by itself |
| medium | credential-reference | `reference/node_mcp_server.md:737` | mentions a credential location; worth reading in context, not a refusal by itself |
| medium | credential-reference | `reference/node_mcp_server.md:744` | mentions a credential location; worth reading in context, not a refusal by itself |
| medium | network-fetch | `reference/python_mcp_server.md:260` | reaches the network; no trust tier grants network access |
| medium | executable-script | `scripts/connections.py` | executable code, not instruction content; forbidden below the audited tier |
| medium | credential-reference | `scripts/connections.py:80` | mentions a credential location; worth reading in context, not a refusal by itself |
| medium | credential-reference | `scripts/connections.py:84` | mentions a credential location; worth reading in context, not a refusal by itself |
| medium | executable-script | `scripts/evaluation.py` | executable code, not instruction content; forbidden below the audited tier |
| medium | credential-reference | `scripts/evaluation.py:344` | mentions a credential location; worth reading in context, not a refusal by itself |

## What this report is not

A clean report is not proof of safety. Static inspection cannot decide intent,
and natural-language instructions can be hostile without matching any pattern.
DevForge never executes skill content, which is the control that does not depend
on this report being right.
