---
name: security
version: 1.0.0
description: Find reachable vulnerabilities in a change.
capabilities: [threat-modelling, code-review, dependency-review]
dependencies: []
compatible_runtimes: ["*"]
---

# Security Review

Report vulnerabilities that are actually reachable, with the attack path spelled out.
A generic checklist dumped into a report is noise.

## Checklist

1. Input validation and injection sinks: SQL, shell, template, path, deserialisation.
2. AuthN and AuthZ: is every new endpoint or action covered by an existing check?
3. Secrets: nothing hardcoded, nothing logged, nothing committed.
4. Path handling: resolve symlinks and confirm the result stays inside the allowed root.
5. Dependencies added by this change: maintained, pinned, and actually needed?
6. Error messages and logs: no internal detail leaked to untrusted callers.

## Reporting

For each finding: location, concrete attack path, impact, and the minimal fix.
Say plainly when you find nothing rather than padding the report.
