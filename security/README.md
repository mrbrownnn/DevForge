# `security/` — the operator-owned security surface

Everything in this directory is data a human edits and a reviewer reads. No code
lives here.

## `baseline.yaml`

Findings that have been looked at and accepted. Three properties make an
acceptance cost something:

* it names **one rule at one location** — there are no wildcards, so a suppression
  cannot silently cover a file nobody has seen yet;
* it requires a written **reason**, in the file, where a reviewer will find it;
* it requires an **expiry date**. Suppressions rot. An expired entry stops
  suppressing *and* raises `SEC-BASELINE-001`, so an acceptance nobody has
  re-confirmed becomes visible instead of permanent.

Suppressed findings are still reported. `devforge security report` lists them in
their own section with the reasons attached — a report that quietly omitted them
would misrepresent what the scan found.

## Reading the reports

```bash
devforge security scan      # what is in this workspace
devforge security audit     # whether the declared controls are in place
devforge security report    # both, plus the inventory and the residual risk
```

The reports have no score and no overall verdict, deliberately. See
[`docs/security/security-center.md`](../docs/security/security-center.md).
