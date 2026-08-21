# The Security Center

DevForge executes model-directed code against your files, your network position
and your credentials. That makes it a security-sensitive platform whatever else it
is, and this page describes the machinery that treats it as one.

```bash
devforge security scan      # what is in this workspace
devforge security audit     # whether the declared controls are in place
devforge security sbom      # what is installed and where it came from
devforge security threats   # the threat model and the layers
devforge security report    # all of it, plus the residual risk
```

Exit codes: `0` when nothing is blocking, `1` on a high finding or a failed
control check. Warnings never fail a build — the audit warns on every run that
there is no OS-level sandbox, and a permanent unfixable warning that breaks CI is
a warning people delete.

## There is no verdict, and that is deliberate

Nothing here prints a score, a grade or the word "secure". A number would
summarise the checks that exist, which is not the same as summarising the risk,
and readers do not keep that distinction in mind. What the reports give you is:
what was examined, what was found, what could not be evaluated, and what remains
true when every check passes.

Three rules the output obeys:

* **`unknown` is never `pass`.** A control that could not be evaluated is reported
  as unknown. Anything else trains the reader to read absence of evidence as
  evidence.
* **Known-absent controls are printed every run.** There is no sandbox, and the
  audit says so even when nothing else is wrong. A reader should not have to
  already know.
* **Suppressed findings are still reported.** They move to their own section with
  their reasons; they are never silently dropped.

## The twelve threats

| id | threat | primary controls | residual |
| --- | --- | --- | --- |
| TM1 | Malicious repository | workspace confinement, deny rules, structure-only index | running the repo's own tests executes its code |
| TM2 | Malicious skill | no install-time execution, static inspection, pin + hash | a skill's *instructions* are still read by a model |
| TM3 | Malicious MCP server | deny-until-named tools, stdio only, no sampling | a named tool can do other than it says |
| TM4 | Malicious webpage | per-request network policy, scheme allowlist, isolated context | Chromium's sandbox is Chromium's, not ours |
| TM5 | Malicious dependency | four runtime deps, opt-in extras, SBOM | no vulnerability database |
| TM6 | Prompt injection | fencing, injection scan, scope from workflow not prompt | fencing is a convention, not enforcement |
| TM7 | Compromised runtime | opt-in runtimes, scrubbed env, binary hashing | hashing detects substitution, prevents nothing |
| TM8 | Compromised tool | schema + scope + policy + audit on every call | a built-in tool is our own code |
| TM9 | Leaked credentials | redaction at both persistence boundaries, deny list | shapeless secrets pass redaction |
| TM10 | Unsafe generated code | `security scan`, patch guard, verification | pattern matching, not taint analysis |
| TM11 | Supply-chain attack | full-SHA pins, content hashes, re-audit on move | a pin proves sameness, not safety |
| TM12 | Confused deputy | policy decides from config, per-request checks, narrow scope | any held capability can be misdirected within its scope |

`devforge security threats` prints this from `devforge.security.catalog`, which is
the same data the audit maps its checks onto. Every threat carries a residual risk
and none of them says "none".

## The eight layers

| # | Layer | Status | What it does not do |
| --- | --- | --- | --- |
| 1 | Input validation | implemented | understands a documented subset of JSON Schema; unknown keywords are ignored, not enforced |
| 2 | Policy engine | implemented | an allowlist, not a sandbox — allowed commands hold your full privileges |
| 3 | Least privilege | implemented | binds calls that come *through* DevForge; an external CLI runtime runs its own |
| 4 | Sandbox / isolation | **partial** | **no OS-level sandbox.** Isolated browser contexts, scrubbed subprocess env, stdio-only MCP — that is all |
| 5 | Secret management | **partial** | no secret manager integration; redaction is pattern-based |
| 6 | Audit logging | implemented | a local file owned by the same user the agent runs as |
| 7 | Verification | implemented | verifiers run what the project defines; the patch guard sees known patterns |
| 8 | Human approval | implemented | approval fatigue defeats any gate |

`test_every_layer_points_at_modules_that_exist` imports every module each layer
claims. A layer cannot go on advertising an implementation after a refactor
deletes it — the catalogue is checked against the tree, not trusted as prose.

## What the scanner looks for

`SEC-SECRET-001` credential-shaped literal in source · `SEC-SECRET-002` credential
file present · `SEC-INJECT-001` injection-shaped instructions in documentation ·
`SEC-CODE-001` eval/exec on a runtime value · `-002` shell from a constructed
string · `-003` unsafe deserialisation · `-004` transport security disabled ·
`-005` string-built SQL · `-006` HTML injection sink · `-007` path from a request
value · `-008` weak randomness for a security value · `-009` insecure temp file.

Two design decisions are worth stating.

**It does not read the files most likely to contain secrets.** `.env`, key
material and `**/secrets/**` are reported by *presence* and never opened. A
scanner that opened them to confirm what it already knows would pull credentials
into memory, into a report, and possibly into a model's context.

**It distinguishes a value from a name.** The first implementation reused the log
redactor, which is deliberately aggressive because a log line reading `API_KEY=`
almost certainly carries one. In source code that flagged every constant whose
*name* contained "token" or "secret" — forty of them in DevForge's own tree, and
not one real credential. Comments and docstrings are skipped too, and code rules
do not apply to Markdown: prose describing `os.system` is not a call to it.

The trade this makes: the scanner is fast, dependency-free and has no taint
analysis and no vulnerability database. A clean scan means no pattern matched. It
is not evidence that the code is safe.

## Accepting a finding

`security/baseline.yaml` records findings that have been reviewed and accepted.
Three properties make an acceptance cost something:

* it names **one rule** at **one location** — `path:line`, or a bare `path` to
  accept that rule anywhere in one file. There are no wildcards across the tree;
* a written **reason** is required, in the file, where a reviewer will find it;
* an **expiry date** is required. An expired entry stops suppressing *and* raises
  `SEC-BASELINE-001`, so an acceptance nobody has re-confirmed becomes visible
  instead of permanent.

A baseline that fails to parse is an error, never an empty baseline — a typo must
not silently suppress nothing while its author believes something is suppressed.

DevForge's own baseline is in this repository and is worth reading as an example:
every entry is either an adversarial test fixture that must contain the dangerous
construct, or security documentation that quotes the phrases it warns about.

## Inventory

`devforge security sbom` emits CycloneDX 1.5 JSON covering four kinds of thing
that can execute or steer execution: Python distributions, installed skills, MCP
servers and agent runtime binaries. Declared and installed versions are both
recorded, because the difference is the interesting part — a dependency declared
but absent means a feature is silently unavailable.

It says what is here and where it came from. It does not say whether any of it is
vulnerable: DevForge ships no vulnerability database and queries no feed, because
adding one would be a new trust relationship and a new egress path — the
operator's decision, not a default.

## Adversarial testing

`tests/security/` holds one marked section per attack class: prompt injection,
command injection, path traversal, SSRF, secret exfiltration, malicious skill,
malicious MCP, malicious website, dependency confusion, privilege escalation.
`test_every_attack_class_is_covered` fails if a section loses its tests, so the
coverage claim cannot quietly become false.

None of these tests mock the boundary they test — a test that mocks the policy
engine proves the mock refuses. And where a control is partial the test asserts
what is actually true:
`test_the_allowlist_is_not_a_sandbox` asserts that an *allowed* command runs with
the user's privileges, so anyone who later claims DevForge sandboxes execution has
to change a test that says otherwise out loud.

**Every security regression becomes a permanent test here.** A control that was
broken once will be broken again by a future refactor unless something fails
loudly.

## Residual risk

Printed in full by `devforge security report`, on every run. The summary:

- **DevForge runs as you.** Every control constrains what DevForge's own tools do
  on your behalf. None constrains a process that already has your privileges.
- **No OS-level sandbox exists.** Run DevForge in a container or VM when the
  workspace is not trusted.
- **Redaction is a net, not a wall.** It catches credential-shaped strings. The
  control that actually keeps credentials out is the filesystem deny list.
- **Fencing does not enforce.** A model can still be persuaded by injected text.
  What limits the damage is that persuasion grants no permissions — the policy
  engine never reads a prompt.
- **A pin proves sameness, not safety.** It proves you got the same bytes as last
  time, not that those bytes were ever good.
- **Pattern matching finds known patterns.** Both the scanner and the patch guard
  cover constructs someone thought of. Neither finds a logic flaw.

DevForge does not claim to be secure. It claims to make a specific set of mistakes
harder and a specific set of actions visible.
