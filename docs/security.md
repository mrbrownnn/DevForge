# Security model

## The honest summary

**DevForge is not a sandbox.** The policy layer is a deny-by-default allowlist over
processes that run as you, with your privileges. It is designed to stop accidents and
drift — an agent wandering outside the workspace, force-pushing, deleting files,
reading `.env`. It is **not** a security boundary against an adversarial agent.

Escaping an allowlist is trivial for anything actively trying: write a script into an
allowed path and ask an allowed interpreter to run it. `python -m pytest` can open
sockets and delete files. If you are running an untrusted model against code you care
about, you need an OS-level boundary — container, VM, seccomp/AppArmor — which DevForge
deliberately does not implement in the MVP and does not claim to.

Everything below is what the layer *does* do.

## What is enforced

### Shell commands

Evaluation order: **deny → require_approval → allow → default** (deny).

- Matching happens on the argv DevForge will pass to `exec`. **No shell is ever
  spawned.**
- Tokens that only make sense to a shell (`&&`, `||`, `|`, `;`, `>`, backtick, `$(`)
  are rejected outright. Without this, an allow rule like `git status*` could be widened
  by appending arguments.
- Timeouts are mandatory; a process that exceeds one is killed.

```yaml
shell:
  default: deny
  allow: ["python -m pytest*", "git status*", "git commit*"]
  require_approval: ["git push*", "pip install*", "*deploy*"]
  deny: ["rm -rf /*", "git push --force*", "*curl * | *sh*"]
```

### Filesystem

- Every path is resolved with symlinks followed, then checked against the workspace
  root. A symlink pointing outside is denied, not followed.
- `read` and `write` have separate allowlists; writes are narrower.
- Deny rules beat both: `.env`, `**/secrets/**`, `*.pem`, `*.key`, `id_rsa*`, `.git/**`.
- Glob matching uses real path semantics: `*` does not cross `/`, only `**` does. Plain
  `fnmatch` would let `*.js` match `node_modules/pkg/index.js` and silently widen every
  write rule.
- `delete` is its own mode, gated on approval by default. Recursive directory removal is
  not offered at all.

### Network

Disabled by default for DevForge tools. Note the limit clearly: an allowed command
(`python`, `npm`) can still reach the network. This flag governs what DevForge itself
does, not what a subprocess can do.

### Approval gates

`policies/approvals.yaml` declares gates. An undeclared gate is treated as **blocking**
— fail closed, never open.

```yaml
gates:
  architecture:
    description: Approve the design before any code is written.
    blocking: true
    auto_approve: false
```

`auto_approve: true` is an explicit opt-in for CI or a trusted local loop. Nothing is
auto-approved by default. A pending gate persists in the task record, so the decision
can be made later from another process:

```bash
devforge approve --gate architecture --by you --reason "design ok"
devforge approve --gate architecture --reject --reason "wrong layer"
```

Policy-triggered approvals use the same mechanism: a destructive command returns
`denied` with `awaiting_approval`, and re-running after the gate is granted proceeds.

## Overriding policy per project

Resolution order: `./.devforge/policies/` → `./policies/` → built-in. Copy the built-in
file and edit it:

```bash
mkdir -p policies
cp "$(python -c 'import devforge.builtin,pathlib;print(pathlib.Path(devforge.builtin.__file__).parent)')/policies/permissions.yaml" policies/
```

Widening the allowlist is a real decision. `allow: ["*"]` disables the command
allowlist entirely.

## Runtime-specific notes

The Claude Code adapter maps DevForge tool names to CLI tool permissions, so a step
declaring `tools: [filesystem]` cannot run shell commands. `permission_mode` is unset by
default; `bypassPermissions` removes the permission checks of the CLI itself and should
only be used inside a real sandbox with no network.

## Secret redaction

Implemented at two write boundaries and nowhere else: `RunLogger.emit` before an event
reaches any sink, and `ProjectStore.save_task` before a task record touches disk.

Caught: known credential shapes (Anthropic, OpenAI, GitHub, AWS, Google, Slack, JWT),
values assigned to secret-named keys, `-----BEGIN PRIVATE KEY-----` blocks, and
credentials embedded in URLs.

**Not caught:** a secret with no recognisable shape. Redaction reduces exposure; it does
not license logging secrets. The controls that actually keep credentials out are the
filesystem deny rules on `.env`, `**/secrets/**` and key files.

## Skill trust at consumption

A skill is instructions handed to an agent that holds tool permissions, so origin decides
the rule:

| Origin | Rule |
| --- | --- |
| shipped with DevForge | trusted |
| under the project root | inspected; a critical finding fails the step |
| anywhere else | refused unless the registry records a review at that exact content hash |

A refused skill **fails the step** rather than being silently dropped: a prompt missing
the instructions it was meant to carry is a different prompt.

## Child process environment

Subprocesses get a **constructed** environment, never the host one. Only variables a
build genuinely needs are carried over (PATH, HOME, temp dirs, locale, platform
essentials, non-secret toolchain vars), plus anything named in `process.allow_env`.

Everything else is dropped, secret-shaped or not. Redacting secrets from logs while
handing them to every child process would have been theatre.

This is not isolation: an allowed interpreter can still read `~/.aws/credentials` from
disk. It removes the easiest leak and nothing more.

## Network destinations (SSRF)

Any URL fetch on an agent's behalf is an SSRF primitive. A destination must clear three
checks in order:

1. **Scheme** — http/https only (`file://`, `gopher://` refused).
2. **Address** — loopback, private, link-local, multicast, reserved and cloud metadata
   endpoints refused, *including hostnames that resolve to them*.
3. **Allowlist** — the host must be named in `network.allow_hosts`.

Network access is off by default, so the out-of-the-box answer to "fetch this page" is
no. **DNS rebinding is not solved**: the address checked can differ from the one
connected to moments later. Closing that requires pinning the connection to the
validated address inside the client.

## Untrusted tool output

Text from outside the workspace — MCP responses, fetched pages — is bounded, scanned for
injection shapes, and wrapped in a labelled fence declaring it data rather than
instructions. Fence markers inside the content are neutralised so it cannot close the
fence early.

This mitigates prompt injection; it does not solve it. Assume a determined injection
gets through and rely on the layers that do not depend on the model behaving.

## Inline code execution

`python -c`, `node -e`, `bash -c` and friends are **approval-gated regardless of the
allowlist**. An allow rule like `python -c *` reads as narrow and is in fact total:
`python -c "import os; os.system(...)"` runs anything. No glob over a command line can
constrain inline code, so a human decides.

## Known gaps

- No process isolation, no resource limits, no syscall filtering.
- Tool calls made inside an *external CLI runtime's* turn are executed by that runtime,
  not proxied through the DevForge tool layer. A runtime that accepts a `ToolExecutor`
  (the mock does) has every call policy-checked and audited; one that runs its own tools
  cannot, and is constrained only by the permissions DevForge derives for it.
- MCP servers are trusted per configuration, not pinned by content hash the way skills
  are: a reviewed server that changes is not re-verified.
- Secrets are protected by deny patterns only. A command that is allowed can read
  anything the user can read.
- No audit signing: `events.jsonl` is a plain, locally writable file.
- No multi-user model. Approvals record whatever `--by` says; there is no authentication.

## Reporting a problem

Open an issue describing the behaviour and the policy configuration that produced it. If
it is a real bypass of a documented guarantee, say so explicitly in the title.


## The Security Center

`devforge security scan | audit | sbom | threats | report` is the operational side
of this page: the twelve threats and eight layers as data the CLI prints and the
test suite checks, a workspace scanner, a configuration audit, and a CycloneDX
inventory.

It computes no score and never prints the word "secure" as a verdict, for the
reason this page has repeated throughout: DevForge makes a specific set of mistakes
harder and a specific set of actions visible, and claiming more than that would
undo the value of stating it honestly.

See [security/security-center.md](security/security-center.md).

## Falsification

The falsification subsystem (`docs/falsification/security.md`) executes code that a
model wrote, against a repository that may be hostile. It is treated as untrusted
and reuses every control described above - the command allowlist, path confinement,
per-agent narrowing, redaction and untrusted-content fencing - plus two of its own:
runs happen in an isolated worktree or copy and refuse rather than downgrade when
neither is available, and the falsifier's write scope is enforced by a content-hash
filesystem snapshot rather than by an instruction in a prompt.

The same limitation applies there as everywhere else here: isolation means the
user's files are not touched. It is not an OS-level sandbox.
