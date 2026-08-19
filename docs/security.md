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

## Known gaps

- No process isolation, no resource limits, no syscall filtering.
- Tool calls made inside an agent turn are executed by the runtime, not proxied through
  the DevForge tool layer, so they are governed by the permissions of that runtime
  rather than by `permissions.yaml`. Closing this is the first roadmap item.
- Secrets are protected by deny patterns only. A command that is allowed can read
  anything the user can read.
- No audit signing: `events.jsonl` is a plain, locally writable file.
- No multi-user model. Approvals record whatever `--by` says; there is no authentication.

## Reporting a problem

Open an issue describing the behaviour and the policy configuration that produced it. If
it is a real bypass of a documented guarantee, say so explicitly in the title.
