# Falsification security model

The falsifier is treated as an **untrusted execution component**. It reads a
repository that may be hostile, it is driven by a model whose output cannot be
trusted, and it executes code.

## The controls that hold

These do not depend on the model behaving:

1. **Isolation.** Every run happens in a linked git worktree or a filtered copy. The
   user's working tree is never mutated. If neither is available the run reports
   `ISOLATION_UNAVAILABLE` and refuses - there is no tier in which it proceeds against
   the real tree.
2. **Write scope.** After the agent runs, the filesystem is compared against a
   content-hash snapshot. Any write outside the scratch directory fails the strategy
   and discards its findings.
3. **Command allowlist.** Every command passes `PolicyEngine.check_command` before it
   runs. A refused command is an error, never a pass. Inline-code flags (`python -c`)
   are gated for approval regardless of any allow rule.
4. **Permission narrowing.** The falsifier agent declares the narrowest permissions in
   the tree - `write: [".falsification/**"]`, `allow_shell: false`, `network: false` -
   and `scope_for_agent` intersects, so it can never widen the project policy.
5. **Redaction.** Reports, rendered documents, corpus entries and events all pass
   `redact_value`.
6. **Secret exclusion.** The sandbox declines to copy `.env`, `*.pem`, `*.key`,
   `id_rsa*` at all, on top of the policy already denying them.

## The LLM permission invariant

```
LLM output -> tool request -> policy engine -> ALLOW / DENY -> execution
```

Never `LLM output -> execution`. A model cannot grant itself a permission, edit a
policy file, alter the sandbox rules, disable a control or read a credential. This is
regression-tested in `tests/security/test_falsification_security.py`.

## Prompt injection

Source, comments, README files, documentation, fixtures and generated output are all
untrusted. They are bounded, scanned and fenced through `devforge.tools.untrusted`
before reaching a prompt, and detected patterns are logged as findings.

Priority order: **system policy > DevForge policy > workflow > tool output >
repository content.**

This is **mitigation, not a control**. A model can still choose to follow instructions
inside a fenced block, and a paraphrase no pattern matches will not be flagged. Assume
a determined injection gets through, and rely on the six controls above - each of
which holds regardless.

## What this is not

**Not an OS-level sandbox.** A test runner started inside a worktree executes as the
current user with that user's full privileges and can reach anything that user can
reach. Isolation here means *the user's files are not touched*. Real containment needs
a container, a VM or seccomp, and that remains out of scope - the same limitation
`docs/security.md` states for the rest of DevForge.
