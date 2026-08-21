"""Per-agent policy narrowing.

An agent's declared permissions become a policy engine that is strictly tighter
than the project's. The direction matters and is enforced here rather than trusted:
an agent spec can *remove* access, never add it. A documentation agent that declared
``write: ["/etc/**"]`` gets nothing new, because the project policy still refuses it
and both must agree.

Implemented by intersection, not replacement:

* **read/write** - the agent's globs are added as an additional constraint, so a
  path must satisfy the project policy *and* the agent's list.
* **shell** - an agent with ``allow_shell: false`` gets a policy that denies every
  command outright, whatever tools the step named. With it true, its patterns
  intersect the project allowlist.
* **network** - off unless both allow it.
"""

from __future__ import annotations

from devforge.agents.spec import AgentPermissions
from devforge.policy.engine import PolicyEngine
from devforge.policy.models import Effect, PermissionPolicy


def scope_for_agent(policy: PolicyEngine, permissions: AgentPermissions) -> PolicyEngine:
    """A policy engine narrowed to what this agent declared.

    Returns the original engine when the agent declared nothing, so an unconstrained
    agent behaves exactly as before rather than silently losing access.
    """
    if not _declares_anything(permissions):
        return policy

    base = policy.permissions
    narrowed = PermissionPolicy.model_validate(base.model_dump())

    # Filesystem: intersect by appending the agent's globs. `check_path` requires a
    # rule to match, so a shorter list is a tighter policy.
    if permissions.read:
        narrowed.filesystem.read = _intersect(base.filesystem.read, permissions.read)
    if permissions.write:
        narrowed.filesystem.write = _intersect(base.filesystem.write, permissions.write)
    else:
        # Declaring no write globs means this agent writes nothing. Silence here
        # would be the widest possible reading of an empty list, which is backwards.
        narrowed.filesystem.write = []

    # Deletion is never granted by an agent spec; it stays with the project gate.
    narrowed.filesystem.delete = base.filesystem.delete

    if not permissions.allow_shell:
        narrowed.shell.allow = []
        narrowed.shell.require_approval = []
        narrowed.shell.default = Effect.DENY
    elif permissions.shell:
        narrowed.shell.allow = _intersect(base.shell.allow, permissions.shell)

    narrowed.network.enabled = base.network.enabled and permissions.network

    return PolicyEngine(narrowed, policy.approvals, workspace=policy.workspace)


def _declares_anything(permissions: AgentPermissions) -> bool:
    return bool(
        permissions.read
        or permissions.write
        or permissions.shell
        or permissions.allow_shell
        or permissions.network
    )


def _intersect(project: list[str], agent: list[str]) -> list[str]:
    """Keep only agent patterns the project would also have allowed.

    An exact match is obvious. Beyond that this is conservative: a pattern the
    project does not list verbatim is kept only when the project allows everything
    (`**`), because deciding whether one glob is a subset of another in general is
    a rabbit hole, and guessing wrong here would widen access.
    """
    if not project:
        return []
    if "**" in project or "*" in project:
        return list(agent)
    return [pattern for pattern in agent if pattern in project] or []


def describe_scope(permissions: AgentPermissions) -> str:
    if not _declares_anything(permissions):
        return "project defaults (agent declares no narrower scope)"
    return permissions.summary()
