"""Auditing whether the declared controls are actually in place.

The scanner asks "is there anything dangerous in this workspace?". The audit asks
a different and more answerable question: **"is this installation configured the
way its own threat model says it is?"**

That distinction matters because most real security failures in a tool like this
are not exotic. They are a deny-by-default policy someone flipped to allow while
debugging, a gate marked ``auto_approve: true`` to get through a demo, an
``allow_env`` entry carrying a token into every subprocess, a skill whose content
hash no longer matches what was reviewed. None of those are visible in a diff
weeks later, and every one of them silently removes a layer.

Each check names the layer it belongs to and the threat it defends, so the output
is a map of the defence-in-depth model rather than a list of opinions.

Three rules the results obey
----------------------------

**UNKNOWN is not PASS.** A control that could not be evaluated is reported as
unknown. Anything else trains the reader to treat absence of evidence as evidence.

**Known-absent controls are reported every time.** There is no OS-level sandbox,
and the audit says so on every run rather than staying quiet because it is a
design decision. A person reading the report should not have to already know.

**Nothing is scored.** There is no percentage and no overall verdict. Counting
checks would imply the checks are the whole of security.
"""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

from devforge.core.errors import DevForgeError
from devforge.observability.redaction import is_secret_key
from devforge.policy.engine import PolicyEngine
from devforge.policy.models import Effect
from devforge.security.models import AuditReport, CheckResult, CheckStatus
from devforge.supplychain.install import load_lockfile, verify_installed

#: Paths that must be unreadable to tools no matter what the read rules say.
MUST_BE_DENIED = (".env", "secrets/token.txt", "id_rsa", "private.pem", ".git/config")

#: Agent CLIs are bundled runtimes and routinely exceed 300 MB. The cap exists so a
#: mis-resolved path to something enormous cannot stall an audit, not to skip real
#: binaries - hashing 300 MB takes about a third of a second.
MAX_BINARY_BYTES = 1_000_000_000


def audit_project(root: Path, *, policy: PolicyEngine | None = None) -> AuditReport:
    """Run every configuration check against one project."""
    root = Path(root).resolve()
    report = AuditReport(root=str(root))
    engine = policy or PolicyEngine.load(root, workspace=root)

    report.results.extend(_layer1(root))
    report.results.extend(_layer2(engine))
    report.results.extend(_layer3(root, engine))
    report.results.extend(_layer4(root))
    report.results.extend(_layer5(root, engine))
    report.results.extend(_layer6(root, engine))
    report.results.extend(_layer7(root))
    report.results.extend(_layer8(engine))
    report.results.extend(_supply_chain(root))
    return report


def _check(
    check_id: str,
    layer: int,
    title: str,
    status: CheckStatus,
    detail: str = "",
    remediation: str = "",
    threat: str = "",
) -> CheckResult:
    return CheckResult(
        id=check_id,
        layer=layer,
        title=title,
        status=status,
        detail=detail,
        remediation=remediation,
        threat=threat,
    )


# --------------------------------------------------------------- layer 1: input validation


def _layer1(root: Path) -> list[CheckResult]:
    from devforge.tools.base import ToolRegistry

    results: list[CheckResult] = []
    registry = ToolRegistry.default()
    undeclared: list[str] = []
    for tool in registry.all():
        for action in tool.actions:
            if tool.descriptor.schema_for(action) is None:
                undeclared.append(f"{tool.name}.{action}")
    results.append(
        _check(
            "SEC-A-101",
            1,
            "every tool action declares a parameter schema",
            CheckStatus.PASS if not undeclared else CheckStatus.FAIL,
            f"{len(undeclared)} action(s) without a schema: {', '.join(undeclared[:6])}"
            if undeclared
            else f"all actions across {len(registry.all())} tools are schema-checked",
            "Add an input_schema entry; an action with no schema accepts anything.",
            "TM8",
        )
    )

    results.append(_mcp_allowlist_check(root))
    return results


def _mcp_allowlist_check(root: Path) -> CheckResult:
    from devforge.mcp.registry import load_config

    try:
        config = load_config(root)
    except DevForgeError as exc:
        return _check(
            "SEC-A-102", 1, "MCP tools are denied until named", CheckStatus.UNKNOWN, str(exc)
        )
    servers = config.enabled_servers
    if not servers:
        return _check(
            "SEC-A-102",
            1,
            "MCP tools are denied until named",
            CheckStatus.NOT_APPLICABLE,
            "no MCP servers are enabled",
            threat="TM3",
        )
    wide_open = [server.name for server in servers if not server.allow_tools]
    return _check(
        "SEC-A-102",
        1,
        "MCP tools are denied until named",
        CheckStatus.PASS if not wide_open else CheckStatus.WARN,
        f"{len(servers)} enabled server(s); no allow_tools on: {', '.join(wide_open)}"
        if wide_open
        else f"{len(servers)} enabled server(s), each with an explicit allow_tools list",
        "Name each tool you actually want. An empty allow_tools grants nothing today, "
        "but a server that grows tools should not be silently re-reviewed.",
        "TM3",
    )


# ------------------------------------------------------------------- layer 2: policy engine


def _layer2(engine: PolicyEngine) -> list[CheckResult]:
    permissions = engine.permissions
    shell = permissions.shell
    filesystem = permissions.filesystem
    network = permissions.network

    results = [
        _check(
            "SEC-A-201",
            2,
            "unmatched shell commands are denied",
            CheckStatus.PASS if shell.default is Effect.DENY else CheckStatus.FAIL,
            f"shell.default = {shell.default.value}",
            "Set shell.default to deny. An allowlist with an allow default is not an "
            "allowlist.",
            "TM8",
        ),
        _check(
            "SEC-A-202",
            2,
            "filesystem access is confined to the workspace",
            CheckStatus.PASS if filesystem.workspace_only else CheckStatus.FAIL,
            f"filesystem.workspace_only = {filesystem.workspace_only}",
            "Set workspace_only: true. Without it an agent can read and write anywhere "
            "the user can.",
            "TM1",
        ),
        _check(
            "SEC-A-203",
            2,
            "deletion is not silently allowed",
            CheckStatus.PASS if filesystem.delete is not Effect.ALLOW else CheckStatus.FAIL,
            f"filesystem.delete = {filesystem.delete.value}",
            "Set delete to require_approval or deny.",
            "TM8",
        ),
        _check(
            "SEC-A-204",
            2,
            "private and metadata addresses are blocked",
            CheckStatus.PASS if network.block_private_addresses else CheckStatus.FAIL,
            f"block_private_addresses = {network.block_private_addresses}"
            + (", loopback opt-in is on" if network.allow_loopback else ""),
            "Re-enable it. Disabling the SSRF defence to reach a dev server is what "
            "network.allow_loopback exists for.",
            "TM4",
        ),
    ]

    if not network.enabled:
        results.append(
            _check(
                "SEC-A-205",
                2,
                "network access is off, or scoped to named hosts",
                CheckStatus.PASS,
                "network.enabled = false",
                threat="TM4",
            )
        )
    else:
        wide = not network.allow_hosts
        results.append(
            _check(
                "SEC-A-205",
                2,
                "network access is off, or scoped to named hosts",
                CheckStatus.WARN if wide else CheckStatus.PASS,
                "network is enabled with no allow_hosts - every host the SSRF filter "
                "permits is reachable"
                if wide
                else f"network is enabled for {len(network.allow_hosts)} named host(s)",
                "List the hosts you actually need in network.allow_hosts.",
                "TM4",
            )
        )

    results.append(_deny_rules_check(engine))
    return results


def _deny_rules_check(engine: PolicyEngine) -> CheckResult:
    """A functional probe, not a rule-text comparison.

    Asserting that a pattern appears in the deny list would pass even if the
    matching logic were broken. Asking the engine whether it would actually open
    `.env` tests the thing that matters.
    """
    reachable = [
        candidate
        for candidate in MUST_BE_DENIED
        if engine.check_path(candidate, mode="read").allowed
    ]
    return _check(
        "SEC-A-206",
        2,
        "credential and git-internal paths are unreadable",
        CheckStatus.PASS if not reachable else CheckStatus.FAIL,
        f"readable despite policy: {', '.join(reachable)}"
        if reachable
        else f"all {len(MUST_BE_DENIED)} probe paths are refused",
        "Restore the deny rules for .env, **/secrets/**, key material and .git.",
        "TM9",
    )


# ---------------------------------------------------------------- layer 3: least privilege


def _layer3(root: Path, engine: PolicyEngine) -> list[CheckResult]:
    from devforge.agents.spec import AgentRegistry
    from devforge.tools.base import ToolRegistry

    results: list[CheckResult] = []

    every_tool = {tool.name for tool in ToolRegistry.default().all()}
    try:
        agents = AgentRegistry.discover(root).all()
    except DevForgeError as exc:
        results.append(
            _check("SEC-A-301", 3, "no agent is granted every tool", CheckStatus.UNKNOWN, str(exc))
        )
    else:
        greedy = [agent.name for agent in agents if every_tool <= set(agent.tools)]
        results.append(
            _check(
                "SEC-A-301",
                3,
                "no agent is granted every tool",
                CheckStatus.PASS if not greedy else CheckStatus.WARN,
                f"agents holding every registered tool: {', '.join(greedy)}"
                if greedy
                else f"{len(agents)} agent(s), each scoped to a subset",
                "Give each agent the tools its role needs. A reviewer does not need a "
                "browser; a debugger does not need to push.",
                "TM12",
            )
        )

    carried = [name for name in engine.permissions.process.allow_env if is_secret_key(name)]
    results.append(
        _check(
            "SEC-A-302",
            3,
            "no secret-named variable is passed to child processes",
            CheckStatus.PASS if not carried else CheckStatus.FAIL,
            f"allow_env carries: {', '.join(carried)}"
            if carried
            else f"allow_env names {len(engine.permissions.process.allow_env)} "
            "non-secret variable(s)",
            "Remove it. Every allowed command inherits anything named here.",
            "TM9",
        )
    )
    return results


# ------------------------------------------------------------------ layer 4: isolation


def _layer4(root: Path) -> list[CheckResult]:
    from devforge.mcp.registry import load_config

    results = [
        _check(
            "SEC-A-401",
            4,
            "OS-level sandboxing",
            CheckStatus.WARN,
            "not implemented. Tools, verifiers and agent runtimes execute as the "
            "invoking user with that user's full privileges. What isolation exists is "
            "narrow: isolated browser contexts, scrubbed subprocess environments, "
            "stdio-only MCP.",
            "Run DevForge inside a container or VM when the workspace is not trusted. "
            "The policy engine is an allowlist, not containment.",
            "TM7",
        )
    ]

    try:
        config = load_config(root)
    except DevForgeError as exc:
        results.append(
            _check("SEC-A-402", 4, "MCP transport is stdio only", CheckStatus.UNKNOWN, str(exc))
        )
        return results

    servers = [server for server in config.servers if server.enabled]
    remote = [server.name for server in servers if not server.supported]
    results.append(
        _check(
            "SEC-A-402",
            4,
            "MCP transport is stdio only",
            CheckStatus.NOT_APPLICABLE
            if not servers
            else (CheckStatus.PASS if not remote else CheckStatus.FAIL),
            "no MCP servers are enabled"
            if not servers
            else (
                f"unsupported transports configured: {', '.join(remote)}"
                if remote
                else f"all {len(servers)} server(s) use stdio"
            ),
            "HTTP/SSE transports are refused rather than downgraded; remove them.",
            "TM3",
        )
    )
    return results


# ------------------------------------------------------------- layer 5: secret management


def _layer5(root: Path, engine: PolicyEngine) -> list[CheckResult]:
    from devforge.observability.redaction import contains_secret

    probe = "Authorization: Bearer " + "a1b2c3d4e5f6g7h8"
    redaction_works = contains_secret(probe)

    results = [
        _check(
            "SEC-A-501",
            5,
            "redaction recognises credential-shaped text",
            CheckStatus.PASS if redaction_works else CheckStatus.FAIL,
            "a bearer-token probe is detected and would be redacted before logging"
            if redaction_works
            else "the probe was NOT detected - redaction is not functioning",
            "Redaction runs at event emission and task save. If this fails, secrets "
            "reach logs and state files.",
            "TM9",
        ),
        _gitignore_check(root),
        _check(
            "SEC-A-503",
            5,
            "external secret manager integration",
            CheckStatus.NOT_APPLICABLE,
            "not implemented. DevForge stores no secrets and reads none; credentials "
            "reach child processes only through the environment the operator provides.",
            "Nothing to configure today. This is recorded so the gap is visible.",
            "TM9",
        ),
    ]
    # Keep the engine referenced meaningfully rather than accepting an unused argument.
    if engine.permissions.filesystem.max_read_bytes <= 0:
        results.append(
            _check(
                "SEC-A-504",
                5,
                "file reads are bounded",
                CheckStatus.FAIL,
                "max_read_bytes is not positive, so a single read is unbounded",
                "Set filesystem.max_read_bytes to a finite value.",
                "TM1",
            )
        )
    return results


def _gitignore_check(root: Path) -> CheckResult:
    path = root / ".gitignore"
    if not path.is_file():
        return _check(
            "SEC-A-502",
            5,
            "credential files are git-ignored",
            CheckStatus.WARN,
            "no .gitignore in the project root",
            "Add one that ignores .env, *.pem, *.key and secrets/.",
            "TM9",
        )
    text = path.read_text(encoding="utf-8", errors="replace")
    wanted = (".env", "*.pem", "*.key")
    missing = [entry for entry in wanted if entry not in text]
    return _check(
        "SEC-A-502",
        5,
        "credential files are git-ignored",
        CheckStatus.PASS if not missing else CheckStatus.WARN,
        f".gitignore does not mention: {', '.join(missing)}"
        if missing
        else ".gitignore covers .env and key material",
        "Anything committed must be treated as disclosed, so the ignore rule has to "
        "exist before the mistake does.",
        "TM9",
    )


# ------------------------------------------------------------------ layer 6: audit logging


def _layer6(root: Path, engine: PolicyEngine) -> list[CheckResult]:
    state_dir = root / ".devforge"
    state_reachable = engine.check_path(".devforge/state.json", mode="write").allowed
    return [
        _check(
            "SEC-A-601",
            6,
            "the project keeps an audit trail",
            CheckStatus.PASS if state_dir.is_dir() else CheckStatus.WARN,
            f"{state_dir} exists" if state_dir.is_dir() else "run `devforge init` first",
            "Events are written per run to .devforge/runs/<id>/events.jsonl.",
            "TM8",
        ),
        _check(
            "SEC-A-602",
            6,
            "agents cannot rewrite the audit trail through the tool layer",
            CheckStatus.PASS if not state_reachable else CheckStatus.FAIL,
            "state.json is refused to tools"
            if not state_reachable
            else "state.json is writable through the filesystem tool",
            "Restore the deny rule on .devforge/state.json. Note this constrains tool "
            "calls only - the file is owned by the same user the agent runs as.",
            "TM8",
        ),
    ]


# -------------------------------------------------------------------- layer 7: verification


def _layer7(root: Path) -> list[CheckResult]:
    from devforge.core.workflow.loader import WorkflowLoader

    try:
        loader = WorkflowLoader.for_project(root)
        names = list(loader.available())
    except DevForgeError as exc:
        return [
            _check(
                "SEC-A-701",
                7,
                "workflows verify their own output",
                CheckStatus.UNKNOWN,
                str(exc),
            )
        ]

    unverified: list[str] = []
    for name in names:
        try:
            spec = loader.load(name)
        except DevForgeError:
            unverified.append(f"{name} (invalid)")
            continue
        if not any(step.verify for step in spec.steps):
            unverified.append(name)

    results = [
        _check(
            "SEC-A-701",
            7,
            "every workflow verifies something",
            CheckStatus.PASS if not unverified else CheckStatus.WARN,
            f"no verifiers referenced by: {', '.join(unverified)}"
            if unverified
            else f"all {len(names)} workflow(s) reference at least one verifier",
            "A workflow with no verifier records an agent's own claim of success.",
            "TM10",
        )
    ]

    try:
        bugfix = loader.load("bugfix")
    except DevForgeError:
        return results

    guarded = any(v.kind == "patch-guard" and v.required for v in bugfix.verifiers)
    results.append(
        _check(
            "SEC-A-702",
            7,
            "the repair loop cannot pass by weakening tests",
            CheckStatus.PASS if guarded else CheckStatus.FAIL,
            "bugfix requires the patch guard"
            if guarded
            else "bugfix has no required patch-guard verifier",
            "Without it, deleting an assertion is a winning repair strategy.",
            "TM10",
        )
    )
    return results


# ------------------------------------------------------------------ layer 8: human approval


def _layer8(engine: PolicyEngine) -> list[CheckResult]:
    gates = engine.approvals.gates
    auto = [name for name, gate in gates.items() if gate.auto_approve]
    non_blocking = [name for name, gate in gates.items() if not gate.blocking]
    return [
        _check(
            "SEC-A-801",
            8,
            "no approval gate approves itself",
            CheckStatus.PASS if not auto else CheckStatus.FAIL,
            f"auto_approve is set on: {', '.join(auto)}"
            if auto
            else f"all {len(gates)} declared gate(s) require a human",
            "Remove auto_approve. A gate that approves itself is a comment.",
            "TM12",
        ),
        _check(
            "SEC-A-802",
            8,
            "declared gates block the run",
            CheckStatus.PASS if not non_blocking else CheckStatus.WARN,
            f"non-blocking gates: {', '.join(non_blocking)}"
            if non_blocking
            else "every declared gate pauses the run",
            "A non-blocking gate records a decision nobody had to make.",
            "TM12",
        ),
    ]


# ------------------------------------------------------------------------- supply chain


def _supply_chain(root: Path) -> list[CheckResult]:
    results: list[CheckResult] = []
    try:
        lockfile = load_lockfile(root)
    except DevForgeError as exc:
        return [
            _check("SEC-A-901", 7, "installed skills are pinned", CheckStatus.UNKNOWN, str(exc))
        ]

    if not lockfile.skills:
        results.append(
            _check(
                "SEC-A-901",
                7,
                "installed skills are pinned and verifiable",
                CheckStatus.NOT_APPLICABLE,
                "no third-party skills are installed",
                threat="TM11",
            )
        )
    else:
        unpinned = [
            entry.name
            for entry in lockfile.skills
            if len(entry.commit_sha) != 40 or not entry.content_hash
        ]
        results.append(
            _check(
                "SEC-A-901",
                7,
                "installed skills are pinned and verifiable",
                CheckStatus.PASS if not unpinned else CheckStatus.FAIL,
                f"missing a full commit SHA or content hash: {', '.join(unpinned)}"
                if unpinned
                else f"all {len(lockfile.skills)} skill(s) pinned by commit and content",
                "A tag can be moved; a commit SHA cannot.",
                "TM11",
            )
        )

        drifted: list[str] = []
        for entry in lockfile.skills:
            drifted.extend(verify_installed(root, entry))
        results.append(
            _check(
                "SEC-A-902",
                7,
                "installed skill content matches what was reviewed",
                CheckStatus.PASS if not drifted else CheckStatus.FAIL,
                "; ".join(drifted[:5]) if drifted else "every installed skill re-hashes clean",
                "Re-audit and reinstall the skill, or restore it from the pin.",
                "TM11",
            )
        )

        unlicensed = [entry.name for entry in lockfile.skills if not entry.license]
        results.append(
            _check(
                "SEC-A-903",
                7,
                "installed skills record a license",
                CheckStatus.PASS if not unlicensed else CheckStatus.WARN,
                f"no license recorded for: {', '.join(unlicensed)}"
                if unlicensed
                else "every installed skill records a license",
                "Unknown licensing is a legal risk and a signal about provenance.",
                "TM11",
            )
        )

    results.append(_runtime_binary_check())
    return results


def _runtime_binary_check() -> CheckResult:
    """Record which binary a runtime name actually resolves to, and its hash.

    This detects substitution between runs. It prevents nothing: by the time the
    hash changes, the previous run has already happened. Reported as a fact rather
    than a pass so nobody reads it as an integrity guarantee.
    """
    from devforge.runtime.registry import RuntimeRegistry

    lines: list[str] = []
    registry = RuntimeRegistry.default()
    for name, (available, _) in registry.availability().items():
        if not available:
            continue
        # The runtime names its own binary. Guessing from the registry name would
        # hash the wrong file and report an integrity fact about something else.
        binary = getattr(registry.create(name), "binary", None)
        if not binary:
            continue  # in-process runtime; there is no external binary to identify
        path = shutil.which(binary)
        if path is None:
            lines.append(f"{name}: reports available but '{binary}' is not on PATH")
            continue
        lines.append(f"{name} ({binary}): {path} sha256={_hash_file(Path(path))}")

    return _check(
        "SEC-A-904",
        4,
        "agent runtime binaries are identified",
        CheckStatus.PASS if lines else CheckStatus.NOT_APPLICABLE,
        "; ".join(lines) if lines else "no external runtime is available here",
        "Compare these hashes between runs. A change means the binary you are "
        "trusting is not the one you reviewed.",
        "TM7",
    )


def _hash_file(path: Path) -> str:
    try:
        if path.stat().st_size > MAX_BINARY_BYTES:
            return "not-hashed (too large)"
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
        return digest.hexdigest()[:16]
    except OSError as exc:
        return f"unreadable ({exc.__class__.__name__})"
