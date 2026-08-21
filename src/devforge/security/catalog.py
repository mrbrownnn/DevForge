"""The threat model and the defence-in-depth layers, as data rather than prose.

`docs/security/threat-model.md` is the narrative version. This module is the same
content in a form the CLI can print, the audit can map its checks onto, and the
test suite can assert against - so a layer cannot go on claiming an implementation
after the module implementing it is deleted, and a threat cannot lose its last
control without something failing.

The `residual` field on every threat is mandatory and never says "none". Every
control here is a partial mitigation; a threat model whose residual column is
empty is a marketing document.
"""

from __future__ import annotations

from devforge.security.models import Layer, LayerStatus, Severity, Threat

LAYERS: tuple[Layer, ...] = (
    Layer(
        number=1,
        name="Input validation",
        intent=(
            "Reject malformed or hostile input at the boundary, before any handler "
            "touches a path, a process or a socket."
        ),
        status=LayerStatus.IMPLEMENTED,
        modules=[
            "devforge.tools.descriptor",
            "devforge.core.workflow.spec",
            "devforge.mcp.registry",
        ],
        limits=(
            "The schema language is a documented subset of JSON Schema. Keywords it "
            "does not understand are ignored rather than treated as satisfied, which "
            "means an MCP server can express a constraint DevForge will not enforce."
        ),
    ),
    Layer(
        number=2,
        name="Policy engine",
        intent=(
            "Every command, path and network destination is checked against a "
            "deny-by-default allowlist before a tool acts."
        ),
        status=LayerStatus.IMPLEMENTED,
        modules=["devforge.policy.engine", "devforge.policy.models", "devforge.policy.network"],
        limits=(
            "An allowlist, not a sandbox. An allowed command runs with the invoking "
            "user's full privileges and can do anything that user can do."
        ),
    ),
    Layer(
        number=3,
        name="Least privilege",
        intent=(
            "An agent gets the tools its step declared and nothing else; a tool "
            "declares the permissions it needs and is given no others."
        ),
        status=LayerStatus.IMPLEMENTED,
        modules=[
            "devforge.policy.agent_scope",
            "devforge.tools.executor",
            "devforge.tools.environment",
        ],
        limits=(
            "Scoping binds calls that come through DevForge. A runtime that executes "
            "its own tool calls inside a turn - an external CLI - is constrained only "
            "by the permissions DevForge derives for the process it spawns."
        ),
    ),
    Layer(
        number=4,
        name="Sandbox / isolation",
        intent="Contain what a compromised agent or tool can reach.",
        status=LayerStatus.PARTIAL,
        modules=["devforge.browser.session", "devforge.tools.process", "devforge.mcp.client"],
        limits=(
            "There is NO OS-level sandbox. What exists is real but narrow: isolated "
            "browser contexts with no profile or credentials, subprocesses with a "
            "scrubbed environment and bounded output, and MCP over stdio only. "
            "Processes run as the invoking user. Do not read this layer as containment."
        ),
    ),
    Layer(
        number=5,
        name="Secret management",
        intent="Keep credentials out of prompts, logs, state and reports.",
        status=LayerStatus.PARTIAL,
        modules=[
            "devforge.observability.redaction",
            "devforge.context.guard",
            "devforge.tools.environment",
        ],
        limits=(
            "DevForge stores no secrets and integrates with no secret manager. "
            "Redaction is pattern-based: it catches credential-shaped strings, not a "
            "bare high-entropy word. The control that actually keeps credentials out "
            "is the filesystem deny list."
        ),
    ),
    Layer(
        number=6,
        name="Audit logging",
        intent=(
            "Every tool call, denial, approval and verification is a structured event "
            "on disk, so a run can be reconstructed after the fact."
        ),
        status=LayerStatus.IMPLEMENTED,
        modules=["devforge.observability.logging", "devforge.core.state.store"],
        limits=(
            "The audit trail is a local file owned by the same user the agent runs as. "
            "It is evidence against mistakes and drift, not against an attacker who "
            "already has that user's privileges - they can rewrite it."
        ),
    ),
    Layer(
        number=7,
        name="Verification",
        intent=(
            "An agent's claim of success is evidence of nothing; verifiers are the only "
            "authority, and the patch itself is reviewed, not just the outcome."
        ),
        status=LayerStatus.IMPLEMENTED,
        modules=[
            "devforge.verification.engine",
            "devforge.verification.repair",
            "devforge.debug.patch_guard",
        ],
        limits=(
            "Verifiers run commands the project defines. The patch guard reads a diff "
            "for known cheating patterns and cannot see one it has no pattern for."
        ),
    ),
    Layer(
        number=8,
        name="Human approval",
        intent=(
            "Irreversible and outward-facing actions stop and wait for a person, and "
            "the decision is recorded."
        ),
        status=LayerStatus.IMPLEMENTED,
        modules=["devforge.approval.gate", "devforge.policy.models"],
        limits=(
            "Approval fatigue is the cheapest bypass of any gate. Gates are kept few "
            "and specific for that reason, but a human who approves without reading "
            "provides no protection at all."
        ),
    ),
)


THREATS: tuple[Threat, ...] = (
    Threat(
        id="TM1",
        name="Malicious repository",
        description=(
            "The workspace itself is hostile: files crafted to be read by an agent, a "
            "build script that runs on test, a symlink pointing outside the tree."
        ),
        severity=Severity.HIGH,
        layers=[1, 2, 3, 5],
        controls=[
            "workspace-confined paths with symlinks resolved before the check",
            "deny rules on .env, secrets, key material and .git",
            "repository content is never treated as instruction (see TM6)",
            "the index records structure, never file contents",
        ],
        residual=(
            "Running the project's own test suite executes the repository's code. That "
            "is what a test suite is; DevForge does not sandbox it."
        ),
    ),
    Threat(
        id="TM2",
        name="Malicious skill",
        description=(
            "A third-party skill that carries an installer, an executable payload, or "
            "instructions written to redirect the agent that reads it."
        ),
        severity=Severity.HIGH,
        layers=[1, 5, 7, 8],
        controls=[
            "no install-time code execution: DevForge never runs a skill's scripts",
            "static inspection before install, with findings shown to a human",
            "pinned by commit and content hash; a moved pin is a fresh decision",
            "executable files quarantined rather than installed",
        ],
        residual=(
            "A skill's *instructions* are still read by a model. Inspection is static "
            "and a plausible, useful, subtly wrong skill is not distinguishable by "
            "pattern matching."
        ),
    ),
    Threat(
        id="TM3",
        name="Malicious MCP server",
        description=(
            "A configured server returns hostile tool descriptions or results, or "
            "grows new tools after it was reviewed."
        ),
        severity=Severity.HIGH,
        layers=[1, 2, 3, 5],
        controls=[
            "tools denied until named in allow_tools",
            "stdio transport only; HTTP/SSE refused rather than downgraded",
            "sampling deliberately unimplemented - it would let a server drive the model",
            "the server command goes through the shell allowlist like any subprocess",
            "results are wrapped as untrusted output",
        ],
        residual=(
            "A named tool that does something other than what its description says is "
            "indistinguishable from one that does. Trust in a server is trust."
        ),
    ),
    Threat(
        id="TM4",
        name="Malicious webpage",
        description=(
            "A page the browser agent visits attacks the workstation: SSRF to internal "
            "services, file:// navigation, drive-by download, or text aimed at the model."
        ),
        severity=Severity.HIGH,
        layers=[1, 2, 4, 5],
        controls=[
            "network policy applied to every request the page makes, not just the first",
            "scheme allowlist; file:, data: and javascript: refused",
            "private and loopback addresses blocked by default",
            "isolated context with no profile, no storage_state, no cookies",
            "downloads refused, dialogs dismissed, console and text bounded",
        ],
        residual=(
            "Chromium runs as the invoking user with Chromium's own sandbox, not "
            "DevForge's. A browser exploit is out of scope."
        ),
    ),
    Threat(
        id="TM5",
        name="Malicious dependency",
        description=(
            "A package a skill script or the project imports ships hostile code that "
            "runs during ordinary tooling."
        ),
        severity=Severity.MEDIUM,
        layers=[1, 7],
        controls=[
            "four runtime dependencies, enforced by an architecture test",
            "optional extras are opt-in and named",
            "skill dependencies are recorded and surfaced, never auto-installed",
            "`devforge security sbom` inventories what is actually present",
        ],
        residual=(
            "DevForge does not scan package contents and has no vulnerability database. "
            "The inventory tells you what you have, not whether it is safe."
        ),
    ),
    Threat(
        id="TM6",
        name="Prompt injection",
        description=(
            "Text from a file, README, web page, tool result or MCP response instructs "
            "the model to ignore its policy, exfiltrate a secret or call a tool."
        ),
        severity=Severity.HIGH,
        layers=[1, 3, 5, 7, 8],
        controls=[
            "all external text is fenced, labelled untrusted and injection-scanned",
            "fence markers inside the content are neutralised so it cannot close its own fence",
            "tool scope is set by the workflow, not by anything the model reads",
            "destructive actions need a human regardless of what the model was told",
        ],
        residual=(
            "Fencing is a strong convention, not an enforcement boundary. A model can "
            "still be persuaded. What limits the damage is that persuasion does not "
            "grant permissions - the policy engine never reads the prompt."
        ),
    ),
    Threat(
        id="TM7",
        name="Compromised agent runtime",
        description=(
            "The CLI or SDK that executes agents is backdoored, or a different binary "
            "is resolved from PATH than the one that was reviewed."
        ),
        severity=Severity.MEDIUM,
        layers=[3, 4, 6],
        controls=[
            "runtimes are opt-in per run; the default runtime is the local mock",
            "availability is discovered and reported, never assumed",
            "child processes get a scrubbed environment, not the parent's wholesale",
            "`devforge security audit` records the resolved path and hash of each binary",
        ],
        residual=(
            "A compromised runtime executes with the user's privileges. Recording its "
            "hash detects substitution between runs; it prevents nothing."
        ),
    ),
    Threat(
        id="TM8",
        name="Compromised tool",
        description="A tool - built-in or MCP-provided - does more than it declares.",
        severity=Severity.MEDIUM,
        layers=[1, 2, 3, 6],
        controls=[
            "every call is scope-checked, schema-validated, policy-checked and audited",
            "tools declare their permissions; the declaration is inspectable",
            "destructive risk routes through an approval gate",
        ],
        residual=(
            "A built-in tool is DevForge's own code: if it is compromised, so is the "
            "harness. The executor constrains callers, not the implementation."
        ),
    ),
    Threat(
        id="TM9",
        name="Leaked credentials",
        description=(
            "A token reaches a log, a state file, a prompt, an artifact or a security "
            "report, and outlives the run."
        ),
        severity=Severity.HIGH,
        layers=[1, 5, 6],
        controls=[
            "redaction at the two persistence boundaries: event emission and task save",
            "filesystem deny list on .env, secrets directories and key material",
            "the index refuses credential-shaped files",
            "evidence, patch review and security findings are redacted before rendering",
        ],
        residual=(
            "Pattern-based redaction cannot catch a secret with no recognisable shape. "
            "An allowed command can also print one to a terminal DevForge never sees."
        ),
    ),
    Threat(
        id="TM10",
        name="Unsafe generated code",
        description=(
            "The agent writes code that is dangerous in itself: eval on input, a shell "
            "invocation built by string concatenation, TLS verification disabled, a "
            "hardcoded credential."
        ),
        severity=Severity.HIGH,
        layers=[7, 8],
        controls=[
            "`devforge security scan` reads the workspace for these patterns",
            "the patch guard fails a repair that disables a check",
            "verification and review steps run before an approval gate",
        ],
        residual=(
            "Pattern matching finds known-dangerous constructs. It does not find a "
            "logic flaw, and it produces false positives that a human must triage."
        ),
    ),
    Threat(
        id="TM11",
        name="Supply-chain attack",
        description=(
            "Typosquatting, a mirror substituted for the real repository, a moved tag, "
            "or a compromised maintainer pushing to a source already trusted."
        ),
        severity=Severity.HIGH,
        layers=[1, 5, 7, 8],
        controls=[
            "sources pinned by full commit SHA, never by tag or branch",
            "content hashed at install and re-verifiable afterwards",
            "a moved pin is re-audited and re-approved, never silently upgraded",
            "licenses recorded; trust decisions require a written justification",
        ],
        residual=(
            "A pin proves you got the same bytes as last time. It does not prove those "
            "bytes were ever safe."
        ),
    ),
    Threat(
        id="TM12",
        name="Confused deputy",
        description=(
            "Untrusted content persuades a component that legitimately holds a "
            "permission to exercise it on the attacker's behalf - the browser fetching "
            "an internal URL, an agent reading a file for a page that asked it to."
        ),
        severity=Severity.HIGH,
        layers=[2, 3, 4, 8],
        controls=[
            "the policy engine decides from configuration, never from model output",
            "browser requests are policy-checked per request, so a redirect gains nothing",
            "loopback is a narrow opt-in that applies only to the locally served side",
            "tool scope comes from the workflow, so persuasion cannot widen it",
        ],
        residual=(
            "Any capability an agent legitimately has can be misdirected within its "
            "scope. The defence is that the scope is small, not that misdirection is "
            "impossible."
        ),
    ),
)


def layer(number: int) -> Layer:
    for entry in LAYERS:
        if entry.number == number:
            return entry
    raise KeyError(number)


def threat(threat_id: str) -> Threat:
    for entry in THREATS:
        if entry.id == threat_id:
            return entry
    raise KeyError(threat_id)


def threats_for_layer(number: int) -> list[Threat]:
    return [entry for entry in THREATS if number in entry.layers]
