"""Tests for the execution platform.

The premise of the phase is that a worker can be compromised, so most of this
file is written from the worker's side of the boundary trying things it should
not be able to do: forge a signature, replay a message, return a result for a
task it was never leased, write an artifact outside its task, claim a capability
it does not hold, and - the important one - lie about its own verification.

The last is the cheapest attack in the whole design and the one a naive control
plane loses to silently, so it gets its own test with the mismatch asserted
explicitly.
"""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

import pytest

from devforge.core.errors import DevForgeError
from devforge.core.models import utcnow
from devforge.core.state.store import ProjectStore
from devforge.platform.audit import AuditTrail, digest_of
from devforge.platform.control import ControlPlane
from devforge.platform.identity import (
    AuthError,
    AuthzError,
    WorkerRegistry,
    authorize,
    keys_path,
    sign,
)
from devforge.platform.isolation import (
    collect_artifacts,
    prepare_workspace,
    store_artifacts,
    task_environment,
)
from devforge.platform.models import (
    Artifact,
    Capability,
    Message,
    TaskEnvelope,
    TaskState,
    VerificationClaim,
    WorkerResult,
)
from devforge.platform.queue import TaskQueue
from devforge.platform.transport import (
    InProcessTransport,
    SubprocessTransport,
    TransportError,
    decode,
    encode,
    signed,
)
from devforge.platform.worker import Worker, default_capabilities


@pytest.fixture()
def project(tmp_path: Path) -> Path:
    ProjectStore.initialize(tmp_path, name="platform-test", default_runtime="mock")
    return tmp_path


@pytest.fixture()
def control(project: Path) -> ControlPlane:
    return ControlPlane(project)


def register(control: ControlPlane, worker_id: str = "w1", **kwargs):
    kwargs.setdefault("capabilities", default_capabilities())
    kwargs.setdefault("runtimes", ["mock"])
    return control.register_worker(worker_id=worker_id, **kwargs)


def envelope(**kwargs) -> TaskEnvelope:
    base = {"description": "do the thing", "workflow": "demo", "runtime": "mock"}
    return TaskEnvelope(**{**base, **kwargs})


# ------------------------------------------------------------------------ identity


def test_a_key_is_shown_once_and_is_not_in_the_registry(control: ControlPlane) -> None:
    identity, key = register(control)

    registry = (control.root / ".devforge" / "platform" / "workers.yaml").read_text("utf-8")

    assert key not in registry
    assert identity.key_fingerprint in registry


def test_keys_live_in_a_file_the_existing_controls_already_refuse(control: ControlPlane) -> None:
    """`workers.key` matches the `*.key` deny pattern three other controls share."""
    from devforge.security.scan import CREDENTIAL_FILES
    from devforge.vcs.guard import screen_paths

    register(control)
    path = keys_path(control.root)
    assert path.is_file()

    relative = path.relative_to(control.root).as_posix()
    assert any(pattern.search(relative) for pattern in CREDENTIAL_FILES)

    flags = screen_paths(control.root, [relative])
    assert flags and flags[0].blocking, "the commit guard must refuse the key file"


def test_revoking_destroys_the_key(control: ControlPlane) -> None:
    register(control)
    control.registry.revoke("w1")

    assert not control.registry.get("w1").enabled
    with pytest.raises(AuthError, match="no signing key"):
        control.registry.key("w1")


def test_registering_the_same_worker_twice_is_refused(control: ControlPlane) -> None:
    register(control)
    with pytest.raises(DevForgeError, match="already registered"):
        register(control)


def test_an_unreadable_key_file_is_an_error_not_an_empty_registry(control: ControlPlane) -> None:
    """Emptying it silently would reject every worker as unknown."""
    register(control)
    keys_path(control.root).write_text("{not json", encoding="utf-8")

    with pytest.raises(DevForgeError, match="could not read worker keys"):
        WorkerRegistry(control.root)


# ------------------------------------------------------------------ authentication


def test_a_valid_message_authenticates(control: ControlPlane) -> None:
    _, key = register(control)
    message = signed("execute", "w1", key, {"hello": "world"})

    assert control.authenticate(message).worker_id == "w1"


def test_a_forged_signature_is_refused(control: ControlPlane) -> None:
    register(control)
    message = signed("execute", "w1", "not-the-key", {"hello": "world"})

    with pytest.raises(AuthError, match="bad signature"):
        control.authenticate(message)


def test_editing_a_signed_payload_invalidates_it(control: ControlPlane) -> None:
    _, key = register(control)
    message = signed("execute", "w1", key, {"amount": 1})
    message.payload["amount"] = 1_000_000

    with pytest.raises(AuthError, match="bad signature"):
        control.authenticate(message)


def test_a_replayed_message_is_refused(control: ControlPlane) -> None:
    _, key = register(control)
    message = signed("execute", "w1", key, {"hello": "world"})

    control.authenticate(message)
    with pytest.raises(AuthError, match="seen before"):
        control.authenticate(message)


def test_a_stale_message_is_refused(control: ControlPlane) -> None:
    """A captured message stops being usable once the skew window passes."""
    _, key = register(control)
    message = Message(kind="execute", worker_id="w1", sent_at=utcnow() - timedelta(hours=1))
    message.signature = sign(key, message)

    with pytest.raises(AuthError, match="out of step"):
        control.authenticate(message)


def test_a_revoked_worker_cannot_authenticate(control: ControlPlane) -> None:
    _, key = register(control)
    message = signed("execute", "w1", key, {})
    control.registry.revoke("w1")

    with pytest.raises(AuthError):
        ControlPlane(control.root).authenticate(message)


def test_a_rejected_message_is_audited(control: ControlPlane) -> None:
    """An operator wants refusals in the trail; an exception is not a record."""
    register(control)
    with pytest.raises(AuthError):
        control.authenticate(signed("execute", "w1", "wrong", {}))

    assert any(event.event == "auth.rejected" for event in control.audit.read())


def test_a_protocol_mismatch_refuses_rather_than_guessing(control: ControlPlane) -> None:
    _, key = register(control)
    message = Message(kind="execute", worker_id="w1", protocol=99)
    message.signature = sign(key, message)

    with pytest.raises(AuthError, match="protocol"):
        control.authenticate(message)


# ------------------------------------------------------------------ authorisation


def test_a_worker_without_the_capability_is_not_leased_the_task(control: ControlPlane) -> None:
    identity, _ = register(control, capabilities=[Capability.AGENT])
    control.submit(envelope(requires=[Capability.BROWSER]))

    assert control.schedulable(identity) == []
    assert control.lease_next("w1") is None


def test_a_worker_is_not_leased_a_tool_it_does_not_hold(control: ControlPlane) -> None:
    identity, _ = register(control, tools=["filesystem"])

    with pytest.raises(AuthzError, match="not permitted the tool"):
        authorize(identity, envelope(tools=["shell"]))


def test_network_needs_its_own_capability(control: ControlPlane) -> None:
    identity, _ = register(control)

    with pytest.raises(AuthzError, match="network"):
        authorize(identity, envelope(network={"enabled": True}))


def test_the_worker_refuses_the_same_envelope_the_control_plane_would_have(
    control: ControlPlane, project: Path
) -> None:
    """Both sides check. One protects the operator, the other protects the machine."""
    identity, _ = register(control, capabilities=[Capability.AGENT])

    result = Worker(identity, root=project).execute(envelope(requires=[Capability.BROWSER]))

    assert not result.ok
    assert "refused" in result.error


# ------------------------------------------------------------------------- queue


def test_a_task_is_only_leased_once(control: ControlPlane) -> None:
    register(control)
    register(control, worker_id="w2")
    control.submit(envelope())

    assert control.lease_next("w1") is not None
    assert control.lease_next("w2") is None


def test_an_expired_lease_returns_the_task_to_the_queue(control: ControlPlane) -> None:
    register(control)
    control.submit(envelope(max_attempts=3))
    control.lease_next("w1", seconds=-1)

    ready = control.queue.ready()

    assert [record.state for record in ready] == [TaskState.QUEUED]


def test_a_task_out_of_attempts_expires_rather_than_looping(control: ControlPlane) -> None:
    register(control)
    control.submit(envelope(max_attempts=1))
    control.lease_next("w1", seconds=-1)

    control.queue.ready()

    assert control.queue.all()[0].state is TaskState.EXPIRED


def test_a_result_is_only_accepted_from_the_worker_holding_the_lease(
    control: ControlPlane,
) -> None:
    """Authentication proves who is speaking, not what they were asked to do."""
    register(control)
    register(control, worker_id="w2")
    record = control.submit(envelope())
    control.lease_next("w1")

    with pytest.raises(DevForgeError, match="leased to 'w1'"):
        control.accept(WorkerResult(task_id=record.task_id, worker_id="w2", ok=True))


def test_a_task_id_that_is_a_path_is_refused(control: ControlPlane) -> None:
    with pytest.raises(DevForgeError, match="not a task id"):
        TaskQueue(control.root).path_for("../../etc/passwd")


# ------------------------------------------------------- the compromised worker


def test_a_worker_cannot_lie_its_way_to_verified(control: ControlPlane) -> None:
    """The cheapest attack in the design, and the one it exists to stop.

    The worker reports success and claims every verifier passed, but returns no
    artifact. The control plane checks for itself and rejects, recording that the
    two accounts disagree.
    """
    register(control)
    record = control.submit(envelope(verify=["docs/plan.md"]))
    control.lease_next("w1")

    final = control.accept(
        WorkerResult(
            task_id=record.task_id,
            worker_id="w1",
            ok=True,
            claims=[VerificationClaim(verifier="docs/plan.md", status="passed")],
        )
    )

    assert final.state is TaskState.REJECTED
    assert "disagree" in final.reason
    assert [claim.status for claim in final.verified] == ["failed"]


def test_the_disagreement_is_recorded_in_the_audit_trail(control: ControlPlane) -> None:
    register(control)
    record = control.submit(envelope(verify=["docs/plan.md"]))
    control.lease_next("w1")
    control.accept(
        WorkerResult(
            task_id=record.task_id,
            worker_id="w1",
            ok=True,
            claims=[VerificationClaim(verifier="docs/plan.md", status="passed")],
        )
    )

    rejected = [event for event in control.audit.read() if event.event == "task.rejected"]

    assert rejected and rejected[-1].detail.get("disagreed") is True


def test_nothing_declared_means_nothing_confirmed(control: ControlPlane) -> None:
    """`verified` is the strongest word available; it needs more than an opinion."""
    register(control)
    record = control.submit(envelope(verify=[]))
    control.lease_next("w1")

    final = control.accept(WorkerResult(task_id=record.task_id, worker_id="w1", ok=True))

    assert final.state is TaskState.EXECUTED
    assert "confirmed nothing independently" in final.reason


def test_a_worker_that_returns_an_escaping_artifact_name_is_refused() -> None:
    with pytest.raises(ValueError, match="must be relative"):
        Artifact(name="../../escaped.txt", content="x")


def test_an_absolute_artifact_name_is_refused() -> None:
    with pytest.raises(ValueError, match="must be relative"):
        Artifact(name="/etc/passwd", content="x")


def test_artifacts_are_written_inside_one_task_and_nowhere_else(tmp_path: Path) -> None:
    destination = tmp_path / "task-a"

    store_artifacts(destination, [Artifact(name="docs/report.md", content="hello")])

    assert (destination / "docs" / "report.md").read_text(encoding="utf-8") == "hello"
    assert not (tmp_path / "report.md").exists()


def test_a_tampered_artifact_digest_is_refused(tmp_path: Path) -> None:
    artifact = Artifact(name="a.txt", content="real", digest="0" * 64)

    with pytest.raises(DevForgeError, match="does not match the digest"):
        store_artifacts(tmp_path / "task", [artifact])


def test_an_oversized_artifact_is_refused() -> None:
    with pytest.raises(ValueError, match="exceeds"):
        Artifact(name="big.txt", content="x" * 5_000_000)


# --------------------------------------------------------------------- isolation


def test_each_task_gets_an_empty_workspace_of_its_own(tmp_path: Path) -> None:
    first = envelope(inputs={"a.txt": "one"})
    prepared = prepare_workspace(tmp_path, first)
    (prepared / "leftover.txt").write_text("from a previous attempt", encoding="utf-8")

    again = prepare_workspace(tmp_path, first)

    assert (again / "a.txt").read_text(encoding="utf-8") == "one"
    assert not (again / "leftover.txt").exists(), "a workspace must not be reused"


def test_an_input_name_cannot_escape_the_workspace() -> None:
    with pytest.raises(ValueError, match="must be relative"):
        envelope(inputs={"../escaped.txt": "no"})


def test_only_the_declared_artifacts_are_collected(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    (workspace / "wanted.md").write_text("yes", encoding="utf-8")
    (workspace / "private.log").write_text("agent chatter", encoding="utf-8")

    collected = collect_artifacts(workspace, ["wanted.md"])

    assert [artifact.name for artifact in collected] == ["wanted.md"]


def test_a_task_environment_carries_no_worker_credential() -> None:
    """A task that could read its worker's key could impersonate the worker."""
    environment = task_environment(envelope())

    assert "DEVFORGE_WORKER_KEY" not in environment
    assert not any("KEY" in name.upper() for name in environment)


def test_an_envelope_carries_no_secrets() -> None:
    """Asserted on the schema, so a future field cannot quietly add one."""
    fields = set(TaskEnvelope.model_fields)

    for forbidden in ("key", "secret", "token", "password", "credential"):
        assert not any(forbidden in name for name in fields), (
            f"a field named for '{forbidden}' would put a credential on the wire"
        )


# --------------------------------------------------------------------------- audit


def test_the_audit_chain_detects_an_edited_entry(control: ControlPlane) -> None:
    trail = AuditTrail(control.root)
    trail.record("task.submitted", task_id="t1")
    trail.record("task.leased", task_id="t1", worker_id="w1")
    assert trail.verify() == []

    lines = trail.path.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[0])
    tampered["event"] = "task.verified"
    lines[0] = json.dumps(tampered, sort_keys=True)
    trail.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    problems = trail.verify()

    assert problems, "editing an entry must break the chain"
    assert any("does not match its digest" in problem for problem in problems)


def test_the_audit_chain_detects_a_removed_entry(control: ControlPlane) -> None:
    trail = AuditTrail(control.root)
    for index in range(3):
        trail.record("task.submitted", task_id=f"t{index}")

    lines = trail.path.read_text(encoding="utf-8").splitlines()
    trail.path.write_text("\n".join([lines[0], lines[2]]) + "\n", encoding="utf-8")

    assert trail.verify(), "removing an entry must break the chain"


def test_an_audit_entry_commits_to_its_own_content(control: ControlPlane) -> None:
    trail = AuditTrail(control.root)
    event = trail.record("task.submitted", task_id="t1", detail_field="value")

    assert event.digest == digest_of(event)


def test_audit_details_are_redacted(control: ControlPlane) -> None:
    """The trail is durable and widely read - a bad place for a credential."""
    trail = AuditTrail(control.root)
    trail.record("worker.registered", api_key="sk-live-not-a-real-key-000")

    written = trail.path.read_text(encoding="utf-8")

    assert "sk-live-not-a-real-key-000" not in written


def test_every_lifecycle_stage_reaches_the_trail(control: ControlPlane) -> None:
    register(control)
    record = control.submit(envelope(verify=[]))
    control.lease_next("w1")
    control.accept(WorkerResult(task_id=record.task_id, worker_id="w1", ok=True))

    events = [event.event for event in control.audit.read()]

    for stage in ("worker.registered", "task.submitted", "task.leased", "task.result_received"):
        assert stage in events, f"'{stage}' is missing from the audit trail"
    assert control.audit.verify() == []


# ------------------------------------------------------------------------ transport


def test_the_in_process_transport_still_signs_and_verifies(
    control: ControlPlane, project: Path
) -> None:
    """A local transport that skipped authentication would leave it untested."""
    identity, _ = register(control)
    record = control.submit(envelope(verify=[]))
    control.lease_next("w1")

    transport = InProcessTransport(
        registry=control.registry, worker=Worker(identity, root=project), control=control
    )
    result = transport.dispatch(record.envelope)

    assert result.worker_id == "w1"
    assert result.task_id == record.task_id


def test_a_message_survives_encoding(control: ControlPlane) -> None:
    _, key = register(control)
    message = signed("execute", "w1", key, {"envelope": {"description": "x"}})

    assert decode(encode(message)).signature == message.signature


def test_an_oversized_line_is_refused_before_parsing() -> None:
    with pytest.raises(TransportError, match="refusing to parse"):
        decode("{" + "x" * 9_000_000 + "}")


def test_a_line_that_is_not_a_message_is_refused() -> None:
    with pytest.raises(TransportError, match="not a protocol message"):
        decode('{"nonsense": true}')


def test_the_subprocess_transport_reads_the_last_json_line() -> None:
    """A worker's own logging shares stdout, so the reader cannot assume it owns it."""
    from devforge.platform.transport import _last_json_line

    assert _last_json_line('noise\n{"a": 1}\nmore noise\n{"b": 2}\n') == '{"b": 2}'
    assert _last_json_line("no json here") is None


@pytest.mark.slow
def test_a_task_crosses_a_real_process_boundary(control: ControlPlane, project: Path) -> None:
    """The DONE criterion: scheduled, executed, verified, persisted, audited."""
    register(control, tools=[], runtimes=["mock"])
    record = control.submit(
        envelope(workflow="demo", verify=["docs/requirements.md"], approved_gates=["architecture"])
    )
    control.lease_next("w1")

    transport = SubprocessTransport(
        registry=control.registry, worker_id="w1", root=project, timeout_s=300
    )
    result = transport.dispatch(record.envelope)
    final = control.accept(result)

    assert final.state is TaskState.VERIFIED, final.reason
    assert final.artifact_paths == ["docs/requirements.md"]
    assert [claim.status for claim in final.verified] == ["passed"]

    stored = ProjectStore.discover(project).artifacts_dir(record.task_id)
    assert (stored / "docs" / "requirements.md").is_file()
    assert control.audit.verify() == []


@pytest.mark.slow
def test_a_worker_pauses_at_a_gate_it_was_not_granted(
    control: ControlPlane, project: Path
) -> None:
    """A worker has nobody to ask, so an ungranted gate pauses rather than fails."""
    identity, _ = register(control)
    record = control.submit(envelope(workflow="demo", verify=[]))
    control.lease_next("w1")

    result = Worker(identity, root=project).execute(record.envelope)
    final = control.accept(result)

    assert final.state is TaskState.AWAITING_APPROVAL
    assert "architecture" in final.reason


@pytest.mark.slow
def test_an_approval_is_recorded_by_the_control_plane_not_the_worker(
    control: ControlPlane, project: Path
) -> None:
    identity, _ = register(control)
    record = control.submit(envelope(workflow="demo", verify=["docs/requirements.md"]))
    control.lease_next("w1")
    control.accept(Worker(identity, root=project).execute(record.envelope))

    control.approve(record.task_id, "architecture", by="an operator")
    reloaded = control.queue.load(record.task_id)

    assert reloaded.state is TaskState.QUEUED
    assert reloaded.envelope.approved_gates == ["architecture"]

    control.lease_next("w1")
    final = control.accept(Worker(identity, root=project).execute(reloaded.envelope))

    assert final.state is TaskState.VERIFIED, final.reason
    granted = [e for e in control.audit.read() if e.event == "approval.granted"]
    assert granted and granted[0].actor == "an operator"


def test_approving_something_that_is_not_waiting_is_refused(control: ControlPlane) -> None:
    register(control)
    record = control.submit(envelope())

    with pytest.raises(DevForgeError, match="nothing is waiting"):
        control.approve(record.task_id, "architecture")


# ------------------------------------------------------------------- architecture


def test_the_platform_imports_no_http_client() -> None:
    """The rule that decided the transport. Asserted here as well as globally so
    that a future network transport is a deliberate change to a stated principle
    rather than an import somebody added."""
    import ast

    banned = {"requests", "httpx", "aiohttp", "urllib", "http", "socket", "socketserver"}
    root = Path(__file__).resolve().parents[1] / "src" / "devforge" / "platform"

    for path in sorted(root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for name in names:
                assert name.split(".")[0] not in banned, f"{path.name} imports {name}"


def test_the_control_plane_reports_whether_its_audit_is_intact(control: ControlPlane) -> None:
    register(control)
    status = control.status()

    assert status["audit_intact"] is True
    assert status["counts"] == {}
    assert [worker["worker_id"] for worker in status["workers"]] == ["w1"]
