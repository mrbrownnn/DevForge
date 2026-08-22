"""What crosses the boundary between the control plane and a worker.

Every type here is part of a wire protocol, which changes how they are designed:
a field is not merely data, it is something a possibly-hostile peer can set.
Three consequences run through the file.

**An envelope carries no secrets.** Not a token, not a key, not an API
credential. A worker gets a task description, a policy and a workspace name. If
a worker needs a credential to do its job, that is a gap to close by giving the
worker its own configured credential - never by shipping one through the queue,
where it would land in the audit log and in every crash dump on the way.

**Results are claims until checked.** ``WorkerResult`` records what the worker
says happened. Nothing in it is authoritative; ``TaskRecord.verified`` is set by
the control plane after it re-runs verification against the artifacts it
actually received.

**Paths are names, not paths.** Artifacts cross as a relative name plus content.
A worker cannot return ``../../../etc/cron.d/x``: the control plane resolves
every name inside the one task's artifact directory and refuses anything that
escapes.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from devforge.core.models import new_id, utcnow

#: Protocol version. A worker and a control plane that disagree refuse to talk
#: rather than guessing what a field meant.
PROTOCOL_VERSION = 1

#: How far apart two clocks may be before a signed message is refused. Wide
#: enough for ordinary drift, narrow enough that a captured message stops being
#: replayable quickly.
MAX_CLOCK_SKEW = timedelta(minutes=2)

#: Bound on one artifact crossing the boundary. A worker that wants to return a
#: gigabyte is either broken or hostile, and either way the control plane should
#: not find out by running out of memory.
MAX_ARTIFACT_BYTES = 4_000_000
MAX_ARTIFACTS = 200


class Capability(str, Enum):
    """What a worker is permitted to do, and what a task needs done.

    Deliberately coarse. A capability is a thing an operator decides about a
    machine - "this box may drive a browser", "this box may run agents" - and a
    vocabulary fine enough to express every tool would be one nobody configures
    correctly.
    """

    AGENT = "agent"
    TOOLS = "tools"
    BROWSER = "browser"
    VERIFY = "verify"
    SHELL = "shell"
    NETWORK = "network"


class TaskState(str, Enum):
    """Where a submitted task is.

    ``EXECUTED`` and ``VERIFIED`` are separate on purpose: the first is what the
    worker reported, the second is what the control plane confirmed.
    """

    QUEUED = "queued"
    LEASED = "leased"
    AWAITING_APPROVAL = "awaiting_approval"
    EXECUTED = "executed"
    VERIFIED = "verified"
    REJECTED = "rejected"
    FAILED = "failed"
    EXPIRED = "expired"

    @property
    def terminal(self) -> bool:
        return self in {TaskState.VERIFIED, TaskState.REJECTED, TaskState.FAILED}


class WorkerIdentity(BaseModel):
    """A worker as the control plane knows it.

    The signing key is **not** here. It lives in a separate file the filesystem
    policy already treats as credential material, so an identity record can be
    read, logged and shipped around without carrying the thing that authenticates
    it.
    """

    model_config = ConfigDict(extra="forbid")

    worker_id: str
    #: Free text: which machine, which operator, which purpose.
    description: str = ""
    capabilities: list[Capability] = Field(default_factory=list)
    #: Tools this worker may be asked to use. Empty means none.
    tools: list[str] = Field(default_factory=list)
    #: Runtimes this worker can execute. Empty means none.
    runtimes: list[str] = Field(default_factory=list)
    #: sha256 of the signing key, so two records can be compared without either
    #: holding the secret.
    key_fingerprint: str = ""
    registered_at: datetime = Field(default_factory=utcnow)
    enabled: bool = True

    def has(self, capability: Capability) -> bool:
        return capability in self.capabilities

    def missing(self, required: list[Capability]) -> list[Capability]:
        return [capability for capability in required if not self.has(capability)]


class NetworkPolicy(BaseModel):
    """What a task may reach. Default deny, stated explicitly on every envelope."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    allow_hosts: list[str] = Field(default_factory=list)
    allow_loopback: bool = False


class TaskEnvelope(BaseModel):
    """A unit of work, as it crosses to a worker.

    This is the whole of what a worker is told. Anything absent from it is
    something a compromised worker cannot learn from being given a task.
    """

    model_config = ConfigDict(extra="forbid")

    protocol: int = PROTOCOL_VERSION
    task_id: str = Field(default_factory=lambda: new_id("ptask"))
    #: The project this belongs to, for audit correlation. Not a path.
    project_id: str = ""
    description: str
    workflow: str = "feature"
    runtime: str = "mock"
    #: Capabilities a worker must hold to be leased this task.
    requires: list[Capability] = Field(default_factory=list)
    #: Tool names the work is scoped to. A worker refuses names it does not hold.
    tools: list[str] = Field(default_factory=list)
    network: NetworkPolicy = Field(default_factory=NetworkPolicy)
    #: Files the task starts from: relative name -> content. The worker
    #: materialises these into an isolated workspace and nothing else.
    inputs: dict[str, str] = Field(default_factory=dict)
    #: Verifier ids the control plane will re-run on what comes back. Sent so the
    #: worker can run them too; authoritative only when the control plane runs them.
    verify: list[str] = Field(default_factory=list)
    #: Gates a human has approved through the control plane, by name. The worker
    #: answers exactly these and declines everything else - approval authority
    #: stays with the control plane, and the worker receives a narrow grant
    #: rather than the ability to decide.
    approved_gates: list[str] = Field(default_factory=list)
    timeout_s: int = 900
    max_attempts: int = 1
    submitted_at: datetime = Field(default_factory=utcnow)

    @model_validator(mode="after")
    def _check(self) -> TaskEnvelope:
        if not self.description.strip():
            raise ValueError("a task envelope needs a description")
        for name in self.inputs:
            _reject_escaping_name(name, "input")
        return self


class Artifact(BaseModel):
    """A file a worker produced, by name and content.

    Content rather than a path, because a path would be a path on the worker's
    machine and a name the control plane would have to trust. A name is checked;
    a path would have to be believed.
    """

    model_config = ConfigDict(extra="forbid")

    name: str
    content: str
    #: sha256 of the content, so tampering between production and storage shows.
    digest: str = ""

    @model_validator(mode="after")
    def _check(self) -> Artifact:
        _reject_escaping_name(self.name, "artifact")
        if len(self.content.encode("utf-8", errors="ignore")) > MAX_ARTIFACT_BYTES:
            raise ValueError(f"artifact '{self.name}' exceeds {MAX_ARTIFACT_BYTES} bytes")
        return self


class VerificationClaim(BaseModel):
    """A verifier result *as reported by the worker*.

    The name says what it is. A compromised worker can put anything here, so
    nothing reads it as a result - it is recorded next to the control plane's own
    verification so a mismatch is visible.
    """

    model_config = ConfigDict(extra="forbid")

    verifier: str
    status: str
    summary: str = ""
    exit_code: int | None = None


class WorkerResult(BaseModel):
    """What a worker returns. Every field is a claim."""

    model_config = ConfigDict(extra="forbid")

    protocol: int = PROTOCOL_VERSION
    task_id: str
    worker_id: str
    ok: bool = False
    summary: str = ""
    output: str = ""
    error: str = ""
    artifacts: list[Artifact] = Field(default_factory=list)
    claims: list[VerificationClaim] = Field(default_factory=list)
    duration_ms: int = 0
    #: Anything the worker wants to say that is not part of the contract.
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _check(self) -> WorkerResult:
        if len(self.artifacts) > MAX_ARTIFACTS:
            raise ValueError(f"a result may carry at most {MAX_ARTIFACTS} artifacts")
        return self


class Lease(BaseModel):
    """A worker's exclusive, expiring claim on one task.

    Expiry is what makes a lost worker survivable: the task returns to the queue
    when the lease runs out, rather than sitting leased forever by a process that
    is never coming back.
    """

    model_config = ConfigDict(extra="forbid")

    lease_id: str = Field(default_factory=lambda: new_id("lease"))
    task_id: str
    worker_id: str
    granted_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime

    def expired(self, now: datetime | None = None) -> bool:
        return (now or utcnow()) > self.expires_at


class TaskRecord(BaseModel):
    """The control plane's record of one task. The source of truth."""

    model_config = ConfigDict(extra="forbid")

    envelope: TaskEnvelope
    state: TaskState = TaskState.QUEUED
    attempts: int = 0
    lease: Lease | None = None
    #: What the worker claimed.
    result: WorkerResult | None = None
    #: What the control plane confirmed by re-running verification itself.
    verified: list[VerificationClaim] = Field(default_factory=list)
    #: Where the artifacts were written, relative to the project's artifact root.
    artifact_paths: list[str] = Field(default_factory=list)
    reason: str = ""
    updated_at: datetime = Field(default_factory=utcnow)

    @property
    def task_id(self) -> str:
        return self.envelope.task_id

    def touch(self) -> None:
        self.updated_at = utcnow()


class Message(BaseModel):
    """One signed protocol message.

    The signature covers the canonical form of ``payload`` together with the
    worker id, the nonce and the timestamp - so moving a valid signature onto a
    different payload, a different worker or a different moment all fail.
    """

    model_config = ConfigDict(extra="forbid")

    protocol: int = PROTOCOL_VERSION
    kind: str
    worker_id: str
    nonce: str = Field(default_factory=lambda: new_id("n"))
    sent_at: datetime = Field(default_factory=utcnow)
    payload: dict[str, Any] = Field(default_factory=dict)
    signature: str = ""


class AuditEvent(BaseModel):
    """One entry in the hash-chained audit trail."""

    model_config = ConfigDict(extra="forbid")

    sequence: int
    at: datetime = Field(default_factory=utcnow)
    event: str
    actor: str = "control-plane"
    task_id: str = ""
    worker_id: str = ""
    detail: dict[str, Any] = Field(default_factory=dict)
    #: sha256 of the previous entry's canonical form. Removing or editing an
    #: entry breaks every link after it.
    previous: str = ""
    digest: str = ""


def _reject_escaping_name(name: str, kind: str) -> None:
    """A name is a name. Anything that could become a path elsewhere is refused.

    Checked at parse time rather than at write time so that a hostile value never
    reaches code that joins it to a directory - there is no second place to
    remember the check.
    """
    if not name or name.strip() != name:
        raise ValueError(f"{kind} name must be a non-empty, untrimmed-free string")
    normalised = name.replace("\\", "/")
    if normalised.startswith("/") or ".." in normalised.split("/"):
        raise ValueError(f"{kind} name '{name}' must be relative and must not traverse")
    if ":" in normalised or "\x00" in normalised:
        raise ValueError(f"{kind} name '{name}' contains a character that is not a name")
