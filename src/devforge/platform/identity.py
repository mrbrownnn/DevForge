"""Worker identity, authentication and authorisation.

Three questions, answered separately, in this order:

*Who is this?* A worker registers once and receives an id and a signing key. The
key is written to a file the existing filesystem policy already treats as
credential material - ``workers.key`` matches the deny rules the policy engine,
the security scanner and the commit guard all share, so it is refused by three
controls that were written before this phase existed.

*Is this really them?* Every message carries an HMAC over its canonical form,
the sender, a nonce and a timestamp. A signature that is valid for one payload
is not valid for another payload, another worker, or another moment.

*May they do this?* Capability and tool checks, applied on both sides. The
control plane will not lease work to a worker that lacks a capability, and the
worker refuses the same envelope again on receipt. A compromised control plane
and a compromised worker are different failures, and neither is a reason to skip
the other's check.

What HMAC does and does not give you
------------------------------------

It authenticates the message and defeats replay within a bounded window. It does
**not** encrypt: over stdio that is fine, since the channel is a pipe between two
processes under the same operator. A transport that crossed a network would need
confidentiality, and this module does not provide it.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import os
import secrets
import stat
from datetime import datetime
from pathlib import Path

import yaml
from pydantic import ValidationError

from devforge.core.errors import DevForgeError
from devforge.core.models import utcnow
from devforge.platform.models import (
    MAX_CLOCK_SKEW,
    PROTOCOL_VERSION,
    Capability,
    Message,
    TaskEnvelope,
    WorkerIdentity,
)

#: Registry of known workers. Public metadata only.
REGISTRY_FILENAME = "workers.yaml"
#: Signing keys. Named `.key` deliberately: the filesystem policy, the security
#: scanner and the commit content guard all already refuse `*.key` by pattern.
KEYS_FILENAME = "workers.key"
#: How many nonces to remember. Enough to cover the skew window at any sane
#: message rate; bounded so a hostile peer cannot grow it without limit.
NONCE_MEMORY = 4096


class AuthError(DevForgeError):
    """A message could not be attributed to a known worker."""


class AuthzError(DevForgeError):
    """A worker is known, and may not do this."""


def platform_dir(root: Path) -> Path:
    return Path(root) / ".devforge" / "platform"


def registry_path(root: Path) -> Path:
    return platform_dir(root) / REGISTRY_FILENAME


def keys_path(root: Path) -> Path:
    return platform_dir(root) / KEYS_FILENAME


def fingerprint(key: str) -> str:
    """A comparable, non-reversible name for a key."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


# --------------------------------------------------------------------------- registry


class WorkerRegistry:
    """Known workers and their keys, on disk.

    Keys and identities are stored separately so that the identity file - the one
    that gets read, printed and copied - never contains a secret.
    """

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self._identities: dict[str, WorkerIdentity] = {}
        self._keys: dict[str, str] = {}
        self._load()

    # -- persistence ------------------------------------------------------------

    def _load(self) -> None:
        registry = registry_path(self.root)
        if registry.is_file():
            try:
                raw = yaml.safe_load(registry.read_text(encoding="utf-8")) or {}
            except (OSError, yaml.YAMLError) as exc:
                raise DevForgeError(f"could not read {registry}: {exc}") from exc
            try:
                self._identities = {
                    entry["worker_id"]: WorkerIdentity.model_validate(entry)
                    for entry in raw.get("workers", [])
                }
            except (KeyError, ValidationError) as exc:
                raise DevForgeError(f"{registry}: invalid worker registry: {exc}") from exc

        keys = keys_path(self.root)
        if keys.is_file():
            try:
                self._keys = json.loads(keys.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                # Fails closed: an unreadable key file must not become an empty
                # one, which would silently reject every worker as unknown.
                raise DevForgeError(f"could not read worker keys at {keys}: {exc}") from exc

    def _save(self) -> None:
        directory = platform_dir(self.root)
        directory.mkdir(parents=True, exist_ok=True)

        registry_path(self.root).write_text(
            yaml.safe_dump(
                {"workers": [identity.model_dump(mode="json") for identity in self.all()]},
                sort_keys=False,
            ),
            encoding="utf-8",
        )

        keys = keys_path(self.root)
        keys.write_text(json.dumps(self._keys, indent=1), encoding="utf-8")
        _restrict(keys)

    # -- registration -----------------------------------------------------------

    def register(
        self,
        *,
        worker_id: str = "",
        description: str = "",
        capabilities: list[Capability] | None = None,
        tools: list[str] | None = None,
        runtimes: list[str] | None = None,
    ) -> tuple[WorkerIdentity, str]:
        """Create a worker and return it with its key.

        The key is returned **once**, here. It is not recoverable from the
        registry afterwards by design: a key that can be read back is a key that
        leaks through every later convenience.
        """
        worker_id = worker_id or f"worker-{secrets.token_hex(4)}"
        if worker_id in self._identities:
            raise DevForgeError(f"worker '{worker_id}' is already registered")

        key = secrets.token_urlsafe(32)
        identity = WorkerIdentity(
            worker_id=worker_id,
            description=description,
            capabilities=list(capabilities or []),
            tools=list(tools or []),
            runtimes=list(runtimes or []),
            key_fingerprint=fingerprint(key),
        )
        self._identities[worker_id] = identity
        self._keys[worker_id] = key
        self._save()
        return identity, key

    def revoke(self, worker_id: str) -> WorkerIdentity:
        """Disable a worker and destroy its key.

        Disabling without destroying the key would leave a credential that works
        the moment somebody re-enables the worker without thinking about why it
        was revoked.
        """
        identity = self.require(worker_id)
        identity.enabled = False
        self._keys.pop(worker_id, None)
        self._save()
        return identity

    def all(self) -> list[WorkerIdentity]:
        return sorted(self._identities.values(), key=lambda identity: identity.worker_id)

    def get(self, worker_id: str) -> WorkerIdentity | None:
        return self._identities.get(worker_id)

    def require(self, worker_id: str) -> WorkerIdentity:
        identity = self.get(worker_id)
        if identity is None:
            raise AuthError(f"unknown worker '{worker_id}'")
        return identity

    def key(self, worker_id: str) -> str:
        key = self._keys.get(worker_id)
        if key is None:
            raise AuthError(f"no signing key for worker '{worker_id}'")
        return key


def _restrict(path: Path) -> None:
    """Owner-only permissions, where the platform has them.

    Windows does not implement POSIX modes, so this is best-effort. That is
    stated rather than assumed: on Windows the key file's protection is whatever
    the containing directory's ACL provides, which is a real gap and is written
    down in docs/platform.md rather than papered over here.
    """
    with contextlib.suppress(OSError, NotImplementedError):  # platform dependent
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


# ------------------------------------------------------------------ authentication


def canonical(payload: dict) -> str:
    """One byte-for-byte form of a payload, so both sides sign the same thing.

    Sorted keys and no incidental whitespace. Without this, two JSON encoders
    that disagree about spacing produce two different signatures for one message
    and the protocol works only when both ends happen to use the same library.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def sign(key: str, message: Message) -> str:
    material = canonical(
        {
            "protocol": message.protocol,
            "kind": message.kind,
            "worker_id": message.worker_id,
            "nonce": message.nonce,
            "sent_at": message.sent_at.isoformat(),
            "payload": message.payload,
        }
    )
    return hmac.new(key.encode("utf-8"), material.encode("utf-8"), hashlib.sha256).hexdigest()


class MessageVerifier:
    """Checks signatures, clocks and nonces.

    Nonce memory is bounded and ordered: the oldest are dropped once it is full.
    That is safe because a message older than the skew window is refused on its
    timestamp anyway, so a nonce only has to be remembered for as long as its
    message could still be accepted.
    """

    def __init__(self, registry: WorkerRegistry, *, memory: int = NONCE_MEMORY) -> None:
        self.registry = registry
        self.memory = memory
        self._seen: dict[str, None] = {}

    def verify(self, message: Message, *, now: datetime | None = None) -> WorkerIdentity:
        now = now or utcnow()

        if message.protocol != PROTOCOL_VERSION:
            raise AuthError(
                f"protocol {message.protocol} does not match {PROTOCOL_VERSION}; "
                "refusing rather than guessing what a field meant"
            )

        identity = self.registry.require(message.worker_id)
        if not identity.enabled:
            raise AuthError(f"worker '{identity.worker_id}' is revoked")

        skew = abs((now - message.sent_at).total_seconds())
        if skew > MAX_CLOCK_SKEW.total_seconds():
            raise AuthError(
                f"message from '{message.worker_id}' is {skew:.0f}s out of step; "
                f"the accepted window is {MAX_CLOCK_SKEW.total_seconds():.0f}s"
            )

        expected = sign(self.registry.key(message.worker_id), message)
        if not hmac.compare_digest(expected, message.signature):
            raise AuthError(f"bad signature on a message claiming to be '{message.worker_id}'")

        nonce = f"{message.worker_id}:{message.nonce}"
        if nonce in self._seen:
            raise AuthError("this message has been seen before; refusing a replay")
        self._seen[nonce] = None
        while len(self._seen) > self.memory:
            self._seen.pop(next(iter(self._seen)))

        return identity


# ------------------------------------------------------------------- authorisation


def authorize(identity: WorkerIdentity, envelope: TaskEnvelope) -> None:
    """Whether this worker may be given this task. Raises with the reason.

    Applied by the control plane before leasing and by the worker on receipt. The
    duplication is the point: one check protects against handing work to the
    wrong machine, the other against a control plane that has been persuaded to
    ask for something the operator never permitted.
    """
    if not identity.enabled:
        raise AuthzError(f"worker '{identity.worker_id}' is revoked")

    missing = identity.missing(envelope.requires)
    if missing:
        raise AuthzError(
            f"worker '{identity.worker_id}' lacks "
            f"{', '.join(capability.value for capability in missing)}"
        )

    forbidden = [tool for tool in envelope.tools if tool not in identity.tools]
    if forbidden:
        raise AuthzError(
            f"worker '{identity.worker_id}' is not permitted the tool(s) "
            f"{', '.join(sorted(forbidden))}"
        )

    if envelope.runtime and identity.runtimes and envelope.runtime not in identity.runtimes:
        raise AuthzError(
            f"worker '{identity.worker_id}' does not run '{envelope.runtime}'"
        )

    if envelope.network.enabled and not identity.has(Capability.NETWORK):
        raise AuthzError(
            f"the task asks for network access and worker '{identity.worker_id}' "
            "does not hold that capability"
        )
