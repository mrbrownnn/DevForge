"""Keeping one task's work away from every other task's.

Four isolations the brief names, and what each actually amounts to here:

**Task isolation.** Each leased task gets its own directory under the worker's
root, named by task id, created empty. A worker executes with that directory as
its workspace and a policy engine bound to it, so the existing path confinement
applies unchanged.

**Artifact isolation.** Artifacts cross as a name and content, and the control
plane resolves every name inside exactly one task's artifact directory. A worker
cannot write into another task's artifacts, or anywhere else, because it never
supplies a path.

**Secret isolation.** The child process gets a scrubbed environment built by the
same allowlist the tool layer uses. An envelope carries no credentials, so there
is nothing for a compromised worker to read out of its own task.

**What none of this is.** It is not a sandbox. A worker process runs as the user
who started it, with that user's privileges, and a hostile worker can read
anything that user can read. Isolation here separates *tasks from each other* and
bounds what the protocol can express; it does not contain a hostile process.
Running an untrusted worker means running it in a container or a VM, and
``docs/platform.md`` says so.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from devforge.core.errors import DevForgeError
from devforge.platform.models import Artifact, TaskEnvelope
from devforge.tools.environment import build_env

WORKSPACES_DIRNAME = "workspaces"


def workspace_root(root: Path) -> Path:
    return Path(root) / ".devforge" / "platform" / WORKSPACES_DIRNAME


def prepare_workspace(root: Path, envelope: TaskEnvelope) -> Path:
    """An empty directory for one task, with its declared inputs in it.

    Recreated rather than reused. A workspace left over from a previous attempt
    would let one attempt's leftovers become the next attempt's inputs, which is
    the sort of thing that makes a failure impossible to reproduce.
    """
    directory = workspace_root(root) / _safe(envelope.task_id)
    shutil.rmtree(directory, ignore_errors=True)
    directory.mkdir(parents=True, exist_ok=True)

    for name, content in envelope.inputs.items():
        target = _resolve_within(directory, name)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return directory


def discard_workspace(root: Path, task_id: str) -> None:
    shutil.rmtree(workspace_root(root) / _safe(task_id), ignore_errors=True)


def collect_artifacts(workspace: Path, names: list[str]) -> list[Artifact]:
    """Read named files out of a finished workspace.

    Only names the caller asked for. A worker that returned everything it found
    would ship whatever an agent happened to leave lying around, including files
    the control plane never asked about.
    """
    import hashlib

    artifacts: list[Artifact] = []
    for name in names:
        path = _resolve_within(workspace, name)
        if not path.is_file():
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        artifacts.append(
            Artifact(
                name=name,
                content=content,
                digest=hashlib.sha256(content.encode("utf-8")).hexdigest(),
            )
        )
    return artifacts


def store_artifacts(destination: Path, artifacts: list[Artifact]) -> list[str]:
    """Write returned artifacts into one task's directory, and nowhere else.

    Each name is resolved inside ``destination`` and refused if it escapes. The
    check is here as well as in the model because this is the function that
    actually touches a filesystem, and a validation that lives only in a parser
    is one refactor away from being bypassed.
    """
    import hashlib

    destination.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    for artifact in artifacts:
        if artifact.digest:
            recomputed = hashlib.sha256(artifact.content.encode("utf-8")).hexdigest()
            if recomputed != artifact.digest:
                raise DevForgeError(
                    f"artifact '{artifact.name}' does not match the digest the worker sent"
                )
        path = _resolve_within(destination, artifact.name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(artifact.content, encoding="utf-8")
        written.append(artifact.name)
    return written


def task_environment(envelope: TaskEnvelope) -> dict[str, str]:
    """The environment a task's processes get: the allowlist, and nothing added.

    Notably it does not carry the worker's own signing key. A task that could read
    its worker's credential could impersonate the worker for every other task.
    """
    return build_env(allow=[])


def _safe(name: str) -> str:
    if not name or "/" in name or "\\" in name or ".." in name or ":" in name:
        raise DevForgeError(f"'{name}' is not usable as a directory name")
    return name


def _resolve_within(base: Path, name: str) -> Path:
    """Join a name to a base, and refuse anything that leaves it.

    Resolved rather than string-compared, because ``a/../../b`` and a symlink both
    look fine as strings and both leave the directory.
    """
    base = base.resolve()
    target = (base / name).resolve()
    if target != base and base not in target.parents:
        raise DevForgeError(f"'{name}' resolves outside the task directory")
    return target
