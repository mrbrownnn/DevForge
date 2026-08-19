"""Project-local state.

State lives in plain files under ``.devforge/`` - no database, no vector store.
That is a deliberate MVP choice: state is small, human-readable, diffable, and
survives a crashed process.

::

    .devforge/
    ├── config.yaml         project id, default runtime, project-level verifiers
    ├── state.json          index of runs (source of truth for `devforge status`)
    ├── context.md          long-lived project context fed to agents
    ├── architecture.md     architecture notes
    ├── decisions.md        decision log
    ├── conventions.md      coding conventions
    └── runs/<task_id>/
        ├── task.json       the full Task record
        ├── events.jsonl    structured event log
        └── artifacts/      files an agent declared as artifacts

Writes are atomic (temp file + ``os.replace``) so a crash mid-write cannot leave
truncated state behind.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field

from devforge.core.errors import NotInitializedError, StateError
from devforge.core.models import Task, new_id, utcnow
from devforge.core.workflow.spec import VerifierSpec
from devforge.observability.redaction import redact_value

DEVFORGE_DIR = ".devforge"
STATE_VERSION = 1

MEMORY_FILES = ("context.md", "architecture.md", "decisions.md", "conventions.md")


class ProjectConfig(BaseModel):
    """Contents of ``.devforge/config.yaml``."""

    model_config = ConfigDict(extra="forbid")

    project_id: str = Field(default_factory=lambda: new_id("proj"))
    name: str = "project"
    default_runtime: str = "mock"
    default_workflow: str = "feature"
    devforge_version: str = "0.1.0"
    created_at: datetime = Field(default_factory=utcnow)
    # Verifiers available to every workflow in this project.
    verifiers: list[VerifierSpec] = Field(default_factory=list)


class RunIndexEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    task_id: str
    workflow: str
    description: str
    status: str
    current_step: str | None = None
    created_at: datetime
    updated_at: datetime


class ProjectState(BaseModel):
    """Contents of ``.devforge/state.json``."""

    model_config = ConfigDict(extra="forbid")

    version: int = STATE_VERSION
    project_id: str
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
    last_task_id: str | None = None
    runs: list[RunIndexEntry] = Field(default_factory=list)


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # delete=False and a manual close are required: the file is renamed over the
    # target after closing, which a context manager alone cannot express here.
    handle = tempfile.NamedTemporaryFile(  # noqa: SIM115
        "w", encoding="utf-8", dir=str(path.parent), prefix=f".{path.name}.", delete=False
    )
    try:
        with handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(handle.name, path)
    except BaseException:
        Path(handle.name).unlink(missing_ok=True)
        raise


def _json_default(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


class ProjectStore:
    """Read/write access to one project's ``.devforge`` directory."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root).resolve()
        self.devforge_dir = self.root / DEVFORGE_DIR
        self.runs_dir = self.devforge_dir / "runs"

    # -- lifecycle --------------------------------------------------------------

    @classmethod
    def initialize(
        cls,
        root: Path,
        *,
        name: str | None = None,
        default_runtime: str = "mock",
        force: bool = False,
    ) -> ProjectStore:
        store = cls(root)
        if store.devforge_dir.exists() and not force:
            raise StateError(f"{store.devforge_dir} already exists (use --force to re-initialise)")
        store.runs_dir.mkdir(parents=True, exist_ok=True)

        config = ProjectConfig(name=name or store.root.name, default_runtime=default_runtime)
        store.save_config(config)
        store.save_state(ProjectState(project_id=config.project_id))
        store._seed_memory_files()
        return store

    @classmethod
    def discover(cls, start: Path | None = None) -> ProjectStore:
        """Find the nearest ancestor directory containing ``.devforge``."""
        current = Path(start or Path.cwd()).resolve()
        for candidate in [current, *current.parents]:
            if (candidate / DEVFORGE_DIR / "config.yaml").is_file():
                return cls(candidate)
        raise NotInitializedError(
            f"no DevForge project found at or above {current} - run 'devforge init' first"
        )

    @property
    def initialized(self) -> bool:
        return (self.devforge_dir / "config.yaml").is_file()

    def _seed_memory_files(self) -> None:
        from devforge import builtin

        templates = Path(builtin.__file__).parent / "templates"
        for filename in MEMORY_FILES:
            target = self.devforge_dir / filename
            if target.exists():
                continue
            source = templates / filename
            if source.is_file():
                shutil.copyfile(source, target)
            else:  # templates are optional; never fail init over a missing seed
                target.write_text(f"# {filename[:-3].title()}\n", encoding="utf-8")

    # -- config / state ---------------------------------------------------------

    @property
    def config_path(self) -> Path:
        return self.devforge_dir / "config.yaml"

    @property
    def state_path(self) -> Path:
        return self.devforge_dir / "state.json"

    def load_config(self) -> ProjectConfig:
        if not self.config_path.is_file():
            raise NotInitializedError(f"missing {self.config_path} - run 'devforge init'")
        raw = yaml.safe_load(self.config_path.read_text(encoding="utf-8")) or {}
        return ProjectConfig.model_validate(raw)

    def save_config(self, config: ProjectConfig) -> None:
        payload = json.loads(config.model_dump_json())
        _atomic_write(self.config_path, yaml.safe_dump(payload, sort_keys=False))

    def load_state(self) -> ProjectState:
        if not self.state_path.is_file():
            raise NotInitializedError(f"missing {self.state_path} - run 'devforge init'")
        return ProjectState.model_validate_json(self.state_path.read_text(encoding="utf-8"))

    def save_state(self, state: ProjectState) -> None:
        state.updated_at = utcnow()
        _atomic_write(self.state_path, state.model_dump_json(indent=2))

    def memory_file(self, name: str) -> Path:
        return self.devforge_dir / name

    def read_memory(self) -> dict[str, str]:
        """The project's long-lived markdown memory, as ``{filename: contents}``."""
        memory: dict[str, str] = {}
        for filename in MEMORY_FILES:
            path = self.memory_file(filename)
            if path.is_file():
                memory[filename] = path.read_text(encoding="utf-8")
        return memory

    # -- runs -------------------------------------------------------------------

    def run_dir(self, task_id: str) -> Path:
        return self.runs_dir / task_id

    def events_path(self, task_id: str) -> Path:
        return self.run_dir(task_id) / "events.jsonl"

    def artifacts_dir(self, task_id: str) -> Path:
        return self.run_dir(task_id) / "artifacts"

    def task_path(self, task_id: str) -> Path:
        return self.run_dir(task_id) / "task.json"

    def save_task(self, task: Task) -> None:
        """Persist a task, with secret-shaped strings redacted first.

        State outlives the terminal, so an unredacted token in an agent transcript or
        a verifier output tail is a durable leak (threat T12). Redaction happens here,
        at the single write boundary.
        """
        task.touch()
        payload = redact_value(json.loads(task.model_dump_json()))
        _atomic_write(self.task_path(task.task_id), json.dumps(payload, indent=2))
        self._index_task(task)

    def load_task(self, task_id: str) -> Task:
        path = self.task_path(task_id)
        if not path.is_file():
            raise StateError(f"unknown task '{task_id}' (no {path})")
        return Task.model_validate_json(path.read_text(encoding="utf-8"))

    def list_tasks(self) -> list[RunIndexEntry]:
        """Runs newest first."""
        state = self.load_state()
        return sorted(state.runs, key=lambda entry: entry.created_at, reverse=True)

    def latest_task(self) -> Task | None:
        state = self.load_state()
        if state.last_task_id is None:
            return None
        try:
            return self.load_task(state.last_task_id)
        except StateError:
            return None

    def resolve_task(self, task_id: str | None) -> Task:
        """Load a task by id, or the most recent run when no id is given."""
        if task_id:
            return self.load_task(task_id)
        task = self.latest_task()
        if task is None:
            raise StateError("no runs recorded yet - start one with 'devforge run'")
        return task

    def _index_task(self, task: Task) -> None:
        state = self.load_state()
        entry = RunIndexEntry(
            task_id=task.task_id,
            workflow=task.workflow,
            description=task.description,
            status=task.status.value,
            current_step=task.current_step,
            created_at=task.created_at,
            updated_at=task.updated_at,
        )
        state.runs = [run for run in state.runs if run.task_id != task.task_id]
        state.runs.append(entry)
        state.last_task_id = task.task_id
        self.save_state(state)

    def write_artifact(self, task_id: str, relative_path: str, content: str) -> Path:
        """Store a run artifact inside the run directory (never outside it)."""
        target = (self.artifacts_dir(task_id) / relative_path).resolve()
        root = self.artifacts_dir(task_id).resolve()
        if root != target and root not in target.parents:
            raise StateError(f"artifact path escapes the run directory: {relative_path}")
        _atomic_write(target, content)
        return target
