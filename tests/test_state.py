from __future__ import annotations

from pathlib import Path

import pytest

from devforge.core.errors import NotInitializedError, StateError
from devforge.core.models import (
    AgentResult,
    Approval,
    ApprovalStatus,
    StepAttempt,
    StepStatus,
    Task,
    TaskStatus,
    VerificationResult,
    VerificationStatus,
)
from devforge.core.state.store import MEMORY_FILES, ProjectStore


def test_initialize_creates_layout(tmp_path: Path) -> None:
    store = ProjectStore.initialize(tmp_path, name="demo")

    assert store.config_path.is_file()
    assert store.state_path.is_file()
    assert store.runs_dir.is_dir()
    for filename in MEMORY_FILES:
        assert store.memory_file(filename).is_file()

    config = store.load_config()
    assert config.name == "demo"
    assert config.project_id.startswith("proj_")
    assert store.load_state().project_id == config.project_id


def test_initialize_twice_requires_force(tmp_path: Path) -> None:
    ProjectStore.initialize(tmp_path)
    with pytest.raises(StateError):
        ProjectStore.initialize(tmp_path)
    ProjectStore.initialize(tmp_path, force=True)  # does not raise


def test_discover_walks_up_to_project_root(tmp_path: Path) -> None:
    ProjectStore.initialize(tmp_path)
    nested = tmp_path / "src" / "deep" / "dir"
    nested.mkdir(parents=True)

    assert ProjectStore.discover(nested).root == tmp_path.resolve()


def test_discover_without_project_raises(tmp_path: Path) -> None:
    with pytest.raises(NotInitializedError):
        ProjectStore.discover(tmp_path)


def test_task_round_trip_preserves_nested_records(project: ProjectStore) -> None:
    task = Task(project_id="p1", description="d", workflow="feature")
    step = task.ensure_step("implementation", agent="coder")
    step.attempts.append(
        StepAttempt(
            attempt=1,
            status=StepStatus.FAILED,
            agent_result=AgentResult(invocation_id="inv_1", runtime="mock", summary="wrote code"),
            verification=[
                VerificationResult(verifier="tests", kind="command", status=VerificationStatus.FAILED, exit_code=1)
            ],
        )
    )
    task.approvals.append(Approval(gate="architecture", step_id="approve-architecture"))
    task.record_verification(step.attempts[0].verification)

    project.save_task(task)
    loaded = project.load_task(task.task_id)

    assert loaded == task
    assert loaded.step("implementation").attempts[0].verification[0].status is VerificationStatus.FAILED
    assert loaded.approvals[0].status is ApprovalStatus.PENDING


def test_saving_task_updates_run_index(project: ProjectStore) -> None:
    task = Task(project_id="p1", description="first", workflow="feature")
    project.save_task(task)

    entries = project.list_tasks()
    assert [entry.task_id for entry in entries] == [task.task_id]
    assert entries[0].status == TaskStatus.PENDING.value

    task.status = TaskStatus.COMPLETED
    project.save_task(task)

    entries = project.list_tasks()
    assert len(entries) == 1, "re-saving a task must update its index entry, not duplicate it"
    assert entries[0].status == TaskStatus.COMPLETED.value
    assert project.latest_task().task_id == task.task_id


def test_resolve_task_defaults_to_latest(project: ProjectStore) -> None:
    first = Task(project_id="p1", description="a", workflow="feature")
    project.save_task(first)
    second = Task(project_id="p1", description="b", workflow="bugfix")
    project.save_task(second)

    assert project.resolve_task(None).task_id == second.task_id
    assert project.resolve_task(first.task_id).description == "a"
    with pytest.raises(StateError):
        project.resolve_task("task_missing")


def test_atomic_write_leaves_no_temp_files(project: ProjectStore, task: Task) -> None:
    leftovers = [p.name for p in project.devforge_dir.iterdir() if p.name.startswith(".")]
    assert leftovers == []


def test_write_artifact_rejects_path_escape(project: ProjectStore, task: Task) -> None:
    path = project.write_artifact(task.task_id, "notes/plan.md", "hello")
    assert path.read_text(encoding="utf-8") == "hello"

    with pytest.raises(StateError):
        project.write_artifact(task.task_id, "../../escape.md", "nope")


def test_read_memory_returns_seeded_files(project: ProjectStore) -> None:
    memory = project.read_memory()
    assert set(memory) == set(MEMORY_FILES)
    assert "Project Context" in memory["context.md"]
