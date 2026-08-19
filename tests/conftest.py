from __future__ import annotations

from pathlib import Path

import pytest

from devforge.core.models import Task
from devforge.core.state.store import ProjectStore


@pytest.fixture()
def project(tmp_path: Path) -> ProjectStore:
    """An initialised DevForge project in a temporary directory."""
    return ProjectStore.initialize(tmp_path, name="testproj", default_runtime="mock")


@pytest.fixture()
def task(project: ProjectStore) -> Task:
    task = Task(
        project_id=project.load_config().project_id,
        description="Add JWT authentication",
        workflow="feature",
        runtime="mock",
    )
    project.save_task(task)
    return task
