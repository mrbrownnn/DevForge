"""Load workflow definitions from YAML.

Resolution order for a workflow name (first hit wins), so a project can override a
built-in without editing the package:

1. ``<project>/.devforge/workflows/<name>.yaml``
2. ``<project>/workflows/<name>.yaml``
3. the built-ins shipped in ``devforge/builtin/workflows``
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from devforge.core.errors import WorkflowError
from devforge.core.workflow.spec import WorkflowSpec

WORKFLOW_SUFFIXES = (".yaml", ".yml")


def builtin_workflow_dir() -> Path:
    from devforge import builtin

    return Path(builtin.__file__).parent / "workflows"


def load_workflow_file(path: Path) -> WorkflowSpec:
    """Parse and validate one workflow file, raising :class:`WorkflowError` on any problem."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise WorkflowError(f"workflow file not found: {path}") from exc
    except yaml.YAMLError as exc:
        raise WorkflowError(f"invalid YAML in {path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise WorkflowError(f"{path}: workflow must be a YAML mapping, got {type(raw).__name__}")

    raw.setdefault("name", path.stem)
    raw["source_path"] = str(path)
    try:
        return WorkflowSpec.model_validate(raw)
    except ValidationError as exc:
        raise WorkflowError(f"{path}: {_format_errors(exc)}") from exc


def _format_errors(exc: ValidationError) -> str:
    parts = []
    for error in exc.errors():
        location = ".".join(str(item) for item in error["loc"]) or "<root>"
        parts.append(f"{location}: {error['msg']}")
    return "; ".join(parts)


class WorkflowLoader:
    """Discovers and loads workflows across the configured search paths."""

    def __init__(self, search_paths: list[Path]) -> None:
        self.search_paths = [p for p in search_paths if p]

    @classmethod
    def for_project(cls, project_root: Path | None = None) -> WorkflowLoader:
        paths: list[Path] = []
        if project_root is not None:
            paths.append(project_root / ".devforge" / "workflows")
            paths.append(project_root / "workflows")
        paths.append(builtin_workflow_dir())
        return cls(paths)

    def find(self, name: str) -> Path | None:
        for directory in self.search_paths:
            for suffix in WORKFLOW_SUFFIXES:
                candidate = directory / f"{name}{suffix}"
                if candidate.is_file():
                    return candidate
        return None

    def load(self, name: str) -> WorkflowSpec:
        path = self.find(name)
        if path is None:
            available = ", ".join(sorted(self.available())) or "<none>"
            raise WorkflowError(f"unknown workflow '{name}'. Available: {available}")
        return load_workflow_file(path)

    def available(self) -> dict[str, Path]:
        """Map of workflow name -> file path; earlier search paths win."""
        found: dict[str, Path] = {}
        for directory in self.search_paths:
            if not directory.is_dir():
                continue
            for path in sorted(directory.iterdir()):
                if path.suffix in WORKFLOW_SUFFIXES and path.stem not in found:
                    found[path.stem] = path
        return found

    def load_all(self) -> list[WorkflowSpec]:
        return [load_workflow_file(path) for path in self.available().values()]
