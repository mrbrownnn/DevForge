"""The detector interface and the shared file reader.

Reading the tree is done once and handed to every detector. That is not only for
speed: it means every detector sees the same files, so a finding's absence never
depends on which detector happened to skip a directory.

The reader honours the same exclusions as the context indexer - vendored
directories, build output, and anything the guard considers sensitive. A
credential file is never read here, by any detector, for any reason.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from devforge.continuous.models import Category, DetectorReport

#: Directories that are never anybody's source.
IGNORED_DIRS = frozenset(
    {
        ".git",
        ".devforge",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".pytest_cache",
        ".ruff_cache",
        ".mypy_cache",
        "dist",
        "build",
        ".tox",
        ".idea",
        ".vscode",
        "site-packages",
    }
)

#: Suffixes worth reading. Everything else is counted, not parsed.
TEXT_SUFFIXES = frozenset(
    {
        ".py",
        ".pyi",
        ".md",
        ".rst",
        ".txt",
        ".toml",
        ".cfg",
        ".ini",
        ".yaml",
        ".yml",
        ".json",
        ".js",
        ".ts",
        ".tsx",
        ".jsx",
        ".html",
        ".css",
    }
)

#: Files larger than this are recorded but not read. A megabyte of generated
#: JSON produces nothing but false positives in every detector here.
MAX_FILE_BYTES = 512_000


@dataclass(frozen=True)
class SourceFile:
    """One readable file, relative path and content."""

    path: str
    text: str
    suffix: str

    @property
    def is_python(self) -> bool:
        return self.suffix == ".py"

    @property
    def is_doc(self) -> bool:
        return self.suffix in {".md", ".rst", ".txt"}

    @property
    def is_test(self) -> bool:
        name = self.path.rsplit("/", 1)[-1]
        return name.startswith("test_") or name.endswith("_test.py") or "/tests/" in self.path

    def lines(self) -> list[str]:
        return self.text.splitlines()


@dataclass
class Workspace:
    """What the detectors are given: the tree, already read."""

    root: Path
    files: list[SourceFile] = field(default_factory=list)
    #: Paths that exist but were not read, and why. Surfaced so a detector's
    #: silence about them is visible.
    skipped: dict[str, str] = field(default_factory=dict)

    def python(self, *, include_tests: bool = True) -> list[SourceFile]:
        return [
            source
            for source in self.files
            if source.is_python and (include_tests or not source.is_test)
        ]

    def docs(self) -> list[SourceFile]:
        return [source for source in self.files if source.is_doc]


def read_sources(root: Path) -> Workspace:
    """Read the tree once, for everyone."""
    from devforge.security.scan import CREDENTIAL_FILES

    root = Path(root).resolve()
    workspace = Workspace(root=root)

    for path in sorted(root.rglob("*")):
        if path.is_dir() or path.is_symlink():
            continue
        relative = path.relative_to(root).as_posix()
        if any(part in IGNORED_DIRS for part in path.relative_to(root).parts):
            continue
        if any(pattern.search(relative) for pattern in CREDENTIAL_FILES):
            # Never read, by any detector. The security scanner reports these by
            # presence; opening one here would pull a credential into memory for
            # no analytical benefit.
            workspace.skipped[relative] = "credential material; not read"
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES:
            workspace.skipped[relative] = "not a text suffix this analysis understands"
            continue
        try:
            size = path.stat().st_size
        except OSError as exc:
            workspace.skipped[relative] = f"could not stat: {exc}"
            continue
        if size > MAX_FILE_BYTES:
            workspace.skipped[relative] = f"{size:,} bytes; larger than the read limit"
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            workspace.skipped[relative] = f"could not read: {exc}"
            continue
        workspace.files.append(SourceFile(path=relative, text=text, suffix=path.suffix.lower()))

    return workspace


class Detector(Protocol):
    """Answers one question about a repository."""

    name: str
    category: Category

    def run(self, workspace: Workspace) -> DetectorReport: ...


def DETECTORS() -> list[Detector]:  # noqa: N802 - a factory, named like the collection
    """Every shipped detector, constructed fresh.

    A function rather than a module-level list so that importing this package
    does not import ten modules' worth of analysis machinery for a caller that
    only wanted the models.
    """
    from devforge.continuous.detectors.code import (
        DeadCodeDetector,
        DuplicationDetector,
        PerformanceDetector,
        TechDebtDetector,
    )
    from devforge.continuous.detectors.docs import DocDriftDetector
    from devforge.continuous.detectors.quality import (
        ArchitectureDetector,
        FlakyTestDetector,
        MissingTestsDetector,
    )
    from devforge.continuous.detectors.supply import DependencyDetector, SecurityDetector

    return [
        SecurityDetector(),
        DependencyDetector(),
        FlakyTestDetector(),
        DeadCodeDetector(),
        DuplicationDetector(),
        ArchitectureDetector(),
        TechDebtDetector(),
        MissingTestsDetector(),
        PerformanceDetector(),
        DocDriftDetector(),
    ]
