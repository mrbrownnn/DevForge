"""Codebase index and context-pack models.

The index is a structural map of a repository: files, the symbols they define,
what they import, which are tests, which are configuration, which are docs. It is
built from the source itself, stored as JSON under ``.devforge/index/``, and holds
**no file contents** - only locations, names and signatures.

That last point is the security property. An index that stores excerpts is a copy
of the repository with none of the repository's access controls, and it outlives
the files it copied. This one stores where to look, so reading is always a fresh,
policy-checked read of the real file.

No vector database. Retrieval is lexical and structural (see ``retrieval.py``),
which is explainable, deterministic, and needs no embedding model or extra
service. If that stops being good enough, the scorer is the seam to replace.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from devforge.core.models import utcnow


class SymbolKind(str, Enum):
    MODULE = "module"
    CLASS = "class"
    FUNCTION = "function"
    METHOD = "method"
    CONSTANT = "constant"
    #: A route, CLI command, or other externally reachable entry point.
    ENDPOINT = "endpoint"


class FileRole(str, Enum):
    """What a file is *for*. Retrieval weights these differently."""

    SOURCE = "source"
    TEST = "test"
    CONFIG = "config"
    DOCS = "docs"
    SCHEMA = "schema"
    BUILD = "build"
    UNKNOWN = "unknown"


class Symbol(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    kind: SymbolKind
    path: str
    line: int = 0
    end_line: int = 0
    #: Enclosing class for a method, module for a top-level definition.
    parent: str | None = None
    signature: str = ""
    #: First line of the docstring only - enough to judge relevance, not a copy.
    summary: str = ""
    decorators: list[str] = Field(default_factory=list)
    is_public: bool = True

    @property
    def qualified_name(self) -> str:
        return f"{self.parent}.{self.name}" if self.parent else self.name

    @property
    def location(self) -> str:
        return f"{self.path}:{self.line}"


class FileRecord(BaseModel):
    """One indexed file. Contains no file content."""

    model_config = ConfigDict(extra="forbid")

    path: str
    role: FileRole = FileRole.UNKNOWN
    language: str = "unknown"
    size_bytes: int = 0
    lines: int = 0
    #: Hash of the file content, so re-indexing can skip unchanged files.
    content_hash: str = ""
    symbols: list[Symbol] = Field(default_factory=list)
    imports: list[str] = Field(default_factory=list)
    #: Modules in this project that import this file, filled in after the walk.
    imported_by: list[str] = Field(default_factory=list)
    #: Terms from structure - path, symbol names, imports. Strong evidence of
    #: what a file IS.
    terms: list[str] = Field(default_factory=list)
    #: Terms from prose - docstrings and headings. Weaker: a docstring reading
    #: "unrelated to authentication" mentions the word without being about it,
    #: and lexical retrieval cannot tell those apart.
    prose_terms: list[str] = Field(default_factory=list)
    headings: list[str] = Field(default_factory=list)
    indexed_at: datetime = Field(default_factory=utcnow)
    #: Set when the file was seen but deliberately not parsed.
    skipped_reason: str = ""

    @property
    def indexed(self) -> bool:
        return not self.skipped_reason

    @property
    def module_name(self) -> str:
        stem = self.path.rsplit("/", 1)[-1]
        return stem.rsplit(".", 1)[0]


class Dependency(BaseModel):
    """An external package the project declares."""

    model_config = ConfigDict(extra="forbid")

    name: str
    version: str = ""
    source: str = ""
    optional: bool = False


class IndexStats(BaseModel):
    model_config = ConfigDict(extra="forbid")

    files_seen: int = 0
    files_indexed: int = 0
    files_skipped: int = 0
    symbols: int = 0
    duration_ms: int = 0
    #: Files skipped because a path or content rule refused them.
    secrets_excluded: int = 0
    excluded_paths: list[str] = Field(default_factory=list)


class CodebaseIndex(BaseModel):
    """The whole index. Serialised to ``.devforge/index/index.json``."""

    model_config = ConfigDict(extra="forbid")

    version: int = 1
    project_id: str = ""
    root: str = ""
    built_at: datetime = Field(default_factory=utcnow)
    files: list[FileRecord] = Field(default_factory=list)
    dependencies: list[Dependency] = Field(default_factory=list)
    stats: IndexStats = Field(default_factory=IndexStats)

    def file(self, path: str) -> FileRecord | None:
        return next((record for record in self.files if record.path == path), None)

    @property
    def symbols(self) -> list[Symbol]:
        return [symbol for record in self.files for symbol in record.symbols]

    def by_role(self, role: FileRole) -> list[FileRecord]:
        return [record for record in self.files if record.role is role]

    def find_symbols(self, name: str) -> list[Symbol]:
        needle = name.lower()
        return [symbol for symbol in self.symbols if symbol.name.lower() == needle]


# --------------------------------------------------------------------- context pack


class ScoredFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    role: FileRole
    score: float
    reasons: list[str] = Field(default_factory=list)
    symbols: list[str] = Field(default_factory=list)

    def explain(self) -> str:
        return f"{self.path} ({self.score:.1f}): {'; '.join(self.reasons)}"


class ContextPack(BaseModel):
    """What an agent is given instead of the repository.

    Inspectable on purpose: ``devforge context "task"`` prints exactly this, so a
    human can see what the agent will and will not know before anything runs. A
    retrieval layer nobody can audit is a retrieval layer nobody should trust.
    """

    model_config = ConfigDict(extra="forbid")

    task: str
    project_summary: str = ""
    relevant_files: list[ScoredFile] = Field(default_factory=list)
    relevant_symbols: list[Symbol] = Field(default_factory=list)
    dependencies: list[Dependency] = Field(default_factory=list)
    architecture: str = ""
    constraints: str = ""
    previous_decisions: str = ""
    tests: list[ScoredFile] = Field(default_factory=list)
    known_issues: str = ""
    #: Paths the retriever deliberately withheld, and why.
    excluded: list[str] = Field(default_factory=list)
    #: Set when retrieval found nothing it would stand behind.
    retrieval_note: str = ""
    built_at: datetime = Field(default_factory=utcnow)
    #: Populated by the token estimator; -1 when no estimate was made.
    estimated_tokens: int = -1

    @property
    def file_paths(self) -> list[str]:
        return [entry.path for entry in self.relevant_files]

    def render(self) -> str:
        """The pack as prompt text. One place, so what is measured is what is sent."""
        blocks: list[str] = [f"# Task\n\n{self.task}"]

        # Directly under the task so it cannot be skimmed past: an agent treating
        # weak matches as authoritative is the failure mode this section prevents.
        if self.retrieval_note:
            blocks.append(f"## Retrieval caveat\n\n{self.retrieval_note}")

        if self.project_summary.strip():
            blocks.append(f"## Project\n\n{self.project_summary.strip()}")
        if self.architecture.strip():
            blocks.append(f"## Architecture\n\n{self.architecture.strip()}")
        if self.constraints.strip():
            blocks.append(f"## Conventions and constraints\n\n{self.constraints.strip()}")
        if self.previous_decisions.strip():
            blocks.append(f"## Previous decisions\n\n{self.previous_decisions.strip()}")
        if self.known_issues.strip():
            blocks.append(f"## Known issues\n\n{self.known_issues.strip()}")

        if self.relevant_files:
            lines = [
                f"- `{entry.path}` - {'; '.join(entry.reasons)}" for entry in self.relevant_files
            ]
            blocks.append("## Relevant files\n\n" + "\n".join(lines))

        if self.relevant_symbols:
            lines = [
                f"- `{symbol.qualified_name}` ({symbol.kind.value}) at {symbol.location}"
                + (f" - {symbol.summary}" if symbol.summary else "")
                for symbol in self.relevant_symbols
            ]
            blocks.append("## Relevant symbols\n\n" + "\n".join(lines))

        if self.tests:
            lines = [f"- `{entry.path}`" for entry in self.tests]
            blocks.append("## Related tests\n\n" + "\n".join(lines))

        if self.dependencies:
            names = ", ".join(
                f"{dep.name}{(' ' + dep.version) if dep.version else ''}"
                for dep in self.dependencies
            )
            blocks.append(f"## Dependencies\n\n{names}")

        if self.excluded:
            blocks.append(
                "## Withheld\n\n"
                + "\n".join(f"- {item}" for item in self.excluded)
                + "\n\nThese were excluded by policy. Do not ask an operator to paste them."
            )

        blocks.append(
            "## How to use this\n\n"
            "These are pointers, not contents. Read the files you need with your tools - "
            "reading goes through the permission policy, so a path missing here is missing "
            "for a reason."
        )
        return "\n\n".join(blocks)
