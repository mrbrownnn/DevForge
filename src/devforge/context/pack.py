"""Assembling the context pack, and storing the index.

The pack is what an agent gets instead of the repository: the task, a project
summary, the files and symbols that scored, the dependencies, and the project's
own memory - architecture, conventions, decisions, known issues.

Project memory is scoped to one project by construction. It is read from that
project's `.devforge/`, and the index records the root it was built from and is
refused against a different one. Cross-project leakage is prevented by where the
data lives, not by a filter someone has to remember to apply.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from devforge.context.models import CodebaseIndex, ContextPack, FileRole
from devforge.context.retrieval import retrieve
from devforge.core.errors import DevForgeError
from devforge.core.state.store import ProjectStore

INDEX_DIRNAME = "index"
INDEX_FILENAME = "index.json"

#: Rough characters-per-token. Only used when no tokenizer is installed; the
#: benchmark reports which estimator produced its numbers.
CHARS_PER_TOKEN = 4.0

KNOWN_ISSUES_FILE = "known-issues.md"


class IndexError_(DevForgeError):
    """The index is missing, stale, or belongs to a different project."""


def index_path(project_root: Path) -> Path:
    return Path(project_root) / ".devforge" / INDEX_DIRNAME / INDEX_FILENAME


def save_index(project_root: Path, index: CodebaseIndex) -> Path:
    path = index_path(project_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(index.model_dump_json(indent=1), encoding="utf-8")
    return path


def load_index(project_root: Path) -> CodebaseIndex:
    """Load the index, refusing one built somewhere else."""
    path = index_path(project_root)
    if not path.is_file():
        raise IndexError_(f"no index at {path} - run 'devforge index' first")
    try:
        index = CodebaseIndex.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise IndexError_(f"could not read {path}: {exc}") from exc

    recorded = Path(index.root).resolve()
    actual = Path(project_root).resolve()
    if recorded != actual:
        # Structural defence against cross-project leakage: an index carried into
        # another checkout describes files that are not there, and may name paths
        # from a repository this project has no business knowing about.
        raise IndexError_(
            f"index was built for {recorded}, not {actual}. Refusing to use another "
            "project's index; run 'devforge index' here."
        )
    return index


def estimate_tokens(text: str) -> tuple[int, str]:
    """Token count, with the method named.

    Uses ``tiktoken`` when it is installed - it is an optional extra, so the
    benchmark reports real counts on a machine that has it and a clearly-labelled
    approximation on one that does not. Reporting an estimate as a measurement
    would make the benchmark worthless.
    """
    try:
        import tiktoken
    except ImportError:
        return int(len(text) / CHARS_PER_TOKEN), "chars/4 approximation"

    try:
        encoding = tiktoken.get_encoding("cl100k_base")
    except Exception:  # pragma: no cover - network or cache failure
        return int(len(text) / CHARS_PER_TOKEN), "chars/4 approximation"
    return len(encoding.encode(text)), "tiktoken cl100k_base"


def read_known_issues(store: ProjectStore) -> str:
    path = store.memory_file(KNOWN_ISSUES_FILE)
    if path.is_file():
        return path.read_text(encoding="utf-8")
    return ""


def project_summary(index: CodebaseIndex, store: ProjectStore) -> str:
    """A few lines about the project, from its own context file plus index facts."""
    memory = store.read_memory()
    stated = memory.get("context.md", "").strip()

    languages: dict[str, int] = {}
    for record in index.files:
        if record.role is FileRole.SOURCE:
            languages[record.language] = languages.get(record.language, 0) + 1
    ranked = sorted(languages.items(), key=lambda item: -item[1])[:3]
    shape = ", ".join(f"{name} ({count} files)" for name, count in ranked) or "no source detected"

    facts = (
        f"Indexed {index.stats.files_indexed} files and {index.stats.symbols} symbols. "
        f"Primary languages: {shape}."
    )
    if not stated or stated.startswith("# Project Context"):
        # The seeded template says nothing; index facts are more useful than a stub.
        return facts
    return f"{stated}\n\n{facts}"


def build_pack(
    task: str,
    *,
    store: ProjectStore,
    index: CodebaseIndex | None = None,
    max_files: int = 12,
    max_symbols: int = 25,
    count_tokens: bool = True,
) -> ContextPack:
    """Retrieve for a task and assemble the pack an agent will receive."""
    index = index if index is not None else load_index(store.root)
    memory = store.read_memory()
    result = retrieve(index, task, max_files=max_files, max_symbols=max_symbols)

    pack = ContextPack(
        task=task,
        project_summary=project_summary(index, store),
        relevant_files=result.files,
        relevant_symbols=result.symbols,
        dependencies=[dep for dep in index.dependencies if not dep.optional][:25],
        architecture=memory.get("architecture.md", "").strip(),
        constraints=memory.get("conventions.md", "").strip(),
        previous_decisions=memory.get("decisions.md", "").strip(),
        tests=result.tests,
        known_issues=read_known_issues(store).strip(),
        excluded=index.stats.excluded_paths[:10],
        retrieval_note=result.note,
    )

    if count_tokens:
        pack.estimated_tokens = estimate_tokens(pack.render())[0]
    return pack


def full_repository_context(root: Path, index: CodebaseIndex) -> str:
    """The baseline the benchmark compares against: every indexed file, in full.

    This is what "just give the model the repository" actually costs. It reads the
    same files the index allowed, so the comparison is like-for-like: the baseline
    is not penalised by including secrets the retrieved pack excluded.
    """
    blocks: list[str] = []
    for record in index.files:
        path = Path(root) / record.path
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        blocks.append(f"### {record.path}\n\n```\n{text}\n```")
    return "\n\n".join(blocks)


def pack_to_json(pack: ContextPack) -> str:
    return json.dumps(pack.model_dump(mode="json"), indent=2, default=str)


def index_age_days(index: CodebaseIndex) -> float:
    from devforge.core.models import utcnow

    built = index.built_at
    if built.tzinfo is None:
        built = built.replace(tzinfo=utcnow().tzinfo)
    return (utcnow() - built).total_seconds() / 86400.0


def stale_files(root: Path, index: CodebaseIndex) -> list[str]:
    """Indexed files whose content hash no longer matches, plus files that vanished.

    An index that silently describes a repository that has moved on is worse than
    no index: it produces confident, wrong context.
    """
    from devforge.context.indexer import content_hash

    drifted: list[str] = []
    for record in index.files:
        path = Path(root) / record.path
        if not path.is_file():
            drifted.append(f"{record.path} (deleted)")
            continue
        try:
            if content_hash(path.read_text(encoding="utf-8")) != record.content_hash:
                drifted.append(f"{record.path} (changed)")
        except (OSError, UnicodeDecodeError):
            continue
    return drifted


def format_pack_age(built_at: datetime) -> str:
    from devforge.core.models import utcnow

    if built_at.tzinfo is None:
        built_at = built_at.replace(tzinfo=utcnow().tzinfo)
    delta = utcnow() - built_at
    if delta.days:
        return f"{delta.days}d ago"
    hours = int(delta.total_seconds() // 3600)
    return f"{hours}h ago" if hours else "just now"
