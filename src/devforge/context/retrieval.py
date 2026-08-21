"""Retrieval: which files and symbols matter for this task.

Lexical and structural, deliberately. No embeddings, no vector store, no extra
service - three properties that matter more here than raw recall:

* **Explainable.** Every result carries the reasons it was chosen, and the CLI
  prints them. A retrieval layer nobody can audit is one nobody should trust.
* **Deterministic.** The same task and the same index give the same pack, so a
  run can be reproduced and a regression is visible.
* **Free.** No model call, no index rebuild cost beyond parsing.

Scoring, in descending weight:

1. **Exact symbol name** in the task ("change `verify_token`") - the strongest
   signal anyone gives us, and cheap to check.
2. **Term overlap** between the task and a file's harvested terms, weighted by
   inverse document frequency, so "authentication" counts and "the" does not.
3. **Path affinity** - a term appearing in the path is worth more than one buried
   in a symbol, because directory names are how humans organise intent.
4. **Role fit** - a task about tests pulls tests up; every task pulls a little
   documentation and configuration in, because those answer "how is this wired".
5. **Import proximity** - files that import a strong match, or are imported by
   one, get a fraction of its score. This is what finds the caller you forgot.

The weights are constants at the top of the file so they can be argued with.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field

from devforge.context.indexer import split_identifier
from devforge.context.models import CodebaseIndex, FileRecord, FileRole, ScoredFile, Symbol

# -- weights ------------------------------------------------------------------

W_EXACT_SYMBOL = 12.0
W_TERM_BASE = 3.0
#: Prose is weaker evidence than structure. A file whose docstring merely says
#: "unrelated to authentication" should not rank near one that implements it.
W_PROSE_TERM = 0.9
W_PATH_TERM = 2.5
W_HEADING_TERM = 1.5
W_SYMBOL_TERM = 1.0
W_SUMMARY_TERM = 0.8
W_ROLE_FIT = 2.0
W_NEIGHBOUR = 0.35
W_ENTRY_POINT = 1.0

#: A result scoring below this fraction of the best result is noise beside it.
RELATIVE_FLOOR = 0.25
#: Confidence is relative to the corpus, not an absolute score: a nine-file
#: fixture cannot reach the scores a thousand-file repository produces, so a fixed
#: threshold would call every small project unmatched. The question is whether the
#: best result stands out from the background, plus a small floor so a corpus of
#: pure noise never looks confident.
CONFIDENCE_RATIO = 1.8
CONFIDENCE_FLOOR = 6.0

#: How many top-ranked files get their whole public surface listed.
TOP_FILES_FULL_SYMBOLS = 3

#: Words that carry no retrieval signal in an engineering instruction.
STOPWORDS = frozenset(
    [
        "a",
        "an",
        "the",
        "and",
        "or",
        "but",
        "if",
        "then",
        "else",
        "for",
        "to",
        "of",
        "in",
        "on",
        "at",
        "by",
        "with",
        "from",
        "into",
        "over",
        "under",
        "is",
        "are",
        "was",
        "were",
        "be",
        "been",
        "being",
        "do",
        "does",
        "did",
        "done",
        "have",
        "has",
        "had",
        "will",
        "would",
        "should",
        "can",
        "could",
        "may",
        "might",
        "must",
        "shall",
        "this",
        "that",
        "these",
        "those",
        "it",
        "its",
        "as",
        "not",
        "no",
        "yes",
        "so",
        "such",
        "than",
        "add",
        "change",
        "update",
        "fix",
        "make",
        "create",
        "implement",
        "build",
        "write",
        "refactor",
        "improve",
        "support",
        "please",
        "need",
        "want",
        "use",
        "using",
        "new",
        "existing",
        "code",
        "codebase",
        "project",
        "repo",
        "repository",
        "file",
        "files",
        "function",
        "functions",
        "class",
        "classes",
        "method",
        "methods",
        "test",
        "tests",
        "feature",
    ]
)

#: Task words that imply a role should be favoured.
ROLE_HINTS: dict[FileRole, tuple[str, ...]] = {
    FileRole.TEST: ("test", "tests", "testing", "coverage", "regression", "spec"),
    FileRole.CONFIG: ("config", "configuration", "setting", "settings", "env", "deploy"),
    FileRole.DOCS: ("document", "documentation", "docs", "readme", "guide", "explain"),
    FileRole.SCHEMA: ("model", "models", "schema", "migration", "database", "table"),
    FileRole.BUILD: ("build", "ci", "pipeline", "docker", "release"),
}

_TOKEN = re.compile(r"[A-Za-z][A-Za-z0-9_]+")


def tokenize_query(task: str) -> list[str]:
    """Task text into search terms, with identifiers split into their parts."""
    terms: list[str] = []
    for raw in _TOKEN.findall(task):
        lowered = raw.lower()
        if lowered in STOPWORDS or len(lowered) < 2:
            continue
        terms.append(lowered)
        # `verify_token` and `JWTService` also contribute their parts.
        parts = split_identifier(raw)
        terms.extend(part for part in parts if part not in STOPWORDS and part != lowered)
    return terms


@dataclass
class RetrievalResult:
    files: list[ScoredFile] = field(default_factory=list)
    symbols: list[Symbol] = field(default_factory=list)
    tests: list[ScoredFile] = field(default_factory=list)
    query_terms: list[str] = field(default_factory=list)
    considered: int = 0
    top_score: float = 0.0
    #: Mean score of everything *except* the top result.
    mean_score: float = 0.0

    @property
    def paths(self) -> list[str]:
        return [entry.path for entry in self.files]

    @property
    def confident(self) -> bool:
        """Whether the best match stands out from the *rest* of the field.

        Compared against the others, not against an average that includes itself:
        a single surviving result is maximal discrimination, and including it in
        the mean made that case look ambiguous.
        """
        if self.top_score < CONFIDENCE_FLOOR:
            return False
        if self.mean_score <= 0:
            return True
        return self.top_score >= CONFIDENCE_RATIO * self.mean_score

    @property
    def note(self) -> str:
        if not self.query_terms:
            return "The task contained no searchable terms; nothing was retrieved."
        if not self.files:
            return (
                "Nothing in the index matched this task. Treat this as unfamiliar "
                "territory and explore before changing anything."
            )
        if not self.confident:
            return (
                f"No strong match: the best result scored {self.top_score:.1f} against a "
                f"mean of {self.mean_score:.1f}, so nothing stood out. The files below are "
                "weak matches and may be irrelevant - this area may simply not exist in "
                "the codebase yet."
            )
        return ""


def _document_frequency(index: CodebaseIndex) -> Counter[str]:
    frequency: Counter[str] = Counter()
    for record in index.files:
        for term in set(record.terms) | set(record.prose_terms):
            frequency[term] += 1
    return frequency


def _idf(term: str, frequency: Counter[str], total: int) -> float:
    """Rare terms count for more. `authentication` beats `models` in a Django repo."""
    seen = frequency.get(term, 0)
    if seen == 0:
        return 0.0
    return math.log(1 + (total / seen))


def _role_bonus(record: FileRecord, terms: set[str]) -> tuple[float, str]:
    for role, hints in ROLE_HINTS.items():
        if record.role is role and terms.intersection(hints):
            return W_ROLE_FIT, f"task mentions {role.value}"
    # Docs and config answer "how is this wired" for almost any task, at low weight.
    if record.role in {FileRole.DOCS, FileRole.CONFIG}:
        return W_ROLE_FIT * 0.25, "context file"
    return 0.0, ""


def score_file(
    record: FileRecord,
    terms: list[str],
    frequency: Counter[str],
    total_files: int,
) -> ScoredFile:
    unique = set(terms)
    score = 0.0
    reasons: list[str] = []
    matched_symbols: list[str] = []

    path_terms = set(split_identifier(record.path))
    file_terms = set(record.terms)

    matched_path = unique & path_terms
    if matched_path:
        weight = sum(_idf(term, frequency, total_files) for term in matched_path) * W_PATH_TERM
        score += weight
        reasons.append(f"path matches {sorted(matched_path)}")

    matched_terms = (unique & file_terms) - matched_path
    if matched_terms:
        weight = sum(_idf(term, frequency, total_files) for term in matched_terms) * W_TERM_BASE
        score += weight
        reasons.append(f"names include {sorted(matched_terms)[:6]}")

    matched_prose = (unique & set(record.prose_terms)) - matched_path - matched_terms
    if matched_prose:
        weight = sum(_idf(term, frequency, total_files) for term in matched_prose) * W_PROSE_TERM
        score += weight
        reasons.append(f"described as {sorted(matched_prose)[:4]}")

    for symbol in record.symbols:
        symbol_terms = set(split_identifier(symbol.name))
        if not symbol_terms:
            continue
        if symbol.name.lower() in unique:
            score += W_EXACT_SYMBOL
            matched_symbols.append(symbol.qualified_name)
            reasons.append(f"defines `{symbol.name}`")
        elif symbol_terms & unique:
            score += W_SYMBOL_TERM * len(symbol_terms & unique)
            matched_symbols.append(symbol.qualified_name)
        if symbol.summary and unique & set(split_identifier(symbol.summary)):
            score += W_SUMMARY_TERM
        if symbol.kind.value == "endpoint":
            score += W_ENTRY_POINT

    matched_headings = unique & {
        part for heading in record.headings for part in split_identifier(heading)
    }
    if matched_headings:
        score += W_HEADING_TERM * len(matched_headings)
        reasons.append(f"headings mention {sorted(matched_headings)[:4]}")

    bonus, why = _role_bonus(record, unique)
    if bonus:
        score += bonus
        if why:
            reasons.append(why)

    return ScoredFile(
        path=record.path,
        role=record.role,
        score=round(score, 2),
        reasons=reasons,
        symbols=sorted(set(matched_symbols))[:12],
    )


def _spread_to_neighbours(scored: dict[str, ScoredFile], index: CodebaseIndex, limit: int) -> None:
    """Give a fraction of a strong match's score to what it imports and what imports it.

    This is the structural half of retrieval: the file you need to change is often
    not the file that names the concept, but the one that calls it.
    """
    strong = sorted(scored.values(), key=lambda entry: entry.score, reverse=True)[:limit]
    for entry in strong:
        record = index.file(entry.path)
        if record is None or entry.score <= 0:
            continue
        neighbours: set[str] = set(record.imported_by)
        for imported in record.imports:
            tail = imported.rsplit(".", 1)[-1]
            for candidate in index.files:
                if candidate.module_name == tail and candidate.path != record.path:
                    neighbours.add(candidate.path)

        for path in neighbours:
            neighbour = scored.get(path)
            if neighbour is None:
                continue
            gain = entry.score * W_NEIGHBOUR
            if gain <= 0.1:
                continue
            neighbour.score = round(neighbour.score + gain, 2)
            reason = f"linked to {record.path}"
            if reason not in neighbour.reasons:
                neighbour.reasons.append(reason)


def retrieve(
    index: CodebaseIndex,
    task: str,
    *,
    max_files: int = 12,
    max_symbols: int = 25,
    max_tests: int = 5,
    min_score: float = 1.0,
) -> RetrievalResult:
    """Rank the index against a task description."""
    terms = tokenize_query(task)
    if not terms or not index.files:
        return RetrievalResult(query_terms=terms, considered=len(index.files))

    frequency = _document_frequency(index)
    total = max(len(index.files), 1)

    scored = {record.path: score_file(record, terms, frequency, total) for record in index.files}
    _spread_to_neighbours(scored, index, limit=max_files)

    ranked = sorted(
        (entry for entry in scored.values() if entry.score >= min_score),
        key=lambda entry: (-entry.score, entry.path),
    )
    top_score = ranked[0].score if ranked else 0.0
    others = ranked[1:]
    mean_score = (sum(entry.score for entry in others) / len(others)) if others else 0.0
    # A relative floor as well as an absolute one: beside a 60-point match, a
    # 6-point match is noise, and listing it implies a relevance it does not have.
    floor = max(min_score, top_score * RELATIVE_FLOOR)
    ranked = [entry for entry in ranked if entry.score >= floor]

    tests = [entry for entry in ranked if entry.role is FileRole.TEST][:max_tests]
    files = [entry for entry in ranked if entry.role is not FileRole.TEST][:max_files]

    chosen = {entry.path for entry in files}
    symbols: list[Symbol] = []
    unique_terms = set(terms)
    for rank, entry in enumerate(files):
        record = index.file(entry.path)
        if record is None:
            continue
        for symbol in record.symbols:
            symbol_terms = set(split_identifier(symbol.name))
            summary_terms = set(split_identifier(symbol.summary)) if symbol.summary else set()
            matched = (
                symbol.name.lower() in unique_terms
                or symbol_terms & unique_terms
                # `verify_token` does not contain "jwt", but its docstring does, and
                # it is exactly the symbol the task is about.
                or summary_terms & unique_terms
            )
            # For the best few files, list the public API even without a direct term
            # match: pointing an agent at a file without saying what is in it wastes
            # the structural work the index exists to do.
            if matched or (rank < TOP_FILES_FULL_SYMBOLS and symbol.is_public):
                symbols.append(symbol)

    # An exactly-named symbol matters even if its file ranked below the cut.
    for symbol in index.symbols:
        if symbol.name.lower() in unique_terms and symbol.path not in chosen:
            symbols.append(symbol)

    symbols.sort(key=lambda symbol: (symbol.path, symbol.line))
    seen: set[str] = set()
    unique_symbols: list[Symbol] = []
    for symbol in symbols:
        key = f"{symbol.path}:{symbol.line}:{symbol.name}"
        if key not in seen:
            seen.add(key)
            unique_symbols.append(symbol)

    return RetrievalResult(
        files=files,
        symbols=unique_symbols[:max_symbols],
        tests=tests,
        query_terms=terms,
        considered=len(index.files),
        top_score=top_score,
        mean_score=round(mean_score, 2),
    )
