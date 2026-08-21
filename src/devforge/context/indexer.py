"""Building the index.

Python is parsed with the standard library's ``ast``: exact, dependency-free, and
it knows the difference between a method and a module-level function. Other
languages get a deliberately shallow regex pass that finds top-level declarations
and imports.

That asymmetry is stated rather than hidden. A JavaScript file yields worse
symbols than a Python one, and the honest consequence is that retrieval in a
JS-heavy repository leans more on paths and terms than on structure. Tree-sitter
is the obvious upgrade and the extension point is :func:`extract_symbols`; adding
it would improve fidelity without changing anything above this module.

Nothing here stores file contents. Symbols carry names, kinds, lines and the first
line of a docstring - enough to judge relevance, not a copy of the source.
"""

from __future__ import annotations

import ast
import hashlib
import re
import time
import tomllib
from pathlib import Path

from devforge.context.guard import (
    IGNORE_DIRECTORIES,
    GuardDecision,
    IndexGuard,
    load_ignore_file,
)
from devforge.context.models import (
    CodebaseIndex,
    Dependency,
    FileRecord,
    FileRole,
    IndexStats,
    Symbol,
    SymbolKind,
)

LANGUAGE_BY_SUFFIX = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".kt": "kotlin",
    ".swift": "swift",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".hpp": "cpp",
    ".sh": "shell",
    ".sql": "sql",
    ".md": "markdown",
    ".rst": "restructuredtext",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".toml": "toml",
    ".json": "json",
    ".ini": "ini",
    ".cfg": "ini",
}

TEST_MARKERS = ("test_", "_test.", ".test.", ".spec.", "/tests/", "/test/", "/spec/", "__tests__")
CONFIG_NAMES = {
    "pyproject.toml",
    "setup.cfg",
    "setup.py",
    "package.json",
    "tsconfig.json",
    "dockerfile",
    "docker-compose.yml",
    "makefile",
    ".editorconfig",
    "requirements.txt",
    "cargo.toml",
    "go.mod",
    "pom.xml",
    "build.gradle",
}
BUILD_NAMES = {"makefile", "dockerfile", "docker-compose.yml", "build.gradle", "justfile"}
SCHEMA_MARKERS = ("schema", "migration", "models.py", ".proto", ".graphql")

#: Route decorators and definitions that mark an externally reachable entry point.
ENDPOINT_DECORATORS = re.compile(
    r"\b(route|get|post|put|patch|delete|command|task|handler)\b", re.I
)

_JS_SYMBOL = re.compile(
    r"^\s*(?:export\s+)?(?:default\s+)?"
    r"(?:(?:async\s+)?function\s+(?P<func>[A-Za-z_$][\w$]*)"
    r"|class\s+(?P<cls>[A-Za-z_$][\w$]*)"
    r"|(?:const|let|var)\s+(?P<const>[A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\(|function))",
    re.M,
)
_JS_IMPORT = re.compile(
    r"""^\s*(?:import\s[^'"]*from\s*['"](?P<from>[^'"]+)['"]"""
    r"""|import\s*['"](?P<bare>[^'"]+)['"]"""
    r"""|(?:const|let|var)\s[^=]*=\s*require\(\s*['"](?P<req>[^'"]+)['"]\s*\))""",
    re.M,
)
_GO_SYMBOL = re.compile(
    r"^\s*func\s+(?:\([^)]*\)\s*)?(?P<func>[A-Za-z_]\w*)|^\s*type\s+(?P<type>[A-Za-z_]\w*)", re.M
)
_RUST_SYMBOL = re.compile(
    r"^\s*(?:pub\s+)?(?:fn\s+(?P<func>\w+)|struct\s+(?P<struct>\w+)|enum\s+(?P<enum>\w+)|trait\s+(?P<trait>\w+))",
    re.M,
)
_MARKDOWN_HEADING = re.compile(r"^#{1,3}\s+(.+)$", re.M)

_WORD = re.compile(r"[A-Za-z][A-Za-z0-9]+")


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:16]


def split_identifier(name: str) -> list[str]:
    """`JWTTokenService` -> jwt, token, service. Retrieval matches on these."""
    spaced = re.sub(r"[_\-./]+", " ", name)
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", spaced)
    spaced = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", " ", spaced)
    return [part.lower() for part in _WORD.findall(spaced) if len(part) > 1]


def classify_role(relative_path: str, name: str) -> FileRole:
    lowered = relative_path.lower()
    if any(marker in lowered for marker in TEST_MARKERS):
        return FileRole.TEST
    if name.lower() in BUILD_NAMES:
        return FileRole.BUILD
    if name.lower() in CONFIG_NAMES or lowered.endswith((".ini", ".cfg", ".toml")):
        return FileRole.CONFIG
    if lowered.endswith((".md", ".rst", ".txt")) or "/docs/" in lowered:
        return FileRole.DOCS
    if any(marker in lowered for marker in SCHEMA_MARKERS):
        return FileRole.SCHEMA
    if lowered.endswith((".yaml", ".yml", ".json")):
        return FileRole.CONFIG
    if Path(relative_path).suffix in LANGUAGE_BY_SUFFIX:
        return FileRole.SOURCE
    return FileRole.UNKNOWN


# --------------------------------------------------------------------- extraction


def _docstring_summary(node: ast.AST) -> str:
    try:
        text = ast.get_docstring(node)  # type: ignore[arg-type]
    except TypeError:
        return ""
    if not text:
        return ""
    first = text.strip().splitlines()[0].strip()
    return first[:200]


def _signature(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    args = [arg.arg for arg in node.args.args]
    if node.args.vararg:
        args.append(f"*{node.args.vararg.arg}")
    args.extend(arg.arg for arg in node.args.kwonlyargs)
    if node.args.kwarg:
        args.append(f"**{node.args.kwarg.arg}")
    prefix = "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
    return f"{prefix} {node.name}({', '.join(args)})"


def _decorator_names(node: ast.AST) -> list[str]:
    names: list[str] = []
    for decorator in getattr(node, "decorator_list", []):
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        if isinstance(target, ast.Name):
            names.append(target.id)
        elif isinstance(target, ast.Attribute):
            names.append(target.attr)
    return names


def extract_python(relative_path: str, text: str) -> tuple[list[Symbol], list[str]]:
    """Exact structure via the standard library. A syntax error yields nothing, loudly."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return [], []

    symbols: list[Symbol] = []
    imports: list[str] = []

    module_summary = _docstring_summary(tree)
    if module_summary:
        symbols.append(
            Symbol(
                name=Path(relative_path).stem,
                kind=SymbolKind.MODULE,
                path=relative_path,
                line=1,
                summary=module_summary,
            )
        )

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.append(node.module)

    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            decorators = _decorator_names(node)
            symbols.append(
                Symbol(
                    name=node.name,
                    kind=SymbolKind.CLASS,
                    path=relative_path,
                    line=node.lineno,
                    end_line=getattr(node, "end_lineno", node.lineno) or node.lineno,
                    signature=f"class {node.name}",
                    summary=_docstring_summary(node),
                    decorators=decorators,
                    is_public=not node.name.startswith("_"),
                )
            )
            for child in node.body:
                if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef):
                    child_decorators = _decorator_names(child)
                    symbols.append(
                        Symbol(
                            name=child.name,
                            kind=SymbolKind.METHOD,
                            path=relative_path,
                            line=child.lineno,
                            end_line=getattr(child, "end_lineno", child.lineno) or child.lineno,
                            parent=node.name,
                            signature=_signature(child),
                            summary=_docstring_summary(child),
                            decorators=child_decorators,
                            is_public=not child.name.startswith("_"),
                        )
                    )
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            decorators = _decorator_names(node)
            kind = (
                SymbolKind.ENDPOINT
                if any(ENDPOINT_DECORATORS.search(name) for name in decorators)
                else SymbolKind.FUNCTION
            )
            symbols.append(
                Symbol(
                    name=node.name,
                    kind=kind,
                    path=relative_path,
                    line=node.lineno,
                    end_line=getattr(node, "end_lineno", node.lineno) or node.lineno,
                    signature=_signature(node),
                    summary=_docstring_summary(node),
                    decorators=decorators,
                    is_public=not node.name.startswith("_"),
                )
            )
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id.isupper():
                    symbols.append(
                        Symbol(
                            name=target.id,
                            kind=SymbolKind.CONSTANT,
                            path=relative_path,
                            line=node.lineno,
                        )
                    )

    return symbols, sorted(set(imports))


def _line_of(text: str, position: int) -> int:
    return text.count("\n", 0, position) + 1


def extract_regex(relative_path: str, text: str, language: str) -> tuple[list[Symbol], list[str]]:
    """Shallow extraction for languages without a parser here.

    Finds top-level declarations and imports. It will miss nested and generated
    definitions - accepted, and the reason tree-sitter is on the roadmap.
    """
    symbols: list[Symbol] = []
    imports: list[str] = []

    if language in {"javascript", "typescript"}:
        for match in _JS_SYMBOL.finditer(text):
            name = match.group("func") or match.group("cls") or match.group("const")
            if not name:
                continue
            kind = SymbolKind.CLASS if match.group("cls") else SymbolKind.FUNCTION
            symbols.append(
                Symbol(
                    name=name,
                    kind=kind,
                    path=relative_path,
                    line=_line_of(text, match.start()),
                    is_public="export" in match.group(0),
                )
            )
        for match in _JS_IMPORT.finditer(text):
            module = match.group("from") or match.group("bare") or match.group("req")
            if module:
                imports.append(module)
    elif language == "go":
        for match in _GO_SYMBOL.finditer(text):
            name = match.group("func") or match.group("type")
            if name:
                symbols.append(
                    Symbol(
                        name=name,
                        kind=SymbolKind.FUNCTION if match.group("func") else SymbolKind.CLASS,
                        path=relative_path,
                        line=_line_of(text, match.start()),
                        is_public=name[:1].isupper(),
                    )
                )
    elif language == "rust":
        for match in _RUST_SYMBOL.finditer(text):
            name = (
                match.group("func")
                or match.group("struct")
                or match.group("enum")
                or match.group("trait")
            )
            if name:
                symbols.append(
                    Symbol(
                        name=name,
                        kind=SymbolKind.FUNCTION if match.group("func") else SymbolKind.CLASS,
                        path=relative_path,
                        line=_line_of(text, match.start()),
                    )
                )

    return symbols, sorted(set(imports))


def extract_symbols(relative_path: str, text: str, language: str) -> tuple[list[Symbol], list[str]]:
    """The seam a tree-sitter backend would replace."""
    if language == "python":
        return extract_python(relative_path, text)
    return extract_regex(relative_path, text, language)


def extract_headings(text: str) -> list[str]:
    return [heading.strip() for heading in _MARKDOWN_HEADING.findall(text)][:20]


# ------------------------------------------------------------------- dependencies


def read_dependencies(root: Path) -> list[Dependency]:
    """Declared dependencies, from manifests that actually exist."""
    dependencies: list[Dependency] = []

    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        except (tomllib.TOMLDecodeError, OSError):
            data = {}
        project = data.get("project", {}) if isinstance(data, dict) else {}
        for raw in project.get("dependencies", []) or []:
            name = re.split(r"[<>=!\[;\s]", raw, maxsplit=1)[0].strip()
            if name:
                dependencies.append(
                    Dependency(name=name, version=raw[len(name) :].strip(), source="pyproject.toml")
                )
        for group, entries in (project.get("optional-dependencies", {}) or {}).items():
            for raw in entries:
                name = re.split(r"[<>=!\[;\s]", raw, maxsplit=1)[0].strip()
                if name:
                    dependencies.append(
                        Dependency(
                            name=name,
                            version=raw[len(name) :].strip(),
                            source=f"pyproject.toml[{group}]",
                            optional=True,
                        )
                    )

    package_json = root / "package.json"
    if package_json.is_file():
        import json

        try:
            data = json.loads(package_json.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            data = {}
        for key, optional in (("dependencies", False), ("devDependencies", True)):
            for name, version in (data.get(key, {}) or {}).items():
                dependencies.append(
                    Dependency(
                        name=name, version=str(version), source="package.json", optional=optional
                    )
                )

    return dependencies


# ------------------------------------------------------------------------ builder


def build_index(
    root: Path,
    *,
    project_id: str = "",
    guard: IndexGuard | None = None,
    previous: CodebaseIndex | None = None,
) -> CodebaseIndex:
    """Walk the project and build an index.

    ``previous`` enables incremental rebuilds: a file whose content hash is
    unchanged keeps its existing record instead of being re-parsed.
    """
    root = Path(root).resolve()
    started = time.monotonic()
    guard = guard or IndexGuard(root=root, extra_ignores=load_ignore_file(root))
    known = {record.path: record for record in (previous.files if previous else [])}

    records: list[FileRecord] = []
    stats = IndexStats()

    for path in sorted(root.rglob("*")):
        if path.is_dir() or path.is_symlink():
            continue

        relative = guard.relative(path)
        parts = relative.split("/")[:-1]
        # One membership test instead of a directory check per ancestor per file:
        # an ignored directory anywhere in the path skips the whole subtree cheaply.
        if any(part in IGNORE_DIRECTORIES for part in parts):
            continue
        if any(guard.is_sensitive(f"{part}/x") for part in parts):
            stats.files_skipped += 1
            guard.record_exclusion(
                relative, GuardDecision(False, "under a sensitive directory", sensitive=True)
            )
            continue

        stats.files_seen += 1

        decision = guard.check_file(path)
        if not decision.allowed:
            stats.files_skipped += 1
            guard.record_exclusion(relative, decision)
            continue

        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            stats.files_skipped += 1
            continue

        digest = content_hash(text)
        cached = known.get(relative)
        if cached is not None and cached.content_hash == digest:
            records.append(cached)
            stats.files_indexed += 1
            stats.symbols += len(cached.symbols)
            continue

        content_decision = guard.check_content(relative, text)
        if not content_decision.allowed:
            stats.files_skipped += 1
            guard.record_exclusion(relative, content_decision)
            continue

        language = LANGUAGE_BY_SUFFIX.get(path.suffix.lower(), "unknown")
        role = classify_role(relative, path.name)

        if guard.is_generated(text):
            stats.files_skipped += 1
            continue

        symbols, imports = extract_symbols(relative, text, language)
        headings = extract_headings(text) if language in {"markdown", "restructuredtext"} else []

        # Terms come from four places, and leaving any of them out costs real
        # recall: a module whose docstring says "JWT authentication" and which does
        # `import jwt` must match the query "jwt", even though neither word appears
        # in its path or its symbol names.
        terms = set(split_identifier(relative))
        prose_terms: set[str] = set()
        for symbol in symbols:
            terms.update(split_identifier(symbol.name))
            if symbol.summary:
                prose_terms.update(split_identifier(symbol.summary))
        for heading in headings:
            prose_terms.update(split_identifier(heading))
        for imported in imports:
            # The last component is the meaningful one: `app.auth.tokens` -> tokens,
            # and a third-party import names the technology in play.
            terms.update(split_identifier(imported.rsplit(".", 1)[-1]))
        prose_terms -= terms

        records.append(
            FileRecord(
                path=relative,
                role=role,
                language=language,
                size_bytes=len(text.encode("utf-8", errors="replace")),
                lines=text.count("\n") + 1,
                content_hash=digest,
                symbols=symbols,
                imports=imports,
                terms=sorted(terms),
                prose_terms=sorted(prose_terms),
                headings=headings,
            )
        )
        stats.files_indexed += 1
        stats.symbols += len(symbols)

    _link_imports(records)

    stats.duration_ms = int((time.monotonic() - started) * 1000)
    stats.secrets_excluded = guard.secrets_excluded
    stats.excluded_paths = guard.excluded[:50]

    return CodebaseIndex(
        project_id=project_id,
        root=str(root),
        files=records,
        dependencies=read_dependencies(root),
        stats=stats,
    )


def _link_imports(records: list[FileRecord]) -> None:
    """Fill in reverse edges, so retrieval can follow "who uses this"."""
    by_module: dict[str, list[FileRecord]] = {}
    for record in records:
        by_module.setdefault(record.module_name, []).append(record)

    for record in records:
        for imported in record.imports:
            tail = imported.rsplit(".", 1)[-1]
            for target in by_module.get(tail, []):
                if target.path != record.path and record.path not in target.imported_by:
                    target.imported_by.append(record.path)
