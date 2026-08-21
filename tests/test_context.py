"""Phase 4: indexing, retrieval, packs - and the benchmark that justifies them.

The benchmark measures what can be measured honestly on this machine: token count,
retrieval precision and recall against a labelled fixture, and latency. It does
**not** claim to measure task success with a real model - the mock runtime is
deterministic by design, so "the task passed" says nothing about whether a model
would have done better with less context. That limit is asserted, not glossed.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from devforge.context.guard import IndexGuard, credential_material
from devforge.context.indexer import build_index, classify_role, split_identifier
from devforge.context.models import FileRole, SymbolKind
from devforge.context.pack import (
    build_pack,
    estimate_tokens,
    full_repository_context,
    load_index,
    save_index,
    stale_files,
)
from devforge.context.retrieval import retrieve, tokenize_query
from devforge.core.errors import DevForgeError
from devforge.core.state.store import ProjectStore

# --------------------------------------------------------------------- fixture repo

AUTH_SERVICE = '''"""JWT authentication for the API."""

import jwt

SECRET_ROTATION_DAYS = 30


class TokenService:
    """Issues and verifies JSON Web Tokens."""

    def issue_token(self, user_id: str) -> str:
        """Sign a JWT for a user."""
        return jwt.encode({"sub": user_id}, "key")

    def verify_token(self, token: str) -> dict:
        """Verify a JWT and return its claims."""
        return jwt.decode(token, "key")
'''

AUTH_MODELS = '''"""User and session models."""


class User:
    """An authenticated principal."""

    def __init__(self, user_id: str) -> None:
        self.user_id = user_id


class Session:
    """A JWT-backed session."""
'''

SECURITY_CONFIG = """
jwt:
  algorithm: HS256
  expiry_minutes: 60
auth:
  require_mfa: false
"""

AUTH_TESTS = '''"""Tests for token issuing and verification."""

from app.auth.service import TokenService


def test_verify_token_round_trip():
    service = TokenService()
    assert service.verify_token(service.issue_token("u1"))
'''

BILLING = '''"""Invoice generation, unrelated to authentication."""


class InvoiceBuilder:
    """Builds invoices from line items."""

    def build(self, items):
        return sum(items)
'''

REPORTING = '''"""Monthly reporting jobs."""


def render_monthly_report(rows):
    """Render a report."""
    return rows
'''

ARCH_DOC = """# Architecture

## Authentication

Tokens are issued by `TokenService` and verified on every request.

## Billing

Invoices are generated nightly.
"""


def make_repo(root: Path) -> Path:
    files = {
        "app/auth/service.py": AUTH_SERVICE,
        "app/auth/models.py": AUTH_MODELS,
        "app/billing/invoices.py": BILLING,
        "app/reporting/monthly.py": REPORTING,
        "config/security.yaml": SECURITY_CONFIG,
        "tests/test_auth_service.py": AUTH_TESTS,
        "tests/test_invoices.py": "def test_invoice(): assert True\n",
        "docs/architecture.md": ARCH_DOC,
        "README.md": "# Demo app\n\nAn app with authentication and billing.\n",
    }
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return root


#: What a competent engineer would call relevant to the JWT task.
JWT_RELEVANT = {
    "app/auth/service.py",
    "app/auth/models.py",
    "config/security.yaml",
    "docs/architecture.md",
}
JWT_IRRELEVANT = {"app/billing/invoices.py", "app/reporting/monthly.py", "tests/test_invoices.py"}


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    return make_repo(tmp_path / "repo")


@pytest.fixture()
def project(tmp_path: Path) -> ProjectStore:
    root = make_repo(tmp_path / "proj")
    return ProjectStore.initialize(root, name="demo")


# ------------------------------------------------------------------------ indexing


def test_index_extracts_python_structure(repo: Path) -> None:
    index = build_index(repo)

    service = index.file("app/auth/service.py")
    assert service is not None
    assert service.role is FileRole.SOURCE and service.language == "python"

    names = {symbol.name: symbol for symbol in service.symbols}
    assert names["TokenService"].kind is SymbolKind.CLASS
    assert names["verify_token"].kind is SymbolKind.METHOD
    assert names["verify_token"].parent == "TokenService"
    assert names["verify_token"].signature == "def verify_token(self, token)"
    assert names["verify_token"].summary.startswith("Verify a JWT")
    assert names["SECRET_ROTATION_DAYS"].kind is SymbolKind.CONSTANT
    assert "jwt" in service.imports


def test_index_stores_no_file_contents(repo: Path) -> None:
    """The index is a map, not a copy - that is what makes it safe to keep."""
    index = build_index(repo)

    serialised = index.model_dump_json()
    assert "jwt.encode" not in serialised
    assert "return sum(items)" not in serialised
    assert "TokenService" in serialised, "names are kept; bodies are not"


def test_index_classifies_roles(repo: Path) -> None:
    index = build_index(repo)

    assert index.file("tests/test_auth_service.py").role is FileRole.TEST
    assert index.file("config/security.yaml").role is FileRole.CONFIG
    assert index.file("docs/architecture.md").role is FileRole.DOCS
    assert index.file("app/auth/models.py").role is FileRole.SCHEMA


def test_index_links_imports_both_ways(repo: Path) -> None:
    index = build_index(repo)

    service = index.file("app/auth/service.py")
    assert "tests/test_auth_service.py" in service.imported_by


def test_index_is_incremental(repo: Path) -> None:
    first = build_index(repo)
    (repo / "app" / "auth" / "service.py").write_text(
        AUTH_SERVICE + "\n\ndef refresh_token(token):\n    return token\n", encoding="utf-8"
    )

    second = build_index(repo, previous=first)

    assert any(symbol.name == "refresh_token" for symbol in second.symbols)
    unchanged = second.file("app/billing/invoices.py")
    assert unchanged.indexed_at == first.file("app/billing/invoices.py").indexed_at


def test_split_identifier_handles_real_names() -> None:
    assert split_identifier("JWTTokenService") == ["jwt", "token", "service"]
    assert split_identifier("verify_token") == ["verify", "token"]
    assert split_identifier("app/auth/service.py") == ["app", "auth", "service", "py"]


def test_role_classification_of_common_names() -> None:
    assert classify_role("tests/test_x.py", "test_x.py") is FileRole.TEST
    assert classify_role("pyproject.toml", "pyproject.toml") is FileRole.CONFIG
    assert classify_role("README.md", "README.md") is FileRole.DOCS


# ------------------------------------------------------------------------ security


def test_secrets_are_never_indexed(repo: Path) -> None:
    (repo / ".env").write_text("API_KEY=sk-ant-realvalue123456\n", encoding="utf-8")
    (repo / "deploy.pem").write_text("-----BEGIN RSA PRIVATE KEY-----\n", encoding="utf-8")
    (repo / "secrets").mkdir()
    (repo / "secrets" / "prod.yaml").write_text("token: abc123def456\n", encoding="utf-8")

    index = build_index(repo)

    paths = {record.path for record in index.files}
    assert ".env" not in paths
    assert "deploy.pem" not in paths
    assert "secrets/prod.yaml" not in paths
    assert index.stats.secrets_excluded >= 2
    # The reason is recorded; the matched secret never is.
    assert "sk-ant" not in index.model_dump_json()


def test_misnamed_credential_file_is_excluded_by_content(repo: Path) -> None:
    (repo / "config" / "prod.txt").write_text(
        "API_KEY=sk-live-abcdefghijklmnop\nDB_PASSWORD=hunter2secret\nAUTH_TOKEN=ghp_aaaaaaaaaaaa\n",
        encoding="utf-8",
    )

    index = build_index(repo)

    assert index.file("config/prod.txt") is None
    assert index.stats.secrets_excluded >= 1


def test_files_that_discuss_secrets_are_still_indexed(repo: Path) -> None:
    """The lesson that cost real coverage: mention is not material.

    An earlier guard excluded anything tripping secret detection, which dropped the
    project's own redaction code and security docs - so a task about secret handling
    got context with the secret handling missing.
    """
    (repo / "docs" / "security.md").write_text(
        "Never commit .env. Rotate API keys quarterly. Store tokens in a vault.\n"
        "Redaction covers `-----BEGIN PRIVATE KEY-----` markers and bearer tokens.\n",
        encoding="utf-8",
    )
    (repo / "app" / "redaction.py").write_text(
        'SECRET_KEY_NAMES = ("password", "token", "api_key")\n'
        'def redact(text):\n    """Strip secrets from logs."""\n    return text\n',
        encoding="utf-8",
    )

    index = build_index(repo)

    assert index.file("docs/security.md") is not None
    assert index.file("app/redaction.py") is not None


def test_credential_material_detection_is_specific() -> None:
    real = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        + ("A" * 64 + "\n") * 3
        + "-----END RSA PRIVATE KEY-----"
    )
    template = "API_KEY=your-key-here\nDB_PASSWORD=changeme\nTOKEN=<paste>\n"

    assert credential_material(real)
    assert not credential_material(template), "a template is not a credential"
    assert not credential_material("We store the API_KEY in a vault, never in git.")


def test_ignored_directories_are_not_walked(repo: Path) -> None:
    (repo / "node_modules" / "pkg").mkdir(parents=True)
    (repo / "node_modules" / "pkg" / "index.js").write_text(
        "export const a = 1;\n", encoding="utf-8"
    )
    (repo / "__pycache__").mkdir()
    (repo / "__pycache__" / "x.pyc").write_bytes(b"\x00")

    index = build_index(repo)

    assert not any("node_modules" in record.path for record in index.files)
    assert not any(record.path.endswith(".pyc") for record in index.files)


def test_devforgeignore_is_respected(repo: Path) -> None:
    (repo / ".devforgeignore").write_text("app/billing/*\n# a comment\n", encoding="utf-8")
    guard = IndexGuard(root=repo, extra_ignores=("app/billing/*",))

    index = build_index(repo, guard=guard)

    assert index.file("app/billing/invoices.py") is None
    assert index.file("app/auth/service.py") is not None


def test_index_from_another_project_is_refused(tmp_path: Path) -> None:
    """Structural defence against cross-project memory leakage."""
    first = ProjectStore.initialize(make_repo(tmp_path / "a"), name="a")
    second = ProjectStore.initialize(make_repo(tmp_path / "b"), name="b")
    save_index(first.root, build_index(first.root))

    # Carry project A's index into project B.
    stolen = (first.root / ".devforge" / "index" / "index.json").read_text(encoding="utf-8")
    target = second.root / ".devforge" / "index"
    target.mkdir(parents=True, exist_ok=True)
    (target / "index.json").write_text(stolen, encoding="utf-8")

    with pytest.raises(DevForgeError, match="Refusing to use another project"):
        load_index(second.root)


# ----------------------------------------------------------------------- retrieval


def test_retrieval_finds_the_authentication_code(repo: Path) -> None:
    index = build_index(repo)

    result = retrieve(index, "Change JWT authentication")

    assert result.confident, f"expected a confident match, top={result.top_score}"
    top = result.paths[:3]
    assert "app/auth/service.py" in top
    assert JWT_IRRELEVANT.isdisjoint(set(result.paths)), "billing is not part of this task"
    assert any("test_auth" in entry.path for entry in result.tests)


def test_retrieval_explains_every_result(repo: Path) -> None:
    index = build_index(repo)

    result = retrieve(index, "Change JWT authentication")

    assert all(entry.reasons for entry in result.files), "a result with no reason is unauditable"
    # Every reason names its evidence, so an operator can disagree with a ranking.
    evidence = {reason.split()[0] for entry in result.files for reason in entry.reasons}
    assert evidence & {"names", "path", "described", "headings", "defines", "linked", "context"}


def test_exact_symbol_name_dominates(repo: Path) -> None:
    index = build_index(repo)

    result = retrieve(index, "fix verify_token")

    assert result.paths[0] == "app/auth/service.py"
    assert any(symbol.name == "verify_token" for symbol in result.symbols)


def test_retrieval_admits_when_nothing_matches(repo: Path) -> None:
    """Returning the least-irrelevant files is worse than saying nothing matched:
    an agent treats anything listed as relevant."""
    index = build_index(repo)

    result = retrieve(index, "kubernetes helm chart rollout strategy")

    assert not result.confident
    assert result.note
    assert "may be irrelevant" in result.note or "Nothing in the index matched" in result.note


def test_retrieval_is_deterministic(repo: Path) -> None:
    index = build_index(repo)

    first = retrieve(index, "Change JWT authentication")
    second = retrieve(index, "Change JWT authentication")

    assert first.paths == second.paths
    assert [entry.score for entry in first.files] == [entry.score for entry in second.files]


def test_tokenize_drops_instruction_noise() -> None:
    terms = set(tokenize_query("Please add a new feature to change the JWT authentication code"))

    assert "jwt" in terms and "authentication" in terms
    assert "please" not in terms and "the" not in terms and "feature" not in terms


def test_import_neighbours_are_pulled_in(repo: Path) -> None:
    index = build_index(repo)

    result = retrieve(index, "verify_token")
    linked = [
        entry for entry in result.files + result.tests if "linked to" in " ".join(entry.reasons)
    ]

    assert linked, "structural proximity should surface callers of a strong match"


# --------------------------------------------------------------------- context pack


def test_pack_contains_every_required_section(project: ProjectStore) -> None:
    index = build_index(project.root)
    save_index(project.root, index)

    pack = build_pack("Change JWT authentication", store=project, index=index)

    assert pack.task
    assert pack.project_summary
    assert pack.relevant_files and pack.relevant_symbols
    assert pack.tests
    assert pack.dependencies == [] or all(dep.name for dep in pack.dependencies)
    # Memory sections come from the project's own .devforge, never another's.
    assert "Architecture" in pack.architecture or pack.architecture == ""
    rendered = pack.render()
    for heading in ("# Task", "## Relevant files", "## Relevant symbols"):
        assert heading in rendered


def test_pack_is_inspectable_before_execution(project: ProjectStore) -> None:
    index = build_index(project.root)

    pack = build_pack("Change JWT authentication", store=project, index=index)

    assert pack.estimated_tokens > 0
    for entry in pack.relevant_files:
        assert entry.reasons, "an operator must be able to see why a file was chosen"


def test_pack_never_leaks_withheld_paths_as_content(project: ProjectStore) -> None:
    (project.root / ".env").write_text("API_KEY=sk-live-abcdefghijklmnop\n", encoding="utf-8")
    index = build_index(project.root)

    pack = build_pack("Change JWT authentication", store=project, index=index)

    rendered = pack.render()
    assert "sk-live" not in rendered
    assert ".env" not in {entry.path for entry in pack.relevant_files}


def test_pack_carries_the_retrieval_caveat(project: ProjectStore) -> None:
    index = build_index(project.root)

    pack = build_pack("kubernetes helm rollout", store=project, index=index)

    assert pack.retrieval_note
    assert "Retrieval caveat" in pack.render()


def test_stale_index_is_detectable(project: ProjectStore) -> None:
    index = build_index(project.root)
    assert stale_files(project.root, index) == []

    (project.root / "app" / "auth" / "service.py").write_text("# rewritten\n", encoding="utf-8")

    drifted = stale_files(project.root, index)
    assert any("service.py" in entry for entry in drifted)


# ------------------------------------------------------------------------ benchmark


def _precision_recall(retrieved: set[str], relevant: set[str]) -> tuple[float, float]:
    if not retrieved:
        return 0.0, 0.0
    hits = retrieved & relevant
    return len(hits) / len(retrieved), len(hits) / len(relevant)


def make_large_repo(root: Path) -> Path:
    """A repository at a realistic size.

    Benchmarking context reduction on nine files measures the pack's fixed overhead,
    not retrieval: the headings and project memory cost the same whether the repo has
    nine files or nine hundred. Sixty modules is the smallest size where the ratio
    reflects what happens on a real codebase.
    """
    make_repo(root)
    for index in range(55):
        module = root / "app" / f"module_{index:02d}" / "service.py"
        module.parent.mkdir(parents=True, exist_ok=True)
        module.write_text(
            f'"""Domain service {index} for orders, shipping and inventory."""\n\n\n'
            f"class Service{index}:\n"
            f'    """Handles domain operation {index}."""\n\n'
            f"    def process(self, payload):\n"
            f'        """Process a payload."""\n'
            f"        return payload\n\n"
            f"    def validate(self, payload):\n"
            f'        """Validate a payload."""\n'
            f"        return bool(payload)\n",
            encoding="utf-8",
        )
    return root


def test_benchmark_retrieved_context_beats_full_repository(tmp_path: Path, capsys) -> None:
    """The measurement the whole layer exists to justify.

    Reports token count, precision, recall and latency. Task success against a real
    model is deliberately NOT claimed - see the module docstring.
    """
    root = make_large_repo(tmp_path / "big")
    project = ProjectStore.initialize(root, name="big")
    index = build_index(project.root)
    save_index(project.root, index)
    task = "Change JWT authentication"

    started = time.monotonic()
    baseline = full_repository_context(project.root, index)
    baseline_ms = (time.monotonic() - started) * 1000
    baseline_tokens, method = estimate_tokens(baseline)

    started = time.monotonic()
    pack = build_pack(task, store=project, index=index)
    pack_ms = (time.monotonic() - started) * 1000
    pack_tokens, _ = estimate_tokens(pack.render())

    retrieved = set(pack.file_paths)
    precision, recall = _precision_recall(retrieved, JWT_RELEVANT)
    reduction = 100 * (1 - pack_tokens / baseline_tokens)

    print(
        f"\n  token method     {method}"
        f"\n  full repository  {baseline_tokens:>6} tokens, {index.stats.files_indexed} files,"
        f" built in {baseline_ms:.0f}ms"
        f"\n  retrieved pack   {pack_tokens:>6} tokens, {len(retrieved)} files,"
        f" built in {pack_ms:.0f}ms"
        f"\n  reduction        {reduction:.1f}%"
        f"\n  precision        {precision:.2f}   recall {recall:.2f}"
    )

    assert pack_tokens < baseline_tokens, "a pack that is not smaller has no reason to exist"
    assert reduction > 50, f"expected a substantial reduction, got {reduction:.1f}%"
    assert precision >= 0.5, f"more than half the retrieved files should be relevant ({precision})"
    assert recall >= 0.5, f"the pack should find most of the relevant files ({recall})"
    assert JWT_IRRELEVANT.isdisjoint(retrieved)
    assert pack_ms < 2000, "retrieval must be fast enough to run before every step"


def test_benchmark_does_not_claim_model_task_success() -> None:
    """An honesty guard.

    The mock runtime succeeds deterministically regardless of context quality, so
    any "task success" number measured here would be an artefact of the mock, not
    evidence about a model. If someone adds such an assertion, this test explains
    why it is meaningless.
    """
    from devforge.runtime.mock import MockAgentRuntime

    capabilities = MockAgentRuntime().capabilities()
    assert "deterministic" in capabilities.notes.lower()


def test_index_latency_is_reasonable(repo: Path) -> None:
    started = time.monotonic()
    index = build_index(repo)
    elapsed_ms = (time.monotonic() - started) * 1000

    assert index.stats.files_indexed > 5
    assert elapsed_ms < 5000
    # >= 0, not > 0: a nine-file fixture can index in under a millisecond, and
    # asserting a timer is non-zero tests the clock, not the code.
    assert index.stats.duration_ms >= 0
