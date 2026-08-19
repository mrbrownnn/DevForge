"""Executable architecture rules.

docs/principles.md states each principle with the condition that would violate it.
The ones that can be checked mechanically are checked here, so a principle is a
build failure rather than a paragraph nobody reads.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src" / "devforge"
CORE = SRC / "core"

#: The only module allowed to name a specific vendor.
VENDOR_ADAPTERS = {"runtime/claude_code.py"}
VENDOR_TOKENS = ("claude", "anthropic", "openai", "gpt-", "gemini", "codex")


def python_files(root: Path) -> list[Path]:
    return sorted(root.rglob("*.py"))


def relative(path: Path) -> str:
    return path.relative_to(SRC).as_posix()


def imports_of(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


# ------------------------------------------------------- principle 1: runtime agnostic


def test_core_never_imports_a_concrete_runtime() -> None:
    """`base` is the interface and `registry` is the name-to-factory indirection; both
    are abstractions. Importing `runtime.mock` or `runtime.claude_code` from core would
    be the actual violation, because that is where a vendor decision lives.

    `core/orchestrator/context.py` is the composition root and legitimately touches the
    registry. Moving it out of `core/` is a Phase 1 tidy-up, not a correctness issue.
    """
    abstractions = {"devforge.runtime.base", "devforge.runtime.registry"}
    offenders: dict[str, set[str]] = {}
    for path in python_files(CORE):
        bad = {
            name
            for name in imports_of(path)
            if name.startswith("devforge.runtime.") and name not in abstractions
        }
        if bad:
            offenders[relative(path)] = bad

    assert not offenders, f"core must depend on the runtime interface only: {offenders}"


def test_core_never_imports_a_concrete_tool_or_verifier() -> None:
    """`base`, `descriptor`, `executor` and `engine` are tool/verification-layer
    *mechanisms* - the interface, the contract, the policy door, the runner. Importing
    a concrete capability (`tools.git`, `verification.command`) from core would be the
    violation, because that is where a specific implementation choice lives."""
    abstractions = {"base", "descriptor", "executor", "engine"}
    offenders: dict[str, set[str]] = {}
    for path in python_files(CORE):
        bad = set()
        for name in imports_of(path):
            match = re.match(r"devforge\.(?:tools|verification)\.(\w+)$", name)
            if match and match.group(1) not in abstractions:
                bad.add(name)
        if bad:
            offenders[relative(path)] = bad

    assert not offenders, f"core must depend on interfaces only: {offenders}"


def test_no_vendor_name_appears_outside_its_adapter() -> None:
    offenders: dict[str, list[str]] = {}
    for path in python_files(SRC):
        name = relative(path)
        if name in VENDOR_ADAPTERS or name.startswith("supplychain/"):
            continue  # the adapter, and the registry that catalogues third parties
        if name == "observability/redaction.py":
            # Names vendors only as credential prefixes to strip (sk-ant-, AKIA...).
            # That is data about token formats, not a behavioural coupling.
            continue
        text = path.read_text(encoding="utf-8").lower()
        hits = [token for token in VENDOR_TOKENS if token in text]
        if hits:
            offenders[name] = hits

    # cli/main.py and runtime/registry.py legitimately name the adapter to register it.
    allowed = {"runtime/registry.py", "cli/main.py"}
    unexpected = {k: v for k, v in offenders.items() if k not in allowed}
    assert not unexpected, f"vendor names leaked outside the adapter: {unexpected}"


# --------------------------------------------------------- principle 7: secure by default


def test_yaml_is_never_loaded_unsafely() -> None:
    offenders = [
        relative(path)
        for path in python_files(SRC)
        if re.search(
            r"yaml\.load\s*\(|yaml\.unsafe_load|Loader\s*=\s*yaml\.Loader",
            path.read_text(encoding="utf-8"),
        )
    ]

    assert not offenders, f"use yaml.safe_load only: {offenders}"


def test_no_shell_true_anywhere() -> None:
    offenders = [
        relative(path)
        for path in python_files(SRC)
        if "shell=True" in path.read_text(encoding="utf-8")
    ]

    assert not offenders, f"DevForge never spawns a shell: {offenders}"


def test_no_eval_or_exec_of_dynamic_content() -> None:
    offenders: dict[str, list[str]] = {}
    for path in python_files(SRC):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        hits = [
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"eval", "exec", "compile", "__import__"}
        ]
        if hits:
            offenders[relative(path)] = hits

    assert not offenders, f"dynamic execution is not permitted: {offenders}"


# ------------------------------------------------- principle 8: locally runnable / no network


def test_no_http_client_is_imported() -> None:
    """DevForge makes no network calls. An HTTP client would create the capability
    that docs/security/threat-model.md relies on not existing."""
    banned = {"requests", "httpx", "aiohttp", "urllib.request", "urllib3", "http.client"}
    offenders: dict[str, set[str]] = {}
    for path in python_files(SRC):
        bad = {
            name
            for name in imports_of(path)
            if name.split(".")[0] in {b.split(".")[0] for b in banned}
        }
        bad = {name for name in bad if name in banned or name.startswith(tuple(banned))}
        if bad:
            offenders[relative(path)] = bad

    assert not offenders, f"no HTTP client may be imported: {offenders}"


def test_supplychain_layer_neither_fetches_nor_executes() -> None:
    """The whole supply-chain model rests on there being no installer."""
    for path in python_files(SRC / "supplychain"):
        text = path.read_text(encoding="utf-8")
        names = imports_of(path)
        assert "subprocess" not in names, f"{relative(path)} must not spawn processes"
        assert "asyncio" not in names, f"{relative(path)} must not run anything"
        assert "zipfile" not in names and "tarfile" not in names, (
            f"{relative(path)} must not unpack archives"
        )
        assert "urllib.request" not in text and "requests" not in names


# ------------------------------------------------------------- dependency discipline


def test_runtime_dependencies_stay_minimal() -> None:
    import tomllib

    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    dependencies = data["project"]["dependencies"]

    names = {re.split(r"[<>=!\[]", dep)[0].strip().lower() for dep in dependencies}
    assert names == {"pydantic", "typer", "pyyaml", "rich"}, (
        "adding a runtime dependency needs a justification in docs/architecture.md"
    )


@pytest.mark.parametrize(
    "document",
    [
        "docs/architecture.md",
        "docs/principles.md",
        "docs/skill-ecosystem.md",
        "docs/security/threat-model.md",
        "docs/security/skill-supply-chain.md",
        "registry/skills.yaml",
    ],
)
def test_phase_zero_deliverables_exist(document: str) -> None:
    path = Path(__file__).resolve().parents[1] / document

    assert path.is_file(), f"missing deliverable: {document}"
    assert path.stat().st_size > 500, f"{document} is a stub"
