"""Documentation is checked, not trusted.

These tests fail when the docs drift away from the code - a new CLI command that
nobody documented, a doc page that was deleted, or a claim about an unimplemented
capability that quietly turned into a promise.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from devforge.cli.main import app
from devforge.core.workflow.loader import WorkflowLoader

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
README = ROOT / "README.md"

EXPECTED_DOCS = (
    "architecture.md",
    "workflows.md",
    "skills.md",
    "tools.md",
    "runtimes.md",
    "security.md",
    "contributing.md",
)


def cli_command_names() -> list[str]:
    # typer leaves `name` unset when it is inferred from the function name.
    return sorted(
        command.name or command.callback.__name__.replace("_", "-")
        for command in app.registered_commands
    )


def test_docs_pages_exist() -> None:
    missing = [name for name in EXPECTED_DOCS if not (DOCS / name).is_file()]
    assert not missing, f"missing documentation pages: {missing}"


def test_readme_documents_every_cli_command() -> None:
    readme = README.read_text(encoding="utf-8")

    undocumented = [name for name in cli_command_names() if f"devforge {name}" not in readme]
    assert not undocumented, f"CLI commands missing from the README: {undocumented}"


def test_readme_covers_the_required_sections() -> None:
    readme = README.read_text(encoding="utf-8")

    for heading in (
        "Why it exists",
        "Installation",
        "Architecture",
        "Core concepts",
        "CLI",
        "Workflow format",
        "Verification loop",
        "Security model",
        "Current limitations",
        "Roadmap",
    ):
        assert heading in readme, f"README is missing the '{heading}' section"


def test_readme_states_the_sandbox_limitation() -> None:
    readme = README.read_text(encoding="utf-8").lower()

    assert "not a sandbox" in readme
    assert "not implemented" in readme


def test_security_doc_leads_with_the_limitation() -> None:
    security = (DOCS / "security.md").read_text(encoding="utf-8")

    assert "not a sandbox" in security.lower()
    # The caveat must appear early, not be buried at the bottom of the page.
    assert security.lower().index("not a sandbox") < len(security) // 3


@pytest.mark.parametrize("name", ["feature", "bugfix", "refactor", "clone"])
def test_workflows_doc_lists_every_builtin_workflow(name: str) -> None:
    workflows = (DOCS / "workflows.md").read_text(encoding="utf-8")

    assert name in workflows
    assert name in WorkflowLoader.for_project(None).available()


def test_unimplemented_adapters_are_documented_as_such() -> None:
    tools = (DOCS / "tools.md").read_text(encoding="utf-8")

    assert "NOT implemented" in tools or "NOT IMPLEMENTED" in tools
    for name in ("browser", "mcp"):
        assert name in tools
