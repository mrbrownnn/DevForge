"""Documentation that no longer matches the code it describes.

Two rules, both checkable against the tree rather than against a judgement about
writing quality. Whether a page is *good* is not something a detector can say;
whether it links to a file that was deleted is.

The second rule - a documented function that no longer exists - is the one that
matters more and fires less. It is deliberately conservative: a name is only
reported when it appears in prose as a call and exists nowhere in the codebase,
in any form, including inside strings.
"""

from __future__ import annotations

import ast
import re

from devforge.continuous.detectors.base import Workspace
from devforge.continuous.models import (
    Category,
    DetectorReport,
    DetectorStatus,
    Finding,
    Risk,
    Severity,
)

#: Markdown links only.
#:
#: A backticked path in prose was tried first and had to be removed: it produced
#: ninety-four findings on this repository and not one was real. `runtime/x.py`
#: in a sentence means "the module", `decisions.md` means a file the harness
#: writes at run time, and `docs/api-docs.md` is an artifact an example produces.
#: A *link* is different in kind - it is a promise that clicking it goes
#: somewhere - and that is the only thing checked here.
_LINK = re.compile(r"\[[^\]]*\]\((?P<target>[^)#\s]+)\)")
#: A call written in prose: `some_function()`.
_CALL = re.compile(r"`(?P<name>[a-z_][a-z0-9_]{3,})\(\)`")

#: Names that are language or library builtins rather than this project's API.
_NOT_OURS = frozenset(
    {
        "print",
        "input",
        "open",
        "range",
        "len",
        "list",
        "dict",
        "set",
        "str",
        "int",
        "main",
        "init",
        "setup",
        "run",
        "test",
        "exit",
        "help",
    }
)


class DocDriftDetector:
    """Links to files that are gone, and calls to functions that are gone."""

    name = "doc-drift"
    category = Category.DOC_DRIFT

    def run(self, workspace: Workspace) -> DetectorReport:
        report = DetectorReport(detector=self.name, category=self.category)
        docs = workspace.docs()
        report.files_examined = len(docs)
        if not docs:
            report.status = DetectorStatus.UNAVAILABLE
            report.detail = "no Markdown, reStructuredText or text files to check"
            return report

        defined = _defined_names(workspace)
        mentioned_in_code = _all_identifiers(workspace)

        for doc in docs:
            report.findings.extend(self._broken_links(workspace, doc))
            report.findings.extend(self._stale_calls(doc, defined, mentioned_in_code))
        return report

    def _broken_links(self, workspace: Workspace, doc) -> list[Finding]:
        findings: list[Finding] = []
        base = (workspace.root / doc.path).parent
        seen: set[str] = set()

        for match in _LINK.finditer(doc.text):
            target = match.group("target")
            if target.startswith(("http://", "https://", "mailto:", "#")) or target in seen:
                continue
            seen.add(target)
            candidate = (base / target) if not target.startswith("/") else None
            if candidate is None or candidate.exists():
                continue
            # A path may also be written from the repository root.
            if (workspace.root / target).exists():
                continue
            line = doc.text[: match.start()].count("\n") + 1
            findings.append(
                Finding(
                    finding_id="CE-DOC-001",
                    category=self.category,
                    title=f"{doc.path} points at '{target}', which does not exist",
                    severity=Severity.LOW,
                    confidence=0.85,
                    evidence=f"{doc.path}:{line} references '{target}'; no such file on disk.",
                    affected_files=[f"{doc.path}:{line}"],
                    recommended_action=(
                        "Update the link, or remove it. A reference that does not resolve "
                        "teaches readers to stop following them."
                    ),
                    estimated_risk=Risk.LOW,
                    detector=self.name,
                )
            )
        return findings

    def _stale_calls(self, doc, defined: set[str], mentioned: set[str]) -> list[Finding]:
        findings: list[Finding] = []
        for name in sorted({match.group("name") for match in _CALL.finditer(doc.text)}):
            if name in _NOT_OURS or name in defined or name in mentioned:
                continue
            line = doc.text.find(f"`{name}()`")
            line_number = doc.text[:line].count("\n") + 1 if line >= 0 else 1
            findings.append(
                Finding(
                    finding_id="CE-DOC-002",
                    category=self.category,
                    title=f"{doc.path} documents '{name}()', which is not defined anywhere",
                    severity=Severity.MEDIUM,
                    confidence=0.7,
                    evidence=(
                        f"{doc.path}:{line_number} describes '{name}()'. No def, class or "
                        "string in the tree mentions that name, so the documentation "
                        "describes something that is not here."
                    ),
                    affected_files=[f"{doc.path}:{line_number}"],
                    recommended_action=(
                        f"Rename or remove the reference to '{name}()'. Documentation that "
                        "describes a function nobody can call is worse than none: it "
                        "sends readers looking."
                    ),
                    estimated_risk=Risk.LOW,
                    detector=self.name,
                )
            )
        return findings


def _defined_names(workspace: Workspace) -> set[str]:
    names: set[str] = set()
    for source in workspace.python():
        try:
            tree = ast.parse(source.text, filename=source.path)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                names.add(node.name)
    return names


def _all_identifiers(workspace: Workspace) -> set[str]:
    """Every word in every non-documentation file.

    Deliberately broad. A method reached through a registry, a CLI command name,
    a key in a YAML file - all of them are reasons a documented name is not
    stale, and being wrong in that direction files a finding at someone.
    """
    names: set[str] = set()
    for source in workspace.files:
        if source.is_doc:
            continue
        names |= set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", source.text))
    return names
