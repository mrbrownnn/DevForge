"""Detectors that read the code itself: dead code, duplication, debt, performance.

All four are syntactic. None of them runs anything, and none of them can see what
a program does at runtime - which is why their confidences differ so much. A
`FIXME` marker is a fact about the file (0.95). A block of identical lines is a
fact about the file too (0.85). A function nobody names might be an entry point
reached by a decorator, a plugin loader or a string (0.6, and public names are
lower still, which puts them under the threshold by default).

That asymmetry is deliberate. The expensive mistake here is not missing a finding
- it is filing enough weak ones that people stop reading the list.
"""

from __future__ import annotations

import ast
import hashlib
import re
from collections import defaultdict
from dataclasses import dataclass

from devforge.continuous.detectors.base import SourceFile, Workspace
from devforge.continuous.models import (
    Category,
    DetectorReport,
    DetectorStatus,
    Finding,
    Risk,
    Severity,
)

# --------------------------------------------------------------------------- dead code

#: Decorators that register a function somewhere the analysis cannot see. A
#: decorated definition is never reported as dead, whatever the decorator is -
#: the whole point of a decorator is often to create a reference.
_NEVER_DEAD_NAMES = frozenset({"main", "app", "cli", "setup", "teardown"})


class DeadCodeDetector:
    """Module-level definitions that nothing in the tree refers to."""

    name = "dead-code"
    category = Category.DEAD_CODE

    def run(self, workspace: Workspace) -> DetectorReport:
        report = DetectorReport(detector=self.name, category=self.category)
        sources = workspace.python()
        report.files_examined = len(sources)
        if not sources:
            report.status = DetectorStatus.UNAVAILABLE
            report.detail = "no Python files to analyse"
            return report

        definitions: dict[str, tuple[SourceFile, int, bool]] = {}
        used: set[str] = set()
        exported: set[str] = set()

        for source in sources:
            try:
                tree = ast.parse(source.text, filename=source.path)
            except SyntaxError:
                workspace.skipped[source.path] = "could not be parsed as Python"
                continue

            exported |= _dunder_all(tree)
            for node in tree.body:
                if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                    if node.decorator_list or node.name in _NEVER_DEAD_NAMES:
                        continue
                    if source.is_test:
                        continue
                    definitions[node.name] = (source, node.lineno, node.name.startswith("_"))
            used |= _referenced_names(tree)

        for source in workspace.files:
            if not source.is_python:
                # A name mentioned in a config file or a doc is still a reference:
                # DevForge's own agents and workflows name Python identifiers in
                # YAML, and deleting one would break a workflow silently.
                used |= set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", source.text))

        for name, (source, line, private) in sorted(definitions.items()):
            if name in used or name in exported:
                continue
            confidence = 0.68 if private else 0.5
            finding = Finding(
                finding_id="CE-DEAD-001",
                category=self.category,
                title=f"'{name}' is defined and never referenced",
                severity=Severity.LOW,
                confidence=confidence,
                evidence=(
                    f"{source.path}:{line} defines '{name}'. No other file in the tree "
                    "names it, it is not listed in __all__, and it carries no decorator "
                    "that could register it elsewhere."
                ),
                affected_files=[f"{source.path}:{line}"],
                recommended_action=(
                    f"Confirm '{name}' has no caller outside this repository, then remove it."
                ),
                estimated_risk=Risk.MEDIUM if private else Risk.HIGH,
                detector=self.name,
            )
            report.findings.append(finding)
        return report


def _dunder_all(tree: ast.Module) -> set[str]:
    names: set[str] = set()
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
        if "__all__" not in targets or not isinstance(node.value, ast.List | ast.Tuple):
            continue
        names |= {
            element.value
            for element in node.value.elts
            if isinstance(element, ast.Constant) and isinstance(element.value, str)
        }
    return names


def _referenced_names(tree: ast.Module) -> set[str]:
    """Every identifier used as a value, an attribute or an import."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.ImportFrom):
            names |= {alias.asname or alias.name for alias in node.names}
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            # A name in a string is a reference in every dynamic-dispatch design:
            # registries, getattr, entry points. Treating it as one is what keeps
            # this detector's false-positive rate low enough to ship.
            names |= set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", node.value))
    return names


# ------------------------------------------------------------------------ duplication

#: How many consecutive meaningful lines make a block worth reporting. Below
#: this, identical runs are idiom - imports, guard clauses, `return None`.
BLOCK_LINES = 8
_COMMENT = re.compile(r"#.*$")


@dataclass(frozen=True)
class _Block:
    path: str
    start: int
    end: int


class DuplicationDetector:
    """Runs of identical code in more than one place."""

    name = "duplication"
    category = Category.DUPLICATION

    def run(self, workspace: Workspace) -> DetectorReport:
        report = DetectorReport(detector=self.name, category=self.category)
        sources = workspace.python(include_tests=False)
        report.files_examined = len(sources)
        if not sources:
            report.status = DetectorStatus.UNAVAILABLE
            report.detail = "no non-test Python files to analyse"
            return report

        blocks: dict[str, list[_Block]] = defaultdict(list)
        for source in sources:
            for digest, block in _blocks(source):
                blocks[digest].append(block)

        for digest, group in sorted(blocks.items()):
            files = {block.path for block in group}
            if len(group) < 2 or len(files) < 2:
                # Repetition inside one file is often a deliberate table or a
                # sequence of similar cases; across files it is duplication.
                continue
            locations = sorted(f"{b.path}:{b.start}-{b.end}" for b in group)
            report.findings.append(
                Finding(
                    finding_id="CE-DUP-001",
                    category=self.category,
                    title=f"{BLOCK_LINES} identical lines in {len(files)} files",
                    severity=Severity.LOW if len(group) == 2 else Severity.MEDIUM,
                    confidence=0.85,
                    evidence=(
                        f"The same {BLOCK_LINES} meaningful lines (comments and blank "
                        f"lines ignored, digest {digest[:12]}) appear at: "
                        + "; ".join(locations)
                    ),
                    affected_files=locations,
                    recommended_action=(
                        "Extract the shared logic, or record why the copies are "
                        "deliberate. Two copies that must change together will "
                        "eventually not."
                    ),
                    estimated_risk=Risk.MEDIUM,
                    detector=self.name,
                )
            )
        return report


def _blocks(source: SourceFile):
    """Sliding windows of meaningful lines, with their digests."""
    meaningful: list[tuple[int, str]] = []
    for number, line in enumerate(source.lines(), start=1):
        stripped = _COMMENT.sub("", line).strip()
        if stripped and not stripped.startswith(("import ", "from ", '"""', "'''")):
            meaningful.append((number, stripped))

    for index in range(len(meaningful) - BLOCK_LINES + 1):
        window = meaningful[index : index + BLOCK_LINES]
        text = "\n".join(line for _, line in window)
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        yield digest, _Block(path=source.path, start=window[0][0], end=window[-1][0])


# -------------------------------------------------------------------------- tech debt

#: Marker -> (severity, confidence). Confidence is high because the marker is a
#: fact about the file; severity reflects what the word conventionally means.
DEBT_MARKERS: dict[str, tuple[Severity, float]] = {
    "FIXME": (Severity.MEDIUM, 0.95),
    "HACK": (Severity.MEDIUM, 0.95),
    "XXX": (Severity.LOW, 0.9),
    "TODO": (Severity.LOW, 0.95),
}
_MARKER = re.compile(r"\b(FIXME|HACK|XXX|TODO)\b[:\s]*(?P<note>.*)")
#: More than this in one file is a different finding from any single marker.
DEBT_CLUSTER = 5


class TechDebtDetector:
    """Debt the authors already wrote down."""

    name = "tech-debt"
    category = Category.TECH_DEBT

    def run(self, workspace: Workspace) -> DetectorReport:
        report = DetectorReport(detector=self.name, category=self.category)
        sources = [s for s in workspace.files if s.is_python or s.suffix in {".js", ".ts"}]
        report.files_examined = len(sources)

        per_file: dict[str, list[tuple[int, str, str]]] = defaultdict(list)
        for source in sources:
            for number, line in enumerate(source.lines(), start=1):
                match = _MARKER.search(line)
                if match is None:
                    continue
                per_file[source.path].append((number, match.group(1), match.group("note").strip()))

        for path, markers in sorted(per_file.items()):
            if len(markers) >= DEBT_CLUSTER:
                report.findings.append(
                    Finding(
                        finding_id="CE-DEBT-002",
                        category=self.category,
                        title=f"{len(markers)} debt markers in one file",
                        severity=Severity.MEDIUM,
                        confidence=0.9,
                        evidence="\n".join(
                            f"{path}:{number} {word} {note}"[:200] for number, word, note in markers
                        ),
                        affected_files=[path],
                        recommended_action=(
                            "Triage this file's markers together; a cluster usually means "
                            "one unfinished decision rather than several small ones."
                        ),
                        estimated_risk=Risk.LOW,
                        detector=self.name,
                    )
                )
                continue
            for number, word, note in markers:
                severity, confidence = DEBT_MARKERS[word]
                report.findings.append(
                    Finding(
                        finding_id="CE-DEBT-001",
                        category=self.category,
                        title=f"{word}: {note[:60] or 'no note'}",
                        severity=severity,
                        confidence=confidence,
                        evidence=f"{path}:{number} {word} {note}"[:300],
                        affected_files=[f"{path}:{number}"],
                        recommended_action=(
                            "Do it, or delete the marker and file what is left. A marker "
                            "nobody will act on is noise in every future search."
                        ),
                        estimated_risk=Risk.LOW,
                        detector=self.name,
                    )
                )
        return report


# ------------------------------------------------------------------------ performance


class PerformanceDetector:
    """Patterns that are slow by construction, not by measurement.

    Every finding here is a *shape*, never a claim about this program's actual
    hot path. Nothing is profiled, so nothing is asserted about impact - which is
    why the recommended action always starts with measuring.
    """

    name = "performance"
    category = Category.PERFORMANCE

    def run(self, workspace: Workspace) -> DetectorReport:
        report = DetectorReport(detector=self.name, category=self.category)
        sources = workspace.python(include_tests=False)
        report.files_examined = len(sources)

        for source in sources:
            try:
                tree = ast.parse(source.text, filename=source.path)
            except SyntaxError:
                continue
            for loop in [n for n in ast.walk(tree) if isinstance(n, ast.For | ast.While)]:
                report.findings.extend(self._in_loop(source, loop))
        return report

    def _in_loop(self, source: SourceFile, loop: ast.AST) -> list[Finding]:
        findings: list[Finding] = []
        for node in ast.walk(loop):
            if node is loop:
                continue
            if (
                isinstance(node, ast.AugAssign)
                and isinstance(node.op, ast.Add)
                and isinstance(node.value, ast.Constant | ast.JoinedStr)
                and _is_string(node.value)
            ):
                findings.append(
                    self._finding(
                        "CE-PERF-001",
                        "string built by repeated concatenation in a loop",
                        source,
                        node.lineno,
                        confidence=0.75,
                        action=(
                            "Measure first. If this loop is hot, collect the parts in a "
                            "list and join once - repeated concatenation copies the whole "
                            "string each time."
                        ),
                    )
                )
            elif isinstance(node, ast.Call) and _dotted(node.func) == "re.compile":
                findings.append(
                    self._finding(
                        "CE-PERF-002",
                        "regular expression compiled inside a loop",
                        source,
                        node.lineno,
                        confidence=0.85,
                        action=(
                            "Move the compile to module scope. The pattern does not "
                            "change between iterations."
                        ),
                    )
                )
            elif isinstance(node, ast.Compare) and _membership_in_a_list(node):
                findings.append(
                    self._finding(
                        "CE-PERF-003",
                        "membership test against a list inside a loop",
                        source,
                        node.lineno,
                        confidence=0.7,
                        action=(
                            "Measure first. If the collection is large, a set makes this "
                            "constant time instead of linear."
                        ),
                    )
                )
        return findings

    def _finding(
        self,
        finding_id: str,
        title: str,
        source: SourceFile,
        line: int,
        *,
        confidence: float,
        action: str,
    ) -> Finding:
        return Finding(
            finding_id=finding_id,
            category=self.category,
            title=title,
            severity=Severity.LOW,
            confidence=confidence,
            evidence=(
                f"{source.path}:{line}: {title}. This is a shape, not a measurement - "
                "nothing here was profiled and no claim is made about impact."
            ),
            affected_files=[f"{source.path}:{line}"],
            recommended_action=action,
            estimated_risk=Risk.LOW,
            detector=self.name,
        )


def _is_string(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return True
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return f"{node.value.id}.{node.attr}"
    return ""


def _membership_in_a_list(node: ast.Compare) -> bool:
    return any(isinstance(op, ast.In | ast.NotIn) for op in node.ops) and any(
        isinstance(comparator, ast.List) and len(comparator.elts) > 4
        for comparator in node.comparators
    )
