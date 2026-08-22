"""Detectors about the shape of the project: flakiness, architecture, test cover.

The flaky-test detector is the one worth reading carefully. Flakiness is a claim
about behaviour over time, and no amount of reading source code establishes it -
so this detector reads *recorded run history* instead, and reports itself
unavailable when there is none. Guessing which tests look flaky from their
contents would produce a list of tests that use timers, which is not the same
thing at all.
"""

from __future__ import annotations

import ast
from collections import defaultdict
from pathlib import Path

from devforge.continuous.detectors.base import Workspace
from devforge.continuous.models import (
    Category,
    DetectorReport,
    DetectorStatus,
    Finding,
    Risk,
    Severity,
)

# ------------------------------------------------------------------------ flaky tests


class FlakyTestDetector:
    """Verifiers that both passed and failed with nothing changed in between.

    The signal comes from ``verify`` steps: they run verifiers with **no agent**,
    so two attempts on one of them differ only in when they ran. A verifier that
    passed on one attempt and failed on another there is flaky by construction,
    not by inference.
    """

    name = "flaky-test"
    category = Category.FLAKY_TEST

    def run(self, workspace: Workspace) -> DetectorReport:
        from devforge.core.errors import DevForgeError
        from devforge.core.state.store import ProjectStore

        report = DetectorReport(detector=self.name, category=self.category)
        try:
            store = ProjectStore.discover(workspace.root)
            entries = store.list_tasks()
        except DevForgeError as exc:
            report.status = DetectorStatus.UNAVAILABLE
            report.detail = (
                f"no run history to read ({exc}). Flakiness is a claim about behaviour "
                "over time; it cannot be established by reading source."
            )
            return report

        if not entries:
            report.status = DetectorStatus.UNAVAILABLE
            report.detail = (
                "no recorded runs. This detector reports flakiness observed in run "
                "history rather than guessing it from test contents."
            )
            return report

        # verifier -> {status} seen in an agent-free step, with where it happened
        observed: dict[str, set[str]] = defaultdict(set)
        where: dict[str, list[str]] = defaultdict(list)
        examined = 0

        for entry in entries:
            try:
                task = store.load_task(entry.task_id)
            except DevForgeError:
                continue
            examined += 1
            agentless = {step.step_id for step in task.steps if step.kind == "verify"}
            for result in task.verification_results:
                if result.step_id not in agentless:
                    continue
                observed[result.verifier].add(result.status.value)
                where[result.verifier].append(
                    f"{entry.task_id} step '{result.step_id}' attempt {result.attempt}: "
                    f"{result.status.value}"
                )

        report.files_examined = examined
        for verifier, statuses in sorted(observed.items()):
            if not ({"passed"} & statuses and {"failed", "error"} & statuses):
                continue
            report.findings.append(
                Finding(
                    finding_id="CE-FLAKY-001",
                    category=self.category,
                    title=f"verifier '{verifier}' both passed and failed with no agent between",
                    severity=Severity.HIGH,
                    confidence=0.85,
                    evidence="\n".join(where[verifier][:10]),
                    affected_files=[],
                    recommended_action=(
                        f"Find the nondeterminism in '{verifier}' - time, ordering, "
                        "concurrency, a shared fixture - and remove it. A flaky check "
                        "makes every later green run unfalsifiable."
                    ),
                    estimated_risk=Risk.MEDIUM,
                    detector=self.name,
                )
            )
        return report


# ----------------------------------------------------------------------- architecture

#: A module longer than this is doing more than one thing often enough to be
#: worth a look. Not a rule about style - a signal about cohesion.
LONG_MODULE_LINES = 800
#: Branch count above which a function is hard to test exhaustively.
COMPLEX_FUNCTION_BRANCHES = 18


class ArchitectureDetector:
    """Import cycles, oversized modules, functions with too many branches."""

    name = "architecture"
    category = Category.ARCHITECTURE

    def run(self, workspace: Workspace) -> DetectorReport:
        report = DetectorReport(detector=self.name, category=self.category)
        sources = workspace.python(include_tests=False)
        report.files_examined = len(sources)
        if not sources:
            report.status = DetectorStatus.UNAVAILABLE
            report.detail = "no non-test Python files to analyse"
            return report

        graph: dict[str, set[str]] = {}
        for source in sources:
            try:
                tree = ast.parse(source.text, filename=source.path)
            except SyntaxError:
                continue

            module = _module_name(source.path)
            graph[module] = _imported_modules(tree)

            line_count = len(source.lines())
            if line_count > LONG_MODULE_LINES:
                report.findings.append(
                    Finding(
                        finding_id="CE-ARCH-002",
                        category=self.category,
                        title=f"{source.path} is {line_count} lines",
                        severity=Severity.LOW,
                        confidence=0.9,
                        evidence=(
                            f"{source.path} has {line_count} lines, over the "
                            f"{LONG_MODULE_LINES}-line threshold. Length is a signal about "
                            "cohesion, not a rule about style."
                        ),
                        affected_files=[source.path],
                        recommended_action=(
                            "Check whether this module has one reason to change. Split it "
                            "only if it has more than one."
                        ),
                        estimated_risk=Risk.MEDIUM,
                        detector=self.name,
                    )
                )

            for node in ast.walk(tree):
                if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                    continue
                branches = _branch_count(node)
                if branches > COMPLEX_FUNCTION_BRANCHES:
                    report.findings.append(
                        Finding(
                            finding_id="CE-ARCH-003",
                            category=self.category,
                            title=f"'{node.name}' has {branches} branches",
                            severity=Severity.MEDIUM,
                            confidence=0.9,
                            evidence=(
                                f"{source.path}:{node.lineno} '{node.name}' contains "
                                f"{branches} branch points (if/for/while/except/and/or). "
                                "Exhaustive testing needs a case per path."
                            ),
                            affected_files=[f"{source.path}:{node.lineno}"],
                            recommended_action=(
                                "Extract the independent decisions. A function this "
                                "branchy usually has two or three functions inside it."
                            ),
                            estimated_risk=Risk.MEDIUM,
                            detector=self.name,
                        )
                    )

        for cycle in _cycles(graph):
            report.findings.append(
                Finding(
                    finding_id="CE-ARCH-001",
                    category=self.category,
                    title="import cycle between " + " → ".join(cycle),
                    severity=Severity.MEDIUM,
                    confidence=0.9,
                    evidence=(
                        "Modules import each other in a cycle: " + " → ".join([*cycle, cycle[0]])
                    ),
                    affected_files=[module.replace(".", "/") + ".py" for module in cycle],
                    recommended_action=(
                        "Break the cycle by moving the shared piece into a module both "
                        "can depend on. A cycle makes each module untestable alone and "
                        "import order load-bearing."
                    ),
                    estimated_risk=Risk.HIGH,
                    detector=self.name,
                )
            )
        return report


def _module_name(path: str) -> str:
    stem = path[:-3] if path.endswith(".py") else path
    parts = [part for part in stem.split("/") if part not in {"src", ""}]
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _imported_modules(tree: ast.Module) -> set[str]:
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules |= {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            modules.add(node.module)
    return modules


def _cycles(graph: dict[str, set[str]]) -> list[list[str]]:
    """Cycles among the modules in this repository only.

    A cycle through a third-party package is not this project's cycle, and
    reporting one would be an accusation about someone else's code.
    """
    internal = {module: {dep for dep in deps if dep in graph} for module, deps in graph.items()}
    found: list[list[str]] = []
    seen_cycles: set[frozenset[str]] = set()
    path: list[str] = []
    visiting: set[str] = set()
    done: set[str] = set()

    def walk(module: str) -> None:
        if module in done:
            return
        if module in visiting:
            cycle = path[path.index(module) :]
            key = frozenset(cycle)
            if len(cycle) > 1 and key not in seen_cycles:
                seen_cycles.add(key)
                found.append(cycle)
            return
        visiting.add(module)
        path.append(module)
        for dependency in sorted(internal.get(module, ())):
            walk(dependency)
        path.pop()
        visiting.discard(module)
        done.add(module)

    for module in sorted(internal):
        walk(module)
    return found


_BRANCHING = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler, ast.IfExp, ast.Assert)


def _branch_count(node: ast.AST) -> int:
    count = 0
    for child in ast.walk(node):
        if isinstance(child, _BRANCHING):
            count += 1
        elif isinstance(child, ast.BoolOp):
            count += len(child.values) - 1
    return count


# ---------------------------------------------------------------------- missing tests

#: Modules whose absence from the tests is expected: entry points and packages.
_UNTESTABLE_STEMS = frozenset({"__init__", "__main__", "conftest"})


class MissingTestsDetector:
    """Modules with a public surface that no test file mentions."""

    name = "missing-tests"
    category = Category.MISSING_TESTS

    def run(self, workspace: Workspace) -> DetectorReport:
        report = DetectorReport(detector=self.name, category=self.category)
        tests = [source for source in workspace.python() if source.is_test]
        production = [source for source in workspace.python() if not source.is_test]
        report.files_examined = len(production)

        if not tests:
            report.status = DetectorStatus.UNAVAILABLE
            report.detail = (
                "no test files found. 'every module is untested' is a true statement "
                "about this tree and not a useful backlog."
            )
            return report

        test_text = "\n".join(source.text for source in tests)

        for source in production:
            stem = Path(source.path).stem
            if stem in _UNTESTABLE_STEMS:
                continue
            try:
                tree = ast.parse(source.text, filename=source.path)
            except SyntaxError:
                continue

            public = [
                node.name
                for node in tree.body
                if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef)
                and not node.name.startswith("_")
            ]
            if not public:
                continue
            if any(name in test_text for name in public) or _module_name(source.path) in test_text:
                continue

            report.findings.append(
                Finding(
                    finding_id="CE-TEST-001",
                    category=self.category,
                    title=f"{source.path} has {len(public)} public definitions and no test",
                    severity=Severity.MEDIUM,
                    confidence=0.75,
                    evidence=(
                        f"{source.path} defines {', '.join(public[:8])}"
                        f"{'…' if len(public) > 8 else ''}. No file under a test path "
                        "names the module or any of those definitions."
                    ),
                    affected_files=[source.path],
                    recommended_action=(
                        "Add tests for the behaviour this module is responsible for. "
                        "Naming coverage is what this measures - a test that names the "
                        "module without asserting anything would satisfy it, which is "
                        "why the number is a floor and not a score."
                    ),
                    estimated_risk=Risk.LOW,
                    detector=self.name,
                )
            )
        return report
