"""Persisting falsification reports, and the corpus that outlives them.

Two locations, on purpose::

    .devforge/runs/<task_id>/falsification/<run_id>.json   per-run evidence
    .devforge/runs/<task_id>/falsification/<run_id>.md     the rendered report
    .devforge/falsification/                               cross-run corpus
        findings/<finding_id>.json
        counterexamples/<finding_id>.json
        mutants/<run_id>.jsonl
        corpus/<finding_id>/

Per-run evidence belongs with the run, beside ``task.json`` and ``events.jsonl``,
and disappears when the run directory is cleaned. The **corpus outlives runs**: it is
the growing library of real failure modes that later feeds regression tests and
DevForge's own benchmarks. Filing it under ``runs/<task_id>/`` would tie its lifetime
to one run, which is exactly what it must not be.

Everything written here passes through :func:`redact_value` first. State outlives a
terminal buffer, and a counterexample is precisely the kind of record that quotes a
value it was handed - which might be a token.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from devforge.core.errors import StateError
from devforge.core.state.store import ProjectStore, _atomic_write
from devforge.falsification.models import Counterexample, FalsificationReport, TestWeakness
from devforge.observability.redaction import redact_value

FALSIFICATION_DIRNAME = "falsification"


# --------------------------------------------------------------------------- paths


def run_reports_dir(store: ProjectStore, task_id: str) -> Path:
    return store.run_dir(task_id) / FALSIFICATION_DIRNAME


def corpus_root(store: ProjectStore) -> Path:
    return store.devforge_dir / FALSIFICATION_DIRNAME


def findings_dir(store: ProjectStore) -> Path:
    return corpus_root(store) / "findings"


def counterexamples_dir(store: ProjectStore) -> Path:
    return corpus_root(store) / "counterexamples"


def mutants_dir(store: ProjectStore) -> Path:
    return corpus_root(store) / "mutants"


def corpus_dir(store: ProjectStore) -> Path:
    return corpus_root(store) / "corpus"


# --------------------------------------------------------------------------- writing


def save_report(store: ProjectStore, report: FalsificationReport) -> Path:
    """Write one run's report as JSON and as a rendered document.

    The rendered form is written too, rather than generated on demand, because a
    report that can only be read through the tool that produced it is a report
    nobody reads in a post-mortem.
    """
    directory = run_reports_dir(store, report.task_id) if report.task_id else corpus_root(store)
    payload = redact_value(json.loads(report.model_dump_json()))

    path = directory / f"{report.run_id}.json"
    _atomic_write(path, json.dumps(payload, indent=2))
    _atomic_write(directory / f"{report.run_id}.md", redact_value(report.render()))
    return path


def load_report(path: Path) -> FalsificationReport:
    if not path.is_file():
        raise StateError(f"no falsification report at {path}")
    return FalsificationReport.model_validate_json(path.read_text(encoding="utf-8"))


def list_reports(store: ProjectStore, task_id: str | None = None) -> list[Path]:
    """Every persisted report, newest first."""
    directories: list[Path] = []
    if task_id:
        directories.append(run_reports_dir(store, task_id))
    else:
        if store.runs_dir.is_dir():
            directories.extend(
                run / FALSIFICATION_DIRNAME
                for run in sorted(store.runs_dir.iterdir())
                if run.is_dir()
            )
        directories.append(corpus_root(store))

    found: list[Path] = []
    for directory in directories:
        if directory.is_dir():
            found.extend(path for path in directory.glob("*.json"))
    return sorted(found, key=lambda path: path.stat().st_mtime, reverse=True)


def resolve_report(store: ProjectStore, run_id: str | None = None) -> FalsificationReport:
    """A report by run id, or the most recent one."""
    reports = list_reports(store)
    if not reports:
        raise StateError(
            "no falsification run has been recorded yet - run 'devforge falsify' first"
        )
    if not run_id:
        return load_report(reports[0])
    for path in reports:
        if path.stem == run_id:
            return load_report(path)
    raise StateError(f"unknown falsification run '{run_id}'")


def find_finding(
    store: ProjectStore, finding_id: str
) -> tuple[Counterexample | TestWeakness, FalsificationReport] | None:
    """Locate one finding across every persisted report, plus the run it came from.

    The corpus is checked first because it is the smaller index; reports are the
    fallback so a finding remains explainable even if the corpus was cleared.
    """
    corpus_file = counterexamples_dir(store) / f"{finding_id}.json"
    if corpus_file.is_file():
        entry = json.loads(corpus_file.read_text(encoding="utf-8"))
        run_id = entry.get("run_id", "")
        for path in list_reports(store):
            if path.stem == run_id:
                report = load_report(path)
                finding = report.finding(finding_id)
                if finding is not None:
                    return finding, report

    for path in list_reports(store):
        report = load_report(path)
        finding = report.finding(finding_id)
        if finding is not None:
            return finding, report
    return None


# --------------------------------------------------------------------------- corpus


def record_corpus(store: ProjectStore, report: FalsificationReport) -> list[Path]:
    """File every finding into the corpus so it outlives this run.

    Enough metadata to reproduce the failure, and nothing more: an argv, the input,
    the expected and actual behaviour, the file and symbol. Never an environment
    snapshot, never file contents from a denied path - a corpus that accumulates
    secrets over months is a worse liability than the bugs it records.
    """
    written: list[Path] = []

    for example in report.counterexamples:
        entry: dict[str, Any] = {
            "finding_id": example.finding_id,
            "run_id": report.run_id,
            "task_id": report.task_id,
            "commit": report.commit,
            "strategy": example.strategy.value,
            "target": example.target,
            "input": example.input,
            "minimal_input": example.minimal_input,
            "expected": example.expected,
            "actual": example.actual,
            "reproduction": example.reproduction,
            "file": example.file,
            "symbol": example.symbol,
            "severity": example.severity.value,
            "discovered_at": example.discovered_at.isoformat(),
        }
        path = counterexamples_dir(store) / f"{example.finding_id}.json"
        _atomic_write(path, json.dumps(redact_value(entry), indent=2))
        written.append(path)

    for weakness in report.weaknesses:
        entry = {
            "finding_id": weakness.finding_id,
            "run_id": report.run_id,
            "kind": "TEST_WEAKNESS",
            "mutant_id": weakness.mutant_id,
            "file": weakness.file,
            "line": weakness.line,
            "operator": weakness.operator,
            "unchecked_behavior": weakness.unchecked_behavior,
            "relevant_tests": weakness.relevant_tests,
            "proposed_test": weakness.proposed_test,
            "reproduction": weakness.reproduction,
            "severity": weakness.severity.value,
        }
        path = findings_dir(store) / f"{weakness.finding_id}.json"
        _atomic_write(path, json.dumps(redact_value(entry), indent=2))
        written.append(path)

    if report.mutants:
        lines = [
            json.dumps(redact_value(json.loads(mutant.model_dump_json())))
            for mutant in report.mutants
        ]
        path = mutants_dir(store) / f"{report.run_id}.jsonl"
        _atomic_write(path, "\n".join(lines) + "\n")
        written.append(path)

    return written


def corpus_entries(store: ProjectStore) -> list[dict[str, Any]]:
    """Every counterexample the corpus holds, newest first."""
    directory = counterexamples_dir(store)
    if not directory.is_dir():
        return []
    entries: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            entries.append(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError):  # pragma: no cover - corrupt entry
            continue
    return entries
