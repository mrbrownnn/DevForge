"""The falsification corpus: failure modes that outlive the run that found them.

A counterexample is worth more than the run that produced it. Six weeks later the
useful question is not "what did that run say?" but "have we seen this failure
before, and is it still fixed?" - and a finding filed under
``.devforge/runs/<task_id>/`` disappears the moment that run directory is cleaned.

So the corpus is separate and long-lived::

    .devforge/falsification/
        findings/<finding_id>.json          test weaknesses
        counterexamples/<finding_id>.json   reproducible failures
        mutants/<run_id>.jsonl              every mutant and its classification
        corpus/<finding_id>/                reproduction material

It stores exactly what is needed to reproduce a failure: an argv, the input, the
expected and actual behaviour, the file and the symbol. It stores **no environment
snapshot** and no file contents from a path the policy denies. A corpus accumulating
secrets over months is a worse liability than the bugs it records, so every write
passes :func:`redact_value` and a security test asserts a planted credential reaches
none of these files.

The corpus is what later lets a counterexample become a permanent regression test
(see :mod:`devforge.falsification.regression`) and what will feed DevForge's own
evaluation benchmarks.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from devforge.core.state.store import ProjectStore, _atomic_write
from devforge.falsification.models import FalsificationReport
from devforge.falsification.store import (
    counterexamples_dir,
    findings_dir,
    mutants_dir,
)
from devforge.observability.redaction import redact_value


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
