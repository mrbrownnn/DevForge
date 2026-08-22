"""Saving and finding reports.

Reports are plain JSON files under ``reports/``, named so that sorting the
directory sorts them by time. There is no database and no index: a report is a
build artefact, and a directory of timestamped files is the format that survives
being copied to a colleague, attached to a pull request, or read five years from
now by something that is not DevForge.

Nothing here overwrites. A saved report is evidence of what happened at a moment,
and a benchmark run that quietly replaces the previous one destroys the only thing
that makes a regression detectable.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import ValidationError

from devforge.core.errors import ConfigError
from devforge.eval.models import EvalReport
from devforge.eval.suites import PROJECT_REPORT_DIR


def report_dir(root: Path) -> Path:
    return Path(root) / PROJECT_REPORT_DIR


def save_report(report: EvalReport, root: Path) -> Path:
    """Write the report and return its path. Never overwrites an existing file."""
    directory = report_dir(root)
    directory.mkdir(parents=True, exist_ok=True)
    stamp = report.created_at.strftime("%Y%m%dT%H%M%SZ")
    path = directory / f"{_slug(report.config.id)}-{stamp}-{_slug(report.report_id)}.json"
    path.write_text(report.model_dump_json(indent=1), encoding="utf-8")
    return path


def load_report(path: Path) -> EvalReport:
    try:
        return EvalReport.model_validate_json(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(f"no such report: {path}") from exc
    except (OSError, ValidationError) as exc:
        raise ConfigError(f"could not read report {path}: {exc}") from exc


def list_reports(root: Path, *, config_id: str | None = None) -> list[Path]:
    """Newest first. Filenames carry the config id, so filtering needs no parsing."""
    directory = report_dir(root)
    if not directory.is_dir():
        return []
    paths = sorted(directory.glob("*.json"), reverse=True)
    if config_id:
        prefix = f"{_slug(config_id)}-"
        paths = [path for path in paths if path.name.startswith(prefix)]
    return paths


def resolve_report(reference: str, root: Path) -> EvalReport:
    """Accept a path or a configuration id.

    ``devforge eval compare mock-baseline reference`` is what a person types; the
    ids resolve to each configuration's most recent saved report. A path is taken
    literally, so a specific historical report can always be named exactly.
    """
    path = Path(reference)
    if path.is_file():
        return load_report(path)
    candidates = list_reports(root, config_id=reference)
    if not candidates:
        raise ConfigError(
            f"'{reference}' is neither a report file nor a configuration with a saved "
            f"report under {report_dir(root)}"
        )
    return load_report(candidates[0])


def _slug(text: str) -> str:
    """Make one filename component safe.

    Both the configuration id and the report id go into the name, and both come
    from data - a configuration file the project wrote, an id a caller may have
    set. Nothing here reaches a shell, but a component containing a path
    separator would still write somewhere it was not asked to.
    """
    return "".join(char if char.isalnum() or char in "-_" else "_" for char in text)
