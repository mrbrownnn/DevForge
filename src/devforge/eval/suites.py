"""Finding the cases and the configurations.

Both are data on disk, and both resolve the same way: what the project defines
wins over what DevForge ships, matched by id. A project that writes its own
``benchmarks/feature.yaml`` replaces the shipped one rather than merging with it,
because half a suite from each source is a benchmark nobody can reason about.

Shipped cases live inside the package so ``devforge eval run`` works in a
directory that has never seen DevForge. Project cases live at ``benchmarks/`` and
``evals/`` next to the code they measure, where they are reviewed like code.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from devforge.core.errors import ConfigError
from devforge.eval.models import Category, EvalCase, EvalConfig, EvalSuite

#: Where a project keeps its own cases and configurations.
PROJECT_SUITE_DIR = "benchmarks"
PROJECT_CONFIG_DIR = "evals"
#: Where reports are written by default.
PROJECT_REPORT_DIR = "reports"


def builtin_suite_dir() -> Path:
    from devforge import builtin

    return Path(builtin.__file__).parent / "benchmarks" / "eval"


def builtin_config_path() -> Path:
    from devforge import builtin

    return Path(builtin.__file__).parent / "evals" / "configs.yaml"


# --------------------------------------------------------------------------- suites


def suite_paths(root: Path | None = None) -> list[Path]:
    """Every suite file that applies here, project files shadowing shipped ones."""
    shipped = {path.name: path for path in sorted(builtin_suite_dir().glob("*.yaml"))}
    if root is not None:
        project_dir = Path(root) / PROJECT_SUITE_DIR
        if project_dir.is_dir():
            for path in sorted(project_dir.glob("*.yaml")):
                shipped[path.name] = path
    return list(shipped.values())


def load_suites(root: Path | None = None, *, paths: list[Path] | None = None) -> list[EvalSuite]:
    return [EvalSuite.load(path) for path in (paths or suite_paths(root))]


def load_cases(
    root: Path | None = None,
    *,
    paths: list[Path] | None = None,
    categories: list[str] | None = None,
    case_ids: list[str] | None = None,
) -> tuple[list[EvalCase], list[str]]:
    """Cases matching the filters, plus the names of the suites they came from.

    An unknown category or case id is an error rather than an empty selection.
    Silently running nothing looks identical to running everything and passing.
    """
    suites = load_suites(root, paths=paths)
    cases: list[EvalCase] = []
    seen: set[str] = set()
    for suite in suites:
        for case in suite.cases:
            if case.id in seen:
                raise ConfigError(f"duplicate eval case id '{case.id}'")
            seen.add(case.id)
            cases.append(case)

    if categories:
        wanted = {name.lower() for name in categories}
        unknown = wanted - {category.value for category in Category}
        if unknown:
            raise ConfigError(
                f"unknown categor(ies) {sorted(unknown)}; "
                f"expected some of {[c.value for c in Category]}"
            )
        cases = [case for case in cases if case.category.value in wanted]

    if case_ids:
        wanted_ids = set(case_ids)
        unknown_ids = wanted_ids - seen
        if unknown_ids:
            raise ConfigError(f"unknown case(s): {', '.join(sorted(unknown_ids))}")
        cases = [case for case in cases if case.id in wanted_ids]

    names = sorted({suite.name for suite in suites})
    return cases, names


# --------------------------------------------------------------------------- configs


def _read_configs(path: Path) -> list[EvalConfig]:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except FileNotFoundError:
        return []
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"could not read {path}: {exc}") from exc

    entries = raw.get("configs", raw) if isinstance(raw, dict) else raw
    if isinstance(entries, dict):
        entries = [{"id": key, **value} for key, value in entries.items()]
    if not isinstance(entries, list):
        raise ConfigError(f"{path}: expected a list of configurations")
    try:
        return [EvalConfig.model_validate(entry) for entry in entries]
    except ValidationError as exc:
        raise ConfigError(f"{path}: invalid configuration: {exc}") from exc


def load_configs(root: Path | None = None) -> dict[str, EvalConfig]:
    """Shipped configurations, then the project's, later ids winning."""
    configs = {config.id: config for config in _read_configs(builtin_config_path())}
    if root is not None:
        project_dir = Path(root) / PROJECT_CONFIG_DIR
        if project_dir.is_dir():
            for path in sorted(project_dir.glob("*.yaml")):
                for config in _read_configs(path):
                    configs[config.id] = config
    return configs


def load_config(config_id: str, root: Path | None = None) -> EvalConfig:
    configs = load_configs(root)
    config = configs.get(config_id)
    if config is None:
        raise ConfigError(
            f"unknown eval configuration '{config_id}'; "
            f"defined here: {', '.join(sorted(configs)) or '(none)'}"
        )
    return config
