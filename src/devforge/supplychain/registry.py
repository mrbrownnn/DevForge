"""Load and validate the skill source registry.

Reading the registry never touches the network and never executes anything. It is
a YAML file parsed with ``safe_load`` into validated models.

Resolution order mirrors the rest of DevForge, so a project can maintain its own
catalogue: ``<project>/.devforge/registry/`` → ``<project>/registry/`` → the one
shipped with DevForge.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import yaml
from pydantic import ValidationError

from devforge.core.errors import ConfigError
from devforge.supplychain.models import SkillRegistryFile, SourceEntry, TrustTier

REGISTRY_FILENAME = "skills.yaml"


def packaged_registry_path() -> Path:
    """The registry shipped in this repository (``registry/skills.yaml``)."""
    return Path(__file__).resolve().parents[3] / "registry" / REGISTRY_FILENAME


def registry_search_paths(project_root: Path | None) -> list[Path]:
    paths: list[Path] = []
    if project_root is not None:
        paths.append(project_root / ".devforge" / "registry" / REGISTRY_FILENAME)
        paths.append(project_root / "registry" / REGISTRY_FILENAME)
    paths.append(packaged_registry_path())
    return paths


def resolve_registry_path(project_root: Path | None = None) -> Path | None:
    for candidate in registry_search_paths(project_root):
        if candidate.is_file():
            return candidate
    return None


def load_registry_file(path: Path) -> SkillRegistryFile:
    """Parse and validate one registry file. Raises :class:`ConfigError` on any problem."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(f"skill registry not found: {path}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: the skill registry must be a YAML mapping")

    try:
        return SkillRegistryFile.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(f"{path}: {_format(exc)}") from exc


def _format(exc: ValidationError) -> str:
    parts = []
    for error in exc.errors():
        location = ".".join(str(item) for item in error["loc"]) or "<root>"
        parts.append(f"{location}: {error['msg']}")
    return "; ".join(parts)


def load_registry(project_root: Path | None = None) -> SkillRegistryFile:
    path = resolve_registry_path(project_root)
    if path is None:
        searched = ", ".join(str(p) for p in registry_search_paths(project_root))
        raise ConfigError(f"no skill registry found (looked in: {searched})")
    return load_registry_file(path)


def content_hash(directory: Path) -> str:
    """SHA-256 over a directory tree: relative paths and file bytes.

    This is *our* statement about what we received, as opposed to the commit SHA,
    which is upstream's statement about what it published. The two answer different
    questions, which is why both are recorded.

    Path names are hashed alongside content, so a rename is a different hash.
    """
    digest = hashlib.sha256()
    root = Path(directory).resolve()
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return f"sha256:{digest.hexdigest()}"


def tier_allows_scripts(registry: SkillRegistryFile, source: SourceEntry) -> bool:
    """Whether this source may contribute executable content, per its tier."""
    policy = registry.trust_tiers.get(source.trust_tier.value)
    return bool(policy and policy.allow_scripts)


def pin_matches(source: SourceEntry, observed_commit: str) -> bool:
    """A pin comparison is exact. A different commit is a different, untrusted source."""
    return source.pin.commit == observed_commit.strip().lower()


def demote_on_pin_change(source: SourceEntry, observed_commit: str) -> TrustTier:
    """Trust attaches to reviewed bytes, not to a repository name.

    Returns the tier that applies given what was actually fetched: the recorded tier
    when the pin matches, ``untrusted`` otherwise.
    """
    return source.trust_tier if pin_matches(source, observed_commit) else TrustTier.UNTRUSTED
