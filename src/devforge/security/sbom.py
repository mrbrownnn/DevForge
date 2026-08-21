"""A software bill of materials for what this installation actually loads.

Four kinds of thing can execute or steer execution inside DevForge, and all four
belong in one inventory:

* **Python distributions** - the four runtime dependencies and any optional extras
  that are actually installed;
* **Installed skills** - third-party instructions, pinned by commit and content
  hash (TM11);
* **MCP servers** - external processes that supply tools (TM3);
* **Agent runtime binaries** - the CLI that executes agents (TM7).

The format is CycloneDX 1.5 JSON, kept to the subset the data actually supports.
Emitting fields we cannot populate honestly - a PURL for a skill that is a git
checkout, a license we never read - would produce a document that validates and
misinforms, which is worse than a smaller one that does not.

What an SBOM is for
-------------------

It answers "what is here, and where did it come from?". It does not answer "is any
of it vulnerable?". DevForge ships no vulnerability database and does not query
one; adding a network call to a feed would be a new trust relationship and a new
egress path, which is a decision for the operator rather than a default. When a
CVE is announced, this document is how you find out whether it applies to you.
"""

from __future__ import annotations

import hashlib
import shutil
import tomllib
from datetime import datetime
from importlib import metadata
from pathlib import Path
from typing import Any

from devforge import __version__
from devforge.core.errors import DevForgeError
from devforge.core.models import utcnow

SPEC_VERSION = "1.5"
UNKNOWN = "unknown"


def build_sbom(root: Path) -> dict[str, Any]:
    """Assemble the inventory. Never raises for a component it cannot resolve."""
    root = Path(root).resolve()
    components: list[dict[str, Any]] = []
    components.extend(_python_components())
    components.extend(_skill_components(root))
    components.extend(_mcp_components(root))
    components.extend(_runtime_components())

    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "version": 1,
        "metadata": {
            "timestamp": _iso(utcnow()),
            "component": {
                "type": "application",
                "name": "devforge",
                "version": __version__,
            },
            "properties": [
                {
                    "name": "devforge:scope",
                    "value": (
                        "Python distributions, installed skills, MCP servers and agent "
                        "runtime binaries. Not a vulnerability assessment."
                    ),
                }
            ],
        },
        "components": components,
    }


def _iso(value: datetime) -> str:
    return value.isoformat()


def _python_components() -> list[dict[str, Any]]:
    """Declared dependencies, resolved against what is actually importable.

    Declared and installed are different facts and the difference is the
    interesting one: a dependency declared but absent means a feature is silently
    unavailable, and one installed at a version outside its declared range means
    the environment drifted.
    """
    declared = _declared_dependencies()
    components: list[dict[str, Any]] = []
    for name, (constraint, group) in sorted(declared.items()):
        installed = _installed_version(name)
        component: dict[str, Any] = {
            "type": "library",
            "name": name,
            "version": installed or UNKNOWN,
            "scope": "required" if group == "runtime" else "optional",
            "purl": f"pkg:pypi/{name}@{installed}" if installed else f"pkg:pypi/{name}",
            "properties": [
                {"name": "devforge:group", "value": group},
                {"name": "devforge:constraint", "value": constraint or "unconstrained"},
                {
                    "name": "devforge:installed",
                    "value": "yes" if installed else "no - the feature it enables is unavailable",
                },
            ],
        }
        license_name = _license_of(name)
        if license_name:
            component["licenses"] = [{"license": {"name": license_name}}]
        components.append(component)
    return components


def _declared_dependencies() -> dict[str, tuple[str, str]]:
    """name -> (constraint, group), from pyproject when present, else installed metadata.

    Both sources are consulted because they disagree in a way that matters. A source
    checkout's `pyproject.toml` is the truth about what the project declares; the
    installed distribution's metadata is a snapshot from whenever `pip install` last
    ran. An extra added after that install is absent from the metadata, so trusting
    it alone silently omits real components from the inventory. pyproject wins where
    both exist, and anything the metadata knows about is still merged in.
    """
    found: dict[str, tuple[str, str]] = {}
    for raw in _requirements_from_pyproject():
        name, constraint, group = _split_requirement(raw)
        if name:
            found[name] = (constraint, group)
    try:
        installed_requires = metadata.requires("devforge") or []
    except metadata.PackageNotFoundError:
        installed_requires = []
    for raw in installed_requires:
        name, constraint, group = _split_requirement(raw)
        if name and name not in found:
            found[name] = (constraint, group)
    return found


def _requirements_from_pyproject() -> list[str]:
    """Requirements declared in a source checkout, if this is one."""
    path = Path(__file__).resolve().parents[3] / "pyproject.toml"
    if not path.is_file():
        return []
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return []
    project = data.get("project", {})
    requirements = list(project.get("dependencies", []))
    for extra, entries in (project.get("optional-dependencies") or {}).items():
        requirements += [f'{entry} ; extra == "{extra}"' for entry in entries]
    return requirements


def _split_requirement(raw: str) -> tuple[str, str, str]:
    text, _, marker = raw.partition(";")
    group = "runtime"
    if "extra ==" in marker:
        group = marker.split("extra ==", 1)[1].strip().strip("\"'")
    text = text.strip()
    for index, char in enumerate(text):
        if char in "<>=!~ [(":
            return text[:index].strip(), text[index:].strip(), group
    return text, "", group


def _installed_version(name: str) -> str | None:
    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError:
        return None


def _license_of(name: str) -> str:
    try:
        info = metadata.metadata(name)
    except metadata.PackageNotFoundError:
        return ""
    declared = info.get("License-Expression") or info.get("License") or ""
    if declared and len(declared) < 80:
        return declared.strip()
    classifiers = [
        value.split("::")[-1].strip()
        for value in info.get_all("Classifier") or []
        if value.startswith("License ::")
    ]
    return classifiers[0] if classifiers else ""


def _skill_components(root: Path) -> list[dict[str, Any]]:
    from devforge.supplychain.install import load_lockfile

    try:
        lockfile = load_lockfile(root)
    except DevForgeError:
        return []

    components: list[dict[str, Any]] = []
    for entry in lockfile.skills:
        component: dict[str, Any] = {
            "type": "data",
            "name": entry.name,
            "version": entry.version,
            "scope": "required",
            "externalReferences": [{"type": "vcs", "url": entry.repository or entry.source}],
            "properties": [
                {"name": "devforge:kind", "value": "skill"},
                {"name": "devforge:commit", "value": entry.commit_sha or UNKNOWN},
                {"name": "devforge:risk", "value": entry.risk_level},
                {"name": "devforge:security_status", "value": entry.security_status.value},
                {"name": "devforge:approved_by", "value": entry.approved_by or UNKNOWN},
            ],
        }
        if entry.content_hash:
            # Recorded as the content hash it is. Claiming a file-level sha256 for a
            # directory tree would be a format-shaped lie.
            component["properties"].append(
                {"name": "devforge:content_hash", "value": entry.content_hash}
            )
        component["licenses"] = [{"license": {"name": entry.license or UNKNOWN}}]
        components.append(component)
    return components


def _mcp_components(root: Path) -> list[dict[str, Any]]:
    from devforge.mcp.registry import load_config

    try:
        config = load_config(root)
    except DevForgeError:
        return []

    return [
        {
            "type": "application",
            "name": server.name,
            "version": UNKNOWN,
            "scope": "optional" if not server.enabled else "required",
            "properties": [
                {"name": "devforge:kind", "value": "mcp-server"},
                {"name": "devforge:transport", "value": server.transport.value},
                {"name": "devforge:enabled", "value": "yes" if server.enabled else "no"},
                {"name": "devforge:command", "value": " ".join(server.command) or UNKNOWN},
                {
                    "name": "devforge:allow_tools",
                    "value": ", ".join(server.allow_tools) or "none (deny-by-default)",
                },
            ],
        }
        for server in config.servers
    ]


def _runtime_components() -> list[dict[str, Any]]:
    from devforge.runtime.registry import RuntimeRegistry

    registry = RuntimeRegistry.default()
    components: list[dict[str, Any]] = []
    for name, (available, detail) in registry.availability().items():
        binary = getattr(registry.create(name), "binary", None)
        if not binary:
            continue
        path = shutil.which(binary) if available else None
        component: dict[str, Any] = {
            "type": "application",
            "name": name,
            "version": UNKNOWN,
            "scope": "optional",
            "properties": [
                {"name": "devforge:kind", "value": "agent-runtime"},
                {"name": "devforge:binary", "value": binary},
                {"name": "devforge:available", "value": "yes" if available else "no"},
                {"name": "devforge:detail", "value": detail[:200]},
                {"name": "devforge:path", "value": str(path) if path else UNKNOWN},
            ],
        }
        if path:
            digest = _sha256(Path(path))
            if digest:
                component["hashes"] = [{"alg": "SHA-256", "content": digest}]
        components.append(component)
    return components


def _sha256(path: Path) -> str:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return ""


def summarise(sbom: dict[str, Any]) -> dict[str, int]:
    """Counts by component kind, for the report header."""
    counts: dict[str, int] = {}
    for component in sbom.get("components", []):
        kind = "python-package"
        for prop in component.get("properties", []):
            if prop["name"] == "devforge:kind":
                kind = prop["value"]
        counts[kind] = counts.get(kind, 0) + 1
    return counts
