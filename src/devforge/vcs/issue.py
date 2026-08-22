"""Where the work comes in.

An issue may be a YAML file, a Markdown file with front matter, an exported
tracker record, or a sentence someone typed. All four arrive here and leave as an
:class:`~devforge.vcs.models.Issue`, so everything downstream - the branch name,
the commit type, the pull request title - is derived from one shape.

Issue text is **untrusted input**. It is written by whoever filed the issue, which
in a public repository is anyone at all, and it ends up in an agent's prompt. It
is therefore fenced when it reaches a prompt and never interpreted as
configuration: an issue cannot name the branch to force-push or the gate to skip,
because those are not fields it has.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml
from pydantic import ValidationError

from devforge.core.errors import ConfigError
from devforge.vcs.models import Issue, slugify

FRONT_MATTER = re.compile(r"\A---\s*\n(?P<meta>.*?)\n---\s*\n(?P<body>.*)\Z", re.DOTALL)
#: Lines that read as acceptance criteria in a Markdown issue body.
CHECKBOX = re.compile(r"^\s*[-*]\s*\[[ xX]\]\s*(?P<item>.+)$", re.MULTILINE)


def issue_from_text(text: str, *, issue_id: str = "", source: str = "cli") -> Issue:
    """An issue from a sentence. The first line is the title, the rest the body."""
    stripped = text.strip()
    if not stripped:
        raise ConfigError("an issue needs at least a title")
    title, _, body = stripped.partition("\n")
    return Issue(
        id=issue_id or slugify(title, limit=24),
        title=title.strip(),
        body=body.strip(),
        source=source,
        acceptance=[match.group("item").strip() for match in CHECKBOX.finditer(body)],
    )


def load_issue(path: Path) -> Issue:
    """Read an issue from YAML, or from Markdown with optional front matter."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"could not read the issue at {path}: {exc}") from exc

    if Path(path).suffix.lower() in {".yaml", ".yml"}:
        return _from_yaml(text, path)

    match = FRONT_MATTER.match(text)
    if match is None:
        issue = issue_from_text(text, issue_id=slugify(Path(path).stem, limit=24), source=str(path))
        return issue

    try:
        meta = yaml.safe_load(match.group("meta")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path}: invalid front matter: {exc}") from exc
    if not isinstance(meta, dict):
        raise ConfigError(f"{path}: front matter must be a mapping")

    body = match.group("body").strip()
    payload = {
        "id": str(meta.get("id") or slugify(Path(path).stem, limit=24)),
        "title": str(meta.get("title") or _first_heading(body) or Path(path).stem),
        "body": body,
        "source": str(path),
        "labels": [str(label) for label in meta.get("labels", [])],
        "acceptance": [str(item) for item in meta.get("acceptance", [])]
        or [match.group("item").strip() for match in CHECKBOX.finditer(body)],
    }
    return _validate(payload, path)


def _from_yaml(text: str, path: Path) -> Issue:
    try:
        raw = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path}: invalid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: expected a mapping describing one issue")
    raw.setdefault("id", slugify(Path(path).stem, limit=24))
    raw.setdefault("source", str(path))
    return _validate(raw, path)


def _validate(payload: dict, path: Path) -> Issue:
    try:
        return Issue.model_validate(payload)
    except ValidationError as exc:
        raise ConfigError(f"{path}: invalid issue: {exc}") from exc


def _first_heading(body: str) -> str:
    for line in body.splitlines():
        if line.startswith("#"):
            return line.lstrip("#").strip()
    return ""
