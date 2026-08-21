"""The artifact channel.

Agents in a DevForge graph do not talk to each other. A node writes files it
declared, the supervisor records them, and downstream nodes are given a *manifest*
of what exists and where. That is the whole protocol.

Why not agent-to-agent conversation: it is an unbounded channel with no schema, no
audit trail, and no way to verify what was actually produced. A transcript claiming
"I implemented the endpoint" cannot be checked; a `implementation.patch` on disk
can. Artifacts are also what makes failure recoverable - work that reached disk
survives the step that failed, and the next attempt can see it.

Artifacts live under the run directory, so one run cannot read another's, and the
manifest records a content hash so a consumer can tell whether what it read is what
the producer wrote.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from devforge.core.models import utcnow

MAX_PREVIEW_CHARS = 400


class ArtifactRecord(BaseModel):
    """One produced file, as the supervisor saw it."""

    model_config = ConfigDict(extra="forbid")

    name: str
    path: str
    producer: str
    size_bytes: int = 0
    content_hash: str = ""
    format: str = "text"
    created_at: datetime = Field(default_factory=utcnow)
    #: First few lines, for the consumer's manifest. Never the whole file: the
    #: consumer reads it through the tool layer, under policy.
    preview: str = ""
    missing: bool = False

    @property
    def location(self) -> str:
        return f"{self.path} ({self.size_bytes} bytes)"


class ArtifactStore:
    """Records what each node produced, and answers what a consumer may see."""

    def __init__(self, root: Path, run_dir: Path) -> None:
        self.root = Path(root)
        self.run_dir = Path(run_dir)
        self.records: dict[str, ArtifactRecord] = {}

    def resolve(self, name: str, declared_path: str = "") -> Path:
        """Where an artifact should live.

        A declared relative path is honoured inside the workspace; anything else
        lands in the run's artifact directory, which keeps unnamed output from
        scattering through the project.
        """
        target = declared_path or name
        candidate = (self.root / target).resolve()
        if candidate == self.root or self.root in candidate.parents:
            return candidate
        return (self.run_dir / "artifacts" / Path(name).name).resolve()

    def capture(self, name: str, path: Path, producer: str, fmt: str = "text") -> ArtifactRecord:
        """Record an artifact after the node that declared it has run."""
        if not path.is_file():
            record = ArtifactRecord(
                name=name, path=str(path), producer=producer, format=fmt, missing=True
            )
            self.records[name] = record
            return record

        data = path.read_bytes()
        try:
            text = data.decode("utf-8")
            preview = "\n".join(text.splitlines()[:8])[:MAX_PREVIEW_CHARS]
        except UnicodeDecodeError:
            preview = "(binary)"

        record = ArtifactRecord(
            name=name,
            path=str(path),
            producer=producer,
            size_bytes=len(data),
            content_hash=f"sha256:{hashlib.sha256(data).hexdigest()[:16]}",
            format=fmt,
            preview=preview,
        )
        self.records[name] = record
        return record

    def get(self, name: str) -> ArtifactRecord | None:
        return self.records.get(name)

    @property
    def available(self) -> set[str]:
        return {name for name, record in self.records.items() if not record.missing}

    def missing(self, names: list[str]) -> list[str]:
        return [name for name in names if name not in self.records or self.records[name].missing]

    def manifest(self, names: list[str]) -> str:
        """What a consuming node is told. References and previews, not contents.

        The consumer reads the real file with its tools, which goes through the
        permission policy. Inlining the whole artifact would bypass that and blow
        up the prompt for no benefit.
        """
        if not names:
            return ""
        lines = [
            "These artifacts were produced by earlier agents in this graph. Read the",
            "files themselves with your tools; the previews below are for orientation.",
            "",
        ]
        for name in names:
            record = self.records.get(name)
            if record is None or record.missing:
                lines.append(f"- `{name}`: NOT PRODUCED - the upstream step did not write it")
                continue
            lines.append(
                f"- `{name}` from `{record.producer}` at `{record.path}` "
                f"({record.size_bytes} bytes, {record.content_hash})"
            )
            if record.preview:
                indented = "\n".join(f"      {line}" for line in record.preview.splitlines())
                lines.append(indented)
        return "\n".join(lines)

    def summary(self) -> list[dict[str, object]]:
        return [
            {
                "name": record.name,
                "producer": record.producer,
                "path": record.path,
                "bytes": record.size_bytes,
                "hash": record.content_hash,
                "missing": record.missing,
            }
            for record in sorted(self.records.values(), key=lambda item: item.name)
        ]

    def preserve(self, destination: Path) -> list[str]:
        """Copy produced artifacts somewhere durable when a run fails.

        Failure must not discard work. A run that dies after the coder wrote a patch
        keeps that patch, so the next attempt starts from it instead of from nothing.
        """
        import shutil

        destination.mkdir(parents=True, exist_ok=True)
        preserved: list[str] = []
        for record in self.records.values():
            source = Path(record.path)
            if record.missing or not source.is_file():
                continue
            target = destination / Path(record.name).name
            try:
                shutil.copyfile(source, target)
                preserved.append(record.name)
            except OSError:
                continue
        return preserved
