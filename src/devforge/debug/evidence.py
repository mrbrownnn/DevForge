"""Collecting the evidence a diagnosis is allowed to be based on.

The brief names eight categories - stack traces, logs, test failures, git diff,
relevant source, runtime state, browser console, network errors - and this module
collects all eight through one guarded path.

Two rules shape every collector here.

**Nothing is read that policy would not let a tool read.** Every file goes through
:meth:`PolicyEngine.check_path`, so ``.env``, ``**/secrets/**``, key files and
anything outside the workspace are refused. A debugger that could read files the
edit tools cannot would be a privilege escalation dressed as a convenience: "just
show me the config" is how credentials end up in a report that later gets pasted
into an issue.

**Nothing leaves without passing redaction.** Evidence is the highest-risk text in
the harness - it is quoted verbatim from logs and tracebacks, then written to a
report and put in front of a model. :func:`devforge.observability.redaction.redact_text`
runs on every item, and the item records that it happened, because a reader who
cannot see that text was altered will misread what remains.

What redaction does not do is documented in that module: it catches
secret-*shaped* strings, not every secret. It is a net, not a wall. The wall is
the deny list.
"""

from __future__ import annotations

import platform
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

from devforge.debug.models import Evidence, EvidenceBundle, EvidenceKind, Reproduction
from devforge.observability.logging import RunLogger, null_logger
from devforge.observability.redaction import redact_text
from devforge.policy.engine import PolicyEngine
from devforge.tools.process import run_process

MAX_ITEM_CHARS = 6_000
MAX_SOURCE_FILES = 8
SOURCE_CONTEXT_LINES = 12
MAX_LOG_TAIL_LINES = 200

PY_TRACEBACK = re.compile(r"^\s*Traceback \(most recent call last\):", re.MULTILINE)
PY_FRAME = re.compile(r'^\s*File "(?P<path>[^"]+)", line (?P<line>\d+)', re.MULTILINE)
JS_STACK = re.compile(r"^\s*at\s+\S+\s+\(?[^\s)]+:\d+:\d+\)?", re.MULTILINE)
PYTEST_FAILED = re.compile(r"^(FAILED|ERROR)\s+\S+.*$", re.MULTILINE)
PYTEST_ASSERT = re.compile(r"^E\s{2,}.*$", re.MULTILINE)
JEST_FAIL = re.compile(r"^\s*(●|✕|FAIL)\s+.*$", re.MULTILINE)

#: Environment variable names safe to report as *values*. Everything else is
#: reported by name only, if at all - a value is where a secret lives.
SAFE_ENV_VALUES = ("CI", "LANG", "TZ", "PYTHONHASHSEED", "NODE_ENV", "TERM")


def extract_stack_traces(text: str) -> list[str]:
    """Pull traceback blocks out of mixed output.

    A traceback runs from its header to the first line that is neither indented
    nor a continuation - that final unindented line is the exception itself, which
    is the part a reader most needs, so it is kept.
    """
    if not text:
        return []
    blocks: list[str] = []
    lines = text.splitlines()
    for match in PY_TRACEBACK.finditer(text):
        start = text[: match.start()].count("\n")
        block = [lines[start]]
        for line in lines[start + 1 :]:
            block.append(line)
            if line and not line[0].isspace() and not line.startswith("Traceback"):
                break
        blocks.append("\n".join(block))

    js = JS_STACK.findall(text)
    if js and not blocks:
        blocks.append("\n".join(js[:40]))
    return blocks


def traceback_frames(text: str) -> list[tuple[str, int]]:
    """``(path, line)`` pairs from tracebacks, most recent (deepest) first."""
    frames = [(m.group("path"), int(m.group("line"))) for m in PY_FRAME.finditer(text or "")]
    return list(reversed(frames))


def extract_test_failures(text: str) -> str:
    """The lines that say which tests failed and why, without the whole log.

    One ordered pass rather than a match per pattern: the sequence of a pytest
    summary carries meaning (which assertion belongs to which test), and
    collecting by category would shuffle it.
    """
    if not text:
        return ""
    kept = [
        line
        for line in text.splitlines()
        if PYTEST_FAILED.match(line) or PYTEST_ASSERT.match(line) or JEST_FAIL.match(line)
    ]
    return "\n".join(dict.fromkeys(kept))[:MAX_ITEM_CHARS]


#: How many environment variable names one runtime-state record lists. Bounded so a
#: CI environment with hundreds of variables does not bury the rest of the record;
#: the count and an explicit "not listed" note keep the truncation visible.
MAX_ENV_NAMES = 60


@dataclass
class EvidenceCollector:
    """Gathers evidence for one defect, under one policy.

    Stateless between calls apart from the bundle it builds, so a caller can add
    items from several sources - a reproduction, a browser capture, a log file -
    and get one coherent artifact.
    """

    workspace: Path
    policy: PolicyEngine
    logger: RunLogger = field(default_factory=null_logger)
    bundle: EvidenceBundle = field(default_factory=EvidenceBundle)

    # -- primitives -------------------------------------------------------------

    def _item(
        self, kind: EvidenceKind, label: str, content: str, *, source: str = ""
    ) -> Evidence | None:
        if not content or not content.strip():
            return None
        cleaned = redact_text(content)
        truncated = len(cleaned) > MAX_ITEM_CHARS
        return Evidence(
            kind=kind,
            label=label,
            content=cleaned[:MAX_ITEM_CHARS],
            source=source,
            truncated=truncated,
            redacted=cleaned != content,
        )

    def add(self, kind: EvidenceKind, label: str, content: str, *, source: str = "") -> None:
        self.bundle.add(self._item(kind, label, content, source=source))

    def _read(self, relative: str) -> str | None:
        """Read a workspace file, or record a refusal and return ``None``."""
        decision = self.policy.check_path(relative, mode="read")
        if not decision.allowed:
            entry = f"{relative} - {decision.reason}"
            if entry not in self.bundle.refused:
                self.bundle.refused.append(entry)
            self.logger.warn("debug.evidence_refused", path=str(relative)[:200])
            return None
        path = self.policy.resolve_path(relative)
        if not path.is_file():
            return None
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            self.bundle.refused.append(f"{relative} - unreadable: {exc}")
            return None

    # -- collectors -------------------------------------------------------------

    def from_output(self, text: str, *, label: str = "reproduction output") -> None:
        """Split raw command output into traces, test failures and the log itself."""
        for index, trace in enumerate(extract_stack_traces(text), start=1):
            suffix = f" #{index}" if index > 1 else ""
            self.add(EvidenceKind.STACK_TRACE, f"stack trace{suffix}", trace, source=label)

        failures = extract_test_failures(text)
        self.add(EvidenceKind.TEST_FAILURE, "failing tests", failures, source=label)

        self.add(EvidenceKind.LOG, label, _tail(text, MAX_LOG_TAIL_LINES), source=label)

    def from_reproduction(self, reproduction: Reproduction) -> None:
        self.from_output(
            reproduction.failure_output,
            label=" ".join(reproduction.argv) or "reproduction",
        )

    def source_for_traceback(self, text: str, *, context: int = SOURCE_CONTEXT_LINES) -> None:
        """The source around each frame, for frames inside this workspace.

        Frames from the standard library and site-packages are skipped: they are
        not what the repair will change, and reading them would pull large amounts
        of irrelevant text into the model's context.
        """
        seen: set[tuple[str, int]] = set()
        for raw_path, line in traceback_frames(text):
            relative = self._relative(raw_path)
            if relative is None or (relative, line) in seen:
                continue
            seen.add((relative, line))
            content = self._read(relative)
            if content is None:
                continue
            self.add(
                EvidenceKind.SOURCE,
                f"{relative} around line {line}",
                _excerpt(content, line, context),
                source=f"{relative}:{line}",
            )
            if len(self.bundle.of(EvidenceKind.SOURCE)) >= MAX_SOURCE_FILES:
                return

    def source_files(self, paths: list[str]) -> None:
        for relative in paths[:MAX_SOURCE_FILES]:
            content = self._read(relative)
            if content is not None:
                self.add(EvidenceKind.SOURCE, relative, content, source=relative)

    def logs(self, paths: list[str]) -> None:
        for relative in paths:
            content = self._read(relative)
            if content is not None:
                self.add(
                    EvidenceKind.LOG,
                    f"tail of {relative}",
                    _tail(content, MAX_LOG_TAIL_LINES),
                    source=relative,
                )

    async def git_diff(self, *, staged: bool = False, timeout_s: int = 60) -> None:
        """The working diff - what changed recently is what most often broke it."""
        argv = ["git", "diff", "--staged"] if staged else ["git", "diff"]
        decision = self.policy.check_command(argv)
        if not decision.allowed:
            self.bundle.refused.append(f"{' '.join(argv)} - {decision.reason}")
            return
        result = await run_process(
            argv,
            cwd=self.workspace,
            timeout_s=timeout_s,
            allow_env=self.policy.permissions.process.allow_env,
            max_output_chars=self.policy.permissions.process.max_output_chars,
        )
        if result.exit_code != 0:
            return
        self.add(
            EvidenceKind.DIFF,
            "staged changes" if staged else "working tree changes",
            result.stdout,
            source=" ".join(argv),
        )

    def runtime_state(self, extra: dict[str, str] | None = None) -> None:
        """Interpreter, platform and workspace - by value; environment - by name.

        Environment *values* are never collected. Listing the names is enough to
        answer "was this configured?" and it is the one shape of runtime state that
        reliably contains credentials.
        """
        import os

        lines = [
            f"python: {sys.version.split()[0]}",
            f"platform: {platform.platform()}",
            f"workspace: {self.workspace}",
        ]
        for name in SAFE_ENV_VALUES:
            if name in os.environ:
                lines.append(f"env {name}: {os.environ[name]}")
        names = sorted(os.environ)
        shown = names[:MAX_ENV_NAMES]
        listing = ", ".join(shown)
        if len(names) > len(shown):
            # Say that the list was cut. A bare list reads as the whole environment,
            # and "the name is not here" would then be read as "the variable is not
            # set" - a different claim, and one this never checked.
            listing += f", ... ({len(names) - len(shown)} more not listed)"
        lines.append(f"env variables present ({len(names)}), names only: {listing}")
        for key, value in (extra or {}).items():
            lines.append(f"{key}: {value}")
        self.add(
            EvidenceKind.RUNTIME_STATE,
            "runtime state",
            "\n".join(lines),
            source="process environment (names only)",
        )

    def from_page(self, snapshot: object) -> None:
        """Browser console output and failed requests from a captured page.

        Typed loosely on purpose: the debug package must not import the browser
        session, so a caller with a ``PageSnapshot`` can pass it without making
        Playwright a dependency of debugging.
        """
        console = list(getattr(snapshot, "console", []) or [])
        network = list(getattr(snapshot, "failed_requests", []) or [])
        url = str(getattr(snapshot, "url", ""))

        if console:
            errors = [entry for entry in console if getattr(entry, "is_error", False)]
            shown = errors or console
            rendered = "\n".join(
                f"[{entry.level}] {entry.text}"
                + (f"  ({entry.location})" if entry.location else "")
                for entry in shown[:80]
            )
            self.add(
                EvidenceKind.BROWSER_CONSOLE,
                f"console ({len(errors)} error(s) of {len(console)} message(s))",
                rendered,
                source=url,
            )

        if network:
            rendered = "\n".join(
                f"{entry.method} {entry.url} -> "
                + (f"blocked: {entry.blocked_reason}" if entry.blocked else str(entry.status))
                for entry in network[:80]
            )
            self.add(
                EvidenceKind.NETWORK_ERROR,
                f"{len(network)} failed or blocked request(s)",
                rendered,
                source=url,
            )

    # -- helpers ----------------------------------------------------------------

    def _relative(self, raw_path: str) -> str | None:
        """Workspace-relative form of a traceback path, or ``None`` if foreign."""
        try:
            candidate = Path(raw_path)
            if not candidate.is_absolute():
                candidate = (self.workspace / candidate).resolve()
            else:
                candidate = candidate.resolve()
            root = self.workspace.resolve()
            if candidate == root or root not in candidate.parents:
                return None
            return candidate.relative_to(root).as_posix()
        except (OSError, ValueError):
            return None


def _excerpt(content: str, line: int, context: int) -> str:
    lines = content.splitlines()
    start = max(0, line - context - 1)
    end = min(len(lines), line + context)
    width = len(str(end))
    return "\n".join(
        f"{index + 1:>{width}} {'>' if index + 1 == line else ' '} {lines[index]}"
        for index in range(start, end)
    )


def _tail(text: str, lines: int) -> str:
    split = text.splitlines()
    return "\n".join(split[-lines:]) if len(split) > lines else text
