"""What may be indexed, and what must never be.

An index is a second copy of a repository's shape with none of the repository's
access controls, and it outlives the files it described. So the rule here is
stricter than the rule for reading: a file is indexed only if it passes a path
policy *and* a content check, and anything refused is recorded as a count and a
reason rather than silently dropped.

Three layers, in order:

1. **Ignore patterns** - build output, caches, vendored trees. Not a security
   control; a noise control, and the reason the index stays small.
2. **Sensitive paths** - `.env`, key material, `**/secrets/**`, cloud credential
   directories. Refused before the file is opened.
3. **Content check** - a file with no suspicious name can still *be* a credential
   file. This looks for credential **material**, not for any mention of a secret:
   a private key block, or a run of secret-shaped assignments as in a misnamed
   `.env`. Only the exclusion is recorded, never the match.

   The distinction matters and was learned the hard way. An earlier version
   excluded any file whose content tripped secret detection, which dropped
   `observability/redaction.py`, `policy/network.py` and every security test - so
   an agent asked to fix secret handling would have been handed context with the
   secret-handling code missing. The index stores no file contents, only names and
   line numbers, so a file that *discusses* credentials leaks nothing by being
   indexed; a file that *is* credentials should never be listed at all.

Cross-project leakage is prevented structurally rather than by filtering: an index
lives in the project's own `.devforge/`, records the root it was built from, and is
refused if loaded against a different root.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path

#: Never indexed. Names and directories that hold credentials by convention.
SENSITIVE_PATTERNS: tuple[str, ...] = (
    ".env",
    ".env.*",
    "*.env",
    "**/.env",
    "**/.env.*",
    "**/secrets/**",
    "**/secret/**",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.keystore",
    "*.jks",
    "id_rsa*",
    "id_dsa*",
    "id_ecdsa*",
    "id_ed25519*",
    "*.ppk",
    ".npmrc",
    ".netrc",
    ".pypirc",
    ".htpasswd",
    "**/.aws/**",
    "**/.ssh/**",
    "**/.gnupg/**",
    "**/.kube/config",
    "credentials",
    "credentials.*",
    "*_rsa",
    "*.asc",
    "service-account*.json",
    "*serviceaccount*.json",
)

#: Skipped as noise. Excluding these is what keeps an index small enough to be useful.
IGNORE_DIRECTORIES: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".devforge",
        "node_modules",
        "__pycache__",
        ".pytest_cache",
        ".ruff_cache",
        ".mypy_cache",
        ".tox",
        ".venv",
        "venv",
        "env",
        "dist",
        "build",
        "target",
        "out",
        ".next",
        ".nuxt",
        ".cache",
        "coverage",
        "htmlcov",
        ".idea",
        ".vscode",
        "vendor",
        "third_party",
        "site-packages",
        ".terraform",
    }
)

IGNORE_SUFFIXES: frozenset[str] = frozenset(
    {
        ".pyc",
        ".pyo",
        ".so",
        ".dll",
        ".dylib",
        ".exe",
        ".bin",
        ".o",
        ".a",
        ".class",
        ".jar",
        ".war",
        ".zip",
        ".tar",
        ".gz",
        ".tgz",
        ".bz2",
        ".xz",
        ".7z",
        ".rar",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".bmp",
        ".ico",
        ".svg",
        ".webp",
        ".avif",
        ".mp3",
        ".mp4",
        ".mov",
        ".avi",
        ".wav",
        ".ogg",
        ".webm",
        ".pdf",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".ppt",
        ".pptx",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".otf",
        ".db",
        ".sqlite",
        ".sqlite3",
        ".mdb",
        ".lock",
        ".map",
    }
)

#: Bigger than this and a file is recorded but not parsed: no useful structure, and
#: parsing it would dominate index time.
MAX_INDEX_BYTES = 1_000_000

#: A generated file is technically source and practically noise.
GENERATED_MARKERS = (
    re.compile(r"^\s*(#|//|/\*|<!--)\s*(@generated|AUTO-?GENERATED|DO NOT EDIT)", re.I | re.M),
)


#: A real key: the header, then actual base64 body, then the footer. Matching the
#: header alone withheld docs/security.md, which mentions the marker while
#: explaining redaction - the security documentation an agent most needs for a
#: security task.
PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----\s*\n"
    r"(?:[A-Za-z0-9+/=]{40,}\s*\n){2,}"
    r"[^\n]*-----END"
)

#: KEY=value where the key names a secret. One is a code sample; several in a file
#: with little else is a credentials file whatever it is called.
SECRET_ASSIGNMENT = re.compile(
    r"(?im)^\s*(?:export\s+)?[A-Z0-9_]*"
    r"(?:SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIAL)"
    r"[A-Z0-9_]*\s*[=:]\s*\S{8,}"
)

#: Placeholder values that make an assignment a template rather than a secret.
PLACEHOLDER_VALUE = re.compile(
    r"[=:]\s*[\"']?(?:your|my|<|\$\{|changeme|xxx+|placeholder|example|todo|\.\.\.)",
    re.I,
)

MIN_SECRET_ASSIGNMENTS = 3


def credential_material(text: str) -> str:
    """Return a reason when this text looks like credentials, else an empty string."""
    if PRIVATE_KEY_BLOCK.search(text):
        return "private key block"

    matches = [match.group(0) for match in SECRET_ASSIGNMENT.finditer(text)]
    real = [match for match in matches if not PLACEHOLDER_VALUE.search(match)]
    if len(real) >= MIN_SECRET_ASSIGNMENTS:
        return f"{len(real)} secret-shaped assignments"

    # A high concentration in a short file is the misnamed-.env case. The floor of
    # two keeps a single constant in a long source file from tripping it.
    lines = [line for line in text.splitlines() if line.strip()]
    if len(real) >= 2 and lines and len(real) / len(lines) > 0.3:
        return "majority of lines are secret assignments"

    return ""


@dataclass
class GuardDecision:
    allowed: bool
    reason: str = ""
    #: True when the refusal was a security decision rather than a noise filter.
    sensitive: bool = False


@dataclass
class IndexGuard:
    """Decides what the indexer is permitted to look at."""

    root: Path
    extra_ignores: tuple[str, ...] = ()
    #: Refuse files whose content *is* credential material, not merely mentions it.
    scan_content: bool = True
    excluded: list[str] = field(default_factory=list)
    secrets_excluded: int = 0

    def __post_init__(self) -> None:
        self.root = Path(self.root).resolve()

    # -- path rules -------------------------------------------------------------

    def relative(self, path: Path) -> str:
        try:
            return path.resolve().relative_to(self.root).as_posix()
        except ValueError:
            return path.as_posix()

    def within_project(self, path: Path) -> bool:
        """Structural defence against cross-project leakage."""
        resolved = path.resolve()
        return resolved == self.root or self.root in resolved.parents

    def is_sensitive(self, relative_path: str) -> bool:
        name = relative_path.rsplit("/", 1)[-1]
        for pattern in SENSITIVE_PATTERNS:
            if fnmatch(name, pattern) or fnmatch(relative_path, pattern):
                return True
            if pattern.startswith("**/") and fnmatch(relative_path, pattern[3:]):
                return True
        return False

    def check_directory(self, path: Path) -> GuardDecision:
        name = path.name
        if name in IGNORE_DIRECTORIES:
            return GuardDecision(False, f"ignored directory '{name}'")
        relative = self.relative(path)
        if self.is_sensitive(relative + "/x"):
            return GuardDecision(False, f"sensitive directory '{relative}'", sensitive=True)
        for pattern in self.extra_ignores:
            if fnmatch(relative, pattern) or fnmatch(name, pattern):
                return GuardDecision(False, f"matched ignore pattern '{pattern}'")
        return GuardDecision(True)

    def check_file(self, path: Path) -> GuardDecision:
        """Everything that can be decided without opening the file."""
        if not self.within_project(path):
            return GuardDecision(False, "path is outside the project root", sensitive=True)

        relative = self.relative(path)

        if self.is_sensitive(relative):
            return GuardDecision(False, "sensitive path", sensitive=True)

        if path.suffix.lower() in IGNORE_SUFFIXES:
            return GuardDecision(False, f"ignored file type '{path.suffix}'")

        for pattern in self.extra_ignores:
            if fnmatch(relative, pattern) or fnmatch(path.name, pattern):
                return GuardDecision(False, f"matched ignore pattern '{pattern}'")

        try:
            size = path.stat().st_size
        except OSError as exc:
            return GuardDecision(False, f"unreadable: {exc}")

        if size == 0:
            return GuardDecision(False, "empty file")
        if size > MAX_INDEX_BYTES:
            return GuardDecision(False, f"larger than {MAX_INDEX_BYTES} bytes")

        return GuardDecision(True)

    # -- content rules ----------------------------------------------------------

    def check_content(self, relative_path: str, text: str) -> GuardDecision:
        """Refuse files that *are* credential material, not files that mention it."""
        if not self.scan_content:
            return GuardDecision(True)
        reason = credential_material(text)
        if reason:
            return GuardDecision(
                False, f"content looks like credential material ({reason})", sensitive=True
            )
        return GuardDecision(True)

    @staticmethod
    def is_generated(text: str) -> bool:
        head = text[:2000]
        return any(marker.search(head) for marker in GENERATED_MARKERS)

    # -- bookkeeping ------------------------------------------------------------

    def record_exclusion(self, relative_path: str, decision: GuardDecision) -> None:
        """Refusals are counted and named, never silent.

        The *reason* is recorded, never the matched text: a log line quoting the
        secret it found would defeat the exclusion it is reporting.
        """
        if decision.sensitive:
            self.secrets_excluded += 1
            self.excluded.append(f"{relative_path} ({decision.reason})")


def load_ignore_file(root: Path) -> tuple[str, ...]:
    """Read ``.devforgeignore`` if present - one glob per line, ``#`` for comments.

    Deliberately not ``.gitignore``: those files routinely un-ignore things with
    ``!`` rules, and misreading one would silently widen what gets indexed.
    """
    path = Path(root) / ".devforgeignore"
    if not path.is_file():
        return ()
    patterns: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            patterns.append(stripped.rstrip("/"))
    return tuple(patterns)
