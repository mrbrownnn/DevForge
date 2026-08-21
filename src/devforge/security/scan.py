"""Scanning a workspace for dangerous content.

Three questions, each mapped to a threat:

* **Are there credentials in here?** (TM9) - credential-shaped literals in source,
  and credential *files* present in a tree that will be committed.
* **Is there text aimed at the model?** (TM6) - injection-shaped instructions in
  the repository's own documentation, which an agent reads as a matter of course.
* **Is there dangerous code?** (TM10) - `eval` on input, shell invocations built by
  concatenation, TLS verification disabled, deserialisation of untrusted data.

One rule governs how it looks for secrets: **it does not read the files that are
most likely to contain them.** `.env`, `**/secrets/**` and key material are
reported by *presence*, never by content. A scanner that opened them to confirm
what it already knows would be reading credentials into memory, into a report and
possibly into a model's context - which is the very thing it exists to prevent.

What this is
------------

Pattern matching over text. It finds known-dangerous constructs and produces false
positives that a human triages; that is the trade a scanner makes to be fast and
dependency-free. It is not taint analysis, it has no vulnerability database, and
a clean scan is not evidence that the code is safe.
"""

from __future__ import annotations

import re
from datetime import date
from pathlib import Path

from devforge.observability.redaction import PATTERNS as REDACTION_PATTERNS
from devforge.observability.redaction import redact_text
from devforge.security.baseline import (
    BASELINE_DIRNAME,
    BASELINE_FILENAME,
    Baseline,
    load_baseline,
)
from devforge.security.models import Category, Finding, ScanReport, Severity
from devforge.tools.untrusted import scan as scan_for_injection

MAX_FILE_BYTES = 1_000_000
MAX_EVIDENCE_CHARS = 160

#: Directories that are not the project's own source and would swamp the results.
SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        ".venv",
        "venv",
        "env",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "dist",
        "build",
        ".tox",
        ".next",
        ".nuxt",
        "vendor",
        ".devforge",
        "site-packages",
    }
)

TEXT_SUFFIXES = frozenset(
    {
        ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".rb", ".rs",
        ".java", ".kt", ".php", ".cs", ".sh", ".bash", ".ps1", ".sql",
        ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".env-example",
        ".md", ".markdown", ".rst", ".txt", ".html", ".htm", ".vue", ".svelte",
    }
)

DOC_SUFFIXES = frozenset({".md", ".markdown", ".rst", ".txt", ".html", ".htm"})

#: Files whose mere presence in the tree is worth reporting. Never opened.
CREDENTIAL_FILES = (
    re.compile(r"(^|/)\.env(\..+)?$"),
    re.compile(r"(^|/)id_(rsa|dsa|ecdsa|ed25519)$"),
    re.compile(r"\.(pem|key|p12|pfx|keystore|jks)$"),
    re.compile(r"(^|/)\.npmrc$"),
    re.compile(r"(^|/)\.pypirc$"),
    re.compile(r"(^|/)credentials(\.json|\.yaml|\.yml)?$"),
    re.compile(r"(^|/)service-account.*\.json$"),
)

#: Names that are examples by convention and carry no real credential.
CREDENTIAL_FILE_EXCEPTIONS = re.compile(
    r"(example|sample|template|\.dist|test|fixture)", re.IGNORECASE
)


class Rule:
    """One pattern, its severity, and what to do about it."""

    __slots__ = ("id", "title", "pattern", "severity", "category", "threat", "remediation", "langs")

    def __init__(
        self,
        rule_id: str,
        title: str,
        pattern: str,
        severity: Severity,
        category: Category,
        threat: str,
        remediation: str,
        langs: frozenset[str] | None = None,
    ) -> None:
        self.id = rule_id
        self.title = title
        self.pattern = re.compile(pattern)
        self.severity = severity
        self.category = category
        self.threat = threat
        self.remediation = remediation
        self.langs = langs


PY = frozenset({".py"})
JS = frozenset({".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte"})
WEB = JS | frozenset({".html", ".htm"})


CODE_RULES: tuple[Rule, ...] = (
    Rule(
        "SEC-CODE-001",
        "eval or exec on a runtime value",
        r"\b(eval|exec)\s*\(\s*(?!['\"])[A-Za-z_$]",
        Severity.HIGH,
        Category.UNSAFE_CODE,
        "TM10",
        "Parse the value explicitly. eval on anything reachable from input is "
        "arbitrary code execution.",
    ),
    Rule(
        "SEC-CODE-002",
        "shell invocation from a constructed string",
        r"\bos\.system\s*\(|\bsubprocess\.[a-z_]+\([^)]*shell\s*=\s*True"
        r"|\bchild_process\.exec\s*\(|\bexecSync\s*\(",
        Severity.HIGH,
        Category.UNSAFE_CODE,
        "TM10",
        "Pass an argument vector instead of a shell string; a quoting bug in a shell "
        "string is command injection.",
    ),
    Rule(
        "SEC-CODE-003",
        "deserialising untrusted data",
        r"\bpickle\.loads?\s*\(|\bmarshal\.loads\s*\(|\byaml\.load\s*\((?![^)]*Safe)"
        r"|\bcPickle\.|\bjoblib\.load\s*\(",
        Severity.HIGH,
        Category.UNSAFE_CODE,
        "TM10",
        "Use yaml.safe_load, or a data format that cannot construct objects. "
        "Unpickling attacker-controlled bytes is code execution.",
    ),
    Rule(
        "SEC-CODE-004",
        "transport security disabled",
        r"\bverify\s*=\s*False|\bCERT_NONE\b|\bcheck_hostname\s*=\s*False"
        r"|\b_create_unverified_context\b|\brejectUnauthorized\s*:\s*false"
        r"|NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*['\"]?0",
        Severity.HIGH,
        Category.UNSAFE_CODE,
        "TM10",
        "Fix the certificate chain rather than turning verification off; without it "
        "the connection is not authenticated at all.",
    ),
    Rule(
        "SEC-CODE-005",
        "SQL assembled by string building",
        r"(execute|executemany|query|raw)\s*\(\s*f['\"]"
        r"|(execute|query)\s*\(\s*['\"][^'\"]*(SELECT|INSERT|UPDATE|DELETE)"
        r"[^'\"]*['\"]\s*(\+|%|\.format)",
        Severity.HIGH,
        Category.UNSAFE_CODE,
        "TM10",
        "Use parameter binding. String-built SQL is injectable no matter how the "
        "value was obtained.",
    ),
    Rule(
        "SEC-CODE-006",
        "unescaped HTML injection sink",
        r"\.innerHTML\s*=|\bdangerouslySetInnerHTML\b|\bdocument\.write\s*\("
        r"|\bv-html\b|\|\s*safe\b|\bautoescape\s*=\s*False",
        Severity.MEDIUM,
        Category.UNSAFE_CODE,
        "TM10",
        "Render text, or sanitise explicitly. These sinks turn any reflected value "
        "into script.",
        WEB,
    ),
    Rule(
        "SEC-CODE-007",
        "path built from a request value",
        r"(open|readFile|readFileSync|send_file|sendFile|createReadStream)\s*\("
        r"[^)]*\b(request|req)\b",
        Severity.MEDIUM,
        Category.UNSAFE_CODE,
        "TM10",
        "Resolve the path and confirm it stays inside the intended root before "
        "opening it - the same containment rule DevForge applies to its own tools.",
    ),
    Rule(
        "SEC-CODE-008",
        "weak randomness for a security value",
        r"\b(random\.(random|randint|choice|randrange)|Math\.random)\s*\([^)]*\)"
        r"\s*(?=.*\b(token|secret|password|nonce|salt|session|key)\b)",
        Severity.MEDIUM,
        Category.UNSAFE_CODE,
        "TM10",
        "Use secrets (Python) or crypto.randomBytes (Node). A predictable token is a "
        "guessable one.",
    ),
    Rule(
        "SEC-CODE-009",
        "insecure temporary file",
        r"\btempfile\.mktemp\s*\(|\b/tmp/[A-Za-z0-9_.-]+['\"]",
        Severity.LOW,
        Category.UNSAFE_CODE,
        "TM10",
        "Use tempfile.mkstemp or TemporaryDirectory; a predictable path in a shared "
        "directory is a symlink race.",
        PY,
    ),
    # SEC-CODE-010 (broad exception handler) was removed rather than tuned. Judging
    # a handler needs its body, and a line-level rule cannot see it - every
    # `except Exception as exc:` that correctly re-raises was reported. The case that
    # actually matters, a repair *introducing* a swallowed exception, is caught by
    # devforge.debug.patch_guard, which reads the diff and can see both lines.
)


def scan_workspace(
    root: Path,
    *,
    baseline: Baseline | None = None,
    today: date | None = None,
    max_file_bytes: int = MAX_FILE_BYTES,
) -> ScanReport:
    """Walk the tree and report what looks dangerous."""
    root = Path(root).resolve()
    baseline = baseline if baseline is not None else load_baseline(root)
    today = today or date.today()

    report = ScanReport(root=str(root))
    raw: list[Finding] = []

    for path in _walk(root):
        relative = path.relative_to(root).as_posix()

        credential_finding = _credential_file_finding(relative)
        if credential_finding is not None:
            raw.append(credential_finding)
            # Deliberately not read. See the module docstring.
            report.files_skipped += 1
            continue

        if path.suffix.lower() not in TEXT_SUFFIXES:
            report.files_skipped += 1
            continue
        try:
            if path.stat().st_size > max_file_bytes:
                report.files_skipped += 1
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            report.unreadable.append(f"{relative}: {exc}")
            continue

        report.files_scanned += 1
        raw.extend(scan_text(text, relative))

    raw.extend(_expired_suppressions(baseline, today))

    for finding in raw:
        suppression = baseline.match(finding.id, finding.location, today=today)
        if suppression is None:
            report.findings.append(finding)
        else:
            report.suppressed.append(finding)

    return report


def scan_text(text: str, location: str) -> list[Finding]:
    """Every rule that applies to one file's contents. Exposed for tests and tools."""
    findings: list[Finding] = []
    suffix = Path(location).suffix.lower()
    is_doc = suffix in DOC_SUFFIXES
    is_baseline = location.replace(chr(92), '/').endswith(
        f"{BASELINE_DIRNAME}/{BASELINE_FILENAME}"
    )

    for number, line in _code_lines(text, suffix):
        if len(line) > 2000:
            continue  # minified or generated; matching it produces noise, not findings
        if _credential_literal(line):
            findings.append(
                _finding(
                    "SEC-SECRET-001",
                    "credential-shaped literal in source",
                    Severity.HIGH,
                    Category.SECRET,
                    f"{location}:{number}",
                    line,
                    "Move it to the environment or a secret manager and rotate it - "
                    "anything committed must be treated as already disclosed.",
                    "TM9",
                )
            )
        if is_doc or is_baseline:
            # Prose describing `os.system` is not a call to it. Code rules are for
            # files that execute; documentation gets the injection scan instead.
            #
            # The baseline is excluded for a sharper reason: its reasons quote the
            # findings they accept, so scanning it means accepting a finding creates
            # a new one, one line lower, for ever.
            continue
        for rule in CODE_RULES:
            if rule.langs is not None and suffix not in rule.langs:
                continue
            if rule.pattern.search(line):
                findings.append(
                    _finding(
                        rule.id,
                        rule.title,
                        rule.severity,
                        rule.category,
                        f"{location}:{number}",
                        line,
                        rule.remediation,
                        rule.threat,
                    )
                )

    if is_doc:
        findings.extend(_injection_findings(text, location))

    return findings


_PY_COMMENT = re.compile(r"(^|\s)#")
_JS_COMMENT = re.compile(r"(^|\s)//")
_TRIPLE = re.compile(r'"{3}|\'{3}')


def _code_lines(text: str, suffix: str):
    """Yield ``(lineno, line)`` for lines that actually execute.

    Comments and docstrings are skipped for one reason: they do not run. A module
    that documents `verify=False` as a thing to avoid is not doing it, and a
    scanner that cannot tell the difference reports its loudest findings against
    the security documentation - which is how a scanner teaches people to ignore
    it.

    This is deliberately lightweight rather than a parser. It tracks triple-quoted
    regions in Python and strips trailing line comments; it does not model nested
    quoting, and a construct it misreads is reported rather than skipped.
    """
    python = suffix == ".py"
    javascript = suffix in JS
    in_docstring = False

    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw
        if python:
            fences = len(_TRIPLE.findall(line))
            if in_docstring:
                if fences:
                    in_docstring = fences % 2 == 0
                continue
            if fences >= 2 and line.strip().startswith(("'", '"')):
                continue  # a complete one-line docstring
            if fences and fences % 2 == 1 and not line.strip().startswith(("'", '"')):
                # A docstring opening on a code line: keep the code, enter the region.
                in_docstring = True
            elif fences and fences % 2 == 1:
                in_docstring = True
                continue
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            line = _PY_COMMENT.split(line)[0] if _PY_COMMENT.search(line) else line
        elif javascript:
            stripped = line.lstrip()
            if stripped.startswith(("//", "*", "/*")):
                continue
            line = _JS_COMMENT.split(line)[0] if _JS_COMMENT.search(line) else line
        if line.strip():
            yield number, line


#: Value-shaped credential patterns: a match means the *value* looks like a secret,
#: not merely that the variable is called "token".
_VALUE_SHAPED = tuple(
    (kind, pattern, group)
    for kind, pattern, group in REDACTION_PATTERNS
    if kind != "env-assignment"
)

_ASSIGNED_LITERAL = re.compile(
    r"""(?ix)
    \b([A-Z0-9_]*(?:password|passwd|secret|token|api_key|apikey|access_key
        |secret_key|private_key|credential|auth)[A-Z0-9_]*)
    \s*[:=]\s*
    (["'])(?P<value>[^"'
]{8,})\2
    """
)

#: Values that are code, not credentials: a call, an environment lookup, a regex,
#: an interpolation, a type annotation.
_NOT_A_LITERAL = re.compile(r"[()\[\]{}$\]|\bre\.|\bos\.|\bprocess\.|^[A-Za-z_]+$")


def _credential_literal(line: str) -> bool:
    """Does this source line embed something that is actually a credential?

    Reusing the log redactor wholesale was the first implementation and it was
    wrong here. Redaction is deliberately aggressive because a log line named
    `API_KEY=` almost certainly carries one; source code is full of constants whose
    *names* contain "token" or "secret" and whose values are regexes, enum members
    and type annotations. Scanning by name flagged forty of those in DevForge's own
    tree and not one real credential.

    So: a provider-shaped value always counts, and a name-based assignment counts
    only when the value is a plain string literal that is not obviously code.
    """
    for _, pattern, _group in _VALUE_SHAPED:
        if pattern.search(line):
            return not _looks_like_a_placeholder(line)

    match = _ASSIGNED_LITERAL.search(line)
    if match is None:
        return False
    value = match.group("value").strip()
    if _NOT_A_LITERAL.search(value) or _looks_like_a_placeholder(value):
        return False
    return len(set(value)) >= 5


def _injection_findings(text: str, location: str) -> list[Finding]:
    """Instructions in repository documentation, aimed at whoever reads it next.

    An agent reads the README as a matter of course. Text there saying "ignore your
    previous instructions" is not a joke in a comment; it is the cheapest delivery
    mechanism for TM6 in a repository the user already trusts enough to open.
    """
    hits = scan_for_injection(text)
    if not hits:
        return []
    worst = max(hits, key=lambda hit: len(hit.excerpt))
    return [
        _finding(
            "SEC-INJECT-001",
            f"injection-shaped instructions in documentation ({len(hits)} match(es))",
            Severity.MEDIUM,
            Category.INJECTION,
            location,
            worst.excerpt,
            "Confirm this text is meant for humans. DevForge fences file content as "
            "untrusted before it reaches a model, but this is worth a human's eyes.",
            "TM6",
        )
    ]


def _credential_file_finding(relative: str) -> Finding | None:
    if CREDENTIAL_FILE_EXCEPTIONS.search(relative):
        return None
    for pattern in CREDENTIAL_FILES:
        if pattern.search(relative):
            return _finding(
                "SEC-SECRET-002",
                "credential file present in the workspace",
                Severity.HIGH,
                Category.SECRET,
                relative,
                "(not read)",
                "Confirm it is git-ignored and never committed. DevForge's filesystem "
                "policy already denies reading it; this reports its presence only.",
                "TM9",
            )
    return None


def _expired_suppressions(baseline: Baseline, today: date) -> list[Finding]:
    return [
        _finding(
            "SEC-BASELINE-001",
            "security baseline entry has expired",
            Severity.MEDIUM,
            Category.AUDIT,
            f"security/baseline.yaml:{entry.id}:{entry.location}",
            f"expired {entry.expires.isoformat()}: {entry.reason}",
            "Re-review the finding and either fix it or renew the acceptance with a "
            "current date. An expired acceptance is no longer a decision anyone made.",
            "TM9",
        )
        for entry in baseline.expired(today)
    ]


def _finding(
    rule_id: str,
    title: str,
    severity: Severity,
    category: Category,
    location: str,
    evidence: str,
    remediation: str,
    threat: str,
) -> Finding:
    return Finding(
        id=rule_id,
        title=title,
        severity=severity,
        category=category,
        location=location,
        evidence=_evidence(evidence),
        remediation=remediation,
        threat=threat,
    )


def _evidence(text: str) -> str:
    """Findings are written to reports and read by people. Never publish the secret."""
    cleaned = redact_text(text.strip())
    return cleaned[:MAX_EVIDENCE_CHARS] + (" ..." if len(cleaned) > MAX_EVIDENCE_CHARS else "")


_PLACEHOLDER = re.compile(
    r"(?i)(your[_-]?|my[_-]?|example|placeholder|xxx+|\.\.\.|<[^>]+>|\$\{|\{\{|change[_-]?me"
    r"|dummy|fake|sample|redacted|os\.environ|process\.env|getenv)"
)


def _looks_like_a_placeholder(line: str) -> bool:
    """`API_KEY = os.environ["API_KEY"]` is the fix, not the finding.

    Without this the rule fires on every correct piece of configuration code, and a
    scanner whose loudest findings are all correct code is a scanner people learn
    to ignore.
    """
    return bool(_PLACEHOLDER.search(line))


def _walk(root: Path):
    for path in sorted(root.rglob("*")):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.is_symlink() or not path.is_file():
            continue
        yield path
