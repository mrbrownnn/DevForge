"""Secret redaction for logs and persisted state.

Threat T12 in docs/security/threat-model.md: events record commands, agent output
and verifier output, any of which can contain a token. State files have the same
problem, and they are longer-lived than a terminal buffer.

Redaction runs at two boundaries and nowhere else:

* :meth:`RunLogger.emit` - before an event reaches any sink
* :meth:`ProjectStore.save_task` - before a task record touches disk

What this is and is not
-----------------------

It is a pattern-based filter for **secret-shaped** strings: known credential
prefixes, assignments to secret-named keys, private key blocks, URLs carrying
credentials. It is a strong net for the things that actually leak.

It is **not** a guarantee. A secret with no recognisable shape - a bare
high-entropy word, an internal hostname - passes through. Redaction reduces
exposure; it does not license logging secrets on the assumption they will be
caught. The controls that actually keep credentials out are the filesystem deny
rules on ``.env``, ``**/secrets/**`` and key files.
"""

from __future__ import annotations

import re
from typing import Any

REDACTED = "[REDACTED:{kind}]"

#: Keys whose values are secret regardless of what the value looks like.
SECRET_KEY_NAMES = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_key",
    "secret_key",
    "private_key",
    "credential",
    "credentials",
    "authorization",
    "auth_token",
    "session_key",
)

_KEY_ALTERNATION = "|".join(SECRET_KEY_NAMES)

#: (kind, pattern, group holding the secret). Order matters: the most specific first.
PATTERNS: tuple[tuple[str, re.Pattern[str], int], ...] = (
    (
        "private-key",
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
        0,
    ),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{16,}"), 0),
    ("openai-key", re.compile(r"\bsk-(?!ant-)[A-Za-z0-9_\-]{20,}"), 0),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}"), 0),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), 0),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}"), 0),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}"), 0),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"), 0),
    ("bearer-token", re.compile(r"(?i)\b(bearer|basic)\s+([A-Za-z0-9._\-+/=]{12,})"), 2),
    (
        "url-credentials",
        re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://[^\s:/@]+:)([^\s/@]+)(@)"),
        2,
    ),
    (
        "env-assignment",
        re.compile(
            rf"(?i)\b([A-Z0-9_]*(?:{_KEY_ALTERNATION})[A-Z0-9_]*)\s*[=:]\s*"
            r"(\"[^\"\n]{4,}\"|'[^'\n]{4,}'|[^\s,;)}\]]{4,})"
        ),
        2,
    ),
)

#: Values that look secret-shaped but carry no secret.
PLACEHOLDERS = frozenset(
    {"none", "null", "true", "false", "redacted", "changeme", "xxx", "...", "***", "<redacted>"}
)


def redact_text(text: str) -> str:
    """Replace secret-shaped substrings with a labelled marker."""
    if not text:
        return text
    result = text
    for kind, pattern, group in PATTERNS:
        result = _apply(result, kind, pattern, group)
    return result


def _apply(text: str, kind: str, pattern: re.Pattern[str], group: int) -> str:
    def replace(match: re.Match[str]) -> str:
        secret = match.group(group)
        if not secret or secret.strip().strip("\"'").lower() in PLACEHOLDERS:
            return match.group(0)
        if "[REDACTED:" in secret:
            return match.group(0)  # an earlier, more specific pattern already handled it
        marker = REDACTED.format(kind=kind)
        if group == 0:
            return marker
        return match.group(0).replace(secret, marker, 1)

    return pattern.sub(replace, text)


def is_secret_key(name: str) -> bool:
    lowered = name.lower()
    return any(candidate in lowered for candidate in SECRET_KEY_NAMES)


def redact_value(value: Any, *, key: str | None = None) -> Any:
    """Recursively redact a JSON-shaped structure.

    A value under a secret-named key is replaced wholesale - the key already tells
    us what it is, so its shape does not matter.
    """
    named_secret = key is not None and is_secret_key(key) and isinstance(value, str) and value
    if named_secret and value.strip().lower() not in PLACEHOLDERS:
        return REDACTED.format(kind="key-name")

    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {k: redact_value(v, key=str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_value(item) for item in value)
    return value


def contains_secret(text: str) -> bool:
    """True when redaction would change the text. Used by tests and by `doctor`."""
    return redact_text(text) != text
