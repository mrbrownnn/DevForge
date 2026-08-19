"""Environment sanitisation for child processes.

Until Phase 2 every subprocess DevForge spawned inherited the full environment of
the invoking shell. That handed every ambient credential - cloud keys, VCS tokens,
model-provider API keys - to any allowed command, including verifier commands
declared in a workflow file. Redacting secrets from logs while posting them into
every child process would have been theatre.

A child now gets a constructed environment: the variables it genuinely needs to
run (PATH, HOME, temp dirs, locale, platform essentials), plus anything the
project explicitly opts in to. Everything else is dropped.

This is not isolation. An allowed interpreter can still read `~/.aws/credentials`
from disk. It removes the *easiest* leak - ambient credentials in the process
environment - and nothing more.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Iterable

from devforge.observability.redaction import is_secret_key

#: Variables a normal build or test process needs to function at all.
BASE_ALLOWLIST: frozenset[str] = frozenset(
    {
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "SHELL",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TZ",
        "TERM",
        # Windows needs these or nothing starts.
        "SYSTEMROOT",
        "SYSTEMDRIVE",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
        "USERPROFILE",
        "HOMEDRIVE",
        "HOMEPATH",
        "APPDATA",
        "LOCALAPPDATA",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
        "PROGRAMDATA",
        "NUMBER_OF_PROCESSORS",
        "PROCESSOR_ARCHITECTURE",
        "OS",
        # Temp directories: without them many toolchains fail in confusing ways.
        "TMP",
        "TEMP",
        "TMPDIR",
        # Language runtimes, non-secret behaviour flags only.
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONIOENCODING",
        "PYTHONUNBUFFERED",
        "VIRTUAL_ENV",
        "CONDA_PREFIX",
        "NODE_PATH",
        "NVM_DIR",
        "JAVA_HOME",
        "GOPATH",
        "GOROOT",
        "CARGO_HOME",
        "RUSTUP_HOME",
    }
)

#: Set on every child so tools can detect the harness and stay non-interactive.
INJECTED: dict[str, str] = {
    "DEVFORGE": "1",
    "CI": "1",
    "NO_COLOR": "1",
    "PYTHONDONTWRITEBYTECODE": "1",
    "GIT_TERMINAL_PROMPT": "0",  # never block a run waiting for git credentials
}


def build_env(
    *,
    extra: dict[str, str] | None = None,
    allow: Iterable[str] = (),
    base: dict[str, str] | None = None,
) -> dict[str, str]:
    """Construct a child environment from an allowlist.

    ``allow`` names additional variables to carry over from the parent - a project
    opt-in for things like ``DATABASE_URL`` in a test suite. A name that looks like
    a secret is still carried when explicitly allowed: the point of an opt-in is
    that someone decided. It is refused only if it was never named.
    """
    source = os.environ if base is None else base
    names = set(BASE_ALLOWLIST) | {name.upper() for name in allow}

    env: dict[str, str] = {}
    for name, value in source.items():
        if name.upper() in names:
            env[name] = value

    env.update(INJECTED)
    if extra:
        env.update(extra)

    # PATH is not optional; a child with no PATH cannot find its own interpreter.
    if "PATH" not in env and "Path" not in env:
        env["PATH"] = os.defpath
    if sys.platform == "win32" and "SYSTEMROOT" not in {k.upper() for k in env}:
        # Windows environment names are case-insensitive, and os.environ follows suit.
        env["SYSTEMROOT"] = os.environ.get("SYSTEMROOT", "C:\\Windows")
    return env


def dropped_secret_names(base: dict[str, str] | None = None) -> list[str]:
    """Secret-looking variables that sanitisation removes. Used by `doctor` and tests."""
    source = os.environ if base is None else base
    return sorted(
        name for name in source if is_secret_key(name) and name.upper() not in BASE_ALLOWLIST
    )
