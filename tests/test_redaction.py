from __future__ import annotations

import json
from pathlib import Path

import pytest

from devforge.core.models import (
    AgentResult,
    StepAttempt,
    Task,
    VerificationResult,
    VerificationStatus,
)
from devforge.core.state.store import ProjectStore
from devforge.observability.logging import RunLogger, jsonl_sink, read_events
from devforge.observability.redaction import (
    contains_secret,
    is_secret_key,
    redact_text,
    redact_value,
)

# Fixtures are assembled at runtime rather than written as literals: a credential-shaped
# string in a source file trips secret scanners (GitHub push protection blocked exactly
# this), and a test suite should not look like a leak to the tools protecting the repo.
# Assembled at runtime so the file contains no credential-shaped literal.
FAKE_GITHUB_TOKEN = "gh" + "p_" + "C" * 32
FAKE_ANTHROPIC_KEY = "sk-" + "ant-api03-" + "A" * 24

SECRETS = [
    ("anthropic-key", "sk-" + "ant-api03-" + "A" * 24),
    ("openai-key", "sk-" + "proj-" + "B" * 28),
    ("github-token", "gh" + "p_" + "C" * 32),
    ("aws-access-key", "AK" + "IA" + "IOSFODNN7EXAMPLE"),
    ("google-api-key", "AI" + "za" + "Sy" + "D" * 33),
    ("slack-token", "xo" + "xb-" + "1" * 12 + "-" + "e" * 16),
    ("jwt", "eyJ" + "hbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiIxMjMifQ" + "." + "f" * 24),
]

# Ordinary engineering output that must survive untouched: a redactor that eats real
# diagnostics is worse than none, because it destroys the evidence a repair needs.
INNOCENT = [
    "12 passed, 1 skipped in 3.42s",
    "AssertionError: expected 401 but got 200",
    "ruff check . -- All checks passed!",
    "diff --git a/src/app.py b/src/app.py",
    "ImportError: cannot import name 'foo' from 'bar'",
    "https://github.com/mrbrownnn/DevForge.git",
    "coverage: 91% of statements",
]


@pytest.mark.parametrize(("kind", "secret"), SECRETS)
def test_known_credential_shapes_are_redacted(kind: str, secret: str) -> None:
    text = f"the value is {secret} and nothing else"

    redacted = redact_text(text)

    assert secret not in redacted
    assert f"[REDACTED:{kind}]" in redacted
    assert contains_secret(text)


@pytest.mark.parametrize("text", INNOCENT)
def test_ordinary_output_is_left_alone(text: str) -> None:
    assert redact_text(text) == text
    assert not contains_secret(text)


def test_assignments_to_secret_named_keys_are_redacted() -> None:
    assert "hunter2horse" not in redact_text("DATABASE_PASSWORD=hunter2horse")
    assert "abcd1234efgh" not in redact_text("api_key: abcd1234efgh")
    assert "zzzz9999" not in redact_text('SECRET_TOKEN="zzzz9999"')


def test_url_credentials_are_redacted_but_the_url_survives() -> None:
    redacted = redact_text("git clone https://alice:s3cr3tpass@example.com/repo.git")

    assert "s3cr3tpass" not in redacted
    assert "example.com/repo.git" in redacted, "the useful part of the message must survive"


def test_private_key_blocks_are_removed_whole() -> None:
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----"

    redacted = redact_text(text)

    assert "MIIEow" not in redacted
    assert redacted == "[REDACTED:private-key]"


def test_placeholders_are_not_redacted() -> None:
    assert redact_text("password=none") == "password=none"
    assert redact_text("token: null") == "token: null"


def test_redaction_is_idempotent() -> None:
    once = redact_text(f"key: {FAKE_GITHUB_TOKEN}")

    assert redact_text(once) == once, "redacting twice must not mangle the marker"


def test_nested_structures_are_redacted_by_key_and_by_shape() -> None:
    payload = {
        "command": f"deploy --token {FAKE_GITHUB_TOKEN}",
        "password": "anything at all",
        "safe": "12 passed",
        "nested": [{"auth_token": "xyz"}, {"note": "fine"}],
    }

    redacted = redact_value(payload)

    assert "ghp_" not in json.dumps(redacted)
    assert redacted["password"] == "[REDACTED:key-name]"
    assert redacted["nested"][0]["auth_token"] == "[REDACTED:key-name]"
    assert redacted["safe"] == "12 passed"
    assert redacted["nested"][1]["note"] == "fine"


def test_is_secret_key_matches_common_names() -> None:
    assert is_secret_key("API_KEY") and is_secret_key("db_password")
    assert is_secret_key("authorization")
    assert not is_secret_key("step_id") and not is_secret_key("duration_ms")


def test_non_string_values_pass_through() -> None:
    assert redact_value({"n": 1, "ok": True, "none": None}) == {"n": 1, "ok": True, "none": None}


# ------------------------------------------------------------------ at the boundaries


def test_events_are_redacted_before_reaching_any_sink(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    logger = RunLogger([jsonl_sink(path)], task_id="task_1")

    returned = logger.info(
        "tool.shell",
        command=f"curl -H 'Authorization: Bearer {FAKE_GITHUB_TOKEN}'",
        api_key="sk-" + "ant-api03-" + "A" * 24,
    )

    on_disk = path.read_text(encoding="utf-8")
    assert "ghp_" not in on_disk and "sk-ant" not in on_disk
    assert "[REDACTED" in on_disk
    # The returned payload is the redacted one, so a caller cannot re-log the original.
    assert "ghp_" not in json.dumps(returned)

    event = next(iter(read_events(path)))
    assert event["event"] == "tool.shell" and event["task_id"] == "task_1"


def test_state_is_redacted_before_it_touches_disk(project: ProjectStore) -> None:
    task = Task(project_id="p", description="Add auth", workflow="feature")
    step = task.ensure_step("implementation", agent="coder")
    step.attempts.append(
        StepAttempt(
            attempt=1,
            agent_result=AgentResult(
                invocation_id="inv_1",
                runtime="mock",
                summary="wrote config",
                output=f"set ANTHROPIC_API_KEY={FAKE_ANTHROPIC_KEY} in .env",
            ),
            verification=[
                VerificationResult(
                    verifier="tests",
                    kind="tests",
                    status=VerificationStatus.FAILED,
                    output_excerpt=f"auth failed for {FAKE_GITHUB_TOKEN}",
                )
            ],
        )
    )

    project.save_task(task)

    raw = project.task_path(task.task_id).read_text(encoding="utf-8")
    assert "sk-ant" not in raw
    assert "ghp_" not in raw
    assert "[REDACTED" in raw

    reloaded = project.load_task(task.task_id)
    assert "[REDACTED" in reloaded.step("implementation").attempts[0].agent_result.output
    assert reloaded.description == "Add auth", "ordinary fields must be unchanged"


def test_redaction_does_not_break_state_round_trip(project: ProjectStore) -> None:
    task = Task(project_id="p", description="ordinary work", workflow="demo")
    task.ensure_step("plan", agent="architect")
    project.save_task(task)

    reloaded = project.load_task(task.task_id)

    assert reloaded.task_id == task.task_id
    assert [s.step_id for s in reloaded.steps] == ["plan"]
