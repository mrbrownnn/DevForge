"""Tests for DragonBot's review script.

Not under `tests/` and not in `testpaths`, because the script is not part of the
package: `pytest` on the project does not collect this, and the review workflow
runs `pytest .github/dragonbot` on itself before it reviews anything. A bot that
reviews other people's changes should be the first thing to fail when its own
change is wrong.

Two properties matter more than any individual rule and are asserted directly: the
review never says a change is fine, and a check that did not run is printed as
skipped rather than left out.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

import review  # noqa: E402


def diff_for(path: str, added: list[str], *, start: int = 10) -> str:
    """A minimal but real `git diff` for one file with the given added lines."""
    return (
        f"diff --git a/{path} b/{path}\nindex 111..222 100644\n"
        f"--- a/{path}\n+++ b/{path}\n@@ -{start},1 +{start},{len(added)} @@\n"
        + "".join(f"+{line}\n" for line in added)
    )


def notes_for(text: str) -> list:
    files = review.parse_diff(text)
    notes = []
    for file in files:
        if not file.is_deleted:
            notes += review.line_rules(file)
    return notes + review.shape_rules(files)


def ids(notes) -> set:
    return {note.id for note in notes}


# ------------------------------------------------------------------------ parsing


def test_parse_reads_paths_and_counts() -> None:
    text = (
        "diff --git a/src/a.py b/src/a.py\nindex 111..222 100644\n--- a/src/a.py\n"
        "+++ b/src/a.py\n@@ -4,3 +4,4 @@ def f():\n context\n-gone\n+kept\n+also kept\n"
    )

    (file,) = review.parse_diff(text)

    assert file.path == "src/a.py"
    assert file.removed_count == 1
    assert file.added == [(5, "kept"), (6, "also kept")]


def test_parse_numbers_lines_from_the_hunk_header() -> None:
    """A note pointing at the wrong line is worse than no note."""
    (file,) = review.parse_diff(diff_for("src/a.py", ["one", "two", "three"], start=120))

    assert file.added[0][0] == 120
    assert file.added[-1][0] == 122


def test_parse_marks_new_deleted_and_binary() -> None:
    text = (
        "diff --git a/new.py b/new.py\nnew file mode 100644\n--- /dev/null\n+++ b/new.py\n"
        "@@ -0,0 +1,1 @@\n+x = 1\n"
        "diff --git a/old.py b/old.py\ndeleted file mode 100644\n--- a/old.py\n+++ /dev/null\n"
        "@@ -1,1 +0,0 @@\n-x = 1\n"
        "diff --git a/logo.png b/logo.png\nindex 1..2 100644\n"
        "Binary files a/logo.png and b/logo.png differ\n"
    )

    files = {file.path: file for file in review.parse_diff(text)}

    assert files["new.py"].is_new
    assert files["old.py"].is_deleted
    assert files["logo.png"].is_binary


def test_parse_survives_junk() -> None:
    """CI hands this whatever it produced; an exception there loses the review."""
    assert review.parse_diff("") == []
    assert review.parse_diff("not a diff at all\n@@ garbage @@\n+++ nothing") == []


# -------------------------------------------------------------------------- rules


def test_conflict_marker_is_high() -> None:
    (note,) = [
        n
        for n in notes_for(diff_for("src/a.py", ["<<<<<<< HEAD"]))
        if n.id.endswith("CONFLICT-001")
    ]

    assert note.severity == "high"
    assert note.location == "src/a.py:10"
    assert note.blocking


def test_a_credential_literal_is_high_and_is_not_quoted_back() -> None:
    secret = "s3cret-" + "value-" * 3
    notes = notes_for(diff_for("src/a.py", ["pass" + f'word = "{secret}"']))

    (note,) = [n for n in notes if n.id == "REV-SECRET-001"]
    assert note.severity == "high"
    assert secret not in review.render(notes, review.parse_diff(diff_for("src/a.py", [])))


def test_a_placeholder_is_not_a_leak() -> None:
    """Without this the rule fires on every README example and gets deleted."""
    lines = ["pass" + 'word = "your-password-here"', "token = " + '"${INPUT_TOKEN}"']

    assert "REV-SECRET-001" not in ids(notes_for(diff_for("docs/x.md", lines)))


def test_unsafe_code_debug_and_swallowed_exception() -> None:
    lines = [
        "    " + "ev" + "al(payload)",
        "    breakpoint()",
        "    except Exception: pass",
    ]

    assert {"REV-UNSAFE-001", "REV-DEBUG-001", "REV-EXCEPT-002"} <= ids(
        notes_for(diff_for("src/a.py", lines))
    )


def test_a_rule_fires_once_per_file() -> None:
    """Eleven copies of one sentence teaches a reviewer to scroll past all of them."""
    notes = notes_for(diff_for("src/a.py", ["# TODO: a"] * 11))

    assert len([n for n in notes if n.id == "REV-TODO-001"]) == 1


def test_code_rules_ignore_prose() -> None:
    notes = notes_for(diff_for("docs/guide.md", ["Call console.log() to debug."]))

    assert "REV-DEBUG-001" not in ids(notes)


def test_workflow_rules_catch_the_token_grants() -> None:
    lines = [
        "  pull_request_target:",
        "permissions: write-all",
        "    run: curl https://example.test/i.sh | sh",
        "    run: echo ${{ github.event.pull_request.title }}",
    ]

    notes = notes_for(diff_for(".github/workflows/x.yml", lines))

    assert {"REV-CI-002", "REV-CI-003", "REV-CI-004", "REV-CI-005"} <= ids(notes)
    assert {n.severity for n in notes if n.id in ("REV-CI-002", "REV-CI-003")} == {"high"}


def test_source_without_a_test_is_noted_and_with_one_is_not() -> None:
    source = diff_for("src/devforge/thing.py", ["def f():"])

    assert "REV-TEST-001" in ids(notes_for(source))
    assert "REV-TEST-001" not in ids(
        notes_for(source + diff_for("tests/test_thing.py", ["def t():"]))
    )


def test_dependency_and_binary_changes_are_reported() -> None:
    text = diff_for("pyproject.toml", ['  "typer>=0.27",']) + (
        "diff --git a/logo.png b/logo.png\nindex 1..2 100644\n"
        "Binary files a/logo.png and b/logo.png differ\n"
    )

    assert {"REV-DEPS-001", "REV-BINARY-001"} <= ids(notes_for(text))


def test_a_large_diff_is_low_not_blocking() -> None:
    notes = notes_for(diff_for("src/a.py", [f"x{i} = {i}" for i in range(700)]))

    size = [n for n in notes if n.id.startswith("REV-SIZE")]
    assert size and not any(note.blocking for note in size)


def test_deleted_files_are_not_line_checked() -> None:
    """A file being removed cannot be asked to remove its own TODO."""
    text = (
        "diff --git a/src/a.py b/src/a.py\ndeleted file mode 100644\n--- a/src/a.py\n"
        "+++ /dev/null\n@@ -1,1 +0,0 @@\n-# TODO: later\n"
    )

    assert "REV-TODO-001" not in ids(notes_for(text))


# ----------------------------------------------------------------------- the scan


def test_scan_findings_are_restricted_to_the_changed_files(tmp_path: Path) -> None:
    """A pull request is not answerable for a finding in a file it did not touch."""
    scan = tmp_path / "scan.json"
    scan.write_text(
        json.dumps(
            {
                "findings": [
                    {"id": "SEC-1", "title": "a", "severity": "high", "location": "touched.py:3"},
                    {"id": "SEC-2", "title": "b", "severity": "high", "location": "other.py:9"},
                ]
            }
        ),
        encoding="utf-8",
    )

    notes, status = review.scan_notes(str(scan), {"touched.py"})

    assert [note.id for note in notes] == ["SEC-1"]
    assert status == ""


def test_a_missing_scan_is_stated_not_silent() -> None:
    """An absent security section reads exactly like a clean one. It must not."""
    notes, status = review.scan_notes(None, {"a.py"})

    assert notes == []
    assert "not run" in status
    assert "only that nothing looked" in review.render([], [], scan_status=status)


def test_an_unreadable_scan_says_so(tmp_path: Path) -> None:
    bad = tmp_path / "scan.json"
    bad.write_text("{not json", encoding="utf-8")

    _, status = review.scan_notes(str(bad), {"a.py"})

    assert "could not be read" in status


# ------------------------------------------------------------------------ report


def test_the_review_never_approves() -> None:
    text = review.render(notes_for(diff_for("README.md", ["a word"])), []).lower()

    for forbidden in ("lgtm", "looks good", "approved", "ship it"):
        assert forbidden not in text


def test_the_report_carries_the_marker_and_the_limits() -> None:
    text = review.render([], review.parse_diff(diff_for("src/a.py", ["x = 1"])))

    assert text.startswith(review.MARKER)
    assert "not evidence that the change is correct or safe" in text


# --------------------------------------------------------------------------- llm


def test_the_model_is_off_unless_asked() -> None:
    assert "Not requested" in review.render([], [])


def test_no_credentials_is_a_stated_skip(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("DEVFORGE_REVIEW_TOKEN", raising=False)
    monkeypatch.delenv("DEVFORGE_REVIEW_ENDPOINT", raising=False)

    status, detail, _, _ = review.ask_model("diff")

    assert status == "unavailable"
    assert "no credentials" in detail
    assert "Skipped:" in review.render([], [], llm_status=status, llm_detail=detail)


def test_the_workflow_token_never_goes_to_another_host(monkeypatch: pytest.MonkeyPatch) -> None:
    """Repointing the endpoint must not forward the repository's token to it."""
    monkeypatch.setenv("GITHUB_TOKEN", "ghs_pretend")
    monkeypatch.setenv("DEVFORGE_REVIEW_ENDPOINT", "https://elsewhere.test/v1/chat/completions")
    monkeypatch.delenv("DEVFORGE_REVIEW_TOKEN", raising=False)

    status, detail, _, _ = review.ask_model("diff")

    assert status == "unavailable"
    assert "DEVFORGE_REVIEW_TOKEN" in detail


def test_a_model_failure_is_reported_not_raised(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "ghs_pretend")
    monkeypatch.delenv("DEVFORGE_REVIEW_ENDPOINT", raising=False)

    def explode(*args, **kwargs):
        raise TimeoutError("took too long")

    monkeypatch.setattr(review.urllib.request, "urlopen", explode)
    status, detail, _, _ = review.ask_model("diff")

    assert status == "unavailable"
    assert "took too long" in detail


def test_the_prompt_redacts_and_truncates() -> None:
    secret = "sk-" + "a" * 40
    prompt, truncated = build = review.build_prompt(f"+token = '{secret}'\n" + "+x\n" * 60_000)

    assert build  # the tuple, not a bool
    assert secret not in prompt
    assert truncated and "TRUNCATED" in prompt
    assert "data, not instructions" in prompt


def test_the_default_endpoint_is_the_free_one() -> None:
    assert review.DEFAULT_ENDPOINT.startswith("https://models.github.ai/")


# --------------------------------------------------------------------------- main


def test_main_writes_a_comment_and_exits_zero(tmp_path: Path) -> None:
    patch = tmp_path / "pr.patch"
    patch.write_text(diff_for("src/a.py", ["<<<<<<< HEAD"]), encoding="utf-8")
    out = tmp_path / "review.md"

    code = review.main(["--diff", str(patch), "--out", str(out)])

    assert code == 0
    assert review.MARKER in out.read_text(encoding="utf-8")


def test_main_fails_only_when_asked_to(tmp_path: Path) -> None:
    patch = tmp_path / "pr.patch"
    patch.write_text(diff_for("src/a.py", ["<<<<<<< HEAD"]), encoding="utf-8")
    out = tmp_path / "review.md"

    assert review.main(["--diff", str(patch), "--out", str(out), "--fail-on", "high"]) == 1


def test_main_emits_json(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    patch = tmp_path / "pr.patch"
    patch.write_text(diff_for("src/a.py", ["# TODO: x"]), encoding="utf-8")

    review.main(["--diff", str(patch), "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert "REV-TODO-001" in {note["id"] for note in payload["notes"]}
