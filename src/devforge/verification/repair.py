"""Verifiers that check *how* a defect was fixed, not just that tests pass.

A green suite is necessary and nowhere near sufficient. The two cheapest ways to
turn a suite green are to fix the bug and to remove the check that noticed it, and
the second is faster. Everything else in the harness measures the outcome; these
two verifiers measure the patch.

``patch-guard``
    Reads the diff for known cheating patterns - deleted assertions, added skip
    markers, disabled authentication, bypassed validation, swallowed exceptions,
    security settings turned off, edits to DevForge's own policy files. A major
    finding fails the step, so the repair loop cannot exit through the back door.

``repair-report``
    Enforces "no silent modifications": the run must leave behind a report naming
    the diagnosis, the changed files, the tests and the verification result. A
    repair whose reasoning is not written down cannot be reviewed, and an
    unreviewable repair in a codebase is a liability whether or not it works.

Both are configured entirely from YAML::

    - id: patch-guard
      kind: patch-guard
      required: true
      params:
        base: HEAD              # optional: diff against a ref instead of the worktree
        report: REPAIR-REVIEW.md

    - id: repair-report
      kind: repair-report
      required: true
      params:
        path: REPAIR-REPORT.md
"""

from __future__ import annotations

import re

from devforge.core.models import VerificationResult, VerificationStatus
from devforge.core.workflow.spec import VerifierSpec
from devforge.debug.models import PatchVerdict
from devforge.debug.patch_guard import review_patch
from devforge.tools.process import run_process
from devforge.verification.base import VerificationContext, Verifier

DEFAULT_REPORT_PATH = "REPAIR-REPORT.md"
MAX_DIFF_CHARS = 400_000

#: The four parts the brief requires of every repair, as report headings.
REQUIRED_SECTIONS = ("Diagnosis", "Changed files", "Tests", "Verification")

EMPTY_MARKERS = ("_None recorded._", "_No verification was run._", "_No summary given._")


class PatchGuardVerifier(Verifier):
    """Fail a repair whose patch weakens the checks instead of fixing the code."""

    kind = "patch-guard"

    async def run(self, spec: VerifierSpec, ctx: VerificationContext) -> VerificationResult:
        params = spec.params or {}
        diff, problem = await _collect_diff(ctx, params)
        if problem:
            return self.result(
                spec,
                ctx,
                status=VerificationStatus.UNAVAILABLE,
                summary="the patch could not be read, so it was not reviewed",
                output_excerpt=problem,
            )

        review = review_patch(diff)
        verdict = review.verdict()

        report_path = str(params.get("report") or "").strip()
        written = _write(ctx, report_path, review.render()) if report_path else ""

        if verdict is PatchVerdict.EMPTY:
            # An empty diff is not a clean patch. Reporting PASSED here would let a
            # step that changed nothing satisfy a required guard.
            return self.result(
                spec,
                ctx,
                status=VerificationStatus.SKIPPED,
                summary="no changes to review",
                output_excerpt="The diff is empty; there is no patch to inspect.",
            )

        lines = [finding.describe() for finding in review.findings]
        if written:
            lines.append(f"review written to {written}")

        if verdict is PatchVerdict.SUSPICIOUS:
            return self.result(
                spec,
                ctx,
                status=VerificationStatus.FAILED,
                summary=(
                    f"{len(review.major)} suspicious pattern(s) in "
                    f"{len(review.files_changed)} changed file(s) - the patch weakens "
                    "checks rather than fixing the defect"
                ),
                output_excerpt="\n".join(lines),
            )

        return self.result(
            spec,
            ctx,
            status=VerificationStatus.PASSED,
            summary=(
                f"no known cheating pattern in {len(review.files_changed)} changed file(s)"
                + (f"; {len(review.minor)} minor note(s)" if review.minor else "")
            ),
            output_excerpt="\n".join(lines) or "clean",
        )


class RepairReportVerifier(Verifier):
    """Require a complete, human-readable account of the repair."""

    kind = "repair-report"

    async def run(self, spec: VerifierSpec, ctx: VerificationContext) -> VerificationResult:
        params = spec.params or {}
        relative = str(params.get("path") or DEFAULT_REPORT_PATH)

        decision = ctx.policy.check_path(relative, mode="read")
        if not decision.allowed:
            return self.result(
                spec,
                ctx,
                status=VerificationStatus.ERROR,
                summary="the report path is refused by policy",
                output_excerpt=f"{relative}: {decision.reason}",
            )

        path = ctx.policy.resolve_path(relative)
        if not path.is_file():
            return self.result(
                spec,
                ctx,
                status=VerificationStatus.FAILED,
                summary=f"no repair report at {relative}",
                output_excerpt=(
                    "Every repair must record its diagnosis, changed files, tests and "
                    "verification result. A change with no report is a silent "
                    "modification."
                ),
            )

        text = path.read_text(encoding="utf-8", errors="replace")
        missing = _missing_sections(text)

        if missing:
            return self.result(
                spec,
                ctx,
                status=VerificationStatus.FAILED,
                summary=f"repair report is incomplete: missing {', '.join(missing)}",
                output_excerpt=(
                    f"{relative} must contain a non-empty section for each of: "
                    f"{', '.join(REQUIRED_SECTIONS)}."
                ),
            )

        return self.result(
            spec,
            ctx,
            status=VerificationStatus.PASSED,
            summary=f"{relative} records all {len(REQUIRED_SECTIONS)} required parts",
            output_excerpt=f"sections present: {', '.join(REQUIRED_SECTIONS)}",
        )


def _missing_sections(text: str) -> list[str]:
    """A heading with nothing under it does not count as a section.

    Checking only for the heading would accept the template - which is exactly what
    an agent produces when it writes a report to satisfy the verifier rather than
    to explain what it did.
    """
    missing: list[str] = []
    for name in REQUIRED_SECTIONS:
        body = _section_body(text, name)
        if body is None:
            missing.append(name)
        elif _is_placeholder(body):
            missing.append(f"{name} (empty)")
    return missing


def _section_body(text: str, name: str) -> str | None:
    pattern = re.compile(rf"^#{{1,6}}\s*{re.escape(name)}\s*$", re.MULTILINE | re.IGNORECASE)
    match = pattern.search(text)
    if not match:
        return None
    rest = text[match.end() :]
    next_heading = re.search(r"^#{1,6}\s+\S", rest, re.MULTILINE)
    body = rest[: next_heading.start()] if next_heading else rest
    return body.strip()


def _is_placeholder(body: str) -> bool:
    stripped = body.strip()
    if not stripped:
        return True
    return any(marker in stripped for marker in EMPTY_MARKERS) and len(stripped) < 120


async def _collect_diff(ctx: VerificationContext, params: dict) -> tuple[str, str]:
    """The patch under review: a supplied file, or git's view of the worktree.

    Reading it through ``git`` rather than walking the tree is what makes deletions
    and removed lines visible at all - the guard's whole job is to see what is no
    longer there.
    """
    supplied = str(params.get("diff_file") or "").strip()
    if supplied:
        decision = ctx.policy.check_path(supplied, mode="read")
        if not decision.allowed:
            return "", f"{supplied}: {decision.reason}"
        path = ctx.policy.resolve_path(supplied)
        if not path.is_file():
            return "", f"{supplied}: no such file in the workspace"
        return path.read_text(encoding="utf-8", errors="replace")[:MAX_DIFF_CHARS], ""

    base = str(params.get("base") or "").strip()
    argv = ["git", "diff", "--no-color"]
    if base:
        argv.append(base)
    else:
        # Staged and unstaged both, so `git add` before verification does not hide
        # the patch from the guard.
        argv.append("HEAD")

    decision = ctx.policy.check_command(argv)
    if not decision.allowed:
        return "", f"{' '.join(argv)}: {decision.reason}"

    result = await run_process(
        argv,
        cwd=ctx.workspace,
        timeout_s=int(params.get("timeout_s") or 120),
        allow_env=ctx.policy.permissions.process.allow_env,
        max_output_chars=MAX_DIFF_CHARS,
    )
    if result.exit_code != 0 and not base:
        # A repository with no commits has no HEAD to diff against. The worktree
        # diff is still meaningful there, so fall back rather than reporting the
        # patch unreadable.
        result = await run_process(
            ["git", "diff", "--no-color"],
            cwd=ctx.workspace,
            timeout_s=int(params.get("timeout_s") or 120),
            allow_env=ctx.policy.permissions.process.allow_env,
            max_output_chars=MAX_DIFF_CHARS,
        )
    if result.exit_code != 0:
        return "", (
            f"`{' '.join(argv)}` failed with exit {result.exit_code}: "
            f"{(result.error or result.combined)[:500]}"
        )
    return result.stdout, ""


def _write(ctx: VerificationContext, relative: str, content: str) -> str:
    decision = ctx.policy.check_path(relative, mode="write")
    if not decision.allowed:
        ctx.logger.warn("verification.report_denied", path=relative, reason=decision.reason)
        return ""
    path = ctx.policy.resolve_path(relative)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return relative
