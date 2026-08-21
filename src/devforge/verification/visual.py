"""Visual verifier: does the reproduction actually look like the original?

Phase 0 shipped this as a declared-unavailable stub because DevForge had no browser
driver. Playwright is now an optional dependency, so the check is real - and it
keeps the same honesty rule it started with: when the driver, the reference or the
candidate is missing, it reports ``UNAVAILABLE``. It never reports ``PASSED``
without having compared two actual renders.

Configured from the workflow, no Python needed::

    - id: visual
      kind: visual
      params:
        reference: https://example.com
        serve: dist            # or: candidate: http://localhost:4173
        viewports: [mobile, desktop]
        threshold: 0.9
        report: visual-report.md

``serve`` is what closes the clone loop without asking the operator to start
anything: DevForge serves that workspace directory itself on an ephemeral loopback
port for the length of the comparison and uses it as the candidate. ``candidate``
remains available for a build that is already running somewhere.

The verdict comes from structural similarity - geometry, typography, spacing and
colour of matched elements - not from a pixel percentage. A pixel diff is recorded
alongside it as corroboration, because two pages can differ by 30% of pixels and be
correct (different photo), or by 2% and be wrong (illegible heading).

Because ``VerificationResult.blocking_failure`` treats a required-but-unavailable
verifier as a failure, a clone run that cannot see its own output stops rather than
finishing on an unchecked assumption.
"""

from __future__ import annotations

from contextlib import nullcontext
from pathlib import Path

from devforge.browser.models import DEFAULT_VIEWPORTS, Viewport
from devforge.browser.session import SessionPolicy, playwright_available
from devforge.core.models import VerificationResult, VerificationStatus
from devforge.core.workflow.spec import VerifierSpec
from devforge.verification.base import VerificationContext, Verifier
from devforge.visual.compare import VisualDiffReport, compare_responsive
from devforge.visual.serve import static_site

DEFAULT_THRESHOLD = 0.9
#: Where captures land, relative to the workspace. Inside .devforge so a clone run
#: does not litter the tree it is building.
ARTIFACT_DIR = Path(".devforge") / "visual"

MISSING_CONFIG = (
    "the visual verifier needs params.reference (the site being reproduced) and "
    "either params.serve (a workspace directory DevForge will serve on loopback) "
    "or params.candidate (a URL your build is already served at). Without both "
    "sides there is nothing to compare and DevForge will not guess."
)


class VisualVerifier(Verifier):
    """Compare a candidate render against a reference render."""

    kind = "visual"

    async def run(self, spec: VerifierSpec, ctx: VerificationContext) -> VerificationResult:
        params = spec.params or {}
        reference_url = str(params.get("reference") or "").strip()
        candidate_url = str(params.get("candidate") or "").strip()
        serve_dir = str(params.get("serve") or "").strip()

        if not reference_url or not (candidate_url or serve_dir):
            return self._unavailable(spec, ctx, MISSING_CONFIG)

        available, detail = playwright_available()
        if not available:
            return self._unavailable(spec, ctx, detail)

        viewports = _viewports(params.get("viewports"))
        threshold = float(params.get("threshold") or DEFAULT_THRESHOLD)

        # The reference is a remote site and is held to the project's full network
        # policy: a verifier is not a licence to reach somewhere a tool could not.
        reference_policy = SessionPolicy.from_network(ctx.policy.permissions.network)
        allowed, reason = reference_policy.check(reference_url)
        if not allowed:
            return self._unavailable(
                spec,
                ctx,
                f"the reference URL {reference_url} is refused by the network policy: "
                f"{reason}. Add the host to network.allow_hosts.",
            )

        if serve_dir:
            root, problem = _serve_root(ctx, serve_dir)
            if problem:
                return self._unavailable(spec, ctx, problem)
            server = static_site(root)
        else:
            # An externally hosted candidate gets no special treatment beyond the
            # loopback opt-in the operator already declared in the policy file.
            allowed, reason = reference_policy.check(candidate_url)
            if not allowed:
                return self._unavailable(
                    spec,
                    ctx,
                    f"the candidate URL {candidate_url} is refused by the network "
                    f"policy: {reason}. Set network.allow_loopback for a local dev "
                    "server, or use params.serve and let DevForge host the build.",
                )
            server = nullcontext(candidate_url)

        try:
            with server as base_url:
                candidate = _join(base_url, str(params.get("path") or ""))
                # Loopback is permitted only for the side that is actually local.
                # The reference keeps the strict policy, so a redirect from the
                # reference site cannot reach the machine's own services.
                candidate_policy = (
                    SessionPolicy(network=ctx.policy.permissions.network, allow_loopback=True)
                    if serve_dir
                    else reference_policy
                )
                reports = await self._compare(
                    spec,
                    ctx,
                    reference_policy,
                    candidate_policy,
                    reference_url,
                    candidate,
                    viewports,
                )
        except Exception as exc:
            # A driver failure is missing evidence, not a pass and not a code defect.
            return self._unavailable(spec, ctx, f"capture failed: {type(exc).__name__}: {exc}")

        written = _write_report(ctx, spec, params, reports)
        return _to_result(self, spec, ctx, reports, threshold, written)

    async def _compare(
        self,
        spec: VerifierSpec,
        ctx: VerificationContext,
        reference_policy: SessionPolicy,
        candidate_policy: SessionPolicy,
        reference_url: str,
        candidate_url: str,
        viewports: list[Viewport],
    ) -> list[VisualDiffReport]:
        from devforge.browser.capture import capture_responsive

        base = ctx.workspace / ARTIFACT_DIR / spec.id
        reference = await capture_responsive(
            reference_policy,
            reference_url,
            viewports,
            screenshot_dir=base / "reference",
            logger=ctx.logger,
        )
        candidate = await capture_responsive(
            candidate_policy,
            candidate_url,
            viewports,
            screenshot_dir=base / "candidate",
            logger=ctx.logger,
        )
        return compare_responsive(reference, candidate, diff_image_dir=base / "diff")

    def _unavailable(
        self, spec: VerifierSpec, ctx: VerificationContext, reason: str
    ) -> VerificationResult:
        ctx.logger.warn(
            "verification.unavailable",
            verifier=spec.id,
            kind=spec.kind,
            step=ctx.step_id,
            reason=reason,
        )
        return self.result(
            spec,
            ctx,
            status=VerificationStatus.UNAVAILABLE,
            summary="visual verification could not be performed",
            output_excerpt=reason,
        )


def _serve_root(ctx: VerificationContext, serve_dir: str) -> tuple[Path, str]:
    """Resolve ``serve`` inside the workspace, or explain why it cannot be served.

    Symlinks are resolved before the containment check: serving a directory that
    escapes the workspace would publish arbitrary local files to a browser we then
    read back.
    """
    workspace = ctx.workspace.resolve()
    root = (workspace / serve_dir).resolve()
    if root != workspace and workspace not in root.parents:
        return root, (
            f"params.serve must stay inside the workspace; {serve_dir} resolves to {root}"
        )
    if not root.is_dir():
        return root, (
            f"params.serve points at {serve_dir}, which does not exist in the workspace. "
            "Build the reproduction before verifying it."
        )
    return root, ""


def _join(base_url: str, path: str) -> str:
    """Append an optional entry path, e.g. a build that lives at /index.html."""
    if not path:
        return base_url
    return base_url.rstrip("/") + "/" + path.lstrip("/")


def _viewports(names) -> list[Viewport]:
    """Resolve viewport names, defaulting to the full responsive set."""
    if not names:
        return list(DEFAULT_VIEWPORTS)
    by_name = {viewport.name: viewport for viewport in DEFAULT_VIEWPORTS}
    chosen = [by_name[name] for name in names if name in by_name]
    return chosen or list(DEFAULT_VIEWPORTS)


def _write_report(ctx: VerificationContext, spec: VerifierSpec, params, reports) -> str:
    """Persist the full diff. The summary line is never the whole story."""
    relative = str(params.get("report") or (ARTIFACT_DIR / f"{spec.id}.md"))
    target = ctx.workspace / relative
    body = "\n\n---\n\n".join(report.render() for report in reports)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")
    except OSError as exc:
        ctx.logger.warn("verification.report_write_failed", verifier=spec.id, error=str(exc)[:200])
        return ""
    return relative


def _to_result(
    verifier: Verifier,
    spec: VerifierSpec,
    ctx: VerificationContext,
    reports: list[VisualDiffReport],
    threshold: float,
    report_path: str,
) -> VerificationResult:
    verdicts = {report.viewport: report.verdict(threshold=threshold) for report in reports}

    if all(value == "UNVERIFIED" for value in verdicts.values()):
        return verifier.result(
            spec,
            ctx,
            status=VerificationStatus.UNAVAILABLE,
            summary="no viewport produced a comparable capture",
            output_excerpt="\n\n".join(report.render() for report in reports)[:4000],
        )

    failed = [viewport for viewport, value in verdicts.items() if value != "PASS"]
    scores = ", ".join(
        f"{report.viewport}={report.structural_similarity:.2f}" for report in reports
    )
    findings = sum(len(report.findings) for report in reports)
    excerpt_parts = [
        f"threshold: {threshold}",
        f"structural similarity: {scores}",
        f"findings: {findings}",
        f"report: {report_path or '(not written)'}",
    ]
    for report in reports:
        for finding in report.major[:8]:
            excerpt_parts.append(f"[{report.viewport}] {finding.describe()}")

    ctx.logger.info(
        "verification.visual",
        verifier=spec.id,
        step=ctx.step_id,
        verdicts=verdicts,
        findings=findings,
        report=report_path or None,
    )

    return verifier.result(
        spec,
        ctx,
        status=VerificationStatus.FAILED if failed else VerificationStatus.PASSED,
        summary=(
            f"visual differences at {', '.join(failed)}"
            if failed
            else f"all {len(reports)} viewport(s) within threshold {threshold}"
        ),
        output_excerpt="\n".join(excerpt_parts)[:4000],
    )
