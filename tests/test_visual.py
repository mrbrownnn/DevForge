"""Visual comparison and the visual verifier.

The comparison tests are deterministic and need no browser: they build snapshots
directly, which is how the tolerance and severity rules can be pinned down exactly.
The end-to-end clone tests do drive a real browser against a real (loopback-only)
site, and skip when Playwright or its chromium build is absent - a skip is honest,
a mocked browser proving visual verification works would not be.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from devforge.browser.models import (
    DEFAULT_VIEWPORTS,
    AssetRef,
    BoxModel,
    CaptureStatus,
    ElementSnapshot,
    ElementStyles,
    PageSnapshot,
    Viewport,
)
from devforge.core.models import VerificationStatus
from devforge.core.state.store import ProjectStore
from devforge.core.workflow.loader import load_workflow_file
from devforge.core.workflow.spec import VerifierSpec
from devforge.policy.engine import PolicyEngine
from devforge.verification.base import VerificationContext
from devforge.verification.visual import VisualVerifier
from devforge.visual.compare import (
    DiffCategory,
    DiffSeverity,
    colours_match,
    compare_responsive,
    compare_snapshots,
    match_elements,
    sizes_match,
)
from devforge.visual.serve import static_site

DESKTOP = DEFAULT_VIEWPORTS[-1]

REFERENCE_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><title>Acme</title><style>
 body { margin:0; font-family: Georgia, serif; background:#ffffff; color:#111111; }
 header { height:80px; background:#0b5fff; color:#ffffff; display:flex;
          align-items:center; padding:0 24px; }
 h1 { font-size:32px; margin:0; }
 main { padding:24px; }
 p { font-size:16px; line-height:24px; }
</style></head>
<body><header><h1>Acme</h1></header><main><p>Hello world</p></main></body></html>
"""

#: Same document with a smaller heading and a different brand colour. Both are the
#: kind of mistake a reproduction actually makes.
WRONG_HTML = REFERENCE_HTML.replace("font-size:32px", "font-size:18px").replace(
    "#0b5fff", "#ff0000"
)


# --------------------------------------------------------------- snapshot builders


def element(selector: str, tag: str = "div", **overrides) -> ElementSnapshot:
    box = BoxModel(**overrides.pop("box", {"x": 0, "y": 0, "width": 100, "height": 40}))
    styles = ElementStyles(**overrides.pop("styles", {}))
    return ElementSnapshot(selector=selector, tag=tag, box=box, styles=styles, **overrides)


def snapshot(*elements: ElementSnapshot, url: str = "http://example.test/", **kwargs):
    return PageSnapshot(url=url, viewport=DESKTOP, elements=list(elements), **kwargs)


# ---------------------------------------------------------------------- primitives


@pytest.mark.parametrize(
    ("first", "second", "expected"),
    [
        ("rgb(255, 255, 255)", "rgb(255, 255, 255)", True),
        ("rgb(255, 255, 255)", "rgb(250, 252, 255)", True),  # within tolerance
        ("rgb(0, 0, 0)", "rgb(255, 255, 255)", False),
        ("rgba(11, 95, 255, 1)", "rgb(11, 95, 255)", True),  # alpha notation only
        ("white", "rgb(255, 255, 255)", False),  # unparseable keyword: not guessed
    ],
)
def test_colours_match_numerically(first: str, second: str, expected: bool) -> None:
    assert colours_match(first, second) is expected


def test_sizes_match_absorbs_subpixel_noise_but_not_real_differences() -> None:
    assert sizes_match(100.0, 102.0), "2px is render noise, not a design difference"
    assert sizes_match(1000.0, 1020.0), "2% of a large element is within ratio tolerance"
    assert not sizes_match(100.0, 140.0)


def test_match_elements_pairs_by_text_when_class_names_differ() -> None:
    """A clone reproduces the design, not the class names."""
    reference = snapshot(element("header > h1.brand", tag="h1", text="Acme"))
    candidate = snapshot(element("header > h1.site-title", tag="h1", text="Acme"))

    pairs = match_elements(reference, candidate)

    assert len(pairs) == 1
    _, matched = pairs[0]
    assert matched is not None and matched.selector == "header > h1.site-title"


# ------------------------------------------------------------------- comparison


def test_identical_snapshots_report_no_findings() -> None:
    page = snapshot(
        element("h1", tag="h1", text="Acme", styles={"font_size": "32px", "color": "rgb(0,0,0)"})
    )
    report = compare_snapshots(page, page.model_copy(deep=True))

    assert report.findings == []
    assert report.structural_similarity == 1.0
    assert report.verdict() == "PASS"


def test_font_size_difference_is_major_and_fails() -> None:
    reference = snapshot(element("h1", tag="h1", text="Acme", styles={"font_size": "32px"}))
    candidate = snapshot(element("h1", tag="h1", text="Acme", styles={"font_size": "18px"}))

    report = compare_snapshots(reference, candidate)

    typography = [f for f in report.findings if f.category is DiffCategory.TYPOGRAPHY]
    assert [f.severity for f in typography] == [DiffSeverity.MAJOR]
    assert report.verdict() == "FAIL", "a major finding fails regardless of the score"


def test_missing_element_is_a_major_layout_finding() -> None:
    reference = snapshot(
        element("header", tag="header", text="Acme"),
        element("footer", tag="footer", text="(c) Acme"),
    )
    candidate = snapshot(element("header", tag="header", text="Acme"))

    report = compare_snapshots(reference, candidate)

    layout = [f for f in report.findings if f.category is DiffCategory.LAYOUT]
    assert len(layout) == 1
    assert layout[0].severity is DiffSeverity.MAJOR
    assert "missing" in layout[0].detail


def test_spacing_and_colour_differences_are_reported_separately() -> None:
    reference = snapshot(
        element("main", styles={"padding": "24px", "background_color": "rgb(255, 255, 255)"})
    )
    candidate = snapshot(
        element("main", styles={"padding": "8px", "background_color": "rgb(0, 0, 0)"})
    )

    categories = {f.category for f in compare_snapshots(reference, candidate).findings}

    assert DiffCategory.SPACING in categories
    assert DiffCategory.COLORS in categories


def test_image_inventory_difference_is_reported() -> None:
    reference = snapshot(
        element("img", tag="img"),
        assets=[AssetRef(kind="image", url="http://a/1.png", width=100, height=100)],
    )
    candidate = snapshot(element("img", tag="img"))

    images = [
        f
        for f in compare_snapshots(reference, candidate).findings
        if f.category is DiffCategory.IMAGES
    ]
    assert images and images[0].property == "image count"


def test_empty_reference_is_unverified_not_passed() -> None:
    """The whole point: no evidence is never a pass."""
    report = compare_snapshots(snapshot(), snapshot(element("h1", tag="h1")))

    assert report.verdict() == "UNVERIFIED"
    assert report.unverified


def test_failed_candidate_capture_is_a_major_finding() -> None:
    reference = snapshot(element("h1", tag="h1"))
    candidate = PageSnapshot(
        url="http://example.test/",
        viewport=DESKTOP,
        status=CaptureStatus.FAILED,
        error="net::ERR_CONNECTION_REFUSED",
    )

    report = compare_snapshots(reference, candidate)

    assert report.verdict() == "FAIL"
    assert "failed to load" in report.findings[0].detail


def test_report_never_claims_pixel_perfection() -> None:
    text = compare_snapshots(
        snapshot(element("h1", tag="h1")), snapshot(element("h1", tag="h1"))
    ).render()

    assert "does not say the reproduction is pixel perfect" in text
    assert "not performed" in text, "no screenshots means the pixel gap is stated, not hidden"


def test_pixel_comparison_is_not_attempted_without_screenshots() -> None:
    report = compare_snapshots(snapshot(element("h1", tag="h1")), snapshot(element("h1", tag="h1")))

    assert report.pixels.compared is False
    assert report.pixels.reason


def test_responsive_divergence_is_called_out() -> None:
    mobile = Viewport(name="mobile", width=390, height=844)
    good = ElementSnapshot(selector="h1", tag="h1", styles=ElementStyles(font_size="32px"))
    bad = ElementSnapshot(selector="h1", tag="h1", styles=ElementStyles(font_size="12px"))

    references = [
        PageSnapshot(url="http://a/", viewport=mobile, elements=[good]),
        PageSnapshot(url="http://a/", viewport=DESKTOP, elements=[good]),
    ]
    candidates = [
        PageSnapshot(url="http://b/", viewport=mobile, elements=[bad]),
        PageSnapshot(url="http://b/", viewport=DESKTOP, elements=[good]),
    ]

    reports = compare_responsive(references, candidates)
    responsive = [
        f
        for report in reports
        for f in report.findings
        if f.category is DiffCategory.RESPONSIVE
    ]
    assert responsive, "one breakpoint failing while another passes is itself a finding"


def test_missing_candidate_viewport_is_unverified() -> None:
    references = [PageSnapshot(url="http://a/", viewport=DESKTOP, elements=[element("h1", "h1")])]

    reports = compare_responsive(references, [])

    assert reports[0].verdict() == "UNVERIFIED"
    assert reports[0].unverified


# ------------------------------------------------------------------ static server


def test_static_site_serves_only_loopback_and_stops_afterwards(tmp_path: Path) -> None:
    import urllib.request

    (tmp_path / "index.html").write_text("<h1>hi</h1>", encoding="utf-8")

    with static_site(tmp_path) as url:
        assert url.startswith("http://127.0.0.1:")
        with urllib.request.urlopen(f"{url}/index.html", timeout=5) as response:
            assert b"hi" in response.read()

    with pytest.raises(OSError):
        urllib.request.urlopen(f"{url}/index.html", timeout=2)


def test_static_site_refuses_a_non_directory(tmp_path: Path) -> None:
    target = tmp_path / "index.html"
    target.write_text("x", encoding="utf-8")

    with pytest.raises(NotADirectoryError), static_site(target):
        pass


# ---------------------------------------------------------------- the verifier


@pytest.fixture()
def context(project: ProjectStore) -> VerificationContext:
    return VerificationContext(
        workspace=project.root,
        policy=PolicyEngine.load(None, workspace=project.root),
        step_id="visual-verification",
    )


async def test_verifier_is_unavailable_without_configuration(context: VerificationContext) -> None:
    spec = VerifierSpec(id="visual", kind="visual", required=True)

    result = await VisualVerifier().run(spec, context)

    assert result.status is VerificationStatus.UNAVAILABLE
    assert "params.reference" in result.output_excerpt


async def test_verifier_refuses_a_reference_the_network_policy_blocks(
    context: VerificationContext,
) -> None:
    """A verifier is not a licence to reach somewhere a tool could not."""
    spec = VerifierSpec(
        id="visual",
        kind="visual",
        required=True,
        params={"reference": "http://169.254.169.254/latest/meta-data/", "serve": "site"},
    )

    result = await VisualVerifier().run(spec, context)

    assert result.status is VerificationStatus.UNAVAILABLE
    assert "network policy" in result.output_excerpt


async def test_verifier_refuses_to_serve_outside_the_workspace(
    context: VerificationContext,
) -> None:
    spec = VerifierSpec(
        id="visual",
        kind="visual",
        required=True,
        params={"reference": "http://127.0.0.1:1/", "serve": "../../secrets"},
    )
    context.policy.permissions.network.enabled = True
    context.policy.permissions.network.allow_loopback = True

    result = await VisualVerifier().run(spec, context)

    assert result.status is VerificationStatus.UNAVAILABLE
    assert "inside the workspace" in result.output_excerpt


async def test_verifier_reports_a_missing_build_directory(context: VerificationContext) -> None:
    spec = VerifierSpec(
        id="visual",
        kind="visual",
        required=True,
        params={"reference": "http://127.0.0.1:1/", "serve": "site"},
    )
    context.policy.permissions.network.enabled = True
    context.policy.permissions.network.allow_loopback = True

    result = await VisualVerifier().run(spec, context)

    assert result.status is VerificationStatus.UNAVAILABLE
    assert "does not exist in the workspace" in result.output_excerpt


def test_unavailable_visual_verifier_blocks_a_required_step(context: VerificationContext) -> None:
    """UNAVAILABLE must not read as success for a required check."""
    from devforge.core.models import VerificationResult

    result = VerificationResult(
        verifier="visual", kind="visual", required=True, status=VerificationStatus.UNAVAILABLE
    )
    assert result.blocking_failure


# ------------------------------------------------------------- the clone workflow


def test_clone_workflow_is_a_real_loop() -> None:
    from devforge.core.workflow.loader import builtin_workflow_dir

    spec = load_workflow_file(builtin_workflow_dir() / "clone.yaml")

    visual = next(v for v in spec.verifiers if v.id == "visual")
    assert visual.required, "an unverified clone must not be able to pass"
    assert visual.params["serve"] == "site"
    assert len(visual.params["viewports"]) >= 3, "responsive behaviour needs several viewports"

    refinement = spec.step("visual-refinement")
    assert refinement is not None and refinement.repairable
    assert "visual" in refinement.verify
    assert refinement.max_attempts >= 2, "the repair loop needs more than one attempt"
    assert "incomplete" not in spec.tags


# ----------------------------------------------------- end to end, real browser

playwright = pytest.importorskip("playwright", reason="devforge[browser] is not installed")


async def _capture_pair(reference_dir: Path, candidate_dir: Path, shots: Path):
    from devforge.browser.capture import capture_responsive
    from devforge.browser.session import SessionPolicy
    from devforge.policy.models import NetworkPolicy

    policy = SessionPolicy(network=NetworkPolicy(enabled=True), allow_loopback=True)
    viewports = [DESKTOP]
    with static_site(reference_dir) as reference_url, static_site(candidate_dir) as candidate_url:
        reference = await capture_responsive(
            policy, reference_url, viewports, screenshot_dir=shots / "reference"
        )
        candidate = await capture_responsive(
            policy, candidate_url, viewports, screenshot_dir=shots / "candidate"
        )
    return reference, candidate


def _write_site(root: Path, html: str) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "index.html").write_text(html, encoding="utf-8")
    return root


@pytest.fixture()
def chromium_or_skip():
    """Skip rather than fail when only the driver, not the browser, is installed."""
    import asyncio

    from devforge.browser.models import Viewport as _Viewport
    from devforge.browser.session import BrowserSession, BrowserUnavailable, SessionPolicy
    from devforge.policy.models import NetworkPolicy

    async def probe() -> None:
        session = BrowserSession(policy=SessionPolicy(network=NetworkPolicy(enabled=True)))
        await session.start(_Viewport(name="desktop", width=800, height=600))
        await session.close()

    try:
        asyncio.run(probe())
    except BrowserUnavailable as exc:
        pytest.skip(f"chromium is not installed: {exc}")


async def test_clone_of_itself_passes_visual_verification(tmp_path: Path, chromium_or_skip) -> None:
    """The DONE criterion: a real render of a real site, compared objectively."""
    reference = _write_site(tmp_path / "reference", REFERENCE_HTML)
    candidate = _write_site(tmp_path / "candidate", REFERENCE_HTML)

    references, candidates = await _capture_pair(reference, candidate, tmp_path / "shots")
    report = compare_responsive(references, candidates)[0]

    assert references[0].status is CaptureStatus.OK
    assert references[0].elements, "the reference capture must contain real elements"
    assert report.verdict() == "PASS"
    assert report.pixels.compared, "screenshots existed, so the pixel check must have run"


async def test_wrong_reproduction_fails_with_actionable_findings(
    tmp_path: Path, chromium_or_skip
) -> None:
    reference = _write_site(tmp_path / "reference", REFERENCE_HTML)
    candidate = _write_site(tmp_path / "candidate", WRONG_HTML)

    references, candidates = await _capture_pair(reference, candidate, tmp_path / "shots")
    report = compare_responsive(references, candidates)[0]

    assert report.verdict() == "FAIL"
    properties = {f.property for f in report.findings}
    assert "font-size" in properties
    assert "background-color" in properties
    assert "expected 32px, got 18px" in report.render()


async def test_visual_verifier_end_to_end_serves_the_build_itself(
    project: ProjectStore, tmp_path: Path, chromium_or_skip
) -> None:
    """`serve:` closes the loop: no dev server, no hardcoded port, real comparison."""
    _write_site(project.root / "site", REFERENCE_HTML)
    origin = _write_site(tmp_path / "origin", REFERENCE_HTML)

    policy = PolicyEngine.load(None, workspace=project.root)
    policy.permissions.network.enabled = True
    policy.permissions.network.allow_loopback = True
    context = VerificationContext(workspace=project.root, policy=policy, step_id="s")

    with static_site(origin) as reference_url:
        spec = VerifierSpec(
            id="visual",
            kind="visual",
            required=True,
            params={
                "reference": reference_url,
                "serve": "site",
                "viewports": ["desktop"],
                "report": "site/VISUAL-REPORT.md",
            },
        )
        result = await VisualVerifier().run(spec, context)

    assert result.status is VerificationStatus.PASSED, result.output_excerpt
    written = (project.root / "site" / "VISUAL-REPORT.md").read_text(encoding="utf-8")
    assert "Structural similarity" in written
    assert "pixel perfect" in written, "the report keeps stating what it does not prove"
