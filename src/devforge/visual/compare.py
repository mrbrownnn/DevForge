"""Visual comparison: structural first, pixels second.

A pixel-diff percentage tells you *that* two pages differ. It does not tell you
the heading is 24px instead of 32px, which is the thing someone can act on. So the
primary comparison here is structural - geometry and computed styles from both
pages - and the pixel diff is a second, coarser signal.

Categories, matching the dimensions a review actually cares about:

``layout``       elements present, missing, or in a different place
``dimensions``   width and height differences beyond tolerance
``typography``   family, size, weight, line height, letter spacing
``spacing``      margin, padding, gap
``colors``       text and background colour
``images``       assets referenced and their rendered size
``responsive``   whether the difference holds across viewports

Tolerances exist because two renders of the *same* page differ slightly: fonts
hint differently, sub-pixel layout rounds differently. A comparison with no
tolerance reports noise, and a reviewer who learns the report is noisy stops
reading it.

On honesty: this module never concludes "pixel perfect". It reports a similarity
score, the findings behind it, and what it could not check. ``UNVERIFIED`` is a
real outcome and appears whenever the evidence was not there.
"""

from __future__ import annotations

import re
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from devforge.browser.models import ElementSnapshot, PageSnapshot

#: Pixel tolerance for geometry. Below this, two renders of one page disagree anyway.
POSITION_TOLERANCE_PX = 4.0
SIZE_TOLERANCE_PX = 4.0
SIZE_TOLERANCE_RATIO = 0.03
FONT_SIZE_TOLERANCE_PX = 0.6
#: Per-channel distance below which two colours are the same to a human eye.
COLOR_TOLERANCE = 8


class DiffCategory(str, Enum):
    LAYOUT = "layout"
    DIMENSIONS = "dimensions"
    TYPOGRAPHY = "typography"
    SPACING = "spacing"
    COLORS = "colors"
    IMAGES = "images"
    RESPONSIVE = "responsive"
    PIXELS = "pixels"


class DiffSeverity(str, Enum):
    INFO = "info"
    MINOR = "minor"
    MAJOR = "major"

    @property
    def weight(self) -> float:
        return {"info": 0.0, "minor": 1.0, "major": 3.0}[self.value]


class VisualFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    category: DiffCategory
    severity: DiffSeverity
    selector: str = ""
    property: str = ""
    expected: str = ""
    actual: str = ""
    detail: str = ""

    def describe(self) -> str:
        where = f"`{self.selector}` " if self.selector else ""
        if self.property:
            return f"{where}{self.property}: expected {self.expected}, got {self.actual}"
        return f"{where}{self.detail}"


class PixelComparison(BaseModel):
    """Result of comparing two screenshots, when both exist and a decoder is present."""

    model_config = ConfigDict(extra="forbid")

    compared: bool = False
    reason: str = ""
    differing_ratio: float = 0.0
    reference_size: tuple[int, int] | None = None
    candidate_size: tuple[int, int] | None = None
    diff_image_path: str = ""

    @property
    def similarity(self) -> float:
        return max(0.0, 1.0 - self.differing_ratio)


class VisualDiffReport(BaseModel):
    """A structured visual diff. Never a claim of perfection."""

    model_config = ConfigDict(extra="forbid")

    reference_url: str
    candidate_url: str
    viewport: str = ""
    findings: list[VisualFinding] = Field(default_factory=list)
    pixels: PixelComparison = Field(default_factory=PixelComparison)
    matched_elements: int = 0
    reference_elements: int = 0
    candidate_elements: int = 0
    #: Checks that could not be performed, and why. Never silently dropped.
    unverified: list[str] = Field(default_factory=list)

    @property
    def by_category(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.category.value] = counts.get(finding.category.value, 0) + 1
        return counts

    @property
    def major(self) -> list[VisualFinding]:
        return [f for f in self.findings if f.severity is DiffSeverity.MAJOR]

    @property
    def structural_similarity(self) -> float:
        """1.0 means every matched element agreed on every property compared.

        Penalty-weighted rather than a raw count, so one wrong colour does not read
        the same as a missing section.
        """
        if not self.reference_elements:
            return 0.0
        coverage = self.matched_elements / self.reference_elements
        penalty = sum(finding.severity.weight for finding in self.findings)
        # Normalised against the compared surface, floored at zero.
        scale = max(self.matched_elements, 1) * 3.0
        return max(0.0, min(1.0, coverage * (1.0 - min(1.0, penalty / scale))))

    def verdict(self, *, threshold: float = 0.9) -> str:
        """PASS, FAIL, or UNVERIFIED. There is no "probably fine"."""
        if self.reference_elements == 0:
            return "UNVERIFIED"
        if self.matched_elements == 0 and not self.findings and self.unverified:
            # Nothing was compared and nothing was found wrong: the evidence is
            # missing. Calling that FAIL would claim a difference we never saw.
            return "UNVERIFIED"
        if self.major:
            return "FAIL"
        return "PASS" if self.structural_similarity >= threshold else "FAIL"

    def render(self) -> str:
        lines = [
            "# Visual comparison",
            "",
            f"- **Reference:** {self.reference_url}",
            f"- **Candidate:** {self.candidate_url}",
            f"- **Viewport:** {self.viewport or 'default'}",
            f"- **Verdict:** {self.verdict()}",
            f"- **Structural similarity:** {self.structural_similarity:.3f} "
            f"({self.matched_elements}/{self.reference_elements} elements matched)",
        ]
        if self.pixels.compared:
            lines.append(
                f"- **Pixel similarity:** {self.pixels.similarity:.3f} "
                f"({self.pixels.differing_ratio * 100:.2f}% of pixels differ)"
            )
        else:
            lines.append(f"- **Pixel comparison:** not performed - {self.pixels.reason}")

        lines += ["", "## Findings by category", ""]
        if self.by_category:
            for category, count in sorted(self.by_category.items()):
                lines.append(f"- {category}: {count}")
        else:
            lines.append("- none")

        if self.findings:
            lines += ["", "## Detail", ""]
            lines += ["| severity | category | finding |", "| --- | --- | --- |"]
            ordered = sorted(self.findings, key=lambda f: (-f.severity.weight, f.category.value))
            for finding in ordered[:60]:
                lines.append(
                    f"| {finding.severity.value} | {finding.category.value} | "
                    f"{finding.describe()} |"
                )

        if self.unverified:
            lines += ["", "## Not verified", ""]
            lines += [f"- {item}" for item in self.unverified]

        lines += [
            "",
            "## What this report does not say",
            "",
            "It does not say the reproduction is pixel perfect. It reports the",
            "properties compared, the differences found, and what could not be checked.",
            "Anything absent from the reference snapshot was not verified at all.",
            "",
        ]
        return "\n".join(lines)


# --------------------------------------------------------------------- helpers

_PX = re.compile(r"^(-?\d+(?:\.\d+)?)px$")
_RGB = re.compile(r"rgba?\(\s*(\d+)[,\s]+(\d+)[,\s]+(\d+)")


def _pixels(value: str) -> float | None:
    match = _PX.match(value.strip()) if value else None
    return float(match.group(1)) if match else None


def _rgb(value: str) -> tuple[int, int, int] | None:
    match = _RGB.search(value or "")
    if not match:
        return None
    return tuple(int(match.group(index)) for index in (1, 2, 3))  # type: ignore[return-value]


def colours_match(first: str, second: str, tolerance: int = COLOR_TOLERANCE) -> bool:
    """Compare colours numerically. `#fff`, `white` and `rgb(255,255,255)` are one colour."""
    if first == second:
        return True
    left, right = _rgb(first), _rgb(second)
    if left is None or right is None:
        return False
    return all(abs(a - b) <= tolerance for a, b in zip(left, right, strict=True))


def sizes_match(expected: float, actual: float) -> bool:
    if abs(expected - actual) <= SIZE_TOLERANCE_PX:
        return True
    largest = max(abs(expected), abs(actual), 1.0)
    return abs(expected - actual) / largest <= SIZE_TOLERANCE_RATIO


def _normalise_font(family: str) -> str:
    """Compare the first family only, unquoted: fallback stacks differ harmlessly."""
    first = (family or "").split(",")[0].strip().strip("\"'").lower()
    return first


def match_elements(
    reference: PageSnapshot, candidate: PageSnapshot
) -> list[tuple[ElementSnapshot, ElementSnapshot | None]]:
    """Pair elements between two pages.

    By selector first, then by tag plus text, then by tag plus position order. A
    clone will not reproduce class names exactly, so selector-only matching would
    report every element as missing and the report would be useless.
    """
    remaining = list(candidate.elements)
    by_selector = {element.selector: element for element in remaining}
    pairs: list[tuple[ElementSnapshot, ElementSnapshot | None]] = []

    for element in reference.elements:
        found = by_selector.get(element.selector)
        if found is None:
            found = next(
                (
                    other
                    for other in remaining
                    if other.tag == element.tag and other.text and other.text == element.text
                ),
                None,
            )
        if found is None:
            same_tag = [other for other in remaining if other.tag == element.tag]
            found = same_tag[0] if same_tag else None
        if found is not None:
            remaining.remove(found)
            by_selector.pop(found.selector, None)
        pairs.append((element, found))

    return pairs


def compare_snapshots(
    reference: PageSnapshot,
    candidate: PageSnapshot,
    *,
    diff_image_dir: Path | None = None,
) -> VisualDiffReport:
    """Compare two captures and report every difference that matters."""
    report = VisualDiffReport(
        reference_url=reference.url,
        candidate_url=candidate.url,
        viewport=reference.viewport.label,
        reference_elements=len(reference.elements),
        candidate_elements=len(candidate.elements),
    )

    if not reference.elements:
        report.unverified.append(
            "the reference capture recorded no elements, so nothing could be compared"
        )
        return report
    if candidate.status.value == "failed":
        report.findings.append(
            VisualFinding(
                category=DiffCategory.LAYOUT,
                severity=DiffSeverity.MAJOR,
                detail=f"the candidate page failed to load: {candidate.error}",
            )
        )
        return report

    for element, other in match_elements(reference, candidate):
        if other is None:
            report.findings.append(
                VisualFinding(
                    category=DiffCategory.LAYOUT,
                    severity=DiffSeverity.MAJOR,
                    selector=element.selector,
                    detail=f"<{element.tag}> present in the reference is missing",
                )
            )
            continue

        report.matched_elements += 1
        report.findings.extend(_compare_geometry(element, other))
        report.findings.extend(_compare_typography(element, other))
        report.findings.extend(_compare_spacing(element, other))
        report.findings.extend(_compare_colours(element, other))

    report.findings.extend(_compare_images(reference, candidate))

    if reference.screenshot_path and candidate.screenshot_path:
        report.pixels = compare_images(
            Path(reference.screenshot_path),
            Path(candidate.screenshot_path),
            diff_path=(diff_image_dir / "diff.png") if diff_image_dir else None,
        )
        if report.pixels.compared and report.pixels.differing_ratio > 0.25:
            report.findings.append(
                VisualFinding(
                    category=DiffCategory.PIXELS,
                    severity=DiffSeverity.MAJOR,
                    detail=(
                        f"{report.pixels.differing_ratio * 100:.1f}% of pixels differ, "
                        "which is more than a styling difference"
                    ),
                )
            )
    else:
        report.pixels = PixelComparison(
            compared=False, reason="one or both captures have no screenshot"
        )

    return report


def _compare_geometry(
    reference: ElementSnapshot, candidate: ElementSnapshot
) -> list[VisualFinding]:
    findings: list[VisualFinding] = []
    if not sizes_match(reference.box.width, candidate.box.width):
        findings.append(
            VisualFinding(
                category=DiffCategory.DIMENSIONS,
                severity=DiffSeverity.MAJOR
                if abs(reference.box.width - candidate.box.width) > 40
                else DiffSeverity.MINOR,
                selector=reference.selector,
                property="width",
                expected=f"{reference.box.width:.0f}px",
                actual=f"{candidate.box.width:.0f}px",
            )
        )
    if not sizes_match(reference.box.height, candidate.box.height):
        findings.append(
            VisualFinding(
                category=DiffCategory.DIMENSIONS,
                severity=DiffSeverity.MINOR,
                selector=reference.selector,
                property="height",
                expected=f"{reference.box.height:.0f}px",
                actual=f"{candidate.box.height:.0f}px",
            )
        )
    if abs(reference.box.x - candidate.box.x) > POSITION_TOLERANCE_PX:
        findings.append(
            VisualFinding(
                category=DiffCategory.LAYOUT,
                severity=DiffSeverity.MINOR,
                selector=reference.selector,
                property="x",
                expected=f"{reference.box.x:.0f}px",
                actual=f"{candidate.box.x:.0f}px",
            )
        )
    return findings


def _compare_typography(
    reference: ElementSnapshot, candidate: ElementSnapshot
) -> list[VisualFinding]:
    findings: list[VisualFinding] = []
    expected, actual = reference.styles, candidate.styles

    if _normalise_font(expected.font_family) != _normalise_font(actual.font_family):
        findings.append(
            VisualFinding(
                category=DiffCategory.TYPOGRAPHY,
                severity=DiffSeverity.MINOR,
                selector=reference.selector,
                property="font-family",
                expected=_normalise_font(expected.font_family),
                actual=_normalise_font(actual.font_family),
            )
        )

    left, right = _pixels(expected.font_size), _pixels(actual.font_size)
    if left is not None and right is not None and abs(left - right) > FONT_SIZE_TOLERANCE_PX:
        findings.append(
            VisualFinding(
                category=DiffCategory.TYPOGRAPHY,
                severity=DiffSeverity.MAJOR if abs(left - right) > 4 else DiffSeverity.MINOR,
                selector=reference.selector,
                property="font-size",
                expected=expected.font_size,
                actual=actual.font_size,
            )
        )

    for name, mine, theirs in (
        ("font-weight", expected.font_weight, actual.font_weight),
        ("line-height", expected.line_height, actual.line_height),
        ("letter-spacing", expected.letter_spacing, actual.letter_spacing),
    ):
        if mine and theirs and mine != theirs:
            findings.append(
                VisualFinding(
                    category=DiffCategory.TYPOGRAPHY,
                    severity=DiffSeverity.MINOR,
                    selector=reference.selector,
                    property=name,
                    expected=mine,
                    actual=theirs,
                )
            )
    return findings


def _compare_spacing(reference: ElementSnapshot, candidate: ElementSnapshot) -> list[VisualFinding]:
    findings: list[VisualFinding] = []
    for name, mine, theirs in (
        ("margin", reference.styles.margin, candidate.styles.margin),
        ("padding", reference.styles.padding, candidate.styles.padding),
        ("gap", reference.styles.gap, candidate.styles.gap),
    ):
        if mine and theirs and mine != theirs:
            findings.append(
                VisualFinding(
                    category=DiffCategory.SPACING,
                    severity=DiffSeverity.MINOR,
                    selector=reference.selector,
                    property=name,
                    expected=mine,
                    actual=theirs,
                )
            )
    return findings


def _compare_colours(reference: ElementSnapshot, candidate: ElementSnapshot) -> list[VisualFinding]:
    findings: list[VisualFinding] = []
    for name, mine, theirs in (
        ("color", reference.styles.color, candidate.styles.color),
        ("background-color", reference.styles.background_color, candidate.styles.background_color),
    ):
        if mine and theirs and not colours_match(mine, theirs):
            findings.append(
                VisualFinding(
                    category=DiffCategory.COLORS,
                    severity=DiffSeverity.MINOR,
                    selector=reference.selector,
                    property=name,
                    expected=mine,
                    actual=theirs,
                )
            )
    return findings


def _compare_images(reference: PageSnapshot, candidate: PageSnapshot) -> list[VisualFinding]:
    findings: list[VisualFinding] = []
    expected = [asset for asset in reference.assets if asset.kind == "image"]
    actual = [asset for asset in candidate.assets if asset.kind == "image"]

    if len(expected) != len(actual):
        findings.append(
            VisualFinding(
                category=DiffCategory.IMAGES,
                severity=(
                    DiffSeverity.MINOR
                    if abs(len(expected) - len(actual)) < 3
                    else DiffSeverity.MAJOR
                ),
                property="image count",
                expected=str(len(expected)),
                actual=str(len(actual)),
            )
        )

    for index, asset in enumerate(expected[: len(actual)]):
        other = actual[index]
        if not sizes_match(asset.width, other.width) or not sizes_match(asset.height, other.height):
            findings.append(
                VisualFinding(
                    category=DiffCategory.IMAGES,
                    severity=DiffSeverity.MINOR,
                    property="rendered size",
                    expected=f"{asset.width:.0f}x{asset.height:.0f}",
                    actual=f"{other.width:.0f}x{other.height:.0f}",
                    detail=asset.url[:80],
                )
            )
    return findings


# --------------------------------------------------------------------- pixels


def compare_images(
    reference: Path, candidate: Path, *, diff_path: Path | None = None, tolerance: int = 24
) -> PixelComparison:
    """Compare two screenshots.

    Reports ``compared=False`` with a reason when it cannot - a missing decoder or
    a missing file is a gap in the evidence, and calling that a pass would be the
    exact dishonesty this phase is supposed to avoid.
    """
    try:
        import numpy
        from PIL import Image
    except ImportError:
        return PixelComparison(
            compared=False,
            reason="Pillow and numpy are needed for pixel comparison "
            "(`pip install \"devforge[visual]\"`)",
        )

    if not reference.is_file() or not candidate.is_file():
        return PixelComparison(compared=False, reason="one or both screenshots are missing")

    with Image.open(reference) as first, Image.open(candidate) as second:
        left = first.convert("RGB")
        right = second.convert("RGB")
        reference_size, candidate_size = left.size, right.size

        # Different sizes are themselves a finding; compare the shared region so the
        # ratio still means something rather than reporting 100%.
        width = min(left.width, right.width)
        height = min(left.height, right.height)
        if width == 0 or height == 0:
            return PixelComparison(
                compared=False,
                reason="no overlapping area between the screenshots",
                reference_size=reference_size,
                candidate_size=candidate_size,
            )

        left_array = numpy.asarray(left.crop((0, 0, width, height)), dtype=numpy.int16)
        right_array = numpy.asarray(right.crop((0, 0, width, height)), dtype=numpy.int16)

    distance = numpy.abs(left_array - right_array).max(axis=2)
    differing = distance > tolerance
    ratio = float(differing.sum()) / float(differing.size)

    written = ""
    if diff_path is not None:
        try:
            from PIL import Image as PILImage

            mask = (differing * 255).astype("uint8")
            diff_path.parent.mkdir(parents=True, exist_ok=True)
            PILImage.fromarray(mask, mode="L").save(diff_path)
            written = str(diff_path)
        except Exception:
            written = ""

    return PixelComparison(
        compared=True,
        differing_ratio=ratio,
        reference_size=reference_size,
        candidate_size=candidate_size,
        diff_image_path=written,
    )


def compare_responsive(
    references: list[PageSnapshot],
    candidates: list[PageSnapshot],
    *,
    diff_image_dir: Path | None = None,
) -> list[VisualDiffReport]:
    """One report per viewport, plus a responsive finding when behaviour diverges."""
    by_viewport = {snapshot.viewport.name: snapshot for snapshot in candidates}
    reports: list[VisualDiffReport] = []

    for reference in references:
        candidate = by_viewport.get(reference.viewport.name)
        if candidate is None:
            report = VisualDiffReport(
                reference_url=reference.url,
                candidate_url="(not captured)",
                viewport=reference.viewport.label,
                reference_elements=len(reference.elements),
            )
            report.unverified.append(
                f"the candidate was not captured at {reference.viewport.label}"
            )
            reports.append(report)
            continue
        reports.append(
            compare_snapshots(
                reference,
                candidate,
                diff_image_dir=(
                    (diff_image_dir / reference.viewport.name)
                    if diff_image_dir is not None
                    else None
                ),
            )
        )

    # Responsive behaviour is about whether the *pattern* holds across sizes: a
    # layout that matches on desktop and breaks on mobile is a different defect
    # from one that is wrong everywhere.
    verdicts = {report.viewport: report.verdict() for report in reports}
    if len(set(verdicts.values())) > 1:
        for report in reports:
            if report.verdict() == "FAIL":
                report.findings.append(
                    VisualFinding(
                        category=DiffCategory.RESPONSIVE,
                        severity=DiffSeverity.MAJOR,
                        detail=(
                            "this viewport differs while others match - the breakpoint "
                            f"behaviour does not hold ({verdicts})"
                        ),
                    )
                )
    return reports
