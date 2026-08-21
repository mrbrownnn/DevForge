"""What a page capture records.

A snapshot is structured evidence about a page: element geometry, computed styles,
the assets it referenced, the requests it made, and a screenshot path. It is what
visual verification compares and what a cloning agent reads.

Page text is captured as *data*, never as instruction. Everything that came from
the page is fenced before it can reach a prompt (see
:mod:`devforge.tools.untrusted`), because a page is written by whoever controls
the site, not by the operator.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from devforge.core.models import utcnow


class Viewport(BaseModel):
    """A named viewport. Responsive comparison runs the same page at several."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    width: int
    height: int

    @property
    def label(self) -> str:
        return f"{self.name} ({self.width}x{self.height})"


DEFAULT_VIEWPORTS: tuple[Viewport, ...] = (
    Viewport(name="mobile", width=390, height=844),
    Viewport(name="tablet", width=768, height=1024),
    Viewport(name="desktop", width=1280, height=800),
)


class BoxModel(BaseModel):
    """Geometry, rounded to whole pixels.

    Sub-pixel values differ between runs on the same page for reasons that have
    nothing to do with the design, so comparing them would produce noise that
    looks like findings.
    """

    model_config = ConfigDict(extra="forbid")

    x: float = 0
    y: float = 0
    width: float = 0
    height: float = 0

    @property
    def area(self) -> float:
        return self.width * self.height


class ElementStyles(BaseModel):
    """The computed properties visual comparison actually judges."""

    model_config = ConfigDict(extra="forbid")

    display: str = ""
    position: str = ""
    color: str = ""
    background_color: str = ""
    font_family: str = ""
    font_size: str = ""
    font_weight: str = ""
    line_height: str = ""
    letter_spacing: str = ""
    margin: str = ""
    padding: str = ""
    border_radius: str = ""
    border: str = ""
    flex_direction: str = ""
    justify_content: str = ""
    align_items: str = ""
    gap: str = ""

    def differing(self, other: ElementStyles) -> dict[str, tuple[str, str]]:
        """Properties that differ, as ``{name: (expected, actual)}``."""
        changes: dict[str, tuple[str, str]] = {}
        for name in type(self).model_fields:
            mine = getattr(self, name)
            theirs = getattr(other, name)
            if mine != theirs:
                changes[name] = (mine, theirs)
        return changes


class ElementSnapshot(BaseModel):
    """One element, as rendered."""

    model_config = ConfigDict(extra="forbid")

    selector: str
    tag: str = ""
    #: Trimmed, capped. Enough to identify the element, not a copy of the page.
    text: str = ""
    box: BoxModel = Field(default_factory=BoxModel)
    styles: ElementStyles = Field(default_factory=ElementStyles)
    depth: int = 0
    classes: list[str] = Field(default_factory=list)

    @property
    def key(self) -> str:
        """How elements are matched between two pages: structural, not positional."""
        return f"{self.tag}#{self.depth}:{self.selector}"


class AssetRef(BaseModel):
    """An image, font or stylesheet the page referenced. URL only - nothing fetched."""

    model_config = ConfigDict(extra="forbid")

    kind: str
    url: str
    #: Present for images that were laid out.
    width: float = 0
    height: float = 0
    alt: str = ""


class NetworkEntry(BaseModel):
    """One request the page made.

    Recorded for reconnaissance and for the audit trail: which hosts a page tried
    to reach is exactly what an operator needs to see before trusting it. Bodies
    are never stored.
    """

    model_config = ConfigDict(extra="forbid")

    url: str
    method: str = "GET"
    resource_type: str = ""
    status: int | None = None
    blocked: bool = False
    blocked_reason: str = ""

    @property
    def host(self) -> str:
        from urllib.parse import urlsplit

        return urlsplit(self.url).hostname or ""


class CaptureStatus(str, Enum):
    OK = "ok"
    PARTIAL = "partial"
    FAILED = "failed"


class PageSnapshot(BaseModel):
    """Everything one capture recorded about one page at one viewport."""

    model_config = ConfigDict(extra="forbid")

    url: str
    viewport: Viewport
    status: CaptureStatus = CaptureStatus.OK
    http_status: int | None = None
    title: str = ""
    captured_at: datetime = Field(default_factory=utcnow)

    elements: list[ElementSnapshot] = Field(default_factory=list)
    assets: list[AssetRef] = Field(default_factory=list)
    network: list[NetworkEntry] = Field(default_factory=list)
    #: Colours actually painted, most frequent first.
    palette: list[str] = Field(default_factory=list)
    fonts: list[str] = Field(default_factory=list)

    screenshot_path: str = ""
    document_height: float = 0
    #: Visible text, bounded and fenced by the caller before any prompt use.
    text_excerpt: str = ""
    error: str = ""

    def element(self, selector: str) -> ElementSnapshot | None:
        return next((item for item in self.elements if item.selector == selector), None)

    @property
    def blocked_requests(self) -> list[NetworkEntry]:
        return [entry for entry in self.network if entry.blocked]

    @property
    def hosts(self) -> list[str]:
        return sorted({entry.host for entry in self.network if entry.host})

    def summary(self) -> str:
        return (
            f"{self.url} at {self.viewport.label}: {len(self.elements)} elements, "
            f"{len(self.assets)} assets, {len(self.network)} requests "
            f"({len(self.blocked_requests)} blocked)"
        )
