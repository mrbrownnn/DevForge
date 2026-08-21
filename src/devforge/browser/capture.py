"""Turning a rendered page into a snapshot.

One pass of JavaScript in the page collects geometry, computed styles, assets and
text for the elements that matter. Doing it in one evaluation rather than a call
per element is the difference between a capture that takes a second and one that
takes a minute on a real page.

Two deliberate limits:

* **Only laid-out, visible elements** are recorded, capped at a few hundred. A
  full DOM dump of a real site is tens of thousands of nodes, most of them
  wrappers, and comparing them produces noise rather than findings.
* **Text is trimmed and capped.** A snapshot identifies elements; it is not a copy
  of the page. What the caller does with the text goes through
  :func:`devforge.tools.untrusted.wrap` first.
"""

from __future__ import annotations

from pathlib import Path

from devforge.browser.models import (
    AssetRef,
    BoxModel,
    CaptureStatus,
    ElementSnapshot,
    ElementStyles,
    PageSnapshot,
    Viewport,
)
from devforge.browser.session import BrowserSession

#: Elements worth comparing: structure, typography and interactive surfaces.
CAPTURE_SELECTOR = (
    "header, nav, main, footer, section, article, aside, "
    "h1, h2, h3, h4, "
    "p, a, button, input, textarea, select, label, "
    "img, ul, ol, li, table, form, "
    "div[class], span[class]"
)

MAX_ELEMENTS = 400
MAX_TEXT_CHARS = 120
MAX_EXCERPT_CHARS = 20_000

# Collected in one round trip. Written defensively: a page can define hostile
# getters on prototypes, so nothing here trusts a property to behave.
COLLECT_SCRIPT = """
(args) => {
  const { selector, maxElements, maxText } = args;
  const out = { elements: [], assets: [], palette: {}, fonts: {} };

  const rgbaVisible = (value) => value && value !== 'rgba(0, 0, 0, 0)' && value !== 'transparent';
  const depthOf = (el) => {
    let d = 0, n = el;
    while (n.parentElement) { d++; n = n.parentElement; }
    return d;
  };

  const cssPath = (el) => {
    const parts = [];
    let node = el;
    while (node && node.nodeType === 1 && parts.length < 4) {
      let part = node.tagName.toLowerCase();
      if (node.id) { parts.unshift(part + '#' + node.id); break; }
      const cls = (node.className && typeof node.className === 'string')
        ? node.className.trim().split(/\\s+/).slice(0, 2).join('.') : '';
      if (cls) part += '.' + cls;
      const parent = node.parentElement;
      if (parent) {
        const siblings = Array.from(parent.children).filter((c) => c.tagName === node.tagName);
        if (siblings.length > 1) part += ':nth-of-type(' + (siblings.indexOf(node) + 1) + ')';
      }
      parts.unshift(part);
      node = node.parentElement;
    }
    return parts.join(' > ');
  };

  const nodes = Array.from(document.querySelectorAll(selector)).slice(0, maxElements * 3);
  for (const el of nodes) {
    if (out.elements.length >= maxElements) break;
    const rect = el.getBoundingClientRect();
    if (rect.width < 1 || rect.height < 1) continue;      // not laid out
    const cs = getComputedStyle(el);
    if (cs.visibility === 'hidden' || cs.display === 'none' || cs.opacity === '0') continue;

    out.elements.push({
      selector: cssPath(el),
      tag: el.tagName.toLowerCase(),
      text: (el.textContent || '').trim().replace(/\\s+/g, ' ').slice(0, maxText),
      depth: depthOf(el),
      classes: (el.className && typeof el.className === 'string')
        ? el.className.trim().split(/\\s+/).slice(0, 6) : [],
      box: {
        x: Math.round(rect.x + window.scrollX),
        y: Math.round(rect.y + window.scrollY),
        width: Math.round(rect.width),
        height: Math.round(rect.height),
      },
      styles: {
        display: cs.display, position: cs.position,
        color: cs.color, background_color: cs.backgroundColor,
        font_family: cs.fontFamily, font_size: cs.fontSize,
        font_weight: cs.fontWeight, line_height: cs.lineHeight,
        letter_spacing: cs.letterSpacing,
        margin: cs.margin, padding: cs.padding,
        border_radius: cs.borderRadius, border: cs.border,
        flex_direction: cs.flexDirection, justify_content: cs.justifyContent,
        align_items: cs.alignItems, gap: cs.gap,
      },
    });

    if (rgbaVisible(cs.backgroundColor)) {
      out.palette[cs.backgroundColor] = (out.palette[cs.backgroundColor] || 0) + 1;
    }
    if (rgbaVisible(cs.color)) {
      out.palette[cs.color] = (out.palette[cs.color] || 0) + 1;
    }
    if (cs.fontFamily) out.fonts[cs.fontFamily] = (out.fonts[cs.fontFamily] || 0) + 1;
  }

  for (const img of Array.from(document.images).slice(0, 60)) {
    const rect = img.getBoundingClientRect();
    out.assets.push({
      kind: 'image', url: (img.currentSrc || img.src || '').slice(0, 500),
      width: Math.round(rect.width), height: Math.round(rect.height),
      alt: (img.alt || '').slice(0, 120),
    });
  }
  for (const link of Array.from(document.querySelectorAll('link[rel=stylesheet]')).slice(0, 30)) {
    out.assets.push({
      kind: 'stylesheet', url: (link.href || '').slice(0, 500), width: 0, height: 0, alt: '',
    });
  }
  for (const script of Array.from(document.querySelectorAll('script[src]')).slice(0, 30)) {
    out.assets.push({
      kind: 'script', url: (script.src || '').slice(0, 500), width: 0, height: 0, alt: '',
    });
  }

  out.documentHeight = Math.max(
    document.body ? document.body.scrollHeight : 0,
    document.documentElement ? document.documentElement.scrollHeight : 0
  );
  out.title = document.title || '';
  out.text = (document.body ? document.body.innerText : '').slice(0, 20000);
  return out;
}
"""

MAX_INTERACTIONS = 20


async def replay_interactions(session, page, interactions: list[dict]) -> None:
    """Replay a closed vocabulary of interactions before capture.

    Click, type, scroll, wait - and nothing else. There is deliberately no "evaluate"
    step: accepting a JavaScript string from a caller (and therefore, one indirection
    later, from a page) would hand arbitrary execution to whatever wrote it.
    """
    for step in interactions[:MAX_INTERACTIONS]:
        kind = step.get("action")
        if kind == "click":
            await session.click(page, step["selector"])
        elif kind == "type":
            await session.type_text(page, step["selector"], str(step.get("text", "")))
        elif kind == "scroll":
            await session.scroll(
                page, to=step.get("to", "bottom"), pixels=int(step.get("pixels", 0))
            )
        elif kind == "wait":
            await page.wait_for_timeout(min(int(step.get("ms", 250)), 5_000))


async def capture_page(
    session: BrowserSession,
    url: str,
    viewport: Viewport,
    *,
    screenshot_path: Path | None = None,
    full_page: bool = True,
    scroll_first: bool = True,
    interactions: list[dict] | None = None,
) -> PageSnapshot:
    """Open a URL and record everything visual verification needs.

    ``interactions`` is an optional list of clicks, typing and scrolls replayed
    before capture, so a page behind a tab or a cookie banner can still be
    snapshotted. Each entry is a closed-vocabulary dict, never a script.
    """
    page, response = await session.open(url)
    try:
        await replay_interactions(session, page, interactions or [])

        if scroll_first:
            # Lazy-loaded content does not exist until something scrolls to it, and
            # a snapshot missing half the page produces confident, wrong diffs.
            await session.scroll(page, to="bottom")
            await session.scroll(page, to="top")

        raw = await page.evaluate(
            COLLECT_SCRIPT,
            {"selector": CAPTURE_SELECTOR, "maxElements": MAX_ELEMENTS, "maxText": MAX_TEXT_CHARS},
        )

        shot = ""
        if screenshot_path is not None:
            shot = str(await session.screenshot(page, screenshot_path, full_page=full_page))

        snapshot = _to_snapshot(url, viewport, raw, response, session, shot)
        session.logger.info(
            "browser.capture",
            url=url[:200],
            viewport=viewport.name,
            elements=len(snapshot.elements),
            assets=len(snapshot.assets),
            blocked_requests=len(snapshot.blocked_requests),
        )
        return snapshot
    except Exception as exc:
        return PageSnapshot(
            url=url,
            viewport=viewport,
            status=CaptureStatus.FAILED,
            error=f"{type(exc).__name__}: {exc}",
        )
    finally:
        await page.close()


def _to_snapshot(url, viewport, raw, response, session, screenshot) -> PageSnapshot:
    elements = [
        ElementSnapshot(
            selector=item["selector"],
            tag=item["tag"],
            text=item["text"],
            depth=item["depth"],
            classes=item.get("classes", []),
            box=BoxModel(**item["box"]),
            styles=ElementStyles(**item["styles"]),
        )
        for item in raw.get("elements", [])
    ]
    assets = [AssetRef(**item) for item in raw.get("assets", []) if item.get("url")]

    palette = [
        colour
        for colour, _ in sorted(
            raw.get("palette", {}).items(), key=lambda pair: -pair[1]
        )[:12]
    ]
    fonts = [
        family
        for family, _ in sorted(raw.get("fonts", {}).items(), key=lambda pair: -pair[1])[:6]
    ]

    return PageSnapshot(
        url=url,
        viewport=viewport,
        status=CaptureStatus.OK,
        http_status=response.status if response else None,
        title=str(raw.get("title", ""))[:200],
        elements=elements,
        assets=assets,
        network=list(session.network),
        console=list(session.console),
        palette=palette,
        fonts=fonts,
        screenshot_path=screenshot,
        document_height=float(raw.get("documentHeight", 0) or 0),
        text_excerpt=str(raw.get("text", ""))[:MAX_EXCERPT_CHARS],
    )


async def capture_responsive(
    policy,
    url: str,
    viewports,
    *,
    screenshot_dir: Path | None = None,
    logger=None,
) -> list[PageSnapshot]:
    """Capture the same page at several viewports.

    A separate session per viewport, so nothing carries between them - the second
    capture must not benefit from the first one's cache or cookies.
    """
    from devforge.browser.session import browser_session

    snapshots: list[PageSnapshot] = []
    for viewport in viewports:
        shot = (
            (screenshot_dir / f"{viewport.name}.png") if screenshot_dir is not None else None
        )
        async with browser_session(policy, viewport, logger=logger) as session:
            snapshots.append(await capture_page(session, url, viewport, screenshot_path=shot))
    return snapshots
