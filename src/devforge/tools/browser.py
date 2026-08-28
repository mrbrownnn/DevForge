"""Browser tool, backed by Playwright.

Phase 0 shipped this as a declared-unavailable adapter because DevForge had no
driver. Playwright is now an optional dependency (`pip install devforge[browser]`),
so the tool is real when the driver is installed and still reports ``unavailable``
- never a fabricated result - when it is not.

Every navigation is an SSRF primitive: the agent picks the URL and the request
carries this workstation's network position. Two gates apply, in this order:

1. The tool checks the URL the agent asked for against the network policy.
2. :class:`devforge.browser.session.BrowserSession` checks **every request the page
   then makes**, because a page controls its own subresources and a top-level check
   alone lets any public page fetch ``http://169.254.169.254/`` on our behalf.

Network access is off by default, so the honest out-of-the-box answer to "fetch
this page" is *no*.

Page content is attacker-controlled text destined for a model prompt, so it comes
back fenced and scanned by :mod:`devforge.tools.untrusted`. Element text inside a
snapshot is fenced the same way.

Each invocation gets a fresh isolated context: no profile, no cookies in or out, no
downloads, dialogs dismissed. Nothing carries between calls, which costs a browser
launch per call and is worth it - a shared context is a cross-site data channel.
"""

from __future__ import annotations

import asyncio
from typing import Any

from devforge.browser.models import DEFAULT_VIEWPORTS, Viewport
from devforge.browser.session import (
    BrowserBlocked,
    BrowserUnavailable,
    SessionPolicy,
    browser_session,
    playwright_available,
)
from devforge.core.models import ToolResult, ToolStatus
from devforge.policy.network import check_destination
from devforge.tools.base import Tool, ToolAvailability, ToolContext
from devforge.tools.descriptor import (
    TOOL_OUTPUT_SCHEMA,
    RiskLevel,
    ToolDescriptor,
    ToolPermissions,
    validate_params,
)
from devforge.tools.untrusted import wrap

BROWSER_GATE = "network_access"
DEFAULT_TIMEOUT_MS = 30_000
MAX_TEXT_CHARS = 40_000
MAX_HTML_CHARS = 200_000
#: Elements returned per inspect/styles call. A full DOM dump is noise, not context.
MAX_INSPECT_ELEMENTS = 60

MISSING_BROWSER = (
    "playwright is installed but no browser binary is available. Run `playwright install chromium`."
)

_URL = {"type": "string"}
_TIMEOUT = {"type": "integer"}
_VIEWPORT = {"type": "string", "enum": [v.name for v in DEFAULT_VIEWPORTS]}
#: Interaction steps replayed after load, before capture. A closed vocabulary: the
#: page never supplies these and no JavaScript string is accepted from anywhere.
_INTERACTIONS = {
    "type": "array",
    "items": {
        "type": "object",
        "properties": {
            "action": {"type": "string", "enum": ["click", "type", "scroll", "wait"]},
            "selector": {"type": "string"},
            "text": {"type": "string"},
            "to": {"type": "string", "enum": ["top", "bottom", "by"]},
            "pixels": {"type": "integer"},
            "ms": {"type": "integer"},
        },
        "required": ["action"],
        "additionalProperties": False,
    },
}


def _url_action(**extra) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {"url": _URL, "timeout_ms": _TIMEOUT, **extra},
        "required": ["url"],
        "additionalProperties": False,
    }


class BrowserTool(Tool):
    """Load pages, interact with them, and capture what they render."""

    name = "browser"
    description = "Load pages, interact, and capture DOM, styles, assets and screenshots."
    actions = (
        "fetch",
        "text",
        "html",
        "title",
        "screenshot",
        "snapshot",
        "inspect",
        "styles",
        "assets",
        "network",
        "console",
    )

    descriptor = ToolDescriptor(
        name="browser",
        version="2.0.0",
        description=(
            "Headless browsing through Playwright in an isolated context, gated by the "
            "network policy on every request the page makes."
        ),
        capabilities=[
            "navigation",
            "interaction",
            "text-extraction",
            "dom-capture",
            "computed-styles",
            "asset-inventory",
            "network-inventory",
            "console-capture",
            "screenshot",
        ],
        permissions=ToolPermissions(network=True, filesystem_write=True, gates=[BROWSER_GATE]),
        risk=RiskLevel.EXECUTE,
        input_schema={
            "fetch": _url_action(
                wait_until={
                    "type": "string",
                    "enum": ["load", "domcontentloaded", "networkidle", "commit"],
                }
            ),
            "text": _url_action(),
            "html": _url_action(),
            "title": _url_action(),
            "screenshot": _url_action(
                path={"type": "string"},
                full_page={"type": "boolean"},
                viewport=_VIEWPORT,
                interactions=_INTERACTIONS,
            ),
            "snapshot": _url_action(
                path={"type": "string"},
                viewport=_VIEWPORT,
                interactions=_INTERACTIONS,
            ),
            "inspect": _url_action(
                selector={"type": "string"}, viewport=_VIEWPORT, interactions=_INTERACTIONS
            ),
            "styles": _url_action(
                selector={"type": "string"}, viewport=_VIEWPORT, interactions=_INTERACTIONS
            ),
            "assets": _url_action(viewport=_VIEWPORT),
            "network": _url_action(viewport=_VIEWPORT),
            "console": _url_action(viewport=_VIEWPORT, interactions=_INTERACTIONS),
        },
        output_schema=TOOL_OUTPUT_SCHEMA,
    )

    def availability(self) -> ToolAvailability:
        available, detail = playwright_available()
        return ToolAvailability(available, detail)

    async def invoke(self, action: str, params: dict[str, Any], ctx: ToolContext) -> ToolResult:
        if action not in self.actions:
            return self.unknown_action(action)

        problems = validate_params(self.descriptor.schema_for(action), params)
        if problems:
            return self.fail(action, "; ".join(problems))

        url = params["url"]
        network = ctx.policy.permissions.network
        if not network.enabled:
            ctx.logger.warn(
                "tool.denied",
                tool=self.name,
                action=action,
                url=url,
                reason="network access is disabled by policy",
            )
            return self.fail_denied(
                action,
                "network access is disabled by policy - enable it and add the host to "
                "network.allow_hosts before browsing",
            )

        policy = SessionPolicy.from_network(network)
        allowed, reason = policy.check(url)
        if not allowed:
            # Re-check through check_destination for the canonical message when the
            # refusal was not the loopback carve-out.
            verdict = check_destination(
                url,
                allow_hosts=network.allow_hosts,
                resolve_names=network.block_private_addresses,
            )
            reason = verdict.reason or reason
            ctx.logger.warn("tool.denied", tool=self.name, action=action, url=url, reason=reason)
            return self.fail_denied(action, reason)

        # Availability is checked *after* the policy verdict. Whether a URL may be
        # fetched does not depend on whether a driver happens to be installed, and
        # answering "unavailable" to a request policy forbids reports the weaker
        # fact: it hides a refusal behind a missing dependency, and the refusal is
        # the one the caller needs to hear.
        available, detail = playwright_available()
        if not available:
            ctx.logger.warn("tool.unavailable", tool=self.name, action=action, reason=detail)
            return self.unavailable(action, detail)

        # Writing a screenshot is a filesystem write and is checked as one.
        target_path = None
        if action in {"screenshot", "snapshot"} and (action == "screenshot" or params.get("path")):
            relative = params.get("path") or "screenshot.png"
            decision = ctx.policy.check_path(relative, mode="write")
            refused = self.authorize(action, decision, ctx, gate_prompt=f"write {relative}")
            if refused is not None:
                return refused
            target_path = ctx.policy.resolve_path(relative)

        timeout_ms = int(params.get("timeout_ms") or DEFAULT_TIMEOUT_MS)
        try:
            return await self._drive(action, url, params, ctx, policy, timeout_ms, target_path)
        except BrowserUnavailable as exc:
            return self.unavailable(action, str(exc))
        except BrowserBlocked as exc:
            return self.fail_denied(action, str(exc))
        except Exception as exc:  # a driver failure must not abort the run
            message = f"{type(exc).__name__}: {exc}"
            if "executable doesn" in message.lower() or "playwright install" in message.lower():
                return self.unavailable(action, MISSING_BROWSER)
            ctx.logger.error("tool.error", tool=self.name, action=action, error=message)
            return self.fail(action, message, url=url)

    # -- driving ----------------------------------------------------------------

    async def _drive(
        self,
        action: str,
        url: str,
        params: dict[str, Any],
        ctx: ToolContext,
        policy: SessionPolicy,
        timeout_ms: int,
        target_path,
    ) -> ToolResult:
        from devforge.browser.capture import capture_page, replay_interactions

        viewport = _viewport(params.get("viewport"))
        started = asyncio.get_running_loop().time()

        async with browser_session(
            policy, viewport, logger=ctx.logger, timeout_ms=timeout_ms
        ) as session:
            if action in {"snapshot", "inspect", "styles", "assets", "network", "console"}:
                snapshot = await capture_page(
                    session,
                    url,
                    viewport,
                    screenshot_path=target_path,
                    interactions=params.get("interactions") or [],
                )
                duration_ms = int((asyncio.get_running_loop().time() - started) * 1000)
                return _snapshot_result(self, action, params, ctx, snapshot, duration_ms)

            page, response = await session.open(
                url, wait_until=params.get("wait_until", "load")
            )
            try:
                await replay_interactions(session, page, params.get("interactions") or [])
                status_code = response.status if response else None
                title = await page.title()

                if action == "title":
                    payload, raw_length = title, len(title)
                elif action == "html":
                    content = await page.content()
                    payload, raw_length = content[:MAX_HTML_CHARS], len(content)
                elif action == "screenshot":
                    await session.screenshot(
                        page, target_path, full_page=bool(params.get("full_page", False))
                    )
                    payload, raw_length = "", target_path.stat().st_size
                else:  # fetch and text both return visible text
                    text = await page.inner_text("body")
                    payload, raw_length = text[:MAX_TEXT_CHARS], len(text)
            finally:
                await page.close()

            blocked = [entry.url for entry in session.network if entry.blocked]

        duration_ms = int((asyncio.get_running_loop().time() - started) * 1000)

        if action == "screenshot":
            ctx.logger.info(
                "tool.browser",
                tool=self.name,
                action=action,
                url=url,
                status_code=status_code,
                bytes=raw_length,
                blocked_requests=len(blocked),
                duration_ms=duration_ms,
            )
            result = self.ok(
                action,
                f"captured {raw_length} bytes to {target_path}",
                url=url,
                path=str(target_path) if target_path else None,
                status_code=status_code,
                title=title,
                blocked_requests=blocked,
            )
            result.duration_ms = duration_ms
            return result

        untrusted = wrap(payload, source=f"browser:{url}")
        ctx.logger.info(
            "tool.browser",
            tool=self.name,
            action=action,
            url=url,
            status_code=status_code,
            bytes=raw_length,
            truncated=untrusted.truncated,
            injection_findings=untrusted.rules or None,
            blocked_requests=len(blocked),
            duration_ms=duration_ms,
        )
        if untrusted.suspicious:
            ctx.logger.warn("tool.untrusted_output", tool=self.name, url=url, rules=untrusted.rules)

        return ToolResult(
            tool=self.name,
            action=action,
            status=ToolStatus.OK,
            output=untrusted.fenced(),
            data={
                "url": url,
                "status_code": status_code,
                "title": title,
                "bytes": raw_length,
                "truncated": untrusted.truncated,
                "injection_findings": untrusted.rules,
                "blocked_requests": blocked,
            },
            duration_ms=duration_ms,
        )

    def fail_denied(self, action: str, reason: str) -> ToolResult:
        return ToolResult(tool=self.name, action=action, status=ToolStatus.DENIED, error=reason)


# ------------------------------------------------------------------ helpers


def _viewport(name: str | None) -> Viewport:
    by_name = {viewport.name: viewport for viewport in DEFAULT_VIEWPORTS}
    return by_name.get(name or "desktop", DEFAULT_VIEWPORTS[-1])


def _snapshot_result(tool, action, params, ctx, snapshot, duration_ms) -> ToolResult:
    """Turn a capture into the slice the requested action asked for."""
    if snapshot.status.value == "failed":
        return tool.fail(action, snapshot.error or "capture failed", url=snapshot.url)

    blocked = [entry.url for entry in snapshot.network if entry.blocked]
    selector = params.get("selector")
    elements = snapshot.elements
    if selector:
        needle = selector.lower()
        elements = [e for e in elements if needle in e.selector.lower() or e.tag == needle]
    elements = elements[:MAX_INSPECT_ELEMENTS]

    if action == "assets":
        data = {"assets": [asset.model_dump() for asset in snapshot.assets]}
        summary = f"{len(snapshot.assets)} assets referenced by {snapshot.url}"
    elif action == "network":
        data = {
            "requests": [entry.model_dump() for entry in snapshot.network[:200]],
            "hosts": snapshot.hosts,
            "failed": [entry.model_dump() for entry in snapshot.failed_requests[:100]],
        }
        summary = (
            f"{len(snapshot.network)} requests to {len(snapshot.hosts)} hosts "
            f"({len(blocked)} blocked, {len(snapshot.failed_requests)} failed)"
        )
    elif action == "console":
        # Console text is written by the page. It is returned as data for a human
        # or a debugger to read, never as something to act on.
        data = {
            "messages": [entry.model_dump() for entry in snapshot.console[:200]],
            "errors": len(snapshot.console_errors),
        }
        summary = (
            f"{len(snapshot.console)} console message(s), "
            f"{len(snapshot.console_errors)} error(s) on {snapshot.url}"
        )
    elif action == "styles":
        data = {
            "elements": [
                {"selector": e.selector, "tag": e.tag, "styles": e.styles.model_dump()}
                for e in elements
            ]
        }
        summary = f"computed styles for {len(elements)} elements"
    elif action == "inspect":
        data = {
            "elements": [
                {
                    "selector": e.selector,
                    "tag": e.tag,
                    "text": wrap(e.text, source=f"browser:{snapshot.url}").text,
                    "box": e.box.model_dump(),
                    "depth": e.depth,
                }
                for e in elements
            ]
        }
        summary = f"{len(elements)} elements from {snapshot.url}"
    else:  # snapshot: the whole capture
        data = snapshot.model_dump(mode="json")
        untrusted = wrap(snapshot.text_excerpt, source=f"browser:{snapshot.url}")
        data["text_excerpt"] = untrusted.text
        data["injection_findings"] = untrusted.rules
        summary = snapshot.summary()

    data.setdefault("url", snapshot.url)
    data.setdefault("blocked_requests", blocked)
    if snapshot.screenshot_path:
        data.setdefault("screenshot_path", snapshot.screenshot_path)

    ctx.logger.info(
        "tool.browser",
        tool=tool.name,
        action=action,
        url=snapshot.url[:200],
        elements=len(snapshot.elements),
        blocked_requests=len(blocked),
        duration_ms=duration_ms,
    )
    return ToolResult(
        tool=tool.name,
        action=action,
        status=ToolStatus.OK,
        output=summary,
        data=data,
        duration_ms=duration_ms,
    )
