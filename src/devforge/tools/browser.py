"""Browser tool, backed by Playwright.

Phase 0 shipped this as a declared-unavailable adapter because DevForge had no
driver. Playwright is now an optional dependency (`pip install devforge[browser]`),
so the tool is real when the driver is installed and still reports ``unavailable``
- never a fabricated result - when it is not.

Every navigation is an SSRF primitive: the agent picks the URL and the request
carries this workstation's network position. So a URL must clear
:mod:`devforge.policy.network` first - scheme, resolved address, then the host
allowlist - and network access is off by default, meaning the honest out-of-the-box
answer to "fetch this page" is *no*.

Page content is attacker-controlled text destined for a model prompt, so it comes
back fenced and scanned by :mod:`devforge.tools.untrusted`.

Not implemented: authenticated sessions, cookie persistence, file downloads, and
visual diffing (see devforge.verification.visual). The browser is driven headless
with a fixed viewport so screenshots are reproducible.
"""

from __future__ import annotations

import asyncio
from typing import Any

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
VIEWPORT = {"width": 1280, "height": 800}
MAX_TEXT_CHARS = 40_000
MAX_HTML_CHARS = 200_000

MISSING_DRIVER = (
    "playwright is not installed. Install it with `pip install devforge[browser]` and "
    "`playwright install chromium`. DevForge will not fabricate page content."
)
MISSING_BROWSER = (
    "playwright is installed but no browser binary is available. Run `playwright install chromium`."
)


def _playwright_available() -> tuple[bool, str]:
    try:
        import playwright.async_api  # noqa: F401
    except ImportError:
        return False, MISSING_DRIVER
    return True, "playwright (chromium, headless)"


class BrowserTool(Tool):
    """Load pages, capture text, HTML and screenshots."""

    name = "browser"
    description = "Load pages and capture DOM, text and screenshots (Playwright)."
    actions = ("fetch", "text", "html", "screenshot", "title")

    descriptor = ToolDescriptor(
        name="browser",
        version="1.0.0",
        description="Headless browsing through Playwright, gated by the network policy.",
        capabilities=["navigation", "text-extraction", "dom-capture", "screenshot"],
        permissions=ToolPermissions(network=True, filesystem_write=True, gates=[BROWSER_GATE]),
        risk=RiskLevel.EXECUTE,
        input_schema={
            "fetch": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "timeout_ms": {"type": "integer"},
                    "wait_until": {
                        "type": "string",
                        "enum": ["load", "domcontentloaded", "networkidle", "commit"],
                    },
                },
                "required": ["url"],
                "additionalProperties": False,
            },
            "text": {
                "type": "object",
                "properties": {"url": {"type": "string"}, "timeout_ms": {"type": "integer"}},
                "required": ["url"],
                "additionalProperties": False,
            },
            "html": {
                "type": "object",
                "properties": {"url": {"type": "string"}, "timeout_ms": {"type": "integer"}},
                "required": ["url"],
                "additionalProperties": False,
            },
            "title": {
                "type": "object",
                "properties": {"url": {"type": "string"}, "timeout_ms": {"type": "integer"}},
                "required": ["url"],
                "additionalProperties": False,
            },
            "screenshot": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "path": {"type": "string"},
                    "full_page": {"type": "boolean"},
                    "timeout_ms": {"type": "integer"},
                },
                "required": ["url"],
                "additionalProperties": False,
            },
        },
        output_schema=TOOL_OUTPUT_SCHEMA,
    )

    def availability(self) -> ToolAvailability:
        available, detail = _playwright_available()
        return ToolAvailability(available, detail)

    async def invoke(self, action: str, params: dict[str, Any], ctx: ToolContext) -> ToolResult:
        if action not in self.actions:
            return self.unknown_action(action)

        available, detail = _playwright_available()
        if not available:
            ctx.logger.warn("tool.unavailable", tool=self.name, action=action, reason=detail)
            return self.unavailable(action, detail)

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

        verdict = check_destination(
            url,
            allow_hosts=network.allow_hosts,
            resolve_names=network.block_private_addresses,
        )
        if verdict.blocked:
            ctx.logger.warn(
                "tool.denied", tool=self.name, action=action, url=url, reason=verdict.reason
            )
            return self.fail_denied(action, verdict.reason)

        # Writing a screenshot is a filesystem write and is checked as one.
        target_path = None
        if action == "screenshot":
            relative = params.get("path") or "screenshot.png"
            decision = ctx.policy.check_path(relative, mode="write")
            refused = self.authorize(action, decision, ctx, gate_prompt=f"write {relative}")
            if refused is not None:
                return refused
            target_path = ctx.policy.resolve_path(relative)

        timeout_ms = int(params.get("timeout_ms") or DEFAULT_TIMEOUT_MS)
        try:
            return await self._drive(action, url, params, ctx, timeout_ms, target_path)
        except Exception as exc:  # a driver failure must not abort the run
            message = f"{type(exc).__name__}: {exc}"
            if "executable doesn" in message.lower() or "playwright install" in message.lower():
                return self.unavailable(action, MISSING_BROWSER)
            ctx.logger.error("tool.error", tool=self.name, action=action, error=message)
            return self.fail(action, message, url=url)

    async def _drive(
        self,
        action: str,
        url: str,
        params: dict[str, Any],
        ctx: ToolContext,
        timeout_ms: int,
        target_path,
    ) -> ToolResult:
        from playwright.async_api import async_playwright

        started = asyncio.get_running_loop().time()
        async with async_playwright() as driver:
            browser = await driver.chromium.launch(headless=True)
            try:
                page = await browser.new_page(viewport=VIEWPORT)
                response = await page.goto(
                    url,
                    timeout=timeout_ms,
                    wait_until=params.get("wait_until", "load"),
                )
                status_code = response.status if response else None
                title = await page.title()

                if action == "title":
                    payload, raw_length = title, len(title)
                elif action == "html":
                    content = await page.content()
                    payload, raw_length = content[:MAX_HTML_CHARS], len(content)
                elif action == "screenshot":
                    image = await page.screenshot(
                        full_page=bool(params.get("full_page", False)),
                        path=str(target_path) if target_path else None,
                    )
                    payload, raw_length = "", len(image)
                else:  # fetch and text both return visible text
                    text = await page.inner_text("body")
                    payload, raw_length = text[:MAX_TEXT_CHARS], len(text)
            finally:
                await browser.close()

        duration_ms = int((asyncio.get_running_loop().time() - started) * 1000)

        if action == "screenshot":
            ctx.logger.info(
                "tool.browser",
                tool=self.name,
                action=action,
                url=url,
                status_code=status_code,
                bytes=raw_length,
                duration_ms=duration_ms,
            )
            result = self.ok(
                action,
                f"captured {raw_length} bytes to {target_path}",
                url=url,
                path=str(target_path) if target_path else None,
                status_code=status_code,
                title=title,
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
            duration_ms=duration_ms,
        )
        if untrusted.suspicious:
            ctx.logger.warn("tool.untrusted_output", tool=self.name, url=url, rules=untrusted.rules)

        result = ToolResult(
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
            },
            duration_ms=duration_ms,
        )
        return result

    def fail_denied(self, action: str, reason: str) -> ToolResult:
        return ToolResult(tool=self.name, action=action, status=ToolStatus.DENIED, error=reason)
