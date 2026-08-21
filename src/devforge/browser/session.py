"""An isolated browser session.

A browser agent is the highest-risk component in DevForge: it fetches content
chosen by whoever controls the site, renders it, and hands the result to a model
that holds tool permissions. This module is the containment.

What each session guarantees
----------------------------

**Nothing persists.** A fresh context per session, no user data directory, no
storage state in or out. Cookies, localStorage and cache die with the context, so
one page cannot read what another left and nothing survives the run.

**No developer credentials, ever.** The context is created empty. The operator's
real browser profile, cookie jar and saved passwords are never passed in - there
is no code path that could, which is stronger than a policy that says not to.

**Every request is checked, not just the first.** Phase 2 checked the URL an
operator typed. That is not enough: a page controls its own subresources, so a
public page can request `http://169.254.169.254/` or `http://10.0.0.1/` and the
top-level check never sees it. A route handler here applies the SSRF policy to
**every** request the page makes and records what it refused.

**No file:// and no data: navigation.** Both turn a URL fetcher into a local file
reader.

**Downloads are refused.** A browser that writes to disk is a file-write primitive
driven by a remote site.

**Page content is data.** Text and DOM come back to be fenced by the caller before
any prompt use. Nothing read from a page is treated as instruction.

What this is not
----------------

Not a sandbox. Chromium runs as the invoking user with its own sandbox, which is
real but is Chromium's, not DevForge's. A browser exploit is out of scope here,
and the honest mitigation is the same as everywhere else in this project: do not
point it at hostile input you would not open yourself.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from devforge.browser.models import ConsoleMessage, NetworkEntry, Viewport
from devforge.core.errors import DevForgeError
from devforge.observability.logging import RunLogger, null_logger
from devforge.policy.models import NetworkPolicy
from devforge.policy.network import check_destination

#: Schemes a page may navigate to or request. Everything else is refused.
ALLOWED_SCHEMES = frozenset({"http", "https", "about", "blob"})

DEFAULT_TIMEOUT_MS = 20_000
#: A page controls how much it logs, so we control how much we keep.
MAX_CONSOLE_MESSAGES = 200
MAX_CONSOLE_CHARS = 2_000
#: A page that has not settled by now is captured as-is rather than waited on forever.
SETTLE_TIMEOUT_MS = 5_000

#: A deliberately boring identity. Impersonating a real browser build invites
#: fingerprint-specific behaviour and misrepresents who is asking.
USER_AGENT = "DevForge/0.1 (+https://github.com/mrbrownnn/DevForge; headless verification)"


class BrowserUnavailable(DevForgeError):
    """Playwright or a browser binary is missing."""


class BrowserBlocked(DevForgeError):
    """Navigation was refused by policy."""


def playwright_available() -> tuple[bool, str]:
    try:
        import playwright.async_api  # noqa: F401
    except ImportError:
        return False, (
            "playwright is not installed. `pip install \"devforge[browser]\"` and "
            "`playwright install chromium`. DevForge will not fabricate page data."
        )
    return True, "playwright (chromium, headless, isolated context)"


@dataclass
class SessionPolicy:
    """The network rules this session enforces on every request."""

    network: NetworkPolicy
    #: Loopback is refused by default like any private address. Local development is
    #: the one case where it is legitimate - screenshotting your own dev server - so
    #: it is an explicit opt-in rather than a hole left open.
    allow_loopback: bool = False
    allow_javascript: bool = True

    @classmethod
    def from_network(cls, network: NetworkPolicy, **overrides) -> SessionPolicy:
        """Build a session policy from the project's network policy.

        ``allow_loopback`` follows the policy file rather than the caller, so a run
        cannot quietly widen what the operator declared.
        """
        return cls(network=network, allow_loopback=network.allow_loopback, **overrides)

    def check(self, url: str) -> tuple[bool, str]:
        scheme = (urlsplit(url).scheme or "").lower()
        if scheme and scheme not in ALLOWED_SCHEMES:
            return False, f"scheme '{scheme}' is not allowed"
        if scheme in {"about", "blob"}:
            return True, "internal scheme"

        host = (urlsplit(url).hostname or "").lower()
        if self.allow_loopback and host in {"localhost", "127.0.0.1", "::1", "[::1]"}:
            return True, "loopback allowed for local development"

        verdict = check_destination(
            url,
            allow_hosts=self.network.allow_hosts,
            resolve_names=self.network.block_private_addresses,
        )
        return verdict.allowed, verdict.reason


@dataclass
class BrowserSession:
    """One isolated browsing context, with its request log."""

    policy: SessionPolicy
    logger: RunLogger = field(default_factory=null_logger)
    timeout_ms: int = DEFAULT_TIMEOUT_MS
    network: list[NetworkEntry] = field(default_factory=list)
    console: list[ConsoleMessage] = field(default_factory=list)
    _context: object | None = field(default=None, init=False, repr=False)
    _browser: object | None = field(default=None, init=False, repr=False)
    _playwright: object | None = field(default=None, init=False, repr=False)

    # -- lifecycle --------------------------------------------------------------

    async def start(self, viewport: Viewport) -> None:
        available, detail = playwright_available()
        if not available:
            raise BrowserUnavailable(detail)

        from playwright.async_api import async_playwright

        self._playwright = await async_playwright().start()
        try:
            self._browser = await self._playwright.chromium.launch(headless=True)
        except Exception as exc:  # driver present, browser binary missing
            await self._shutdown()
            raise BrowserUnavailable(
                f"could not launch chromium ({exc}). Run `playwright install chromium`."
            ) from exc

        # A fresh context with nothing carried in: no storage_state, no profile
        # directory, no credentials. Everything it accumulates dies with it.
        self._context = await self._browser.new_context(
            viewport={"width": viewport.width, "height": viewport.height},
            user_agent=USER_AGENT,
            java_script_enabled=self.policy.allow_javascript,
            accept_downloads=False,
            bypass_csp=False,
            ignore_https_errors=False,
            storage_state=None,
            permissions=[],
        )
        self._context.set_default_timeout(self.timeout_ms)
        await self._context.route("**/*", self._route)

    async def _shutdown(self) -> None:
        for closer in (self._context, self._browser):
            if closer is not None:
                # A failed close must not mask the real error.
                with suppress(Exception):
                    await closer.close()
        if self._playwright is not None:
            with suppress(Exception):
                await self._playwright.stop()
        self._context = self._browser = self._playwright = None

    async def close(self) -> None:
        await self._shutdown()

    # -- request policy ---------------------------------------------------------

    async def _route(self, route, request) -> None:
        """Every request, not just the first navigation.

        A page controls its own subresources. Checking only the top-level URL would
        let any public page pull `http://169.254.169.254/` on our behalf.
        """
        url = request.url
        allowed, reason = self.policy.check(url)
        entry = NetworkEntry(
            url=url[:500],
            method=request.method,
            resource_type=request.resource_type,
            blocked=not allowed,
            blocked_reason="" if allowed else reason,
        )
        self.network.append(entry)

        if allowed:
            await route.continue_()
            return

        self.logger.warn(
            "browser.request_blocked",
            url=url[:200],
            resource_type=request.resource_type,
            reason=reason,
        )
        await route.abort("blockedbyclient")

    # -- navigation and interaction --------------------------------------------

    async def open(self, url: str, *, wait_until: str = "load"):
        allowed, reason = self.policy.check(url)
        if not allowed:
            raise BrowserBlocked(f"refusing to open {url}: {reason}")

        page = await self._context.new_page()
        page.on("download", lambda download: asyncio.ensure_future(download.cancel()))
        page.on("dialog", lambda dialog: asyncio.ensure_future(dialog.dismiss()))
        page.on("console", self._record_console)
        page.on("pageerror", self._record_page_error)

        response = await page.goto(url, wait_until=wait_until, timeout=self.timeout_ms)
        await self._settle(page)
        self.logger.info(
            "browser.open",
            url=url[:200],
            status=response.status if response else None,
            viewport=await page.evaluate("() => `${innerWidth}x${innerHeight}`"),
        )
        return page, response

    # -- console ----------------------------------------------------------------

    def _record_console(self, message) -> None:
        """A page's own console output, bounded and never executed.

        Capped in both length and count: a page in a render loop can emit console
        lines faster than we can store them, and an unbounded log is a memory
        exhaustion primitive handed to whoever wrote the page.
        """
        if len(self.console) >= MAX_CONSOLE_MESSAGES:
            return
        location = ""
        with suppress(Exception):
            spot = message.location or {}
            if spot.get("url"):
                location = f"{spot['url']}:{spot.get('lineNumber', 0)}"
        with suppress(Exception):
            self.console.append(
                ConsoleMessage(
                    level=str(message.type)[:20],
                    text=str(message.text)[:MAX_CONSOLE_CHARS],
                    location=location[:300],
                )
            )

    def _record_page_error(self, error) -> None:
        if len(self.console) >= MAX_CONSOLE_MESSAGES:
            return
        self.console.append(
            ConsoleMessage(level="pageerror", text=str(error)[:MAX_CONSOLE_CHARS])
        )

    async def _settle(self, page) -> None:
        """Give the page a moment to finish, but never wait indefinitely."""
        # A page that never idles is captured as-is, which is honest.
        with suppress(Exception):
            await page.wait_for_load_state("networkidle", timeout=SETTLE_TIMEOUT_MS)

    async def click(self, page, selector: str) -> bool:
        try:
            await page.click(selector, timeout=self.timeout_ms)
            await self._settle(page)
            self.logger.info("browser.click", selector=selector)
            return True
        except Exception as exc:
            self.logger.warn("browser.click_failed", selector=selector, error=str(exc)[:200])
            return False

    async def type_text(self, page, selector: str, text: str) -> bool:
        try:
            await page.fill(selector, text, timeout=self.timeout_ms)
            self.logger.info("browser.type", selector=selector, characters=len(text))
            return True
        except Exception as exc:
            self.logger.warn("browser.type_failed", selector=selector, error=str(exc)[:200])
            return False

    async def scroll(self, page, *, to: str = "bottom", pixels: int = 0) -> float:
        if to == "bottom":
            await page.evaluate("() => window.scrollTo(0, document.body.scrollHeight)")
        elif to == "top":
            await page.evaluate("() => window.scrollTo(0, 0)")
        else:
            await page.evaluate("(y) => window.scrollBy(0, y)", pixels)
        await page.wait_for_timeout(150)  # let lazy content react
        return await page.evaluate("() => window.scrollY")

    async def screenshot(self, page, path: Path, *, full_page: bool = True) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        await page.screenshot(path=str(path), full_page=full_page)
        return path


@asynccontextmanager
async def browser_session(
    policy: SessionPolicy,
    viewport: Viewport,
    *,
    logger: RunLogger | None = None,
    timeout_ms: int = DEFAULT_TIMEOUT_MS,
):
    """Open an isolated session and guarantee it is torn down."""
    session = BrowserSession(policy=policy, logger=logger or null_logger(), timeout_ms=timeout_ms)
    await session.start(viewport)
    try:
        yield session
    finally:
        await session.close()
