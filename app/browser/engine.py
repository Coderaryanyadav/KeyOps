import asyncio
from typing import Optional
from playwright.async_api import async_playwright, Playwright, Browser, BrowserContext, Page
from app.config import settings
from app.core.domain_validator import DomainValidator, DomainValidationError
from app.core.audit_logger import audit_logger

class BrowserEngine:
    """
    Playwright Browser Manager. Runs in headed mode by default to ensure
    visibility and seamless human takeover during security verification.
    """

    def __init__(self, headed: Optional[bool] = None):
        self.headed = settings.browser_headed if headed is None else headed
        self.domain_validator = DomainValidator()
        self._playwright: Optional[Playwright] = None
        self._browser: Optional[Browser] = None
        self._context: Optional[BrowserContext] = None

    async def start(self) -> None:
        if not self._playwright:
            self._playwright = await async_playwright().start()
            self._browser = await self._playwright.chromium.launch(
                headless=not self.headed,
                slow_mo=settings.browser_slow_mo_ms,
                args=["--disable-blink-features=AutomationControlled"]
            )
            self._context = await self._browser.new_context(
                viewport={"width": 1280, "height": 800},
                user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            )

    async def new_page(self) -> Page:
        if not self._context:
            await self.start()
        assert self._context is not None
        page = await self._context.new_page()
        return page

    async def safe_navigate(self, page: Page, url: str, expected_service_name: str) -> None:
        """
        Navigates to URL after strictly validating the target domain.
        Raises DomainValidationError if untrusted domain spoofing is detected.
        """
        self.domain_validator.validate_url(url, expected_service_name)
        audit_logger.log_event(expected_service_name, f"Navigating to verified domain URL: {url}")
        await page.goto(url, wait_until="domcontentloaded")
        
        # Post-navigation validation to guard against open redirects
        current_url = page.url
        self.domain_validator.validate_url(current_url, expected_service_name)

    async def stop(self) -> None:
        if self._context:
            await self._context.close()
            self._context = None
        if self._browser:
            await self._browser.close()
            self._browser = None
        if self._playwright:
            await self._playwright.stop()
            self._playwright = None

# Alias for backwards compatibility & orchestrator naming convention
BrowserAutomationEngine = BrowserEngine

