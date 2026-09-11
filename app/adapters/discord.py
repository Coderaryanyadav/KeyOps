from typing import Dict, List, Optional
from playwright.async_api import Page, ElementHandle
from app.adapters.base import PasswordAdapter
from app.browser.field_detector import FieldDetector

class DiscordAdapter(PasswordAdapter):
    @property
    def service_name(self) -> str:
        return "Discord"

    @property
    def official_domains(self) -> List[str]:
        return ["discord.com", "discordapp.com"]

    @property
    def login_url(self) -> str:
        return "https://discord.com/login"

    @property
    def password_change_url(self) -> str:
        return "https://discord.com/channels/@me"

    async def navigate_to_security(self, page: Page) -> bool:
        await page.goto(self.password_change_url, wait_until="domcontentloaded")
        return "discord.com" in page.url

    async def detect_password_fields(self, page: Page) -> Dict[str, Optional[ElementHandle]]:
        return await FieldDetector().detect_password_fields(page)

    async def detect_success(self, page: Page) -> bool:
        content = await page.content()
        return "changed" in content.lower() or "done" in content.lower()

    async def detect_failure(self, page: Page) -> Optional[str]:
        error_el = await page.query_selector("[class*='errorMessage']")
        if error_el:
            return await error_el.text_content()
        return None

class RedditAdapter(PasswordAdapter):
    @property
    def service_name(self) -> str:
        return "Reddit"

    @property
    def official_domains(self) -> List[str]:
        return ["reddit.com"]

    @property
    def login_url(self) -> str:
        return "https://www.reddit.com/login/"

    @property
    def password_change_url(self) -> str:
        return "https://www.reddit.com/settings/"

    async def navigate_to_security(self, page: Page) -> bool:
        await page.goto(self.password_change_url, wait_until="domcontentloaded")
        return "reddit.com" in page.url

    async def detect_password_fields(self, page: Page) -> Dict[str, Optional[ElementHandle]]:
        return await FieldDetector().detect_password_fields(page)

    async def detect_success(self, page: Page) -> bool:
        content = await page.content()
        return "saved" in content.lower()

    async def detect_failure(self, page: Page) -> Optional[str]:
        error_el = await page.query_selector("[role='alert']")
        if error_el:
            return await error_el.text_content()
        return None
