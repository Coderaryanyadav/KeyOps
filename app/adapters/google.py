from typing import Dict, List, Optional
from playwright.async_api import Page, ElementHandle
from app.adapters.base import PasswordAdapter
from app.browser.field_detector import FieldDetector
from app.core.password_generator import PasswordPolicy

class GoogleAdapter(PasswordAdapter):
    @property
    def service_name(self) -> str:
        return "Google"

    @property
    def official_domains(self) -> List[str]:
        return ["google.com", "accounts.google.com", "myaccount.google.com"]

    @property
    def login_url(self) -> str:
        return "https://accounts.google.com/signin"

    @property
    def password_change_url(self) -> str:
        return "https://myaccount.google.com/signinoptions/password"

    def get_password_policy(self) -> PasswordPolicy:
        return PasswordPolicy(length=32, use_uppercase=True, use_lowercase=True, use_digits=True, use_symbols=True)

    async def navigate_to_security(self, page: Page) -> bool:
        await page.goto(self.password_change_url, wait_until="domcontentloaded")
        return "google.com" in page.url

    async def detect_password_fields(self, page: Page) -> Dict[str, Optional[ElementHandle]]:
        detector = FieldDetector()
        return await detector.detect_password_fields(page)

    async def detect_success(self, page: Page) -> bool:
        content = await page.content()
        return "password changed successfully" in content.lower()

    async def detect_failure(self, page: Page) -> Optional[str]:
        error_el = await page.query_selector("[role='alert'], .error-message")
        if error_el:
            return await error_el.text_content()
        return None
