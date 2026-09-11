from typing import Dict, List, Optional
from playwright.async_api import Page, ElementHandle
from app.adapters.base import PasswordAdapter
from app.browser.field_detector import FieldDetector
from app.core.password_generator import PasswordPolicy

class AmazonAdapter(PasswordAdapter):
    @property
    def service_name(self) -> str:
        return "Amazon"

    @property
    def official_domains(self) -> List[str]:
        return ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.ca"]

    @property
    def login_url(self) -> str:
        return "https://www.amazon.com/ap/signin"

    @property
    def password_change_url(self) -> str:
        return "https://www.amazon.com/ap/cnep"

    def get_password_policy(self) -> PasswordPolicy:
        return PasswordPolicy(length=24, use_uppercase=True, use_lowercase=True, use_digits=True, use_symbols=True)

    async def navigate_to_security(self, page: Page) -> bool:
        await page.goto(self.password_change_url, wait_until="domcontentloaded")
        return "amazon.com" in page.url

    async def detect_password_fields(self, page: Page) -> Dict[str, Optional[ElementHandle]]:
        return await FieldDetector().detect_password_fields(page)

    async def fill_password(
        self,
        page: Page,
        fields: Dict[str, Optional[ElementHandle]],
        current_password: Optional[str],
        new_password: str
    ) -> bool:
        if fields.get("current_password") and current_password:
            await fields["current_password"].fill(current_password)
        if fields.get("new_password"):
            await fields["new_password"].fill(new_password)
        if fields.get("confirm_password"):
            await fields["confirm_password"].fill(new_password)
        return True

    async def submit_password_change(self, page: Page, dry_run: bool = False) -> bool:
        if dry_run:
            return True
        btn = await page.query_selector("input#cnep_1D_submit_button, input[type='submit']")
        if btn:
            await btn.click()
            return True
        return False

    async def detect_success(self, page: Page) -> bool:
        content = await page.content()
        return "success" in content.lower() or "saved" in content.lower()

    async def detect_failure(self, page: Page) -> Optional[str]:
        error_el = await page.query_selector(".a-alert-content")
        if error_el:
            return await error_el.text_content()
        return None
