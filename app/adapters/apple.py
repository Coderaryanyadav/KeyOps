from typing import Dict, List, Optional
from playwright.async_api import Page, ElementHandle
from app.adapters.base import PasswordAdapter
from app.browser.field_detector import FieldDetector
from app.core.password_generator import PasswordPolicy

class AppleAdapter(PasswordAdapter):
    @property
    def service_name(self) -> str:
        return "Apple"

    @property
    def official_domains(self) -> List[str]:
        return ["apple.com", "appleid.apple.com", "icloud.com"]

    @property
    def login_url(self) -> str:
        return "https://appleid.apple.com/sign-in"

    @property
    def password_change_url(self) -> str:
        return "https://appleid.apple.com/account/manage/section/security"

    def get_password_policy(self) -> PasswordPolicy:
        return PasswordPolicy(length=24, use_uppercase=True, use_lowercase=True, use_digits=True, use_symbols=True)

    async def navigate_to_security(self, page: Page) -> bool:
        await page.goto(self.password_change_url, wait_until="domcontentloaded")
        return "apple.com" in page.url or "appleid" in page.url

    async def detect_password_fields(self, page: Page) -> Dict[str, Optional[ElementHandle]]:
        detector = FieldDetector()
        return await detector.detect_password_fields(page)

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
        btn = await page.query_selector("button:has-text('Change Password'), button:has-text('Save')")
        if btn:
            await btn.click()
            return True
        return False

    async def detect_success(self, page: Page) -> bool:
        content = await page.content()
        return "password updated" in content.lower()

    async def detect_failure(self, page: Page) -> Optional[str]:
        error_el = await page.query_selector(".form-message-error, [role='alert']")
        if error_el:
            return await error_el.text_content()
        return None
