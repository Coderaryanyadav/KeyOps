from typing import Dict, List, Optional
from playwright.async_api import Page, ElementHandle
from app.adapters.base import PasswordAdapter
from app.browser.field_detector import FieldDetector
from app.core.password_generator import PasswordPolicy

class GitHubAdapter(PasswordAdapter):
    @property
    def service_name(self) -> str:
        return "GitHub"

    @property
    def official_domains(self) -> List[str]:
        return ["github.com"]

    @property
    def login_url(self) -> str:
        return "https://github.com/login"

    @property
    def password_change_url(self) -> str:
        return "https://github.com/settings/security"

    def get_password_policy(self) -> PasswordPolicy:
        return PasswordPolicy(
            length=24,
            use_uppercase=True,
            use_lowercase=True,
            use_digits=True,
            use_symbols=True,
            exclude_ambiguous=True
        )

    async def navigate_to_security(self, page: Page) -> bool:
        if page.url != self.password_change_url:
            await page.goto(self.password_change_url, wait_until="domcontentloaded")
        return "settings/security" in page.url or "login" in page.url

    async def detect_password_fields(self, page: Page) -> Dict[str, Optional[ElementHandle]]:
        detector = FieldDetector()
        form = await detector.detect_password_fields(page)
        
        current_pw = form.current_password or await page.query_selector("input#old_password, input[name='old_password']")
        new_pw = form.new_password or await page.query_selector("input#user_password, input[name='user[password]'], input#new_password")
        confirm_pw = form.confirm_password or await page.query_selector("input#user_password_confirmation, input[name='user[password_confirmation]'], input#confirm_password")

        return {
            "current_password": current_pw,
            "new_password": new_pw,
            "confirm_password": confirm_pw
        }

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

        btn = await page.query_selector("button[type='submit']:has-text('Update password'), input[type='submit'][value='Update password']")
        if btn:
            await btn.click()
            await page.wait_for_timeout(2000)
            return True
        return False

    async def detect_success(self, page: Page) -> bool:
        content = await page.content()
        return "password updated" in content.lower() or "password changed" in content.lower()

    async def detect_failure(self, page: Page) -> Optional[str]:
        error_el = await page.query_selector(".flash-error, div.flash-error, .banner-error")
        if error_el:
            return await error_el.text_content()
        return None
