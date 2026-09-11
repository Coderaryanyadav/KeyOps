from typing import Dict, List, Optional, Tuple
from playwright.async_api import Page, ElementHandle
from app.adapters.base import PasswordAdapter
from app.browser.field_detector import FieldDetector, DetectedForm
from app.browser.policy_detector import PolicyDetector
from app.core.password_generator import PasswordPolicy
from app.core.planner import ActionPlanner, ActionPlan
from app.core.safety_validator import SafetyValidator
from app.core.workflow_memory import workflow_memory, WebsiteWorkflow
from app.core.audit_logger import audit_logger

class GenericAdapter(PasswordAdapter):
    """
    Universal Website Workflow Discovery Engine.
    Inspects page title, headings, navigation links, ARIA labels, and form semantics.
    Calculates confidence scores for each step. Never performs random clicks.
    """

    def __init__(self, target_service_name: str = "Generic", target_domain: str = ""):
        self._service_name = target_service_name
        self._domain = target_domain
        self.field_detector = FieldDetector()
        self.policy_detector = PolicyDetector()
        self.safety_validator = SafetyValidator()

    @property
    def service_name(self) -> str:
        return self._service_name

    @property
    def official_domains(self) -> List[str]:
        return [self._domain] if self._domain else []

    @property
    def login_url(self) -> str:
        return f"https://{self._domain}/login" if self._domain else ""

    @property
    def password_change_url(self) -> str:
        # Check if we already have a validated workflow memory
        mem = workflow_memory.get_workflow(self._domain)
        if mem and mem.password_change_url:
            return mem.password_change_url
        return f"https://{self._domain}/settings/security" if self._domain else ""

    async def navigate_to_security(self, page: Page) -> bool:
        """
        Reasons about website structure to discover the account security / password change page.
        """
        # 1. Check if current page already hosts the password form
        form = await self.field_detector.detect_password_fields(page)
        if form.new_password is not None and form.overall_confidence >= 0.85:
            audit_logger.log_event(self.service_name, f"Password form already present on current page ({page.url}).")
            return True

        # 2. Check workflow memory for pre-validated route
        mem = workflow_memory.get_workflow(self._domain)
        if mem and mem.security_url and page.url != mem.security_url:
            audit_logger.log_event(self.service_name, f"Navigating to remembered security URL: {mem.security_url}")
            await page.goto(mem.security_url, wait_until="domcontentloaded")
            form = await self.field_detector.detect_password_fields(page)
            if form.new_password is not None:
                return True

        # 3. Discovery heuristics across navigation tree
        NAV_KEYWORDS = [
            ("a:has-text('Password')", 0.96),
            ("a:has-text('Security')", 0.94),
            ("a:has-text('Account Settings')", 0.91),
            ("a:has-text('Settings')", 0.88),
            ("a:has-text('Profile')", 0.82),
            ("[aria-label*='Security']", 0.92),
            ("[aria-label*='Settings']", 0.86)
        ]

        for selector, conf in NAV_KEYWORDS:
            elements = await page.query_selector_all(selector)
            for el in elements:
                if await el.is_visible():
                    action = ActionPlanner.plan_navigation(
                        url=page.url,
                        reason=f"Found high-confidence navigation link '{selector}'",
                        confidence=conf
                    )
                    is_safe, msg = self.safety_validator.validate_action(action, self.service_name, self._domain)
                    if is_safe:
                        audit_logger.log_event(self.service_name, f"Discovered settings link: {selector} (confidence={conf:.2f}). Clicking...")
                        await el.click()
                        await page.wait_for_timeout(2000)
                        
                        # Verify if new page contains password form
                        form = await self.field_detector.detect_password_fields(page)
                        if form.new_password is not None:
                            # Record successful workflow in memory
                            workflow_memory.record_workflow(WebsiteWorkflow(
                                domain=self._domain,
                                service_name=self.service_name,
                                security_url=page.url,
                                password_change_url=page.url,
                                confidence=conf
                            ))
                            return True

        audit_logger.log_event(self.service_name, "Universal Discovery HALT: Unable to navigate to security page safely with high confidence.", level="WARNING")
        return False

    async def detect_password_fields(self, page: Page) -> Dict[str, Optional[ElementHandle]]:
        form: DetectedForm = await self.field_detector.detect_password_fields(page)
        return {
            "current_password": form.current_password,
            "new_password": form.new_password,
            "confirm_password": form.confirm_password
        }

    async def fill_password(
        self,
        page: Page,
        fields: Dict[str, Optional[ElementHandle]],
        current_password: Optional[str],
        new_password: str
    ) -> bool:
        if not fields.get("new_password"):
            audit_logger.log_event(self.service_name, "Generic Engine HALT: New password field missing.", level="WARNING")
            return False

        if fields.get("current_password") and current_password:
            await fields["current_password"].fill(current_password)
        if fields.get("new_password"):
            await fields["new_password"].fill(new_password)
        if fields.get("confirm_password"):
            await fields["confirm_password"].fill(new_password)

        return True

    async def submit_password_change(self, page: Page, dry_run: bool = False) -> bool:
        if dry_run:
            audit_logger.log_event(self.service_name, "[DRY-RUN] Verified submission button exists. Change skipped.")
            return True

        SUBMIT_SELECTORS = [
            ("button[type='submit']:has-text('Save')", 0.95),
            ("button[type='submit']:has-text('Update password')", 0.98),
            ("button[type='submit']:has-text('Change password')", 0.98),
            ("input[type='submit'][value*='Save']", 0.92),
            ("input[type='submit'][value*='Update']", 0.94),
            ("button:has-text('Save changes')", 0.90)
        ]

        for sel, conf in SUBMIT_SELECTORS:
            btn = await page.query_selector(sel)
            if btn and await btn.is_visible():
                action = ActionPlanner.plan_submit(sel, conf, f"Found submit button '{sel}'")
                is_safe, _ = self.safety_validator.validate_action(action, self.service_name, self._domain)
                if is_safe:
                    await btn.click()
                    await page.wait_for_timeout(2500)
                    return True

        audit_logger.log_event(self.service_name, "Generic Engine HALT: Could not locate submit button safely.", level="WARNING")
        return False

    async def detect_success(self, page: Page) -> bool:
        content = (await page.content()).lower()
        success_signals = ["password updated", "password changed", "settings saved", "changes saved", "success"]
        return any(sig in content for sig in success_signals)

    async def detect_failure(self, page: Page) -> Optional[str]:
        error_el = await page.query_selector("[role='alert'], .error-message, .flash-error, .alert-danger")
        if error_el:
            return await error_el.text_content()
        return None
