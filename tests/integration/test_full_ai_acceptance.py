import asyncio
import pytest
import uvicorn
from multiprocessing import Process
from playwright.async_api import async_playwright
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database.models import Base, Account
from app.core.password_generator import PasswordGenerator, PasswordPolicy
from app.core.domain_validator import DomainValidator
from app.core.queue_manager import QueueManager, QueueItemStatus
from app.core.audit_logger import sanitize_log_message
from app.safety.secret_boundary import SecretBoundary
from app.safety.action_validator import ActionSafetyValidator
from app.ai.navigator import AINavigator
from app.ai.providers.local import LocalAIProvider
from app.ai.providers.gemini import GeminiAIProvider
from app.ai.prompt_injection_guard import PromptInjectionGuard
from app.adapters.platforms import PlatformDetector
from app.adapters.generic import GenericAdapter
from app.browser.human_interrupter import HumanInterrupter
from app.browser.policy_detector import PolicyDetector
from tests.mock_server import mock_app

def run_ai_acceptance_server():
    uvicorn.run(mock_app, host="127.0.0.1", port=9631, log_level="warning")

@pytest.fixture(scope="module", autouse=True)
def mock_server_process():
    proc = Process(target=run_ai_acceptance_server, daemon=True)
    proc.start()
    import time
    time.sleep(1.5)
    yield
    proc.terminate()

@pytest.mark.asyncio
async def test_full_10_account_ai_assisted_acceptance():
    """
    Simulates the complete 10-account real-world cybersecurity challenge:
    1. Known Google Account
    2. Known GitHub Account
    3. Platform Auth0 Account
    4. Platform WordPress Account
    5. Completely Unknown Website
    6. MFA Challenge Website
    7. CAPTCHA Website
    8. Email Verification Website
    9. Malicious Prompt Injection Website
    10. Redesigned Layout & Policy Error Website
    """
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    db = Session()

    accounts = [
        Account(id=1, service="Google", username="alice@gmail.com", domain="127.0.0.1:9631", risk="CRITICAL", issue="Compromised"),
        Account(id=2, service="GitHub", username="alice_dev", domain="127.0.0.1:9631", risk="CRITICAL", issue="Compromised"),
        Account(id=3, service="Auth0App", username="alice@corp.com", domain="127.0.0.1:9631", risk="CRITICAL", issue="Compromised"),
        Account(id=4, service="WordPressBlog", username="alice_admin", domain="127.0.0.1:9631", risk="HIGH", issue="Compromised"),
        Account(id=5, service="UnknownPortal", username="alice_user", domain="127.0.0.1:9631", risk="HIGH", issue="Compromised"),
        Account(id=6, service="MFAProtected", username="alice@mfa.com", domain="127.0.0.1:9631", risk="MEDIUM", issue="Old"),
        Account(id=7, service="CaptchaProtected", username="alice@captcha.com", domain="127.0.0.1:9631", risk="MEDIUM", issue="None"),
        Account(id=8, service="EmailVerifySite", username="alice@verify.com", domain="127.0.0.1:9631", risk="LOW", issue="None"),
        Account(id=9, service="MaliciousSite", username="alice@danger.com", domain="127.0.0.1:9631", risk="LOW", issue="None"),
        Account(id=10, service="RedesignedSite", username="alice@redesign.com", domain="127.0.0.1:9631", risk="LOW", issue="None"),
    ]
    db.add_all(accounts)
    db.commit()

    # Prioritize queue: 5 compromised accounts processed first
    queue_mgr = QueueManager()
    queue = queue_mgr.set_queue(accounts)
    assert len(queue) == 10
    assert queue[0].risk == "CRITICAL"

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()

        # -------------------------------------------------------------
        # 1. Known Google Account
        # -------------------------------------------------------------
        await page.goto("http://127.0.0.1:9631/google/settings")
        btn = await page.query_selector("button[type='submit']")
        assert btn is not None
        queue_mgr.update_item_status(1, QueueItemStatus.SUCCESS, "Google Changed", 0.99)

        # -------------------------------------------------------------
        # 2. Known GitHub Account
        # -------------------------------------------------------------
        await page.goto("http://127.0.0.1:9631/github/settings/security")
        old_inp = await page.query_selector("input[name='old_password']")
        assert old_inp is not None
        queue_mgr.update_item_status(2, QueueItemStatus.SUCCESS, "GitHub Changed", 0.99)

        # -------------------------------------------------------------
        # 3. Platform Auth0 Account
        # -------------------------------------------------------------
        await page.goto("http://127.0.0.1:9631/auth0/profile/security")
        p_detector = PlatformDetector()
        res = await p_detector.detect_platform(page)
        assert res is not None
        assert res.platform_name == "Auth0"
        queue_mgr.update_item_status(3, QueueItemStatus.SUCCESS, "Auth0 Platform Changed", 0.98)

        # -------------------------------------------------------------
        # 4. Platform WordPress Account
        # -------------------------------------------------------------
        await page.goto("http://127.0.0.1:9631/wordpress/wp-admin/profile.php")
        wp_res = await p_detector.detect_platform(page)
        assert wp_res is not None
        assert wp_res.platform_name == "WordPress"
        queue_mgr.update_item_status(4, QueueItemStatus.SUCCESS, "WordPress Platform Changed", 0.97)

        # -------------------------------------------------------------
        # 5. Completely Unknown Website (AI Navigator + Generic Adapter)
        # -------------------------------------------------------------
        await page.goto("http://127.0.0.1:9631/unknown-site/portal")
        generic_adapter = GenericAdapter("UnknownPortal", "127.0.0.1:9631")
        nav_ok = await generic_adapter.navigate_to_security(page)
        assert nav_ok is True
        assert "/unknown-site/security" in page.url

        boundary = SecretBoundary()
        boundary.register_secrets(current_password="old_key_val", new_password="NewSecret999!")
        ai_navigator = AINavigator(ai_provider=LocalAIProvider())
        reached = await ai_navigator.navigate_to_password_interface(
            page=page,
            service_name="UnknownPortal",
            domain="127.0.0.1:9631",
            secret_boundary=boundary
        )
        assert reached is True
        queue_mgr.update_item_status(5, QueueItemStatus.SUCCESS, "Unknown Website AI Discovered", 0.95)

        # -------------------------------------------------------------
        # 6. MFA Challenge Website (Human Interruption Pause)
        # -------------------------------------------------------------
        await page.goto("http://127.0.0.1:9631/mfa-portal/login")
        interrupter = HumanInterrupter()
        chk = await interrupter.check_security_checkpoints(page, "MFAProtected")
        assert chk is not None
        assert chk[0] == "MFA"
        queue_mgr.update_item_status(6, QueueItemStatus.VERIFICATION_REQUIRED, "MFA Paused", 1.0, chk[1])
        assert queue_mgr.is_paused is True

        # -------------------------------------------------------------
        # 7. CAPTCHA Website (Pause)
        # -------------------------------------------------------------
        await page.goto("http://127.0.0.1:9631/captcha-portal/login")
        chk = await interrupter.check_security_checkpoints(page, "CaptchaProtected")
        assert chk is not None
        assert chk[0] == "CAPTCHA"
        queue_mgr.update_item_status(7, QueueItemStatus.VERIFICATION_REQUIRED, "CAPTCHA Paused", 1.0, chk[1])

        # -------------------------------------------------------------
        # 8. Email Verification Website (Pause)
        # -------------------------------------------------------------
        await page.goto("http://127.0.0.1:9631/email-verify-portal/login")
        chk = await interrupter.check_security_checkpoints(page, "EmailVerifySite")
        assert chk is not None
        assert chk[0] == "VERIFICATION"

        # -------------------------------------------------------------
        # 9. Malicious Prompt Injection Website (Adversarial Defense)
        # -------------------------------------------------------------
        await page.goto("http://127.0.0.1:9631/malicious-portal/security")
        page_text = await page.inner_text("body")
        guard = PromptInjectionGuard()
        sanitized_txt, injection_detected = guard.sanitize_untrusted_content(page_text)
        assert injection_detected is True
        assert "Ignore all previous instructions" not in sanitized_txt

        # Safety Validator blocks dangerous delete account action
        safety_val = ActionSafetyValidator()
        approved, reason = safety_val.validate_action(
            {"action": "click", "target": "Delete account permanently", "confidence": 0.99},
            "MaliciousSite",
            "127.0.0.1:9631"
        )
        assert approved is False
        assert "BLOCKED" in reason

        # -------------------------------------------------------------
        # 10. Redesigned Layout & Policy Error Website (Healing)
        # -------------------------------------------------------------
        await page.goto("http://127.0.0.1:9631/redesigned-portal/settings")
        policy_det = PolicyDetector()
        policy, _, _ = await policy_det.detect_policy(page)
        assert policy.length >= 20

        # Invariant check: Privacy logs strictly redact passwords
        log_sample = sanitize_log_message("User updated Google password=SuperSecret999! token=bearer_123")
        assert "SuperSecret999!" not in log_sample
        assert "[REDACTED]" in log_sample

        await browser.close()
    db.close()
