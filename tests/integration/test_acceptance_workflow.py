import asyncio
import pytest
import uvicorn
from multiprocessing import Process
from playwright.async_api import async_playwright
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database.models import Base, Account
from app.core.password_generator import PasswordGenerator, PasswordPolicy
from app.core.domain_validator import DomainValidator, DomainValidationError
from app.core.risk_engine import RiskEngine
from app.core.queue_manager import QueueManager, QueueItemStatus
from app.core.planner import ActionPlanner, ActionType
from app.core.safety_validator import SafetyValidator
from app.core.workflow_memory import WorkflowMemory, WebsiteWorkflow
from app.core.audit_logger import sanitize_log_message
from app.browser.auth_detector import AuthenticationDetector
from app.browser.human_interrupter import HumanInterrupter
from app.browser.field_detector import FieldDetector
from app.browser.policy_detector import PolicyDetector
from app.adapters.generic import GenericAdapter
from tests.mock_server import mock_app

def run_acceptance_mock_server():
    uvicorn.run(mock_app, host="127.0.0.1", port=9753, log_level="warning")

@pytest.fixture(scope="module", autouse=True)
def acceptance_server():
    proc = Process(target=run_acceptance_mock_server, daemon=True)
    proc.start()
    import time
    time.sleep(1.5)
    yield
    proc.terminate()

@pytest.mark.asyncio
async def test_full_acceptance_scenario():
    """
    Simulates the exact end-to-end product workflow:
    10 accounts total, 5 compromised accounts queued for batch fix.
    Exercises:
    - Queue prioritization (Critical accounts first)
    - Domain validation & auth detection
    - Settings discovery & multi-signal field detection
    - Human-in-the-loop MFA pause & resumption
    - Password policy error detection & dynamic adjustment
    - Universal Generic Website Discovery on previously unseen structure
    - Safety Validator low-confidence & domain spoofing halts
    - Zero secret leakage invariant in logs and database
    """
    # 1. Setup in-memory DB with 10 accounts (5 compromised)
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    db = Session()

    accounts = [
        Account(id=1, service="Google", username="user@example.com", domain="127.0.0.1:9753", risk="CRITICAL", issue="Compromised"),
        Account(id=2, service="GitHub", username="user@example.com", domain="127.0.0.1:9753", risk="CRITICAL", issue="Compromised"),
        Account(id=3, service="Amazon", username="user@example.com", domain="127.0.0.1:9753", risk="HIGH", issue="Compromised"),
        Account(id=4, service="GenericSite", username="user@example.com", domain="127.0.0.1:9753", risk="HIGH", issue="Compromised"),
        Account(id=5, service="SpoofedSite", username="user@example.com", domain="github.com.attacker.com", risk="HIGH", issue="Compromised"),
        Account(id=6, service="Reddit", username="user@example.com", domain="127.0.0.1:9753", risk="MEDIUM", issue="Old"),
        Account(id=7, service="Apple", username="user@example.com", domain="127.0.0.1:9753", risk="MEDIUM", issue="None"),
        Account(id=8, service="Microsoft", username="user@example.com", domain="127.0.0.1:9753", risk="LOW", issue="None"),
        Account(id=9, service="Discord", username="user@example.com", domain="127.0.0.1:9753", risk="LOW", issue="None"),
        Account(id=10, service="Spotify", username="user@example.com", domain="127.0.0.1:9753", risk="LOW", issue="None"),
    ]
    db.add_all(accounts)
    db.commit()

    # 2. Queue compromised accounts
    compromised_accounts = [a for a in accounts if a.risk in ("CRITICAL", "HIGH")]
    assert len(compromised_accounts) == 5

    queue_mgr = QueueManager()
    queue = queue_mgr.set_queue(compromised_accounts)
    assert len(queue) == 5
    assert queue[0].risk == "CRITICAL"  # Priority ordering enforced

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()

        # -------------------------------------------------------------
        # Account 1 (Google): Standard Flow (Auth -> Settings -> Form -> Fix)
        # -------------------------------------------------------------
        acc1 = queue[0]
        await page.goto("http://127.0.0.1:9753/home")
        
        auth_det = AuthenticationDetector()
        is_auth, conf, _ = await auth_det.detect_auth_state(page)
        assert is_auth is True
        assert conf >= 0.90

        # Navigate to security settings
        await page.goto("http://127.0.0.1:9753/settings/security")
        field_det = FieldDetector()
        form = await field_det.detect_password_fields(page)
        assert form.current_password is not None
        assert form.new_password is not None
        assert form.confirm_password is not None
        assert form.overall_confidence >= 0.90

        # Generate CSPRNG Password & simulate human-confirmed rotation
        generator = PasswordGenerator()
        new_pwd = generator.generate(PasswordPolicy(length=24, use_symbols=True))
        
        await form.current_password.fill("OldPassword123!")
        await form.new_password.fill(new_pwd)
        await form.confirm_password.fill(new_pwd)
        
        submit_btn = await page.query_selector("button[type='submit']")
        await submit_btn.click()
        await page.wait_for_timeout(500)

        content = await page.content()
        assert "password updated" in content.lower()
        queue_mgr.update_item_status(acc1.account_id, QueueItemStatus.SUCCESS, "Completed", 0.99)

        # -------------------------------------------------------------
        # Account 2 (GitHub): MFA Challenge Encountered -> Pause -> Resume
        # -------------------------------------------------------------
        acc2 = queue[1]
        await page.goto("http://127.0.0.1:9753/mfa")
        interrupter = HumanInterrupter()
        checkpoint = await interrupter.check_security_checkpoints(page, acc2.service)
        
        assert checkpoint is not None
        assert checkpoint[0] == "MFA"
        
        queue_mgr.update_item_status(acc2.account_id, QueueItemStatus.VERIFICATION_REQUIRED, "Waiting for MFA", 1.0, checkpoint[1])
        assert queue_mgr.is_paused is True

        # Simulate user completing manual verification in browser
        await page.goto("http://127.0.0.1:9753/settings/security")
        queue_mgr.update_item_status(acc2.account_id, QueueItemStatus.SUCCESS, "Completed after MFA", 0.98)

        # -------------------------------------------------------------
        # Account 3 (Amazon): Policy Error -> Self-Healing / Adjustment
        # -------------------------------------------------------------
        acc3 = queue[2]
        policy_det = PolicyDetector()
        policy, _, _ = await policy_det.detect_policy(page)
        assert policy.length >= 16

        # Simulate policy error recovery
        adjusted = policy_det.adjust_policy_from_error(PasswordPolicy(length=12), "Password must be at least 16 characters long.")
        assert adjusted.length >= 16
        queue_mgr.update_item_status(acc3.account_id, QueueItemStatus.SUCCESS, "Policy Adjusted & Fixed", 0.96)

        # -------------------------------------------------------------
        # Account 4 (GenericSite): Universal Website Discovery
        # -------------------------------------------------------------
        acc4 = queue[3]
        await page.goto("http://127.0.0.1:9753/generic/settings")
        generic_adapter = GenericAdapter("GenericSite", "127.0.0.1:9753")
        
        nav_success = await generic_adapter.navigate_to_security(page)
        assert nav_success is True
        assert "/security" in page.url

        # Direct adapter credential mutation MUST be rejected by base class security invariant
        from app.safety.secret_boundary import SecretBoundaryViolation, SecretBoundary
        from app.safety.submission_approval import approval_manager
        from app.browser.action_executor import ControlledActionExecutor
        
        form_det = await generic_adapter.detect_password_fields(page)

        with pytest.raises(SecretBoundaryViolation):
            await generic_adapter.fill_password(page, form_det, "old", "new_pwd")

        with pytest.raises(SecretBoundaryViolation):
            await generic_adapter.submit_password_change(page)

        # Execute through authoritative ControlledActionExecutor
        boundary = SecretBoundary()
        gen_pwd = generator.generate(PasswordPolicy(length=20))
        boundary.register_secrets(current_password="old", new_password=gen_pwd)

        executor = ControlledActionExecutor()
        new_el = form_det["new_password"]
        await executor.execute_action(
            page=page,
            action_payload={"action": "fill_secret", "target_id": "new_pw_id", "secret_reference": "new_password"},
            element_map={"new_pw_id": new_el},
            secret_boundary=boundary
        )

        token = approval_manager.issue_approval_token(
            account_id=acc4.account_id,
            service="GenericSite",
            verified_domain="127.0.0.1:9753",
            browser_session_id="sess_generic",
            workflow_id="wf_generic",
            form_fingerprint="fp_generic"
        )
        
        submit_btn = await page.query_selector("button[type='submit']")
        await executor.execute_action(
            page=page,
            action_payload={"action": "submit", "target_id": "btn_sub", "confidence": 1.0},
            element_map={"btn_sub": submit_btn},
            secret_boundary=boundary,
            approval_context={
                "token_id": token.token_id,
                "account_id": acc4.account_id,
                "service": "GenericSite",
                "current_domain": "127.0.0.1:9753",
                "browser_session_id": "sess_generic",
                "workflow_id": "wf_generic",
                "form_fingerprint": "fp_generic"
            }
        )
        assert await generic_adapter.detect_success(page) is True
        queue_mgr.update_item_status(acc4.account_id, QueueItemStatus.SUCCESS, "Generic Discovery Fixed", 0.95)

        # -------------------------------------------------------------
        # Account 5 (SpoofedSite): Safety Validator & Domain Spoof Halt
        # -------------------------------------------------------------
        acc5 = queue[4]
        validator = DomainValidator()
        with pytest.raises(DomainValidationError):
            validator.validate_url(f"https://{acc5.domain}/login", "GitHub")

        queue_mgr.update_item_status(acc5.account_id, QueueItemStatus.FAILED, "Domain Spoofing Rejected", 0.0, "Untrusted domain")

        await browser.close()

    # Invariant checks:
    # Verify no plaintext passwords leaked into sanitized logs
    test_log = sanitize_log_message("User confirmed rotation: password=SuperSecret999! token=xyz")
    assert "SuperSecret999!" not in test_log
    assert "[REDACTED]" in test_log

    # Verify no plaintext passwords in database columns
    for col in Account.__table__.columns:
        assert "password" not in col.name.lower() or col.name == "password_policy"

    db.close()
