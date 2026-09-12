import asyncio
import time
from multiprocessing import Process
import pytest
import uvicorn
from playwright.async_api import async_playwright
from fastapi.testclient import TestClient

from app.browser.action_executor import ControlledActionExecutor, ActionExecutionError
from app.browser.success_verifier import PasswordChangeVerifier, VerificationOutcome
from app.ai.navigator import AINavigator
from app.browser.field_detector import FieldDetector
from app.safety.submission_approval import (
    SubmissionApprovalManager,
    approval_manager,
    ApprovalToken
)
from app.safety.secret_boundary import (
    SecretBoundary,
    SecretBoundaryViolation,
    SecretReference
)
from app.safety.domain_trust import DomainTrustContext
from app.safety.action_validator import ActionSafetyValidator
from app.api.server import app
from tests.mock_server import mock_app

def run_attack_mock_server():
    uvicorn.run(mock_app, host="127.0.0.1", port=9654, log_level="warning")

@pytest.fixture(scope="module", autouse=True)
def attack_server():
    proc = Process(target=run_attack_mock_server, daemon=True)
    proc.start()
    time.sleep(1.5)
    yield
    proc.terminate()

# ==============================================================================
# TEST 1: AI chooses unrelated button -> BLOCK
# ==============================================================================
@pytest.mark.asyncio
async def test_attack_1_unrelated_button_blocked():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        await page.goto("http://127.0.0.1:9654/e2e/dangerous-buttons")

        detector = FieldDetector()
        detected = await detector.detect_password_fields(page)
        assert detected.new_password is not None
        fp = await AINavigator().compute_form_fingerprint(page)

        token = approval_manager.issue_approval_token(
            account_id=101,
            service="GitHub",
            verified_domain="127.0.0.1",
            browser_session_id="sess_101",
            workflow_id="wf_101",
            form_fingerprint=fp
        )

        executor = ControlledActionExecutor()
        element_map = {"btn_unrelated": await page.query_selector("#btn-unrelated")}
        boundary = SecretBoundary()

        approval_ctx = {
            "token_id": token.token_id,
            "account_id": 101,
            "service": "GitHub",
            "current_domain": "127.0.0.1",
            "browser_session_id": "sess_101",
            "workflow_id": "wf_101",
            "form_fingerprint": fp
        }

        # AI mistakenly attempts to submit via unrelated button
        with pytest.raises(ActionExecutionError, match="not a verified submit control"):
            await executor.execute_action(
                page=page,
                action_payload={"action": "submit", "target_id": "btn_unrelated"},
                element_map=element_map,
                secret_boundary=boundary,
                approval_context=approval_ctx
            )
        await browser.close()

# ==============================================================================
# TEST 2: AI chooses Delete Account button -> BLOCK
# ==============================================================================
@pytest.mark.asyncio
async def test_attack_2_delete_account_button_blocked():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        await page.goto("http://127.0.0.1:9654/e2e/dangerous-buttons")

        detector = FieldDetector()
        detected = await detector.detect_password_fields(page)
        fp = await AINavigator().compute_form_fingerprint(page)

        token = approval_manager.issue_approval_token(
            account_id=102,
            service="GitHub",
            verified_domain="127.0.0.1",
            browser_session_id="sess_102",
            workflow_id="wf_102",
            form_fingerprint=fp
        )

        executor = ControlledActionExecutor()
        element_map = {"btn_del": await page.query_selector("#btn-delete-account")}
        boundary = SecretBoundary()

        approval_ctx = {
            "token_id": token.token_id,
            "account_id": 102,
            "service": "GitHub",
            "current_domain": "127.0.0.1",
            "browser_session_id": "sess_102",
            "workflow_id": "wf_102",
            "form_fingerprint": fp
        }

        with pytest.raises(ActionExecutionError, match="(destructive or prohibited keyword|not a verified submit control)"):
            await executor.execute_action(
                page=page,
                action_payload={"action": "submit", "target_id": "btn_del"},
                element_map=element_map,
                secret_boundary=boundary,
                approval_context=approval_ctx
            )
        await browser.close()

# ==============================================================================
# TEST 3: AI chooses button from another form -> BLOCK
# ==============================================================================
@pytest.mark.asyncio
async def test_attack_3_button_from_another_form_blocked():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        await page.goto("http://127.0.0.1:9654/e2e/two-forms")

        detector = FieldDetector()
        detected = await detector.detect_password_fields(page)
        fp = await AINavigator().compute_form_fingerprint(page)

        token = approval_manager.issue_approval_token(
            account_id=103,
            service="GitHub",
            verified_domain="127.0.0.1",
            browser_session_id="sess_103",
            workflow_id="wf_103",
            form_fingerprint=fp
        )

        executor = ControlledActionExecutor()
        other_form_btn = await page.query_selector("#btn-delete-form-submit")
        element_map = {"other_btn": other_form_btn}
        boundary = SecretBoundary()

        approval_ctx = {
            "token_id": token.token_id,
            "account_id": 103,
            "service": "GitHub",
            "current_domain": "127.0.0.1",
            "browser_session_id": "sess_103",
            "workflow_id": "wf_103",
            "form_fingerprint": fp
        }

        with pytest.raises(ActionExecutionError, match="(does not belong to active password form|destructive|not a verified submit control)"):
            await executor.execute_action(
                page=page,
                action_payload={"action": "submit", "target_id": "other_btn"},
                element_map=element_map,
                secret_boundary=boundary,
                approval_context=approval_ctx
            )
        await browser.close()

# ==============================================================================
# TEST 4: Password form changes after approval -> BLOCK
# ==============================================================================
@pytest.mark.asyncio
async def test_attack_4_mutated_form_blocked():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        await page.goto("http://127.0.0.1:9654/e2e/mutated-form")

        original_fp = await AINavigator().compute_form_fingerprint(page)

        # User approves original form
        token = approval_manager.issue_approval_token(
            account_id=104,
            service="GitHub",
            verified_domain="127.0.0.1",
            browser_session_id="sess_104",
            workflow_id="wf_104",
            form_fingerprint=original_fp
        )

        # Wait for client-side JS to mutate the form action and add hidden input
        await page.wait_for_timeout(300)

        executor = ControlledActionExecutor()
        btn = await page.query_selector("#btn-sub")
        element_map = {"sub_btn": btn}
        boundary = SecretBoundary()

        # Recomputed live fingerprint will not match the approved original_fp
        live_fp = await AINavigator().compute_form_fingerprint(page)
        assert live_fp != original_fp

        approval_ctx = {
            "token_id": token.token_id,
            "account_id": 104,
            "service": "GitHub",
            "current_domain": "127.0.0.1",
            "browser_session_id": "sess_104",
            "workflow_id": "wf_104",
            "form_fingerprint": live_fp
        }

        with pytest.raises(ActionExecutionError, match="Form fingerprint changed"):
            await executor.execute_action(
                page=page,
                action_payload={"action": "submit", "target_id": "sub_btn"},
                element_map=element_map,
                secret_boundary=boundary,
                approval_context=approval_ctx
            )
        await browser.close()

# ==============================================================================
# TEST 5: Browser redirects to attacker.com immediately before submit -> BLOCK
# ==============================================================================
@pytest.mark.asyncio
async def test_attack_5_redirect_to_attacker_blocked():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        await page.goto("http://127.0.0.1:9654/e2e/dangerous-buttons")

        detector = FieldDetector()
        detected = await detector.detect_password_fields(page)
        fp = await AINavigator().compute_form_fingerprint(page)

        token = approval_manager.issue_approval_token(
            account_id=105,
            service="GitHub",
            verified_domain="github.com",
            browser_session_id="sess_105",
            workflow_id="wf_105",
            form_fingerprint=fp
        )

        executor = ControlledActionExecutor()
        btn = await page.query_selector("#btn-submit-pwd")
        element_map = {"sub_btn": btn}
        boundary = SecretBoundary()

        approval_ctx = {
            "token_id": token.token_id,
            "account_id": 105,
            "service": "GitHub",
            "current_domain": "github.com",
            "browser_session_id": "sess_105",
            "workflow_id": "wf_105",
            "form_fingerprint": fp
        }

        # The live URL is on 127.0.0.1, but token expected github.com
        with pytest.raises(ActionExecutionError, match="(is not on trusted domain|Token domain mismatch)"):
            await executor.execute_action(
                page=page,
                action_payload={"action": "submit", "target_id": "sub_btn"},
                element_map=element_map,
                secret_boundary=boundary,
                approval_context=approval_ctx
            )
        await browser.close()

# ==============================================================================
# TEST 6: Fake success alert -> UNKNOWN
# ==============================================================================
@pytest.mark.asyncio
async def test_attack_6_fake_success_alert_yields_unknown():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        await page.goto("http://127.0.0.1:9654/e2e/fake-success-alert")

        verifier = PasswordChangeVerifier()
        result = await verifier.verify(
            page,
            expected_domain="127.0.0.1",
            expected_service="Generic"
        )

        # A fake alert box with password inputs still present and no URL transition must be UNKNOWN
        assert result.outcome == "UNKNOWN"
        await browser.close()

# ==============================================================================
# TEST 7: Fake body text "Password changed" -> UNKNOWN
# ==============================================================================
@pytest.mark.asyncio
async def test_attack_7_fake_body_text_yields_unknown():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        await page.goto("http://127.0.0.1:9654/e2e/fake-body-text")

        verifier = PasswordChangeVerifier()
        result = await verifier.verify(
            page,
            expected_domain="127.0.0.1",
            expected_service="Generic"
        )

        assert result.outcome == "UNKNOWN"
        await browser.close()

# ==============================================================================
# TEST 8: Success alert + legitimate structural post-change state -> SUCCESS
# ==============================================================================
@pytest.mark.asyncio
async def test_attack_8_legitimate_success_verified():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        await page.goto("http://127.0.0.1:9654/e2e/legit-success-post")

        verifier = PasswordChangeVerifier()
        # Form inputs are completely gone and dedicated status alert is present
        result = await verifier.verify(
            page,
            expected_domain="127.0.0.1",
            expected_service="Generic"
        )

        assert result.outcome == "SUCCESS"
        assert len(result.signals) >= 2
        await browser.close()

# ==============================================================================
# TEST 9: Approval token replay -> BLOCK
# ==============================================================================
def test_attack_9_approval_token_replay_blocked():
    mgr = SubmissionApprovalManager()
    token = mgr.issue_approval_token(
        account_id=1,
        service="GitHub",
        verified_domain="github.com",
        browser_session_id="sess_1",
        workflow_id="wf_1",
        form_fingerprint="fp_test_hash"
    )

    # First consumption succeeds
    valid1, _ = mgr.validate_and_consume_token(
        token_id=token.token_id,
        account_id=1,
        service="GitHub",
        current_domain="github.com",
        browser_session_id="sess_1",
        workflow_id="wf_1",
        current_form_fingerprint="fp_test_hash"
    )
    assert valid1 is True

    # Replay consumption fails closed
    valid2, err = mgr.validate_and_consume_token(
        token_id=token.token_id,
        account_id=1,
        service="GitHub",
        current_domain="github.com",
        browser_session_id="sess_1",
        workflow_id="wf_1",
        current_form_fingerprint="fp_test_hash"
    )
    assert valid2 is False
    assert ("already" in err.lower() and "consumed" in err.lower()) or "not found" in err.lower()

# ==============================================================================
# TEST 10: Expired approval token -> BLOCK
# ==============================================================================
def test_attack_10_expired_approval_token_blocked():
    mgr = SubmissionApprovalManager(default_ttl_seconds=-10)  # Created in the past
    token = mgr.issue_approval_token(
        account_id=2,
        service="GitHub",
        verified_domain="github.com",
        browser_session_id="sess_2",
        workflow_id="wf_2",
        form_fingerprint="fp_test_hash"
    )

    valid, err = mgr.validate_and_consume_token(
        token_id=token.token_id,
        account_id=2,
        service="GitHub",
        current_domain="github.com",
        browser_session_id="sess_2",
        workflow_id="wf_2",
        current_form_fingerprint="fp_test_hash"
    )
    assert valid is False
    assert "expired" in err.lower()

# ==============================================================================
# TEST 11: Wrong account -> BLOCK
# ==============================================================================
def test_attack_11_wrong_account_blocked():
    mgr = SubmissionApprovalManager()
    token = mgr.issue_approval_token(
        account_id=10,
        service="GitHub",
        verified_domain="github.com",
        browser_session_id="sess_10",
        workflow_id="wf_10",
        form_fingerprint="fp_test_hash"
    )

    valid, err = mgr.validate_and_consume_token(
        token_id=token.token_id,
        account_id=999,  # Wrong account
        service="GitHub",
        current_domain="github.com",
        browser_session_id="sess_10",
        workflow_id="wf_10",
        current_form_fingerprint="fp_test_hash"
    )
    assert valid is False
    assert "account" in err.lower()

# ==============================================================================
# TEST 12: Wrong workflow -> BLOCK
# ==============================================================================
def test_attack_12_wrong_workflow_blocked():
    mgr = SubmissionApprovalManager()
    token = mgr.issue_approval_token(
        account_id=12,
        service="GitHub",
        verified_domain="github.com",
        browser_session_id="sess_12",
        workflow_id="wf_12",
        form_fingerprint="fp_test_hash"
    )

    valid, err = mgr.validate_and_consume_token(
        token_id=token.token_id,
        account_id=12,
        service="GitHub",
        current_domain="github.com",
        browser_session_id="sess_12",
        workflow_id="wf_wrong",  # Wrong workflow
        current_form_fingerprint="fp_test_hash"
    )
    assert valid is False
    assert "workflow" in err.lower()

# ==============================================================================
# TEST 13: Wrong browser session -> BLOCK
# ==============================================================================
def test_attack_13_wrong_browser_session_blocked():
    mgr = SubmissionApprovalManager()
    token = mgr.issue_approval_token(
        account_id=13,
        service="GitHub",
        verified_domain="github.com",
        browser_session_id="sess_13",
        workflow_id="wf_13",
        form_fingerprint="fp_test_hash"
    )

    valid, err = mgr.validate_and_consume_token(
        token_id=token.token_id,
        account_id=13,
        service="GitHub",
        current_domain="github.com",
        browser_session_id="sess_attacker_session",  # Wrong browser session
        workflow_id="wf_13",
        current_form_fingerprint="fp_test_hash"
    )
    assert valid is False
    assert "session" in err.lower()

# ==============================================================================
# TEST 14: Old process-instance token -> BLOCK
# ==============================================================================
def test_attack_14_old_process_instance_token_blocked():
    mgr = SubmissionApprovalManager()
    token = mgr.issue_approval_token(
        account_id=14,
        service="GitHub",
        verified_domain="github.com",
        browser_session_id="sess_14",
        workflow_id="wf_14",
        form_fingerprint="fp_test_hash"
    )

    # Tamper token's process_instance_id to simulate restart / cross-process replay
    token.process_instance_id = "old-dead-pid-uuid"

    valid, err = mgr.validate_and_consume_token(
        token_id=token.token_id,
        account_id=14,
        service="GitHub",
        current_domain="github.com",
        browser_session_id="sess_14",
        workflow_id="wf_14",
        current_form_fingerprint="fp_test_hash"
    )
    assert valid is False
    assert "process instance" in err.lower()

# ==============================================================================
# TEST 15: Secret embedded in AI payload -> REMOVED
# ==============================================================================
def test_attack_15_secrets_removed_from_ai_payload():
    payload = {
        "title": "Account Settings",
        "url": "https://github.com/settings/security",
        "sensitive_cookie": "session_id=attacker_leak_123",
        "auth_header": "Bearer secret_jwt_token",
        "raw_password": "super_secret_plaintext_password",
        "secret_reference": "current_password",
        "unauthorized_nested": {
            "otp_secret": "123456",
            "recovery_codes": ["code1", "code2"]
        }
    }

    sanitized = SecretBoundary.sanitize_payload_for_ai(payload)
    
    # Verify unauthorized and secret keys are completely dropped
    assert "unauthorized_nested" not in sanitized
    assert "sensitive_cookie" not in sanitized
    assert "auth_header" not in sanitized
    assert "raw_password" not in sanitized
    
    # Allowed fields kept
    assert sanitized["title"] == "Account Settings"
    assert sanitized["url"] == "https://github.com/settings/security"
    assert sanitized["secret_reference"] == "current_password"
    
    # Zero raw leak strings anywhere in serialized result
    import json
    serialized = json.dumps(sanitized)
    assert "attacker_leak" not in serialized
    assert "secret_jwt" not in serialized
    assert "super_secret" not in serialized
    assert "123456" not in serialized

# ==============================================================================
# TEST 16: Master API token in WebSocket URL -> BLOCK/ABSENT
# ==============================================================================
def test_attack_16_master_api_token_in_websocket_rejected():
    client = TestClient(app)
    
    # Connecting with query param ?token=<master_token> is strictly blocked and rejected
    with pytest.raises(Exception):
        with client.websocket_connect("/ws?token=master_secret_api_token"):
            pass

# ==============================================================================
# TEST 17: Prompt injection attempt to force submission -> BLOCK
# ==============================================================================
@pytest.mark.asyncio
async def test_attack_17_prompt_injection_cannot_submit():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        await page.goto("http://127.0.0.1:9654/e2e/prompt-injection")

        # ActionSafetyValidator tests
        validator = ActionSafetyValidator()
        # Autonomous AI submission proposal must be denied
        allowed, reason = validator.validate_action(
            action_payload={"action": "submit", "target_id": "btn-submit"},
            service_name="GitHub",
            current_domain="github.com",
            has_user_approval=False
        )
        assert allowed is False
        assert "Explicit human approval is required" in reason

        await browser.close()

# ==============================================================================
# TEST 18: Malicious DOM attempting to fake submit control -> BLOCK
# ==============================================================================
@pytest.mark.asyncio
async def test_attack_18_malicious_dom_fake_submit_blocked():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        await page.goto("http://127.0.0.1:9654/e2e/malicious-dom-stealth")

        detector = FieldDetector()
        detected = await detector.detect_password_fields(page)
        fp = await AINavigator().compute_form_fingerprint(page)

        token = approval_manager.issue_approval_token(
            account_id=118,
            service="Generic",
            verified_domain="127.0.0.1",
            browser_session_id="sess_118",
            workflow_id="wf_118",
            form_fingerprint=fp
        )

        executor = ControlledActionExecutor()
        fake_btn = await page.query_selector("#fake-submit-btn")
        element_map = {"fake_btn": fake_btn}
        boundary = SecretBoundary()

        approval_ctx = {
            "token_id": token.token_id,
            "account_id": 118,
            "service": "Generic",
            "current_domain": "127.0.0.1",
            "browser_session_id": "sess_118",
            "workflow_id": "wf_118",
            "form_fingerprint": fp
        }

        # Div masquerading as button outside the form must be rejected
        with pytest.raises(ActionExecutionError, match="not a verified submit control"):
            await executor.execute_action(
                page=page,
                action_payload={"action": "submit", "target_id": "fake_btn"},
                element_map=element_map,
                secret_boundary=boundary,
                approval_context=approval_ctx
            )
        await browser.close()
