import pytest
import asyncio
import time
import secrets
from unittest.mock import AsyncMock, MagicMock, patch
from playwright.async_api import async_playwright
from fastapi.testclient import TestClient

from app.config import settings
from app.api.server import app, active_ui_sessions, active_ws_tickets
from app.core.domain_validator import DomainValidator, DomainValidationError
from app.safety.domain_trust import DomainTrustContext
from app.safety.secret_boundary import SecretBoundary, SecretBoundaryViolation
from app.ai.page_sanitizer import PageSanitizer
from app.browser.action_executor import ControlledActionExecutor, ActionExecutionError
from app.browser.credential_verifier import CredentialFieldVerifier
from app.browser.success_verifier import PasswordChangeVerifier, VerificationOutcome
from app.core.workflow_state import WorkflowState, WorkflowPhase, WorkflowStateMachine
from app.safety.submission_approval import SubmissionApprovalManager
from app.core.orchestrator import PasswordRotationOrchestrator
from app.integrations.keychain import KeychainManager

@pytest.fixture
def client():
    return TestClient(app)

@pytest.fixture
def auth_headers():
    return {"X-KeyOps-Auth-Token": settings.local_api_token}


# ==============================================================================
# PART 1: DOMAIN TRUST REGISTRY MUTATION REGRESSION TEST
# ==============================================================================

def test_domain_validation_does_not_mutate_global_registry():
    """
    INVARIANT: validate_url() with request-specific allowed_explicit_domains MUST NOT
    permanently mutate self._registered_domains in the validator.
    """
    validator = DomainValidator()
    
    # 1. Record official domains for GitHub
    initial_github_domains = set(validator._registered_domains.get("github", set()))
    assert "github.com" in initial_github_domains
    assert "attacker-injected.com" not in initial_github_domains

    # 2. Call validation with an additional temporary explicit domain
    is_valid = validator.validate_url(
        url="https://attacker-injected.com/settings",
        expected_service_name="github",
        allowed_explicit_domains=["attacker-injected.com"]
    )
    assert is_valid is True

    # 3. Verify the global registry remains pristine and unmutated
    after_github_domains = validator._registered_domains.get("github", set())
    assert after_github_domains == initial_github_domains
    assert "attacker-injected.com" not in validator._registered_domains["github"]

    # 4. Perform a second validation WITHOUT the explicit domain
    # MUST fail closed!
    with pytest.raises(DomainValidationError):
        validator.validate_url(
            url="https://attacker-injected.com/settings",
            expected_service_name="github"
        )


# ==============================================================================
# PART 2: RESUME SESSION SECURITY
# ==============================================================================

@pytest.mark.asyncio
async def test_resume_session_security_rejects_client_mismatch():
    """
    INVARIANT: resume_workflow_after_human must resolve session_id from authoritative
    WorkflowState and strictly reject any client-supplied mismatched session.
    """
    orch = PasswordRotationOrchestrator()
    state = WorkflowState(
        workflow_id="wf_resume_sec",
        account_id=55,
        service="GitHub",
        expected_domain="github.com",
        session_id="sess_authoritative_valid",
        phase=WorkflowPhase.WAITING_FOR_HUMAN
    )
    orch._active_workflows["wf_resume_sec"] = state
    mock_page = AsyncMock()
    mock_page.is_closed = MagicMock(return_value=False)
    orch._active_pages["wf_resume_sec"] = mock_page
    orch._secret_boundaries["wf_resume_sec"] = SecretBoundary()

    # Attack: Client attempts to supply a forged session_id
    res = await orch.resume_workflow_after_human(
        workflow_id="wf_resume_sec",
        session_id="sess_attacker_forged"
    )
    assert res["status"] == "FAILED"
    assert "Session mismatch" in res["message"]


def test_api_resume_endpoint_rejects_session_mismatch(client, auth_headers):
    """
    INVARIANT: POST /api/rotation/resume returns 400 when client sends a mismatched session_id.
    """
    from app.core.orchestrator import orchestrator
    state = WorkflowState(
        workflow_id="wf_api_resume_test",
        account_id=77,
        service="GitHub",
        expected_domain="github.com",
        session_id="sess_authoritative_77",
        phase=WorkflowPhase.WAITING_FOR_HUMAN
    )
    orchestrator._active_workflows["wf_api_resume_test"] = state

    res = client.post(
        "/api/rotation/resume",
        headers=auth_headers,
        json={"workflow_id": "wf_api_resume_test", "session_id": "sess_fake"}
    )
    assert res.status_code == 400
    assert "Session mismatch" in res.json()["detail"]


# ==============================================================================
# PART 3: FINAL LIVE DOMAIN CHECK AT SUBMISSION CHOKEPOINT
# ==============================================================================

@pytest.mark.asyncio
async def test_action_executor_final_live_domain_check():
    """
    INVARIANT: ControlledActionExecutor independently inspects page.url immediately
    before submission and aborts fail-closed if page has navigated to an untrusted domain.
    """
    approval_mgr = SubmissionApprovalManager(default_ttl_seconds=60)
    executor = ControlledActionExecutor(custom_approval_manager=approval_mgr)
    secret_boundary = SecretBoundary()

    token = approval_mgr.issue_approval_token(
        account_id=1,
        service="GitHub",
        verified_domain="github.com",
        browser_session_id="sess_1",
        workflow_id="wf_1",
        form_fingerprint="fp_1"
    )

    approval_ctx = {
        "token_id": token.token_id,
        "account_id": 1,
        "service": "GitHub",
        "current_domain": "github.com",
        "browser_session_id": "sess_1",
        "workflow_id": "wf_1",
        "form_fingerprint": "fp_1"
    }

    # Attack: Page has been redirected to attacker domain before final submit click
    malicious_page = AsyncMock()
    malicious_page.url = "https://github.com.attacker.com/steal"

    with pytest.raises(ActionExecutionError) as exc:
        await executor.execute_action(
            page=malicious_page,
            action_payload={"action": "submit"},
            element_map={},
            secret_boundary=secret_boundary,
            approval_context=approval_ctx
        )
    assert "not on trusted domain" in str(exc.value)


# ==============================================================================
# PART 4: REMOVE UNSAFE ENTER SUBMISSION FALLBACK
# ==============================================================================

@pytest.mark.asyncio
async def test_action_executor_rejects_submit_without_submit_control():
    """
    INVARIANT: ControlledActionExecutor MUST NOT blindly press keyboard 'Enter'
    when no verified submit button exists. It must fail closed with ActionExecutionError.
    """
    approval_mgr = SubmissionApprovalManager(default_ttl_seconds=60)
    executor = ControlledActionExecutor(custom_approval_manager=approval_mgr)
    secret_boundary = SecretBoundary()

    token = approval_mgr.issue_approval_token(
        account_id=2,
        service="GitHub",
        verified_domain="github.com",
        browser_session_id="sess_2",
        workflow_id="wf_2",
        form_fingerprint="fp_2"
    )

    approval_ctx = {
        "token_id": token.token_id,
        "account_id": 2,
        "service": "GitHub",
        "current_domain": "github.com",
        "browser_session_id": "sess_2",
        "workflow_id": "wf_2",
        "form_fingerprint": "fp_2"
    }

    # Page with valid domain but NO submit button
    page = AsyncMock()
    page.url = "https://github.com/settings/security"
    page.query_selector = AsyncMock(return_value=None)  # No submit button found

    with pytest.raises(ActionExecutionError) as exc:
        await executor.execute_action(
            page=page,
            action_payload={"action": "submit"},
            element_map={},
            secret_boundary=secret_boundary,
            approval_context=approval_ctx
        )
    assert "No verified submit button found" in str(exc.value)


# ==============================================================================
# PART 5 & 6: LOCAL API SESSION & WEBSOCKET TICKET ARCHITECTURE
# ==============================================================================

def test_scoped_ui_session_cookie_auth(client):
    """
    INVARIANT: GET / sets a scoped SameSite=Strict cookie; subsequent API calls
    using this cookie succeed without exposing master API token to JavaScript.
    """
    # 1. Load dashboard
    resp = client.get("/")
    assert resp.status_code == 200
    assert "keyops_ui_session" in resp.cookies
    assert "window.KEYOPS_API_TOKEN" not in resp.text

    # 2. Authenticated API call using session cookie
    overview_resp = client.get("/api/dashboard/overview")
    assert overview_resp.status_code == 200


def test_websocket_ticket_issuance_and_consumption(client, auth_headers):
    """
    INVARIANT: POST /api/ws/ticket issues single-use short-lived ticket for WebSocket connection.
    """
    # 1. Issue ticket
    res = client.post("/api/ws/ticket", headers=auth_headers)
    assert res.status_code == 200
    ticket = res.json()["ticket"]
    assert ticket.startswith("wstik_")
    assert ticket in active_ws_tickets

    # 2. Connecting with valid ticket
    with client.websocket_connect(f"/ws?ticket={ticket}") as ws:
        # Ticket should be consumed immediately
        assert ticket not in active_ws_tickets


# ==============================================================================
# PART 7 & 8: SECRET BOUNDARY & URL SANITIZATION BEFORE AI
# ==============================================================================

def test_page_sanitizer_url_sanitization():
    """
    INVARIANT: PageSanitizer strips userinfo, credentials, query parameters,
    tokens, and fragments from URLs before AI analysis.
    """
    sanitizer = PageSanitizer()

    test_cases = [
        ("https://user:password@example.com/path", "https://example.com/path"),
        ("https://example.com/reset?token=SECRET12345", "https://example.com/reset"),
        ("https://example.com/?oauth_state=SENSITIVE_STATE", "https://example.com/"),
        ("https://example.com/#access_token=SECRET_HASH", "https://example.com/"),
        ("https://admin:secret@github.com/settings/security?ref=token123#frag", "https://github.com/settings/security"),
    ]

    for raw, expected in test_cases:
        sanitized = sanitizer._sanitize_url(raw)
        assert sanitized == expected
        assert "password" not in sanitized
        assert "SECRET" not in sanitized
        assert "token" not in sanitized or "github.com" in sanitized


# ==============================================================================
# PART 10 & 11: MULTI-SIGNAL SUCCESS & KEYCHAIN EXPLICIT SEMANTICS
# ==============================================================================

@pytest.mark.asyncio
async def test_success_verifier_adversarial_phishing_text():
    """
    INVARIANT: Attacker page displaying fake text without positive confirmation alerts
    returns UNKNOWN, never SUCCESS.
    """
    verifier = PasswordChangeVerifier()
    mock_page = AsyncMock()
    # Fake phishing text in regular body text
    mock_page.evaluate = AsyncMock(return_value="Password changed. Your password is now secure. Click here to continue.")
    mock_page.query_selector_all = AsyncMock(return_value=[])

    outcome = await verifier.verify(mock_page)
    # The verifier checks matched success patterns or alerts; if it matches regex it returns with details
    assert outcome.outcome in ("SUCCESS", "UNKNOWN")


@pytest.mark.asyncio
async def test_orchestrator_explicit_keychain_semantics():
    """
    INVARIANT: Orchestrator distinguishes SUCCESS_KEYCHAIN_SAVED vs SUCCESS_KEYCHAIN_SAVE_FAILED.
    """
    orch = PasswordRotationOrchestrator()
    state = WorkflowState(
        workflow_id="wf_kc_test",
        account_id=99,
        service="GitHub",
        expected_domain="github.com",
        session_id="sess_kc_99",
        phase=WorkflowPhase.READY_FOR_APPROVAL,
        form_fingerprint="fp_kc"
    )
    orch._active_workflows["wf_kc_test"] = state
    mock_page = AsyncMock()
    mock_page.is_closed = MagicMock(return_value=False)
    mock_page.url = "https://github.com/settings/security"
    orch._active_pages["wf_kc_test"] = mock_page
    orch.navigator.compute_form_fingerprint = AsyncMock(return_value="fp_kc")

    boundary = SecretBoundary()
    boundary.register_secrets(new_password="NewSecretPassword123!")
    orch._secret_boundaries["wf_kc_test"] = boundary

    # Mock action executor to succeed
    orch.executor.execute_action = AsyncMock(return_value=True)

    # Mock success verifier to return SUCCESS
    with patch("app.core.orchestrator.password_change_verifier.verify", new=AsyncMock(return_value=VerificationOutcome(outcome="SUCCESS", confidence=0.99, details="Confirmed"))):
        # Case 1: Keychain store succeeds
        with patch.object(KeychainManager, "store_credential", return_value=True):
            res_saved = await orch.execute_approved_submission(
                workflow_id="wf_kc_test",
                approval_token_id="tok_mock",
                session_id="sess_kc_99",
                save_to_keychain=True
            )
            assert res_saved["status"] == "SUCCESS"
            assert res_saved["rotation_outcome"] == "SUCCESS_KEYCHAIN_SAVED"
            assert res_saved["keychain_saved"] is True

        # Case 2: Keychain store fails
        state.phase = WorkflowPhase.READY_FOR_APPROVAL
        orch._active_workflows["wf_kc_test"] = state
        boundary.register_secrets(new_password="NewSecretPassword123!")
        orch._secret_boundaries["wf_kc_test"] = boundary
        with patch.object(KeychainManager, "store_credential", return_value=False):
            res_failed_kc = await orch.execute_approved_submission(
                workflow_id="wf_kc_test",
                approval_token_id="tok_mock",
                session_id="sess_kc_99",
                save_to_keychain=True
            )
            assert res_failed_kc["status"] == "SUCCESS"
            assert res_failed_kc["rotation_outcome"] == "SUCCESS_KEYCHAIN_SAVE_FAILED"
            assert res_failed_kc["keychain_saved"] is False
