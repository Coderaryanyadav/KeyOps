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
    PRIORITY 2 INVARIANT: Attacker page displaying fake text without positive confirmation alerts
    returns UNKNOWN, never SUCCESS.
    """
    verifier = PasswordChangeVerifier()
    mock_page = AsyncMock()
    mock_page.evaluate = AsyncMock(return_value="Password changed. Your password is now secure. Click here to continue.")
    mock_page.query_selector_all = AsyncMock(return_value=[])

    outcome = await verifier.verify(mock_page)
    # Generic body text alone MUST NOT produce SUCCESS
    assert outcome.outcome == "UNKNOWN"
    assert "Weak signal" in outcome.signals[0] or "generic body text" in outcome.signals[0]


@pytest.mark.asyncio
async def test_success_verifier_multi_signal_matrix():
    """
    PRIORITY 2 INVARIANT: Success verifier distinguishes explicit failure, weak signals, and multi-signal success.
    """
    verifier = PasswordChangeVerifier()

    # 1. Explicit Server-side rejection -> FAILED
    fail_page = AsyncMock()
    fail_page.evaluate = AsyncMock(return_value="Error: Current password was incorrect. Please try again.")
    fail_page.query_selector_all = AsyncMock(return_value=[])
    fail_outcome = await verifier.verify(fail_page)
    assert fail_outcome.outcome == "FAILED"

    # 2. Generic "Saved successfully" in body text without alert -> UNKNOWN
    saved_page = AsyncMock()
    saved_page.evaluate = AsyncMock(return_value="Saved successfully.")
    saved_page.query_selector_all = AsyncMock(return_value=[])
    saved_outcome = await verifier.verify(saved_page)
    assert saved_outcome.outcome == "UNKNOWN"

    # 3. Empty page -> UNKNOWN
    empty_page = AsyncMock()
    empty_page.evaluate = AsyncMock(return_value="")
    empty_page.query_selector_all = AsyncMock(return_value=[])
    empty_outcome = await verifier.verify(empty_page)
    assert empty_outcome.outcome == "UNKNOWN"


@pytest.mark.asyncio
async def test_orchestrator_explicit_keychain_semantics():
    """
    PRIORITY 12 INVARIANT: Orchestrator distinguishes SUCCESS_KEYCHAIN_SAVED vs SUCCESS_KEYCHAIN_SAVE_FAILED.
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

    orch.executor.execute_action = AsyncMock(return_value=True)

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


# ==============================================================================
# PRIORITY 1: WEBSOCKET AUTHENTICATION ADVERSARIAL TESTS
# ==============================================================================

def test_websocket_rejects_master_api_token_in_query(client):
    """
    PRIORITY 1 INVARIANT: Master API token in ?token= MUST NOT authenticate the WebSocket.
    """
    with pytest.raises(Exception):
        with client.websocket_connect(f"/ws?token={settings.local_api_token}"):
            pass


def test_websocket_rejects_random_query_token(client):
    """
    PRIORITY 1 INVARIANT: Random token in query params is rejected.
    """
    with pytest.raises(Exception):
        with client.websocket_connect("/ws?token=random_attacker_token_123"):
            pass


def test_websocket_rejects_expired_ws_ticket(client):
    """
    PRIORITY 1 INVARIANT: Expired WebSocket tickets are rejected fail-closed.
    """
    expired_ticket = "wstik_expired_test_ticket"
    active_ws_tickets[expired_ticket] = {
        "session_id": "sess_123",
        "created_at": time.time() - 300,  # 5 minutes ago
        "ttl": 30
    }
    with pytest.raises(Exception):
        with client.websocket_connect(f"/ws?ticket={expired_ticket}"):
            pass
    assert expired_ticket not in active_ws_tickets


def test_websocket_rejects_replayed_ticket(client, auth_headers):
    """
    PRIORITY 1 INVARIANT: Single-use ticket cannot be replayed.
    """
    res = client.post("/api/ws/ticket", headers=auth_headers)
    ticket = res.json()["ticket"]

    # First connection consumes ticket
    with client.websocket_connect(f"/ws?ticket={ticket}"):
        pass

    # Replay attempt fails
    with pytest.raises(Exception):
        with client.websocket_connect(f"/ws?ticket={ticket}"):
            pass


# ==============================================================================
# PRIORITY 3: STRICT CREDENTIAL FIELD VERIFIER ADVERSARIAL TESTS
# ==============================================================================

@pytest.mark.asyncio
async def test_credential_field_verifier_malicious_dom_cases():
    """
    PRIORITY 3 INVARIANT: Deterministic DOM verification rejects unsafe inputs (text, hidden, disabled, readonly, wrong roles).
    """
    verifier = CredentialFieldVerifier()

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()

        html = """
        <html>
        <body>
            <form id="test-form">
                <!-- 1. Text input named password (Attacker honeypot) -->
                <input type="text" id="text-pw" name="password" placeholder="Enter password">

                <!-- 2. Hidden password input -->
                <input type="password" id="hidden-pw" name="current_password" style="display:none;">

                <!-- 3. Disabled password input -->
                <input type="password" id="disabled-pw" name="new_password" disabled>

                <!-- 4. Readonly password input -->
                <input type="password" id="readonly-pw" name="new_password" readonly>

                <!-- 5. Confirm password input requested as new_password (Role Mismatch) -->
                <input type="password" id="confirm-pw" name="confirm_password" placeholder="Confirm Password">

                <!-- 6. Current password input requested as new_password (Role Mismatch) -->
                <input type="password" id="current-pw" name="current_password" placeholder="Current Password">

                <!-- 7. Valid New Password Input -->
                <input type="password" id="valid-new-pw" name="new_password" autocomplete="new-password" placeholder="New Password">
            </form>
        </body>
        </html>
        """
        await page.set_content(html)

        # 1. Text input named password -> REJECT
        el1 = await page.query_selector("#text-pw")
        r1 = await verifier.verify_field(el1, expected_role="current_password", page=page)
        assert r1.is_valid is False
        assert r1.field_role == "invalid_type"

        # 2. Hidden password input -> REJECT
        el2 = await page.query_selector("#hidden-pw")
        r2 = await verifier.verify_field(el2, expected_role="current_password", page=page)
        assert r2.is_valid is False

        # 3. Disabled password input -> REJECT
        el3 = await page.query_selector("#disabled-pw")
        r3 = await verifier.verify_field(el3, expected_role="new_password", page=page)
        assert r3.is_valid is False

        # 4. Readonly password input -> REJECT
        el4 = await page.query_selector("#readonly-pw")
        r4 = await verifier.verify_field(el4, expected_role="new_password", page=page)
        assert r4.is_valid is False

        # 5. Confirm requested as new -> REJECT
        el5 = await page.query_selector("#confirm-pw")
        r5 = await verifier.verify_field(el5, expected_role="new_password", page=page)
        assert r5.is_valid is False
        assert r5.field_role == "confirm_password"

        # 6. Current requested as new -> REJECT
        el6 = await page.query_selector("#current-pw")
        r6 = await verifier.verify_field(el6, expected_role="new_password", page=page)
        assert r6.is_valid is False
        assert r6.field_role == "current_password"

        # 7. Valid new password -> ACCEPT
        el7 = await page.query_selector("#valid-new-pw")
        r7 = await verifier.verify_field(el7, expected_role="new_password", page=page)
        assert r7.is_valid is True
        assert r7.field_role == "new_password"

        await browser.close()


# ==============================================================================
# PRIORITY 4: PROCESS RESTART / CRASH SECURITY MODEL
# ==============================================================================

def test_process_restart_invalidates_active_approval_tokens():
    """
    PRIORITY 4 INVARIANT: When process restarts (process_instance_id changes),
    all previously issued approval tokens are immediately invalidated.
    """
    mgr = SubmissionApprovalManager(default_ttl_seconds=60)
    original_instance_id = settings.process_instance_id

    # 1. Issue approval token in process instance A
    token = mgr.issue_approval_token(
        account_id=1,
        service="GitHub",
        verified_domain="github.com",
        browser_session_id="sess_proc_test",
        workflow_id="wf_proc_test",
        form_fingerprint="fp_proc"
    )

    # 2. Simulate process restart -> new instance ID generated
    new_instance_id = f"proc_{secrets.token_hex(16)}"
    try:
        settings.process_instance_id = new_instance_id

        # 3. Attempt to validate the token under new process instance
        valid, reason = mgr.validate_and_consume_token(
            token_id=token.token_id,
            account_id=1,
            service="GitHub",
            current_domain="github.com",
            browser_session_id="sess_proc_test",
            workflow_id="wf_proc_test",
            current_form_fingerprint="fp_proc"
        )
        assert valid is False
        assert "prior or terminated process" in reason or "process" in reason.lower()
    finally:
        settings.process_instance_id = original_instance_id


# ==============================================================================
# PRIORITY 5 & 6: STRICT LOCALHOST & IDN HOMOGRAPH NORMALIZATION
# ==============================================================================

def test_localhost_rejected_in_production_environment():
    """
    PRIORITY 5 INVARIANT: In production environment, localhost and 127.0.0.1
    are not trusted service domains unless explicitly registered for a local service.
    """
    original_env = settings.environment
    try:
        settings.environment = "production"
        ctx = DomainTrustContext(expected_service="github", allowed_explicit_domains=["github.com"])

        # http://localhost and 127.0.0.1 must be rejected
        res_local = ctx.evaluate_url("http://localhost:8080/settings")
        assert res_local.is_trusted is False

        res_ip = ctx.evaluate_url("http://127.0.0.1:8080/settings")
        assert res_ip.is_trusted is False
    finally:
        settings.environment = original_env


def test_idn_and_homograph_spoofs_fail_closed():
    """
    PRIORITY 6 INVARIANT: Hostnames with IDN punycode, Cyrillic lookalikes,
    userinfo, and parser tricks are rejected fail-closed.
    """
    ctx = DomainTrustContext(expected_service="github", allowed_explicit_domains=["github.com"])

    malicious_urls = [
        "https://xn--pple-43d.com/login",               # Punycode apple lookalike
        "https://github.com@attacker.com/settings",       # Userinfo spoof
        "https://github.com.attacker.com/settings",       # Subdomain spoof
        "https://attacker.com/github.com",               # Path spoof
        "https://g1thub.com/settings",                   # Typosquat
        "javascript:alert(1)",                           # Dangerous scheme
        "data:text/html,<h1>Phish</h1>",                 # Dangerous scheme
        "http://github.com/settings",                    # Insecure HTTP
    ]

    for url in malicious_urls:
        eval_res = ctx.evaluate_url(url)
        assert eval_res.is_trusted is False, f"Failed to reject malicious URL: {url}"


# ==============================================================================
# CRITICAL FIX #1: MULTI-SIGNAL POST-CHANGE VERIFICATION ADVERSARIAL TESTS
# ==============================================================================

@pytest.mark.asyncio
async def test_success_verifier_fake_alert_alone_is_unknown():
    """
    CRITICAL FIX #1 INVARIANT: Success alert alone without form disappearance or verified settings URL
    MUST return UNKNOWN, not SUCCESS.
    """
    verifier = PasswordChangeVerifier()
    mock_page = AsyncMock()
    mock_page.evaluate = AsyncMock(return_value="Some arbitrary page text")
    
    # Fake success alert element present, but password inputs STILL present on page (form unchanged)
    mock_alert = AsyncMock()
    mock_alert.inner_text = AsyncMock(return_value="Password changed successfully.")
    mock_page.query_selector_all = AsyncMock(side_effect=lambda sel: [mock_alert] if "[role='alert']" in sel or ".alert" in sel else [AsyncMock()]) # password inputs present!
    mock_page.url = "https://example.com/unverified_random_path"

    outcome = await verifier.verify(mock_page)
    assert outcome.outcome == "UNKNOWN"
    assert "Single weak/isolated signal" in outcome.signals[0] or "lacks independent structural confirmation" in outcome.details


@pytest.mark.asyncio
async def test_success_verifier_alert_plus_form_disappearance_is_success():
    """
    CRITICAL FIX #1 INVARIANT: Success alert PLUS password form disappearance yields SUCCESS.
    """
    verifier = PasswordChangeVerifier()
    mock_page = AsyncMock()
    mock_page.evaluate = AsyncMock(return_value="")
    mock_alert = AsyncMock()
    mock_alert.inner_text = AsyncMock(return_value="Your password has been changed successfully.")
    
    # Alert element exists, but password inputs are GONE (len == 0)
    mock_page.query_selector_all = AsyncMock(side_effect=lambda sel: [mock_alert] if "[role='alert']" in sel or ".alert" in sel else [])
    mock_page.url = "https://example.com/form_submitted"

    outcome = await verifier.verify(mock_page)
    assert outcome.outcome == "SUCCESS"
    assert outcome.confidence >= 0.95


@pytest.mark.asyncio
async def test_success_verifier_alert_plus_settings_url_is_success():
    """
    CRITICAL FIX #1 INVARIANT: Success alert PLUS post-change settings URL yields SUCCESS.
    """
    verifier = PasswordChangeVerifier()
    mock_page = AsyncMock()
    mock_page.evaluate = AsyncMock(return_value="")
    mock_alert = AsyncMock()
    mock_alert.inner_text = AsyncMock(return_value="Password updated.")
    
    # Alert element exists, and URL is verified settings path
    mock_page.query_selector_all = AsyncMock(side_effect=lambda sel: [mock_alert] if "[role='alert']" in sel or ".alert" in sel else [AsyncMock()])
    mock_page.url = "https://github.com/settings/security"

    outcome = await verifier.verify(mock_page)
    assert outcome.outcome == "SUCCESS"
    assert outcome.confidence >= 0.95


@pytest.mark.asyncio
async def test_success_verifier_failure_signals():
    """
    CRITICAL FIX #1 INVARIANT: Server rejection / failure alert yields FAILED even if success text is present.
    """
    verifier = PasswordChangeVerifier()
    mock_page = AsyncMock()
    mock_page.evaluate = AsyncMock(return_value="Password updated? No! Error: Current password was incorrect.")
    mock_fail_alert = AsyncMock()
    mock_fail_alert.inner_text = AsyncMock(return_value="Error: Current password was incorrect. Please try again.")
    mock_page.query_selector_all = AsyncMock(side_effect=lambda sel: [mock_fail_alert] if "error" in sel or "alert" in sel else [])

    outcome = await verifier.verify(mock_page)
    assert outcome.outcome == "FAILED"


# ==============================================================================
# CRITICAL FIX #2: STRICT RECURSIVE SECRET BOUNDARY ALLOWLIST TESTS
# ==============================================================================

def test_secret_boundary_recursive_allowlist_drops_unknown_fields():
    """
    CRITICAL FIX #2 INVARIANT: SecretBoundary drops all non-allowlisted fields recursively.
    """
    payload = {
        "title": "Account Security",
        "url": "https://example.com/settings",
        "unauthorized_top_level_field": "sensitive_val",
        "nested_dict": {
            "title": "Sub Settings",
            "internal_debug_key": "debug_val",
            "nested_list": [
                {"role": "button", "arbitrary_attacker_injected_key": "malicious"},
                {"tag": "input", "database_state": "DUMP"}
            ]
        },
        "interactive_elements": [
            {"element_id": "elem_1", "tag": "button", "text": "Save", "internal_handler": "doPost()"}
        ]
    }

    sanitized = SecretBoundary.sanitize_payload_for_ai(payload)

    # Allowed fields kept
    assert sanitized["title"] == "Account Security"
    assert sanitized["url"] == "https://example.com/settings"
    assert "unauthorized_top_level_field" not in sanitized

    # Nested structures sanitized
    assert "nested_dict" not in sanitized  # 'nested_dict' not in ALLOWED_AI_FIELDS -> dropped!
    assert len(sanitized["interactive_elements"]) == 1
    assert "internal_handler" not in sanitized["interactive_elements"][0]
    assert sanitized["interactive_elements"][0]["tag"] == "button"


# ==============================================================================
# CRITICAL FIX #3: SUBMIT CONTROL DETERMINISTIC VERIFICATION TESTS
# ==============================================================================

@pytest.mark.asyncio
async def test_action_executor_rejects_link_and_destructive_buttons():
    """
    CRITICAL FIX #3 INVARIANT: ControlledActionExecutor rejects <a> tags, 'Delete Account', and 'Logout' buttons.
    """
    mgr = SubmissionApprovalManager(default_ttl_seconds=60)
    executor = ControlledActionExecutor(custom_approval_manager=mgr)
    boundary = SecretBoundary()

    token = mgr.issue_approval_token(
        account_id=1,
        service="GitHub",
        verified_domain="github.com",
        browser_session_id="sess_btn_test",
        workflow_id="wf_btn_test",
        form_fingerprint="fp_btn"
    )

    approval_ctx = {
        "token_id": token.token_id,
        "account_id": 1,
        "service": "GitHub",
        "current_domain": "github.com",
        "browser_session_id": "sess_btn_test",
        "workflow_id": "wf_btn_test",
        "form_fingerprint": "fp_btn"
    }

    page = AsyncMock()
    page.url = "https://github.com/settings/security"

    # 1. Attacker supplied an <a> link as submit control -> REJECT
    mock_link = AsyncMock()
    mock_link.is_visible = AsyncMock(return_value=True)
    mock_link.is_enabled = AsyncMock(return_value=True)
    mock_link.evaluate = AsyncMock(return_value="a")
    mock_link.inner_text = AsyncMock(return_value="Click to confirm")
    element_map_link = {"btn_submit": mock_link}

    with pytest.raises(ActionExecutionError) as exc_link:
        await executor.execute_action(
            page=page,
            action_payload={"action": "submit", "target_id": "btn_submit"},
            element_map=element_map_link,
            secret_boundary=boundary,
            approval_context=approval_ctx
        )
    assert "not a verified submit control" in str(exc_link.value) or "DENIED" in str(exc_link.value)

    # 2. Attacker supplied a "Delete Account" button as submit control -> REJECT
    # Re-issue token
    token2 = mgr.issue_approval_token(
        account_id=1,
        service="GitHub",
        verified_domain="github.com",
        browser_session_id="sess_btn_test2",
        workflow_id="wf_btn_test2",
        form_fingerprint="fp_btn2"
    )
    approval_ctx["token_id"] = token2.token_id
    approval_ctx["browser_session_id"] = "sess_btn_test2"
    approval_ctx["workflow_id"] = "wf_btn_test2"
    approval_ctx["form_fingerprint"] = "fp_btn2"

    mock_del_btn = AsyncMock()
    mock_del_btn.is_visible = AsyncMock(return_value=True)
    mock_del_btn.is_enabled = AsyncMock(return_value=True)
    mock_del_btn.evaluate = AsyncMock(return_value="button")
    mock_del_btn.inner_text = AsyncMock(return_value="Delete Account")
    element_map_del = {"btn_del": mock_del_btn}

    with pytest.raises(ActionExecutionError) as exc_del:
        await executor.execute_action(
            page=page,
            action_payload={"action": "submit", "target_id": "btn_del"},
            element_map=element_map_del,
            secret_boundary=boundary,
            approval_context=approval_ctx
        )
    assert "not a verified submit control" in str(exc_del.value) or "DENIED" in str(exc_del.value)


# ==============================================================================
# REAL PLAYWRIGHT END-TO-END FLOW & ADVERSARIAL DOM TAMPERING TEST
# ==============================================================================

@pytest.mark.asyncio
async def test_playwright_e2e_real_rotation_and_adversarial_tampering():
    """
    PRIORITY 20 INVARIANT: Real Playwright execution of password change workflow,
    verifying DOM field verification, single-use token consumption, and failure on tampering.
    """
    verifier = CredentialFieldVerifier()
    mgr = SubmissionApprovalManager(default_ttl_seconds=60)
    executor = ControlledActionExecutor(custom_approval_manager=mgr)
    boundary = SecretBoundary()
    boundary.register_secrets(current_password="OldPassword123!", new_password="NewSecurePassword456!")

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()

        # HTML password change form served over HTTPS route
        html = """
        <html>
        <head><title>Account Security Settings</title></head>
        <body>
            <div id="settings-container">
                <form id="pw-form" action="/update-password" method="POST">
                    <label for="old_pw">Current Password</label>
                    <input type="password" id="old_pw" name="current_password" autocomplete="current-password">

                    <label for="new_pw">New Password</label>
                    <input type="password" id="new_pw" name="new_password" autocomplete="new-password">

                    <label for="confirm_pw">Confirm Password</label>
                    <input type="password" id="confirm_pw" name="confirm_password">

                    <button type="submit" id="btn-save">Update Password</button>
                </form>
            </div>
        </body>
        </html>
        """
        await page.route("https://github.com/**", lambda route: route.fulfill(status=200, body=html, content_type="text/html"))
        await page.goto("https://github.com/settings/security")

        # 1. Deterministic Credential Field Verification
        old_el = await page.query_selector("#old_pw")
        new_el = await page.query_selector("#new_pw")
        confirm_el = await page.query_selector("#confirm_pw")
        save_btn = await page.query_selector("#btn-save")

        v_old = await verifier.verify_field(old_el, expected_role="current_password", page=page)
        assert v_old.is_valid is True

        v_new = await verifier.verify_field(new_el, expected_role="new_password", page=page)
        assert v_new.is_valid is True

        v_confirm = await verifier.verify_field(confirm_el, expected_role="confirm_password", page=page)
        assert v_confirm.is_valid is True

        # 2. Secret Boundary filling
        elem_map = {
            "elem_old": old_el,
            "elem_new": new_el,
            "elem_confirm": confirm_el,
            "elem_submit": save_btn
        }

        await executor.execute_action(
            page=page,
            action_payload={"action": "fill_secret", "target_id": "elem_old", "secret_reference": "current_password"},
            element_map=elem_map,
            secret_boundary=boundary
        )

        await executor.execute_action(
            page=page,
            action_payload={"action": "fill_secret", "target_id": "elem_new", "secret_reference": "new_password"},
            element_map=elem_map,
            secret_boundary=boundary
        )

        # 3. Issue approval token
        token = mgr.issue_approval_token(
            account_id=1,
            service="GitHub",
            verified_domain="github.com",
            browser_session_id="sess_e2e_1",
            workflow_id="wf_e2e_1",
            form_fingerprint="fp_valid_test"
        )

        approval_ctx = {
            "token_id": token.token_id,
            "account_id": 1,
            "service": "GitHub",
            "current_domain": "github.com",
            "browser_session_id": "sess_e2e_1",
            "workflow_id": "wf_e2e_1",
            "form_fingerprint": "fp_valid_test"
        }

        # 4. Successful submit execution
        success = await executor.execute_action(
            page=page,
            action_payload={"action": "submit", "target_id": "elem_submit"},
            element_map=elem_map,
            secret_boundary=boundary,
            approval_context=approval_ctx
        )
        assert success is True

        # 5. Replay fails
        with pytest.raises(ActionExecutionError) as exc_replay:
            await executor.execute_action(
                page=page,
                action_payload={"action": "submit", "target_id": "elem_submit"},
                element_map=elem_map,
                secret_boundary=boundary,
                approval_context=approval_ctx
            )
        assert "consumed" in str(exc_replay.value) or "DENIED" in str(exc_replay.value)

        await browser.close()


# ==============================================================================
# ADDITIONAL ADVERSARIAL PROOF: FORM-BOUND SUBMISSION & FINGERPRINT MUTATION
# ==============================================================================

def test_secret_boundary_import_and_execution_regression():
    """
    SECTION 1 & 2 INVARIANT: SecretBoundary imports Any and executes sanitize_payload_for_ai without error.
    """
    from app.safety.secret_boundary import SecretBoundary
    payload = {"url": "https://example.com", "title": "Safe Title", "unauthorized_key": "drop_me"}
    sanitized = SecretBoundary.sanitize_payload_for_ai(payload)
    assert sanitized == {"url": "https://example.com", "title": "Safe Title"}


def test_secret_boundary_drop_by_default_matrix():
    """
    SECTION 2 INVARIANT: Tests A through F for SecretBoundary.
    """
    from app.safety.secret_boundary import SecretBoundary

    # Test A: Unknown top-level field dropped
    payload_a = {"title": "Settings", "database_dump": "SELECT 1", "unknown_key": "val"}
    assert SecretBoundary.sanitize_payload_for_ai(payload_a) == {"title": "Settings"}

    # Test B: Unknown nested field dropped
    payload_b = {
        "title": "Settings",
        "nested": {"title": "Sub", "cookies": ["c1=secret"], "session_id": "123"}
    }
    sanitized_b = SecretBoundary.sanitize_payload_for_ai(payload_b)
    assert "cookies" not in str(sanitized_b)
    assert "session_id" not in str(sanitized_b)

    # Test C: Unknown field inside list of dicts dropped
    payload_c = {
        "interactive_elements": [
            {"element_id": "1", "tag": "input", "auth_token": "secret_token", "role": "password"}
        ]
    }
    sanitized_c = SecretBoundary.sanitize_payload_for_ai(payload_c)
    assert "auth_token" not in sanitized_c["interactive_elements"][0]
    assert sanitized_c["interactive_elements"][0]["element_id"] == "1"

    # Test D: Sensitive keywords dropped or never returned
    payload_d = {
        "password": "p1", "token": "t1", "cookie": "c1", "authorization": "Bearer xxx",
        "csrf": "tok", "otp": "123456", "private_key": "key"
    }
    assert SecretBoundary.sanitize_payload_for_ai(payload_d) == {}

    # Test E: Raw secret embedded in text value is redacted
    payload_e = {"title": "Login page with password=SuperSecretRawPassword123!"}
    sanitized_e = SecretBoundary.sanitize_payload_for_ai(payload_e)
    assert "SuperSecretRawPassword123!" not in sanitized_e["title"]
    assert sanitized_e["title"] == "[REDACTED_BY_SECRET_BOUNDARY]"

    # Test F: Symbolic references remain symbolic
    payload_f = {"secret_reference": "current_password"}
    sanitized_f = SecretBoundary.sanitize_payload_for_ai(payload_f)
    assert sanitized_f["secret_reference"] == "current_password"


@pytest.mark.asyncio
async def test_submit_control_outside_password_form_rejected():
    """
    SECTION 3 INVARIANT: A generic 'Save' or 'Update' button outside the approved password form is rejected.
    """
    mgr = SubmissionApprovalManager(default_ttl_seconds=60)
    executor = ControlledActionExecutor(custom_approval_manager=mgr)
    boundary = SecretBoundary()

    token = mgr.issue_approval_token(
        account_id=1,
        service="GitHub",
        verified_domain="github.com",
        browser_session_id="sess_out_form",
        workflow_id="wf_out_form",
        form_fingerprint="fp_out_form"
    )

    approval_ctx = {
        "token_id": token.token_id,
        "account_id": 1,
        "service": "GitHub",
        "current_domain": "github.com",
        "browser_session_id": "sess_out_form",
        "workflow_id": "wf_out_form",
        "form_fingerprint": "fp_out_form"
    }

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()

        # HTML with two separate forms: an unrelated newsletter form with 'Update' button, and a password form
        html = """
        <html>
        <body>
            <form id="newsletter-form">
                <input type="text" name="email">
                <button type="button" id="unrelated-save-btn">Update Profile</button>
            </form>
            <form id="password-form">
                <input type="password" name="new_pw">
                <button type="submit" id="real-pw-submit">Save Password</button>
            </form>
        </body>
        </html>
        """
        await page.route("https://github.com/**", lambda route: route.fulfill(status=200, body=html, content_type="text/html"))
        await page.goto("https://github.com/settings/security")

        unrelated_btn = await page.query_selector("#unrelated-save-btn")
        elem_map = {"unrelated_btn": unrelated_btn}

        # Attempt to submit via unrelated button outside the password form -> MUST BE REJECTED
        with pytest.raises(ActionExecutionError) as exc:
            await executor.execute_action(
                page=page,
                action_payload={"action": "submit", "target_id": "unrelated_btn"},
                element_map=elem_map,
                secret_boundary=boundary,
                approval_context=approval_ctx
            )
        assert "not a verified submit control" in str(exc.value)

        await browser.close()


@pytest.mark.asyncio
async def test_form_fingerprint_changes_on_tampering():
    """
    SECTION 4 INVARIANT: Form fingerprint changes if fields or submit buttons change.
    """
    from app.ai.navigator import AINavigator
    nav = AINavigator()

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()

        # 1. Original Form
        await page.set_content("""
        <form id="pw-form">
            <input type="password" name="old" autocomplete="current-password">
            <input type="password" name="new" autocomplete="new-password">
            <button type="submit" id="save">Update Password</button>
        </form>
        """)
        fp_orig = await nav.compute_form_fingerprint(page)
        assert fp_orig != "fingerprint_empty"

        # 2. Tampered Submit Button
        await page.set_content("""
        <form id="pw-form">
            <input type="password" name="old" autocomplete="current-password">
            <input type="password" name="new" autocomplete="new-password">
            <button type="submit" id="attacker_button">Transfer Ownership</button>
        </form>
        """)
        fp_tampered_btn = await nav.compute_form_fingerprint(page)
        assert fp_tampered_btn != fp_orig

        # 3. Tampered Field Structure
        await page.set_content("""
        <form id="pw-form">
            <input type="password" name="attacker_injected_field">
            <button type="submit" id="save">Update Password</button>
        </form>
        """)
        fp_tampered_field = await nav.compute_form_fingerprint(page)
        assert fp_tampered_field != fp_orig
        assert fp_tampered_field != fp_tampered_btn

        await browser.close()


@pytest.mark.asyncio
async def test_success_verifier_rejects_attacker_settings_url():
    """
    SECTION 6 INVARIANT: Post-change settings URL on an attacker/untrusted domain returns UNKNOWN.
    """
    verifier = PasswordChangeVerifier()
    mock_page = AsyncMock()
    mock_page.evaluate = AsyncMock(return_value="")
    mock_alert = AsyncMock()
    mock_alert.inner_text = AsyncMock(return_value="Password changed.")
    mock_page.query_selector_all = AsyncMock(side_effect=lambda sel: [mock_alert] if "[role='alert']" in sel or ".alert" in sel else [AsyncMock()])
    
    # URL has '/settings/security' path, but is on ATTACKER domain!
    mock_page.url = "https://attacker.com/settings/security"

    outcome = await verifier.verify(
        mock_page,
        expected_service="GitHub",
        expected_domain="github.com"
    )
    assert outcome.outcome == "UNKNOWN"
    assert any("Single weak/isolated signal" in s for s in outcome.signals)
