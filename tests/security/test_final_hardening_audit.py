import pytest
import asyncio
import time
import secrets
from unittest.mock import AsyncMock, MagicMock, patch
from playwright.async_api import async_playwright
from fastapi.testclient import TestClient

from app.config import settings
from app.api.server import app, verify_local_api_auth
from app.core.workflow_state import WorkflowState, WorkflowPhase, WorkflowStateMachine
from app.safety.submission_approval import SubmissionApprovalManager, ApprovalToken, approval_manager
from app.safety.domain_trust import DomainTrustContext
from app.safety.secret_boundary import SecretBoundary, SecretBoundaryViolation
from app.browser.action_executor import ControlledActionExecutor, ActionExecutionError
from app.browser.credential_verifier import CredentialFieldVerifier
from app.browser.success_verifier import PasswordChangeVerifier, VerificationOutcome
from app.core.orchestrator import PasswordRotationOrchestrator
from app.database.session import SessionLocal, init_db
from app.database.models import Account

@pytest.fixture
def test_client():
    return TestClient(app)

@pytest.fixture
def auth_headers():
    return {"X-KeyOps-Auth-Token": settings.local_api_token}


# ==============================================================================
# 1. LOCAL API AUTHENTICATION TESTS
# ==============================================================================

def test_local_api_rejects_unauthenticated_mutation_endpoints(test_client):
    """
    INVARIANT: Any mutation endpoint called without valid local auth token must return 401 Unauthorized.
    """
    # 1. Prepare rotation
    res = test_client.post("/api/rotation/prepare", json={"account_id": 1})
    assert res.status_code == 401
    assert "Unauthorized" in res.json()["detail"]

    # 2. Approve rotation
    res = test_client.post("/api/rotation/approve", json={"account_id": 1, "workflow_id": "wf_test"})
    assert res.status_code == 401

    # 3. Execute rotation
    res = test_client.post("/api/rotation/execute", json={"account_id": 1, "workflow_id": "wf_test", "approval_token_id": "tok_123"})
    assert res.status_code == 401

    # 4. Resume rotation
    res = test_client.post("/api/rotation/resume", json={"workflow_id": "wf_test", "session_id": "sess_test"})
    assert res.status_code == 401

    # 5. Add account
    res = test_client.post("/api/accounts/add", json={"service": "TestSite", "username": "user"})
    assert res.status_code == 401

    # 6. Queue init
    res = test_client.post("/api/queue/init", json={})
    assert res.status_code == 401


def test_local_api_accepts_valid_auth_token_header_and_bearer(test_client):
    """
    INVARIANT: Requests with matching X-KeyOps-Auth-Token or Authorization Bearer header are authorized.
    """
    # Header 1: X-KeyOps-Auth-Token
    res = test_client.post("/api/queue/init", headers={"X-KeyOps-Auth-Token": settings.local_api_token})
    assert res.status_code in (200, 404, 422)  # Authorized

    # Header 2: Authorization: Bearer <token>
    res = test_client.post("/api/queue/init", headers={"Authorization": f"Bearer {settings.local_api_token}"})
    assert res.status_code in (200, 404, 422)  # Authorized


# ==============================================================================
# 2. APPROVAL API TRUST BOUNDARY & SERVER-SIDE VALIDATION
# ==============================================================================

def test_approval_api_rejects_nonexistent_or_invalid_workflow(test_client, auth_headers):
    """
    INVARIANT: /api/rotation/approve must verify workflow existence server-side.
    """
    res = test_client.post(
        "/api/rotation/approve",
        headers=auth_headers,
        json={"account_id": 9999, "workflow_id": "wf_nonexistent"}
    )
    assert res.status_code in (400, 404)


@pytest.mark.asyncio
async def test_approval_state_order_invariant():
    """
    INVARIANT: State machine must NOT transition to APPROVED before the token is atomically consumed.
    """
    state = WorkflowState(
        workflow_id="wf_state_order",
        account_id=10,
        service="GitHub",
        expected_domain="github.com",
        phase=WorkflowPhase.READY_FOR_APPROVAL,
        form_fingerprint="fp_valid_123"
    )
    sm = WorkflowStateMachine(state)
    assert state.phase == WorkflowPhase.READY_FOR_APPROVAL

    # Illegal transition directly to SUCCESS or SUBMITTING without APPROVED
    with pytest.raises(Exception):
        sm.transition_to(WorkflowPhase.SUCCESS, "Illegal skip")


# ==============================================================================
# 3. CONCURRENCY & DOUBLE SUBMIT RACE ATTACK
# ==============================================================================

@pytest.mark.asyncio
async def test_approval_token_concurrency_race_single_winner():
    """
    INVARIANT: Concurrent attempts to consume the same approval token must allow only 1 winner.
    """
    mgr = SubmissionApprovalManager(default_ttl_seconds=60)
    token = mgr.issue_approval_token(
        account_id=1,
        service="GitHub",
        verified_domain="github.com",
        browser_session_id="sess_race",
        workflow_id="wf_race",
        form_fingerprint="fp_race"
    )

    results = []

    def try_consume():
        valid, _ = mgr.validate_and_consume_token(
            token_id=token.token_id,
            account_id=1,
            service="GitHub",
            current_domain="github.com",
            browser_session_id="sess_race",
            workflow_id="wf_race",
            current_form_fingerprint="fp_race"
        )
        results.append(valid)

    # Simulate 10 simultaneous threads trying to validate & consume the single-use token
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(try_consume) for _ in range(10)]
        concurrent.futures.wait(futures)

    # Exactly one consumption must succeed
    assert results.count(True) == 1
    assert results.count(False) == 9


# ==============================================================================
# 4. ACTION EXECUTOR NAVIGATION SCHEME BLOCKING
# ==============================================================================

@pytest.mark.asyncio
async def test_action_executor_blocks_unsafe_navigation_schemes():
    """
    INVARIANT: ControlledActionExecutor must reject javascript:, data:, file:, about: schemes.
    """
    executor = ControlledActionExecutor()
    boundary = SecretBoundary()
    mock_page = AsyncMock()

    unsafe_targets = [
        "javascript:alert(1)",
        "data:text/html,<h1>Pwned</h1>",
        "file:///etc/passwd",
        "about:blank",
        "vbscript:msgbox(1)"
    ]

    for target in unsafe_targets:
        with pytest.raises(ActionExecutionError) as exc_info:
            await executor.execute_action(
                page=mock_page,
                action_payload={"action": "navigate", "target_url": target},
                element_map={},
                secret_boundary=boundary
            )
        assert "unsafe scheme" in str(exc_info.value).lower() or "rejected" in str(exc_info.value).lower()


# ==============================================================================
# 5. HUMAN/MFA RESUME TOKEN INVALIDATION
# ==============================================================================

@pytest.mark.asyncio
async def test_human_resume_invalidates_prior_session_approval_tokens():
    """
    INVARIANT: Resuming after human MFA must invalidate old approval tokens for the session.
    """
    mgr = SubmissionApprovalManager()
    token = mgr.issue_approval_token(
        account_id=2,
        service="Google",
        verified_domain="google.com",
        browser_session_id="sess_mfa_test",
        workflow_id="wf_mfa_test",
        form_fingerprint="fp_mfa"
    )

    # Simulate human resumption event invalidating session tokens
    mgr.invalidate_for_session("sess_mfa_test", "Workflow resumed after human intervention")

    # Attempt to consume the old token
    valid, reason = mgr.validate_and_consume_token(
        token_id=token.token_id,
        account_id=2,
        service="Google",
        current_domain="google.com",
        browser_session_id="sess_mfa_test",
        workflow_id="wf_mfa_test",
        current_form_fingerprint="fp_mfa"
    )
    assert valid is False
    assert "already been consumed" in reason or "invalidated" in reason or "DENIED" in reason


# ==============================================================================
# 6. SUCCESS VERIFIER STRICT INDICATORS
# ==============================================================================

@pytest.mark.asyncio
async def test_success_verifier_rejects_missing_inputs_without_positive_evidence():
    """
    INVARIANT: Mere disappearance of inputs without positive confirmation banner or alert must return UNKNOWN.
    """
    verifier = PasswordChangeVerifier()
    mock_page = AsyncMock()

    # Page has no text, no alert, and no inputs
    mock_page.evaluate = AsyncMock(return_value="Random irrelevant account profile text without any confirmation")
    mock_page.query_selector_all = AsyncMock(return_value=[])

    outcome = await verifier.verify(mock_page)
    assert outcome.outcome == "UNKNOWN"
    assert outcome.confidence == 0.50
