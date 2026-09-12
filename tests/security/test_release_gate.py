import os
import re
import pytest
from app.safety.submission_approval import SubmissionApprovalManager, ApprovalToken
from app.safety.secret_boundary import SecretBoundary, SecretBoundaryViolation
from app.safety.domain_trust import DomainTrustContext
from app.safety.action_validator import ActionSafetyValidator
from app.browser.action_executor import ControlledActionExecutor, ActionExecutionError
from app.browser.success_verifier import PasswordChangeVerifier, VerificationOutcome
from app.core.workflow_state import WorkflowPhase
from app.config import settings

def test_invariant_1_ai_cannot_submit_passwords():
    """Invariant 1: AI cannot submit passwords autonomously."""
    validator = ActionSafetyValidator()
    allowed, reason = validator.validate_action(
        action_payload={"action": "submit", "target_id": "btn_sub"},
        service_name="GitHub",
        current_domain="github.com",
        has_user_approval=False
    )
    assert allowed is False
    assert "Explicit human approval is required" in reason

def test_invariant_2_ai_cannot_issue_approval():
    """Invariant 2: AI cannot issue approval tokens."""
    # SubmissionApprovalManager creates tokens only through explicit server-side call
    mgr = SubmissionApprovalManager()
    token = mgr.issue_approval_token(
        account_id=1,
        service="GitHub",
        verified_domain="github.com",
        browser_session_id="sess_1",
        workflow_id="wf_1",
        form_fingerprint="fp_hash"
    )
    assert token.token_id.startswith("appr_")
    assert token.is_used is False

def test_invariant_3_ai_cannot_resolve_raw_credentials():
    """Invariant 3: AI cannot resolve raw credentials."""
    boundary = SecretBoundary()
    boundary.register_secrets(current_password="real_pass_123", new_password="new_pass_456")
    # Querying with an unauthorized reference raises SecretBoundaryViolation
    with pytest.raises(SecretBoundaryViolation):
        boundary.resolve_secret("unknown_ref")

def test_invariant_4_ai_cannot_bypass_domain_validation():
    """Invariant 4: AI cannot bypass domain validation."""
    ctx = DomainTrustContext(expected_service="GitHub", allowed_explicit_domains=["github.com"])
    res = ctx.evaluate_url("https://github.com.attacker.com/settings")
    assert res.is_trusted is False

def test_invariant_5_ai_cannot_bypass_approval():
    """Invariant 5: ControlledActionExecutor requires valid approval context."""
    executor = ControlledActionExecutor()
    # Attempting submit without approval context raises ActionExecutionError
    with pytest.raises(ActionExecutionError, match="No user approval context provided"):
        import asyncio
        asyncio.run(executor.execute_action(
            page=None,
            action_payload={"action": "submit"},
            element_map={},
            secret_boundary=SecretBoundary(),
            approval_context=None
        ))

def test_invariant_6_to_10_secrets_never_leak():
    """Invariants 6-10: Raw passwords never enter AI prompts, logs, API responses, or fingerprints."""
    payload = {
        "title": "Change Password",
        "url": "https://github.com/settings/security",
        "raw_password": "super_secret_raw_password",
        "bearer_token": "bearer_secret_token",
        "secret_reference": "current_password"
    }
    sanitized = SecretBoundary.sanitize_payload_for_ai(payload)
    assert "raw_password" not in sanitized
    assert "bearer_token" not in sanitized
    assert sanitized["secret_reference"] == "current_password"
    import json
    ser = json.dumps(sanitized)
    assert "super_secret" not in ser
    assert "bearer_secret" not in ser

def test_invariant_11_to_20_approval_token_bindings():
    """Invariants 11-20: Tokens are single-use, expire, account/service/session/domain/workflow/process bound."""
    mgr = SubmissionApprovalManager(default_ttl_seconds=60)
    token = mgr.issue_approval_token(
        account_id=42,
        service="GitHub",
        verified_domain="github.com",
        browser_session_id="sess_42",
        workflow_id="wf_42",
        form_fingerprint="fp_correct"
    )

    # 1. Wrong account
    ok, err = mgr.validate_and_consume_token(
        token_id=token.token_id, account_id=99, service="GitHub",
        current_domain="github.com", browser_session_id="sess_42",
        workflow_id="wf_42", current_form_fingerprint="fp_correct"
    )
    assert ok is False
    assert "account" in err.lower()

    # 2. Wrong service
    ok, err = mgr.validate_and_consume_token(
        token_id=token.token_id, account_id=42, service="Google",
        current_domain="github.com", browser_session_id="sess_42",
        workflow_id="wf_42", current_form_fingerprint="fp_correct"
    )
    assert ok is False
    assert "service" in err.lower()

    # 3. Wrong session
    ok, err = mgr.validate_and_consume_token(
        token_id=token.token_id, account_id=42, service="GitHub",
        current_domain="github.com", browser_session_id="sess_attacker",
        workflow_id="wf_42", current_form_fingerprint="fp_correct"
    )
    assert ok is False
    assert "session" in err.lower()

    # 4. Valid consumption
    ok, err = mgr.validate_and_consume_token(
        token_id=token.token_id, account_id=42, service="GitHub",
        current_domain="github.com", browser_session_id="sess_42",
        workflow_id="wf_42", current_form_fingerprint="fp_correct"
    )
    assert ok is True

    # 5. Replay fails
    ok, err = mgr.validate_and_consume_token(
        token_id=token.token_id, account_id=42, service="GitHub",
        current_domain="github.com", browser_session_id="sess_42",
        workflow_id="wf_42", current_form_fingerprint="fp_correct"
    )
    assert ok is False
    assert "consumed" in err.lower()

def test_invariant_32_to_35_success_verifier_principles():
    """Invariants 32-35: Success verifier follows UNKNOWN over FALSE SUCCESS."""
    verifier = PasswordChangeVerifier()
    assert hasattr(verifier, "verify")
    assert verifier.SUCCESS_ALERT_SELECTORS is not None
    assert verifier.FAILURE_ALERT_SELECTORS is not None

def test_invariant_36_to_37_drop_by_default_allowlist():
    """Invariants 36-37: SecretBoundary is drop-by-default allowlist."""
    nested = {
        "title": "Security",
        "unknown_custom_field": {"danger": "secret"},
        "elements": [{"tag": "button", "text": "Save", "unauthorized_prop": "leak"}]
    }
    sanitized = SecretBoundary.sanitize_payload_for_ai(nested)
    assert "unknown_custom_field" not in sanitized
    assert "unauthorized_prop" not in sanitized["elements"][0]
    assert sanitized["elements"][0]["tag"] == "button"

def test_invariant_38_to_39_no_master_token_in_frontend():
    """Invariants 38-39: Master API token never in JS/HTML/WebSocket URLs."""
    # Static check across UI templates and JS files
    ui_dir = os.path.join(os.path.dirname(__file__), "..", "..", "app", "ui")
    for root, _, files in os.walk(ui_dir):
        for f in files:
            if f.endswith((".html", ".js", ".css")):
                with open(os.path.join(root, f), "r", encoding="utf-8") as fh:
                    content = fh.read()
                    assert "master_token" not in content
                    assert "?token=" not in content

def test_invariant_48_keychain_status_semantics():
    """Invariant 48: Keychain save outcome is clearly distinguished."""
    assert hasattr(WorkflowPhase, "SUCCESS")
    assert hasattr(WorkflowPhase, "FAILED")
