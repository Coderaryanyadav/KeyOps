import time
import pytest
from app.safety.submission_approval import SubmissionApprovalManager, ApprovalToken

def test_approval_token_issuance_and_consumption():
    mgr = SubmissionApprovalManager(default_ttl_seconds=60)
    
    token = mgr.issue_approval_token(
        account_id=101,
        service="github",
        verified_domain="github.com",
        browser_session_id="sess_123",
        workflow_id="wf_abc",
        form_fingerprint="fp_hash_999"
    )

    assert token.token_id.startswith("appr_")
    assert token.is_used is False

    # Successful validation and consumption
    is_valid, reason = mgr.validate_and_consume_token(
        token_id=token.token_id,
        account_id=101,
        service="github",
        current_domain="github.com",
        browser_session_id="sess_123",
        workflow_id="wf_abc",
        current_form_fingerprint="fp_hash_999"
    )
    assert is_valid is True

    # Single-use invariant: second consumption MUST fail
    is_valid2, reason2 = mgr.validate_and_consume_token(
        token_id=token.token_id,
        account_id=101,
        service="github",
        current_domain="github.com",
        browser_session_id="sess_123",
        workflow_id="wf_abc",
        current_form_fingerprint="fp_hash_999"
    )
    assert is_valid2 is False
    assert "single-use" in reason2.lower()

def test_approval_token_rejection_on_form_change():
    mgr = SubmissionApprovalManager(default_ttl_seconds=60)
    token = mgr.issue_approval_token(
        account_id=102,
        service="google",
        verified_domain="google.com",
        browser_session_id="sess_google",
        workflow_id="wf_google",
        form_fingerprint="fp_original"
    )

    # Attempt to consume with altered form fingerprint
    is_valid, reason = mgr.validate_and_consume_token(
        token_id=token.token_id,
        account_id=102,
        service="google",
        current_domain="google.com",
        browser_session_id="sess_google",
        workflow_id="wf_google",
        current_form_fingerprint="fp_tampered_form"
    )
    assert is_valid is False
    assert "fingerprint changed" in reason.lower()

def test_approval_token_expiration():
    mgr = SubmissionApprovalManager(default_ttl_seconds=1)
    token = mgr.issue_approval_token(
        account_id=103,
        service="amazon",
        verified_domain="amazon.com",
        browser_session_id="sess_amz",
        workflow_id="wf_amz",
        form_fingerprint="fp_amz",
        ttl_seconds=1
    )

    time.sleep(1.1)

    is_valid, reason = mgr.validate_and_consume_token(
        token_id=token.token_id,
        account_id=103,
        service="amazon",
        current_domain="amazon.com",
        browser_session_id="sess_amz",
        workflow_id="wf_amz",
        current_form_fingerprint="fp_amz"
    )
    assert is_valid is False
    assert "expired" in reason.lower()

def test_approval_token_domain_mismatch():
    mgr = SubmissionApprovalManager(default_ttl_seconds=60)
    token = mgr.issue_approval_token(
        account_id=104,
        service="discord",
        verified_domain="discord.com",
        browser_session_id="sess_disc",
        workflow_id="wf_disc",
        form_fingerprint="fp_disc"
    )

    is_valid, reason = mgr.validate_and_consume_token(
        token_id=token.token_id,
        account_id=104,
        service="discord",
        current_domain="evil-discord.com",
        browser_session_id="sess_disc",
        workflow_id="wf_disc",
        current_form_fingerprint="fp_disc"
    )
    assert is_valid is False
    assert "domain mismatch" in reason.lower()
