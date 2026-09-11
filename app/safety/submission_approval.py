import secrets
import time
from typing import Dict, Optional, Tuple, Any
from pydantic import BaseModel, Field
from app.core.audit_logger import audit_logger

class ApprovalToken(BaseModel):
    """
    Cryptographic single-use token authorizing a specific password change submission.
    Bound strictly to account, service, verified domain, browser session, workflow, and form fingerprint.
    """
    token_id: str
    account_id: int
    service: str
    verified_domain: str
    browser_session_id: str
    workflow_id: str
    form_fingerprint: str
    created_at: float = Field(default_factory=time.time)
    expires_at: float
    is_used: bool = False

class SubmissionApprovalError(Exception):
    """Raised when submission approval validation fails."""
    pass

class SubmissionApprovalManager:
    """
    Authoritative Manager for User Submission Approvals.
    Enforces that:
    1. AI CAN NEVER trigger submissions autonomously.
    2. Approval tokens are cryptographically secure, single-use, and time-bounded.
    3. Any mismatch in account, service, domain, session, or form fingerprint instantly invalidates approval.
    """

    def __init__(self, default_ttl_seconds: int = 120):
        self.default_ttl_seconds = default_ttl_seconds
        # token_id -> ApprovalToken
        self._tokens: Dict[str, ApprovalToken] = {}
        # session_id -> active token_id
        self._session_tokens: Dict[str, str] = {}

    def issue_approval_token(
        self,
        account_id: int,
        service: str,
        verified_domain: str,
        browser_session_id: str,
        workflow_id: str,
        form_fingerprint: str,
        ttl_seconds: Optional[int] = None
    ) -> ApprovalToken:
        """
        Issues a cryptographically secure, single-use approval token.
        Only called when the human user explicitly clicks 'Approve' in the UI/CLI.
        """
        ttl = ttl_seconds or self.default_ttl_seconds
        token_id = f"appr_{secrets.token_urlsafe(32)}"
        now = time.time()
        
        token = ApprovalToken(
            token_id=token_id,
            account_id=account_id,
            service=service.lower().strip(),
            verified_domain=verified_domain.lower().strip(),
            browser_session_id=browser_session_id,
            workflow_id=workflow_id,
            form_fingerprint=form_fingerprint,
            created_at=now,
            expires_at=now + ttl,
            is_used=False
        )

        # Invalidate any prior token for this browser session
        if browser_session_id in self._session_tokens:
            prior_token_id = self._session_tokens[browser_session_id]
            if prior_token_id in self._tokens:
                self._tokens[prior_token_id].is_used = True

        self._tokens[token_id] = token
        self._session_tokens[browser_session_id] = token_id

        audit_logger.log_event(
            service,
            f"User approval token issued for account #{account_id} on domain '{verified_domain}' (expires in {ttl}s)."
        )
        return token

    def validate_and_consume_token(
        self,
        token_id: str,
        account_id: int,
        service: str,
        current_domain: str,
        browser_session_id: str,
        workflow_id: str,
        current_form_fingerprint: str
    ) -> Tuple[bool, str]:
        """
        Validates token invariants and atomically marks it as used.
        Fails closed on any discrepancy or expiration.
        """
        if not token_id or token_id not in self._tokens:
            return False, "DENIED: Invalid or missing approval token. AI cannot manufacture approvals."

        token = self._tokens[token_id]

        if token.is_used:
            return False, "DENIED: Approval token has already been consumed (single-use invariant violated)."

        now = time.time()
        if now > token.expires_at:
            token.is_used = True
            return False, f"DENIED: Approval token expired {now - token.expires_at:.1f}s ago."

        if token.account_id != account_id:
            return False, f"DENIED: Token account mismatch (expected #{token.account_id}, got #{account_id})."

        if token.service != service.lower().strip():
            return False, f"DENIED: Token service mismatch (expected '{token.service}', got '{service}')."

        if token.verified_domain != current_domain.lower().strip():
            self.invalidate_token(token_id, f"Domain mismatch '{token.verified_domain}' vs '{current_domain}'")
            return False, f"DENIED: Token domain mismatch (expected '{token.verified_domain}', current '{current_domain}')."

        if token.browser_session_id != browser_session_id:
            return False, "DENIED: Token browser session mismatch."

        if token.workflow_id != workflow_id:
            return False, "DENIED: Token workflow ID mismatch."

        if token.form_fingerprint != current_form_fingerprint:
            self.invalidate_token(token_id, "Form DOM structure changed after approval was granted")
            return False, "DENIED: Form fingerprint changed after user approval. Re-approval required."

        # Atomically consume
        token.is_used = True
        audit_logger.log_event(
            service,
            f"Approval token '{token_id[:12]}...' successfully validated and consumed for account #{account_id}."
        )
        return True, "Approval token valid and consumed."

    def invalidate_token(self, token_id: str, reason: str) -> None:
        """Explicitly cancels a token."""
        if token_id in self._tokens:
            self._tokens[token_id].is_used = True
            audit_logger.log_event(
                self._tokens[token_id].service,
                f"Approval token '{token_id[:12]}...' invalidated: {reason}",
                level="WARNING"
            )

    def invalidate_for_session(self, browser_session_id: str, reason: str) -> None:
        """Invalidates all tokens tied to a browser session (e.g. on navigation or redirect)."""
        if browser_session_id in self._session_tokens:
            tid = self._session_tokens[browser_session_id]
            self.invalidate_token(tid, reason)
            del self._session_tokens[browser_session_id]

# Singleton instance
approval_manager = SubmissionApprovalManager()
