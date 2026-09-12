import secrets
import time
import threading
from typing import Dict, Optional, Tuple, Any
from pydantic import BaseModel, Field
from app.config import settings
from app.core.audit_logger import audit_logger

class ApprovalToken(BaseModel):
    """
    Cryptographic single-use token authorizing a specific password change submission.
    Bound strictly to account, service, verified domain, browser session, workflow,
    form fingerprint, and process instance ID.
    """
    token_id: str
    account_id: int
    service: str
    verified_domain: str
    browser_session_id: str
    workflow_id: str
    form_fingerprint: str
    process_instance_id: str
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
    3. Any mismatch in account, service, domain, session, process instance, or form fingerprint instantly invalidates approval.
    """

    def __init__(self, default_ttl_seconds: int = 120):
        self.default_ttl_seconds = default_ttl_seconds
        self._lock = threading.Lock()
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
            process_instance_id=settings.process_instance_id,
            created_at=now,
            expires_at=now + ttl,
            is_used=False
        )

        with self._lock:
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
        Fails closed on any discrepancy, process restart, or expiration.
        """
        with self._lock:
            if not token_id or token_id not in self._tokens:
                return False, "DENIED: Invalid or missing approval token. AI cannot manufacture approvals."

            token = self._tokens[token_id]

            if token.is_used:
                return False, "DENIED: Approval token has already been consumed (single-use invariant violated)."

            if token.process_instance_id != settings.process_instance_id:
                token.is_used = True
                return False, "DENIED: Approval token was issued by a prior or terminated process instance."

            now = time.time()
            if now > token.expires_at:
                token.is_used = True
                return False, f"DENIED: Approval token expired {now - token.expires_at:.1f}s ago."

            if token.account_id != account_id:
                return False, f"DENIED: Token account mismatch (expected #{token.account_id}, got #{account_id})."

            if token.service != service.lower().strip():
                return False, f"DENIED: Token service mismatch (expected '{token.service}', got '{service}')."

            if token.verified_domain != current_domain.lower().strip():
                token.is_used = True
                return False, f"DENIED: Token domain mismatch (expected '{token.verified_domain}', current '{current_domain}')."

            if token.browser_session_id != browser_session_id:
                return False, "DENIED: Token browser session mismatch."

            if token.workflow_id != workflow_id:
                return False, "DENIED: Token workflow ID mismatch."

            # Priority 7 & 10: Reject placeholder or default fingerprints in production
            if settings.environment == "production" and (
                not current_form_fingerprint or
                current_form_fingerprint in ("fp_default", "fp_resumed", "fingerprint_unknown", "default", "unknown")
            ):
                token.is_used = True
                return False, "DENIED: Placeholder or unreliable form fingerprint is prohibited in production."

            if token.form_fingerprint != current_form_fingerprint:
                token.is_used = True
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
        with self._lock:
            if token_id in self._tokens:
                self._tokens[token_id].is_used = True
                service = self._tokens[token_id].service
                audit_logger.log_event(
                    service,
                    f"Approval token '{token_id[:12]}...' invalidated: {reason}",
                    level="WARNING"
                )

    def invalidate_for_session(self, browser_session_id: str, reason: str) -> None:
        """Invalidates all tokens tied to a browser session (e.g. on navigation or redirect)."""
        with self._lock:
            if browser_session_id in self._session_tokens:
                tid = self._session_tokens[browser_session_id]
                if tid in self._tokens:
                    self._tokens[tid].is_used = True
                    service = self._tokens[tid].service
                    audit_logger.log_event(
                        service,
                        f"Approval token '{tid[:12]}...' invalidated for session '{browser_session_id}': {reason}",
                        level="WARNING"
                    )
                del self._session_tokens[browser_session_id]

# Singleton instance
approval_manager = SubmissionApprovalManager()
