from enum import Enum
import time
import uuid
from typing import Dict, Set, Optional, Any, List
from pydantic import BaseModel, Field
from app.core.audit_logger import audit_logger

class WorkflowPhase(str, Enum):
    DISCOVERING_SERVICE = "DISCOVERING_SERVICE"
    VERIFYING_DOMAIN = "VERIFYING_DOMAIN"
    OPENING_SITE = "OPENING_SITE"
    AUTHENTICATION_REQUIRED = "AUTHENTICATION_REQUIRED"
    AUTHENTICATED = "AUTHENTICATED"
    NAVIGATING = "NAVIGATING"
    PASSWORD_INTERFACE_FOUND = "PASSWORD_INTERFACE_FOUND"
    PASSWORD_FORM_DETECTED = "PASSWORD_FORM_DETECTED"
    PASSWORD_POLICY_DETECTED = "PASSWORD_POLICY_DETECTED"
    PASSWORD_PREPARED = "PASSWORD_PREPARED"
    SECURITY_CHALLENGE = "SECURITY_CHALLENGE"
    WAITING_FOR_HUMAN = "WAITING_FOR_HUMAN"
    READY_FOR_APPROVAL = "READY_FOR_APPROVAL"
    APPROVED = "APPROVED"
    SUBMITTING = "SUBMITTING"
    VERIFYING_SUCCESS = "VERIFYING_SUCCESS"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    LOW_CONFIDENCE = "LOW_CONFIDENCE"
    DOMAIN_VIOLATION = "DOMAIN_VIOLATION"

class InvalidWorkflowTransitionError(Exception):
    """Raised when an illegal state transition is attempted."""
    pass

class WorkflowState(BaseModel):
    """
    In-memory workflow state tracker.
    CRITICAL SECURITY INVARIANT: NEVER stores raw passwords, keys, tokens, or credentials.
    """
    workflow_id: str = Field(default_factory=lambda: f"wf_{uuid.uuid4().hex[:12]}")
    account_id: int
    service: str
    expected_domain: str
    current_url: str = ""
    phase: WorkflowPhase = WorkflowPhase.DISCOVERING_SERVICE
    last_safe_state: Optional[WorkflowPhase] = None
    challenge_type: Optional[str] = None
    resume_condition: Optional[str] = None
    form_fingerprint: str = ""
    approval_token_id: Optional[str] = None
    attempt_count: int = 0
    created_at: float = Field(default_factory=time.time)
    updated_at: float = Field(default_factory=time.time)
    history: List[str] = Field(default_factory=list)

class WorkflowStateMachine:
    """
    Strict Finite State Machine governing password rotation lifecycles.
    Enforces that dangerous or skipped transitions are rejected.
    """

    ALLOWED_TRANSITIONS: Dict[WorkflowPhase, Set[WorkflowPhase]] = {
        WorkflowPhase.DISCOVERING_SERVICE: {
            WorkflowPhase.VERIFYING_DOMAIN,
            WorkflowPhase.FAILED,
            WorkflowPhase.CANCELLED
        },
        WorkflowPhase.VERIFYING_DOMAIN: {
            WorkflowPhase.OPENING_SITE,
            WorkflowPhase.DOMAIN_VIOLATION,
            WorkflowPhase.FAILED,
            WorkflowPhase.CANCELLED
        },
        WorkflowPhase.OPENING_SITE: {
            WorkflowPhase.AUTHENTICATION_REQUIRED,
            WorkflowPhase.AUTHENTICATED,
            WorkflowPhase.NAVIGATING,
            WorkflowPhase.SECURITY_CHALLENGE,
            WorkflowPhase.DOMAIN_VIOLATION,
            WorkflowPhase.FAILED,
            WorkflowPhase.CANCELLED
        },
        WorkflowPhase.AUTHENTICATION_REQUIRED: {
            WorkflowPhase.WAITING_FOR_HUMAN,
            WorkflowPhase.FAILED,
            WorkflowPhase.CANCELLED
        },
        WorkflowPhase.AUTHENTICATED: {
            WorkflowPhase.NAVIGATING,
            WorkflowPhase.PASSWORD_INTERFACE_FOUND,
            WorkflowPhase.SECURITY_CHALLENGE,
            WorkflowPhase.FAILED,
            WorkflowPhase.CANCELLED
        },
        WorkflowPhase.NAVIGATING: {
            WorkflowPhase.PASSWORD_INTERFACE_FOUND,
            WorkflowPhase.PASSWORD_FORM_DETECTED,
            WorkflowPhase.SECURITY_CHALLENGE,
            WorkflowPhase.AUTHENTICATION_REQUIRED,
            WorkflowPhase.LOW_CONFIDENCE,
            WorkflowPhase.DOMAIN_VIOLATION,
            WorkflowPhase.FAILED,
            WorkflowPhase.CANCELLED
        },
        WorkflowPhase.PASSWORD_INTERFACE_FOUND: {
            WorkflowPhase.PASSWORD_FORM_DETECTED,
            WorkflowPhase.PASSWORD_POLICY_DETECTED,
            WorkflowPhase.SECURITY_CHALLENGE,
            WorkflowPhase.FAILED,
            WorkflowPhase.CANCELLED
        },
        WorkflowPhase.PASSWORD_FORM_DETECTED: {
            WorkflowPhase.PASSWORD_POLICY_DETECTED,
            WorkflowPhase.PASSWORD_PREPARED,
            WorkflowPhase.SECURITY_CHALLENGE,
            WorkflowPhase.FAILED,
            WorkflowPhase.CANCELLED
        },
        WorkflowPhase.PASSWORD_POLICY_DETECTED: {
            WorkflowPhase.PASSWORD_PREPARED,
            WorkflowPhase.FAILED,
            WorkflowPhase.CANCELLED
        },
        WorkflowPhase.PASSWORD_PREPARED: {
            WorkflowPhase.READY_FOR_APPROVAL,
            WorkflowPhase.SECURITY_CHALLENGE,
            WorkflowPhase.FAILED,
            WorkflowPhase.CANCELLED
        },
        WorkflowPhase.SECURITY_CHALLENGE: {
            WorkflowPhase.WAITING_FOR_HUMAN,
            WorkflowPhase.FAILED,
            WorkflowPhase.CANCELLED
        },
        WorkflowPhase.WAITING_FOR_HUMAN: {
            WorkflowPhase.VERIFYING_DOMAIN,
            WorkflowPhase.AUTHENTICATED,
            WorkflowPhase.NAVIGATING,
            WorkflowPhase.PASSWORD_INTERFACE_FOUND,
            WorkflowPhase.PASSWORD_FORM_DETECTED,
            WorkflowPhase.PASSWORD_PREPARED,
            WorkflowPhase.FAILED,
            WorkflowPhase.CANCELLED
        },
        WorkflowPhase.READY_FOR_APPROVAL: {
            WorkflowPhase.APPROVED,
            WorkflowPhase.CANCELLED,
            WorkflowPhase.FAILED,
            WorkflowPhase.DOMAIN_VIOLATION,
            WorkflowPhase.SECURITY_CHALLENGE
        },
        WorkflowPhase.APPROVED: {
            WorkflowPhase.SUBMITTING,
            WorkflowPhase.DOMAIN_VIOLATION,
            WorkflowPhase.FAILED,
            WorkflowPhase.CANCELLED
        },
        WorkflowPhase.SUBMITTING: {
            WorkflowPhase.VERIFYING_SUCCESS,
            WorkflowPhase.SECURITY_CHALLENGE,
            WorkflowPhase.FAILED
        },
        WorkflowPhase.VERIFYING_SUCCESS: {
            WorkflowPhase.SUCCESS,
            WorkflowPhase.FAILED,
            WorkflowPhase.LOW_CONFIDENCE
        },
        # Terminal states have no further transitions except explicit reset
        WorkflowPhase.SUCCESS: set(),
        WorkflowPhase.FAILED: {WorkflowPhase.DISCOVERING_SERVICE, WorkflowPhase.VERIFYING_DOMAIN},
        WorkflowPhase.CANCELLED: {WorkflowPhase.DISCOVERING_SERVICE},
        WorkflowPhase.LOW_CONFIDENCE: {WorkflowPhase.NAVIGATING, WorkflowPhase.WAITING_FOR_HUMAN, WorkflowPhase.FAILED},
        WorkflowPhase.DOMAIN_VIOLATION: {WorkflowPhase.FAILED}
    }

    def __init__(self, state: WorkflowState):
        self.state = state

    def transition_to(self, target_phase: WorkflowPhase, reason: str = "") -> None:
        """
        Transitions the workflow to a new phase if allowed.
        Fails with InvalidWorkflowTransitionError if transition is illegal.
        """
        current = self.state.phase

        if target_phase == current:
            return

        allowed = self.ALLOWED_TRANSITIONS.get(current, set())
        if target_phase not in allowed:
            raise InvalidWorkflowTransitionError(
                f"Illegal state transition from '{current.value}' to '{target_phase.value}'. "
                f"Allowed transitions: {[p.value for p in allowed]}"
            )

        # Update last safe state before pausing for human or challenge
        if target_phase in (WorkflowPhase.SECURITY_CHALLENGE, WorkflowPhase.WAITING_FOR_HUMAN):
            if current not in (WorkflowPhase.SECURITY_CHALLENGE, WorkflowPhase.WAITING_FOR_HUMAN):
                self.state.last_safe_state = current

        self.state.history.append(f"{current.value} -> {target_phase.value} ({reason or 'standard transition'})")
        self.state.phase = target_phase
        self.state.updated_at = time.time()

        audit_logger.log_event(
            self.state.service,
            f"Workflow {self.state.workflow_id} transitioned: {current.value} -> {target_phase.value} ({reason})"
        )
