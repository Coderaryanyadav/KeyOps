import pytest
from app.core.workflow_state import WorkflowState, WorkflowPhase, WorkflowStateMachine, InvalidWorkflowTransitionError

def test_workflow_state_initialization():
    state = WorkflowState(
        account_id=1,
        service="apple",
        expected_domain="apple.com"
    )
    assert state.phase == WorkflowPhase.DISCOVERING_SERVICE
    assert state.workflow_id.startswith("wf_")
    # Invariant: no raw secrets in model fields
    assert "password" not in state.model_dump()

def test_workflow_state_valid_transitions():
    state = WorkflowState(account_id=1, service="apple", expected_domain="apple.com")
    sm = WorkflowStateMachine(state)

    sm.transition_to(WorkflowPhase.VERIFYING_DOMAIN, "Starting domain check")
    assert state.phase == WorkflowPhase.VERIFYING_DOMAIN

    sm.transition_to(WorkflowPhase.OPENING_SITE, "Opening URL")
    assert state.phase == WorkflowPhase.OPENING_SITE

    sm.transition_to(WorkflowPhase.NAVIGATING, "AI navigation active")
    assert state.phase == WorkflowPhase.NAVIGATING

    sm.transition_to(WorkflowPhase.PASSWORD_FORM_DETECTED, "Form found")
    assert state.phase == WorkflowPhase.PASSWORD_FORM_DETECTED

    sm.transition_to(WorkflowPhase.PASSWORD_PREPARED, "Filled locally")
    assert state.phase == WorkflowPhase.PASSWORD_PREPARED

    sm.transition_to(WorkflowPhase.READY_FOR_APPROVAL, "Awaiting approval")
    assert state.phase == WorkflowPhase.READY_FOR_APPROVAL

    sm.transition_to(WorkflowPhase.APPROVED, "User clicked approve")
    assert state.phase == WorkflowPhase.APPROVED

    sm.transition_to(WorkflowPhase.SUBMITTING, "Submitted with token")
    assert state.phase == WorkflowPhase.SUBMITTING

    sm.transition_to(WorkflowPhase.VERIFYING_SUCCESS, "Checking response")
    assert state.phase == WorkflowPhase.VERIFYING_SUCCESS

    sm.transition_to(WorkflowPhase.SUCCESS, "Verified successfully")
    assert state.phase == WorkflowPhase.SUCCESS

def test_workflow_state_illegal_transitions_rejected():
    state = WorkflowState(account_id=2, service="github", expected_domain="github.com")
    sm = WorkflowStateMachine(state)

    # Attempting to jump directly from DISCOVERING_SERVICE to SUBMITTING must fail
    with pytest.raises(InvalidWorkflowTransitionError):
        sm.transition_to(WorkflowPhase.SUBMITTING)

    # Attempting to jump directly from NAVIGATING to SUBMITTING without approval must fail
    sm.transition_to(WorkflowPhase.VERIFYING_DOMAIN)
    sm.transition_to(WorkflowPhase.OPENING_SITE)
    sm.transition_to(WorkflowPhase.NAVIGATING)

    with pytest.raises(InvalidWorkflowTransitionError):
        sm.transition_to(WorkflowPhase.SUBMITTING)

def test_workflow_security_challenge_pause_and_resume():
    state = WorkflowState(account_id=3, service="google", expected_domain="google.com")
    sm = WorkflowStateMachine(state)

    sm.transition_to(WorkflowPhase.VERIFYING_DOMAIN)
    sm.transition_to(WorkflowPhase.OPENING_SITE)
    sm.transition_to(WorkflowPhase.NAVIGATING)
    
    # Challenge occurs
    sm.transition_to(WorkflowPhase.SECURITY_CHALLENGE, "MFA 2FA detected")
    assert state.last_safe_state == WorkflowPhase.NAVIGATING

    sm.transition_to(WorkflowPhase.WAITING_FOR_HUMAN, "Paused for human user")
    assert state.phase == WorkflowPhase.WAITING_FOR_HUMAN

    # Resumed by human
    sm.transition_to(WorkflowPhase.NAVIGATING, "Resumed after MFA")
    assert state.phase == WorkflowPhase.NAVIGATING
