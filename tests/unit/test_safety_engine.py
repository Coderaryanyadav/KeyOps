import pytest
from app.safety.risk_classifier import DangerousActionClassifier, ActionRiskLevel
from app.safety.action_validator import ActionSafetyValidator
from app.safety.policy import SafetyPolicyConfig

def test_dangerous_action_classifier():
    classifier = DangerousActionClassifier()

    risk, msg = classifier.classify_target("Delete account permanently")
    assert risk == ActionRiskLevel.DANGEROUS_BLOCKED

    risk, msg = classifier.classify_target("Disable 2FA authentication")
    assert risk == ActionRiskLevel.DANGEROUS_BLOCKED

    risk, msg = classifier.classify_target("Transfer money to external account")
    assert risk == ActionRiskLevel.DANGEROUS_BLOCKED

    risk, msg = classifier.classify_target("Change password")
    assert risk == ActionRiskLevel.SAFE

def test_action_validator_blocks_dangerous_proposals():
    validator = ActionSafetyValidator()

    # Proposing dangerous action -> DENIED
    proposal = {
        "action": "click",
        "target": "Delete account permanently",
        "confidence": 0.99,
        "reason": "AI proposes deleting account"
    }
    approved, reason = validator.validate_action(proposal, "TestService", "test.com")
    assert approved is False
    assert "BLOCKED" in reason

def test_action_validator_blocks_autonomous_submit():
    validator = ActionSafetyValidator()

    # Autonomous submit proposed by AI without human approval -> DENIED
    proposal = {
        "action": "submit",
        "target": "submit_btn",
        "confidence": 1.0,
        "reason": "Submitting password form"
    }
    approved, reason = validator.validate_action(proposal, "GitHub", "github.com", has_user_approval=False)
    assert approved is False
    assert "Explicit human approval is required" in reason

    # With explicit user approval -> APPROVED
    approved_ok, reason_ok = validator.validate_action(proposal, "GitHub", "github.com", has_user_approval=True)
    assert approved_ok is True

