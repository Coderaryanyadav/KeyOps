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

def test_action_validator_enforces_confidence_thresholds():
    validator = ActionSafetyValidator()

    # Low confidence -> DENIED
    low_conf_proposal = {
        "action": "navigate",
        "target_url": "https://github.com/settings",
        "confidence": 0.50,
        "reason": "Guessing navigation"
    }
    approved, reason = validator.validate_action(low_conf_proposal, "GitHub", "github.com")
    assert approved is False
    assert "DENIED" in reason
