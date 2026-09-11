from typing import Tuple, Dict, Any, Optional
from app.safety.policy import SafetyPolicyConfig, default_safety_policy
from app.safety.risk_classifier import DangerousActionClassifier, ActionRiskLevel
from app.safety.domain_policy import DomainPolicyEngine
from app.core.domain_validator import DomainValidationError
from app.core.audit_logger import audit_logger

class ActionValidationError(Exception):
    """Raised when an AI action violates the safety policy."""
    pass

class ActionSafetyValidator:
    """
    Authoritative Guardian for all AI-proposed actions.
    Validates proposed actions before Playwright executes them.
    The AI cannot override this authority.
    """

    ALLOWED_ACTIONS = {
        "click",
        "fill_secret",
        "scroll",
        "navigate",
        "wait",
        "request_human_intervention",
        "locate_password_interface",
        "locate_password_field",
        "prepare_password_change",
        "request_submission_approval",
        "submit"
    }

    def __init__(self, policy: Optional[SafetyPolicyConfig] = None):
        self.policy = policy or default_safety_policy
        self.risk_classifier = DangerousActionClassifier()
        self.domain_policy = DomainPolicyEngine()

    def validate_action(
        self,
        action_payload: Dict[str, Any],
        service_name: str,
        current_domain: str,
        has_user_approval: bool = False
    ) -> Tuple[bool, str]:
        """
        Validates the proposed action against all safety rules.
        Returns (is_approved, reason).
        """
        action = action_payload.get("action", "").lower().strip()
        target = str(action_payload.get("target_id") or action_payload.get("target") or action_payload.get("target_url") or "")
        confidence = float(action_payload.get("confidence", 0.0))
        reason = action_payload.get("reason", "")

        # 1. Action type check
        if action not in self.ALLOWED_ACTIONS:
            return False, f"DENIED: Unknown or prohibited action type '{action}'."

        # 2. Dangerous action classification
        risk_level, risk_msg = self.risk_classifier.classify_target(target + " " + reason)
        if risk_level == ActionRiskLevel.DANGEROUS_BLOCKED:
            audit_logger.log_event(service_name, f"Safety Guardian BLOCKED dangerous action on target '{target}': {risk_msg}", level="ERROR")
            return False, risk_msg

        # 3. Confidence threshold checks
        if action == "navigate" and confidence < self.policy.min_navigation_confidence:
            return False, f"DENIED: Navigation confidence ({confidence:.2f}) is below safety threshold ({self.policy.min_navigation_confidence:.2f})."

        if action == "fill_secret":
            if confidence < self.policy.min_field_confidence:
                return False, f"DENIED: Field filling confidence ({confidence:.2f}) is below threshold ({self.policy.min_field_confidence:.2f})."
            secret_ref = action_payload.get("secret_reference", "")
            if secret_ref not in ["current_password", "new_password", "confirm_password"]:
                return False, f"DENIED: Invalid secret reference '{secret_ref}'. Raw passwords are never allowed."

        if action == "submit":
            if not has_user_approval and not action_payload.get("approval_token"):
                return False, "DENIED: Explicit human approval is required before form submission. AI cannot submit autonomously."
            if confidence < self.policy.min_submission_confidence:
                return False, f"DENIED: Submission confidence ({confidence:.2f}) is below threshold ({self.policy.min_submission_confidence:.2f})."

        # 4. Domain check for navigation
        if action == "navigate":
            target_url = action_payload.get("target_url") or target
            try:
                self.domain_policy.validate_navigation(target_url, service_name)
            except DomainValidationError as e:
                return False, f"DENIED: Domain policy violation: {str(e)}"

        audit_logger.log_event(service_name, f"Safety Guardian APPROVED action '{action}' on '{target}' (confidence={confidence:.2f}).")
        return True, "Action approved by Safety Policy Engine."

