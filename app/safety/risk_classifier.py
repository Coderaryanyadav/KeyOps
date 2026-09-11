import re
from enum import Enum
from typing import Tuple

class ActionRiskLevel(str, Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    DANGEROUS_BLOCKED = "DANGEROUS_BLOCKED"

class DangerousActionClassifier:
    """
    Classifies page elements and AI-proposed actions against a taxonomy of destructive,
    account-altering, or high-risk operations. Automatically blocks dangerous actions.
    """

    DANGEROUS_PATTERNS = [
        re.compile(r"\b(delete|close|deactivate|terminate|cancel)\s+(account|profile|membership|subscription)\b", re.IGNORECASE),
        re.compile(r"\b(remove|disable|turn\s*off)\s+(2fa|mfa|two-factor|authenticator|security\s*keys?)\b", re.IGNORECASE),
        re.compile(r"\b(transfer|send|withdraw)\s+(money|funds|crypto|credits?)\b", re.IGNORECASE),
        re.compile(r"\b(change|update|replace)\s+(recovery\s*email|phone\s*number|backup\s*phone)\b", re.IGNORECASE),
        re.compile(r"\b(generate|reset|regenerate)\s+(recovery\s*codes?|backup\s*codes?)\b", re.IGNORECASE),
        re.compile(r"\b(delete|wipe)\s+(all\s*data|vault|passwords?)\b", re.IGNORECASE),
    ]

    ALLOWED_PASSWORD_ACTIONS = [
        re.compile(r"\b(change|update|reset|modify|edit)\s*password\b", re.IGNORECASE),
        re.compile(r"\b(save|submit|update|continue)\b", re.IGNORECASE),
        re.compile(r"\b(security|account|profile|preferences|settings)\b", re.IGNORECASE),
    ]

    def classify_target(self, text_or_selector: str) -> Tuple[ActionRiskLevel, str]:
        target = text_or_selector.strip()

        # Check dangerous patterns
        for pattern in self.DANGEROUS_PATTERNS:
            if pattern.search(target):
                return ActionRiskLevel.DANGEROUS_BLOCKED, f"BLOCKED: Action target matches dangerous pattern '{pattern.pattern}'."

        # Check allowed patterns
        for pattern in self.ALLOWED_PASSWORD_ACTIONS:
            if pattern.search(target):
                return ActionRiskLevel.SAFE, "Target is recognized as safe password rotation navigation."

        return ActionRiskLevel.SAFE, "Target does not match high-risk classification."
