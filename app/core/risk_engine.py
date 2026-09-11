from enum import Enum
from typing import List, Optional
from pydantic import BaseModel
from app.config import HIGH_VALUE_SERVICES

class RiskLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

class PasswordIssue(str, Enum):
    COMPROMISED = "Compromised"
    REUSED = "Reused"
    WEAK = "Weak"
    OLD = "Old Password"
    NO_MFA = "MFA Disabled"
    SECURE = "Secure"

class RiskAnalysis(BaseModel):
    risk_level: RiskLevel
    issues: List[PasswordIssue]
    reason: str
    is_high_value: bool
    priority_score: int  # 0 (lowest) to 100 (highest risk)

class RiskEngine:
    """
    Evaluates cybersecurity risk level for accounts based on breach exposure,
    password reuse, strength, age, MFA coverage, and identity authority.
    """

    def analyze_account(
        self,
        service_name: str,
        issue_status: str,
        mfa_enabled: bool = False,
        password_age_days: int = 0,
        is_reused_count: int = 1
    ) -> RiskAnalysis:
        service_key = service_name.lower()
        is_high_value = service_key in HIGH_VALUE_SERVICES or any(hv in service_key for hv in HIGH_VALUE_SERVICES)

        issues: List[PasswordIssue] = []
        raw_issue = issue_status.lower()

        if "compromised" in raw_issue:
            issues.append(PasswordIssue.COMPROMISED)
        if "reused" in raw_issue or is_reused_count > 1:
            issues.append(PasswordIssue.REUSED)
        if "weak" in raw_issue:
            issues.append(PasswordIssue.WEAK)
        if password_age_days > 365:
            issues.append(PasswordIssue.OLD)
        if not mfa_enabled:
            issues.append(PasswordIssue.NO_MFA)

        if not issues:
            issues.append(PasswordIssue.SECURE)

        # Risk scoring
        priority_score = 0
        if PasswordIssue.COMPROMISED in issues:
            priority_score += 50
        if PasswordIssue.REUSED in issues:
            priority_score += 30
        if PasswordIssue.WEAK in issues:
            priority_score += 20
        if PasswordIssue.NO_MFA in issues:
            priority_score += 15
        if PasswordIssue.OLD in issues:
            priority_score += 10
        if is_high_value:
            priority_score += 20

        # Map to Risk Level
        if PasswordIssue.COMPROMISED in issues and is_high_value:
            risk = RiskLevel.CRITICAL
        elif PasswordIssue.COMPROMISED in issues or (PasswordIssue.REUSED in issues and is_high_value):
            risk = RiskLevel.CRITICAL
        elif PasswordIssue.REUSED in issues or PasswordIssue.WEAK in issues or (is_high_value and PasswordIssue.NO_MFA in issues):
            risk = RiskLevel.HIGH
        elif PasswordIssue.OLD in issues or PasswordIssue.NO_MFA in issues:
            risk = RiskLevel.MEDIUM
        else:
            risk = RiskLevel.LOW

        reason_parts = [i.value for i in issues if i != PasswordIssue.SECURE]
        reason = ", ".join(reason_parts) if reason_parts else "No immediate risk factors detected."

        return RiskAnalysis(
            risk_level=risk,
            issues=issues,
            reason=reason,
            is_high_value=is_high_value,
            priority_score=min(100, priority_score)
        )
