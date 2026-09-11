from enum import Enum
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field

class ActionType(str, Enum):
    NAVIGATE = "NAVIGATE"
    CLICK = "CLICK"
    FILL = "FILL"
    WAIT_FOR_HUMAN = "WAIT_FOR_HUMAN"
    SUBMIT = "SUBMIT"
    VERIFY = "VERIFY"
    HALT = "HALT"

class ActionPlan(BaseModel):
    action_type: ActionType
    target_selector: Optional[str] = None
    target_url: Optional[str] = None
    field_role: Optional[str] = None  # current_password, new_password, confirm_password
    reason: str
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    risk_level: str = "LOW"  # LOW, MEDIUM, HIGH, CRITICAL
    requires_human_approval: bool = False
    metadata: Dict[str, Any] = Field(default_factory=dict)

class ActionPlanner:
    """
    Structured action planner for browser navigation and credential manipulation.
    Generates explicit, explainable actions with attached confidence scores.
    """

    @staticmethod
    def plan_navigation(url: str, reason: str, confidence: float = 0.95) -> ActionPlan:
        return ActionPlan(
            action_type=ActionType.NAVIGATE,
            target_url=url,
            reason=reason,
            confidence=confidence,
            risk_level="LOW",
            requires_human_approval=False
        )

    @staticmethod
    def plan_human_takeover(reason: str, challenge_type: str = "MFA") -> ActionPlan:
        return ActionPlan(
            action_type=ActionType.WAIT_FOR_HUMAN,
            reason=f"Human intervention required: {reason} ({challenge_type})",
            confidence=1.0,
            risk_level="HIGH",
            requires_human_approval=True,
            metadata={"challenge_type": challenge_type}
        )

    @staticmethod
    def plan_fill_field(role: str, selector: str, confidence: float, reason: str) -> ActionPlan:
        return ActionPlan(
            action_type=ActionType.FILL,
            target_selector=selector,
            field_role=role,
            reason=reason,
            confidence=confidence,
            risk_level="MEDIUM",
            requires_human_approval=False
        )

    @staticmethod
    def plan_submit(selector: str, confidence: float, reason: str) -> ActionPlan:
        return ActionPlan(
            action_type=ActionType.SUBMIT,
            target_selector=selector,
            reason=reason,
            confidence=confidence,
            risk_level="HIGH",
            requires_human_approval=True
        )

    @staticmethod
    def plan_halt(reason: str, confidence: float = 0.0) -> ActionPlan:
        return ActionPlan(
            action_type=ActionType.HALT,
            reason=f"SAFETY HALT: {reason}",
            confidence=confidence,
            risk_level="CRITICAL",
            requires_human_approval=True
        )
