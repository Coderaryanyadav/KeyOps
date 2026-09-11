from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field

class ActionProposal(BaseModel):
    """
    Structured action proposed by AI reasoning layer.
    CRITICAL SECURITY INVARIANTS:
    - Never contains raw credentials or secret values.
    - AI CANNOT propose autonomous 'submit'. It proposes 'request_submission_approval'.
    """
    action: str  # click, fill_secret, scroll, navigate, wait, request_human_intervention, locate_password_interface, locate_password_field, prepare_password_change, request_submission_approval
    target_id: Optional[str] = None
    target_url: Optional[str] = None
    secret_reference: Optional[str] = None  # current_password, new_password, confirm_password
    reason: str
    confidence: float = Field(default=0.90, ge=0.0, le=1.0)
    challenge_type: Optional[str] = None

class PageUnderstanding(BaseModel):
    page_type: str  # login, account_settings, security_settings, password_change_form, challenge, unknown
    is_authenticated: bool = True
    has_password_form: bool = False
    challenge_detected: Optional[str] = None
    semantic_sections: List[str] = Field(default_factory=list)
    summary: str = ""

class AIProvider(ABC):
    """
    Abstract AI Reasoning Provider interface.
    Consumes sanitized page states and emits structured action proposals.
    """

    @abstractmethod
    async def analyze_page(self, sanitized_page: Dict[str, Any], goal: str) -> PageUnderstanding:
        pass

    @abstractmethod
    async def plan_next_action(self, sanitized_page: Dict[str, Any], goal: str) -> ActionProposal:
        pass
