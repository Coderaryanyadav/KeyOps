from typing import Dict, Any
from app.ai.base import AIProvider, ActionProposal, PageUnderstanding

class LocalAIProvider(AIProvider):
    """
    Local Deterministic AI Reasoning Provider.
    Operates 100% offline without remote network requests.
    """

    async def analyze_page(self, sanitized_page: Dict[str, Any], goal: str) -> PageUnderstanding:
        title = sanitized_page.get("title", "").lower()
        elements = sanitized_page.get("interactive_elements", [])
        
        has_pw_form = any(el.get("input_type") == "password" or el.get("autocomplete") in ["current-password", "new-password"] for el in elements)

        if has_pw_form:
            return PageUnderstanding(
                page_type="password_change_form",
                is_authenticated=True,
                has_password_form=True,
                summary="Local Engine: Password change form detected."
            )
        elif "security" in title or "settings" in title:
            return PageUnderstanding(
                page_type="security_settings",
                is_authenticated=True,
                has_password_form=False,
                summary="Local Engine: Settings page detected."
            )

        return PageUnderstanding(
            page_type="unknown",
            is_authenticated=True,
            has_password_form=False,
            summary="Local Engine: General page structure."
        )

    async def plan_next_action(self, sanitized_page: Dict[str, Any], goal: str) -> ActionProposal:
        elements = sanitized_page.get("interactive_elements", [])

        # Priority 1: Form field detection
        pw_inputs = [el for el in elements if el.get("input_type") == "password" or "password" in el.get("autocomplete", "")]
        if pw_inputs:
            submit_btn = next((el for el in elements if el.get("role") == "button" and any(w in el.get("text", "").lower() for w in ["save", "update", "change", "submit"])), None)
            if submit_btn:
                return ActionProposal(
                    action="submit",
                    target_id=submit_btn["element_id"],
                    reason="Password inputs ready. Proposing submit with human confirmation.",
                    confidence=0.95
                )

        # Priority 2: Navigation towards Security / Password
        for kw in ["Password", "Security", "Account Settings", "Settings", "Profile"]:
            match = next((el for el in elements if kw.lower() in el.get("text", "").lower()), None)
            if match:
                return ActionProposal(
                    action="click",
                    target_id=match["element_id"],
                    reason=f"Navigating via link '{match['text']}'.",
                    confidence=0.92
                )

        return ActionProposal(
            action="request_human_intervention",
            reason="Local Engine: Confidence insufficient for automated step.",
            confidence=0.50
        )
