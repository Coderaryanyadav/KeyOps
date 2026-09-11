import asyncio
from typing import Dict, Any, Optional, Callable, Awaitable
from playwright.async_api import Page
from app.ai.base import AIProvider, ActionProposal
from app.ai.providers.gemini import GeminiAIProvider
from app.ai.providers.local import LocalAIProvider
from app.ai.page_analyzer import PageAnalyzer
from app.ai.confidence import MultiDimensionalConfidenceEngine
from app.safety.action_validator import ActionSafetyValidator
from app.safety.secret_boundary import SecretBoundary
from app.browser.action_executor import ControlledActionExecutor
from app.browser.human_interrupter import HumanInterrupter
from app.browser.auth_detector import AuthenticationDetector
from app.core.audit_logger import audit_logger

class AINavigator:
    """
    Controlled AI Navigation Loop.
    Executes: Inspect -> Sanitize -> AI Reason -> Action Plan -> Safety Validator -> Controlled Action -> Repeat.
    """

    def __init__(self, ai_provider: Optional[AIProvider] = None):
        self.provider = ai_provider or GeminiAIProvider()
        self.analyzer = PageAnalyzer()
        self.validator = ActionSafetyValidator()
        self.executor = ControlledActionExecutor()
        self.interrupter = HumanInterrupter()
        self.auth_detector = AuthenticationDetector()
        self.confidence_engine = MultiDimensionalConfidenceEngine()

    async def navigate_to_password_interface(
        self,
        page: Page,
        service_name: str,
        domain: str,
        secret_boundary: SecretBoundary,
        max_steps: int = 10,
        on_step_callback: Optional[Callable[[Dict[str, Any]], Awaitable[None]]] = None
    ) -> bool:
        """
        Drives browser navigation towards the password management interface under strict safety controls.
        """
        audit_logger.log_event(service_name, f"Starting AI Navigation loop on domain '{domain}'.")

        for step_idx in range(1, max_steps + 1):
            # 1. Check for MFA, CAPTCHA, or Security Challenges
            checkpoint = await self.interrupter.check_security_checkpoints(page, service_name)
            if checkpoint:
                if on_step_callback:
                    await on_step_callback({
                        "step": step_idx,
                        "status": "HUMAN_INTERVENTION_REQUIRED",
                        "challenge_type": checkpoint[0],
                        "message": f"Security Verification Required: {checkpoint[1]}"
                    })
                return False

            # 2. Check for unauthenticated login requirement
            is_auth, auth_conf, auth_reason = await self.auth_detector.detect_auth_state(page)
            if not is_auth:
                audit_logger.log_event(service_name, f"Login required before rotation: {auth_reason}", level="WARNING")
                if on_step_callback:
                    await on_step_callback({
                        "step": step_idx,
                        "status": "LOGIN_REQUIRED",
                        "message": "Please complete login manually in the browser."
                    })
                return False

            # 3. Inspect and sanitize DOM
            inspection, sanitized = await self.analyzer.analyze(page)

            # 4. AI Reasoning: Plan next action
            proposal: ActionProposal = await self.provider.plan_next_action(
                sanitized,
                goal="Navigate to account security settings and locate password change form."
            )

            # 5. Composite confidence evaluation
            is_cred_action = proposal.action in ("fill_secret", "submit")
            conf_eval = self.confidence_engine.calculate_confidence(
                ai_conf=proposal.confidence,
                dom_conf=0.95 if proposal.target_id in inspection.element_map else 0.50,
                semantic_conf=0.90,
                is_verified_domain=True,
                is_credential_action=is_cred_action
            )

            if conf_eval.decision == "REJECT_LOW_CONFIDENCE":
                audit_logger.log_event(service_name, f"AI action rejected due to low confidence ({conf_eval.overall_confidence:.2f}).", level="WARNING")
                if on_step_callback:
                    await on_step_callback({
                        "step": step_idx,
                        "status": "LOW_CONFIDENCE_HALT",
                        "message": f"Low confidence ({conf_eval.overall_confidence * 100:.0f}%). Human takeover advised."
                    })
                return False

            # 6. Safety Policy Engine Validation
            is_approved, safety_reason = self.validator.validate_action(
                proposal.model_dump(),
                service_name=service_name,
                current_domain=domain
            )

            if not is_approved:
                audit_logger.log_event(service_name, f"Safety Policy Engine DENIED action: {safety_reason}", level="ERROR")
                return False

            # 7. Notify observer
            if on_step_callback:
                await on_step_callback({
                    "step": step_idx,
                    "action": proposal.action,
                    "target": proposal.target_id,
                    "reason": proposal.reason,
                    "confidence": conf_eval.overall_confidence,
                    "safety_status": "APPROVED"
                })

            # Check if we have reached the final submit phase
            if proposal.action == "submit":
                audit_logger.log_event(service_name, "AI Navigation reached password change form and prepared submission.")
                return True

            # 8. Controlled Browser Execution
            await self.executor.execute_action(
                page=page,
                action_payload=proposal.model_dump(),
                element_map=inspection.element_map,
                secret_boundary=secret_boundary
            )

            await asyncio.sleep(1.0)

        audit_logger.log_event(service_name, "AI Navigation loop reached maximum steps without finding password form.", level="WARNING")
        return False
