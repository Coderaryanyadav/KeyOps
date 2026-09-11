import asyncio
import hashlib
from typing import Dict, Any, Optional, Callable, Awaitable
from playwright.async_api import Page
from app.ai.base import AIProvider, ActionProposal
from app.ai.providers.gemini import GeminiAIProvider
from app.ai.providers.local import LocalAIProvider
from app.ai.page_analyzer import PageAnalyzer
from app.ai.confidence import MultiDimensionalConfidenceEngine
from app.safety.action_validator import ActionSafetyValidator
from app.safety.domain_trust import DomainTrustContext, DomainTrustResult
from app.safety.secret_boundary import SecretBoundary
from app.browser.action_executor import ControlledActionExecutor
from app.browser.human_interrupter import HumanInterrupter
from app.browser.auth_detector import AuthenticationDetector
from app.core.audit_logger import audit_logger

class AINavigator:
    """
    Controlled AI Navigation Loop.
    Executes: Inspect -> Sanitize -> AI Reason -> Action Plan -> Safety Validator -> Controlled Action -> Repeat.
    CRITICAL INVARIANT: The AI loop NEVER submits forms autonomously. It halts and requests explicit user approval.
    """

    def __init__(self, ai_provider: Optional[AIProvider] = None):
        self.provider = ai_provider or GeminiAIProvider()
        self.analyzer = PageAnalyzer()
        self.validator = ActionSafetyValidator()
        self.executor = ControlledActionExecutor()
        self.interrupter = HumanInterrupter()
        self.auth_detector = AuthenticationDetector()
        self.confidence_engine = MultiDimensionalConfidenceEngine()

    async def compute_form_fingerprint(self, page: Page) -> str:
        """Computes a deterministic hash of all password fields and form attributes on the page."""
        try:
            inputs_info = await page.evaluate("""() => {
                const inputs = Array.from(document.querySelectorAll("input[type='password'], input[autocomplete*='password'], input[name*='pass']"));
                return inputs.map(i => `${i.tagName}|${i.type}|${i.name}|${i.id}|${i.getAttribute('autocomplete') || ''}`).join(';;');
            }""")
            return hashlib.sha256(inputs_info.encode('utf-8')).hexdigest()[:16]
        except Exception:
            return "fingerprint_unknown"

    async def navigate_to_password_interface(
        self,
        page: Page,
        service_name: str,
        domain: str,
        secret_boundary: SecretBoundary,
        max_steps: int = 10,
        on_step_callback: Optional[Callable[[Dict[str, Any]], Awaitable[None]]] = None,
        domain_trust_context: Optional[DomainTrustContext] = None
    ) -> Dict[str, Any]:
        """
        Drives browser navigation towards the password management interface under strict safety controls.
        Returns a structured result dict with status:
        - "READY_FOR_APPROVAL"
        - "HUMAN_INTERVENTION_REQUIRED"
        - "LOGIN_REQUIRED"
        - "DOMAIN_VIOLATION"
        - "LOW_CONFIDENCE_HALT"
        - "FAILED"
        """
        trust_ctx = domain_trust_context or DomainTrustContext(expected_service=service_name, allowed_explicit_domains=[domain])
        audit_logger.log_event(service_name, f"Starting AI Navigation loop on domain '{domain}'.")

        for step_idx in range(1, max_steps + 1):
            current_url = page.url

            # 1. Runtime Domain Trust Verification
            trust_res: DomainTrustResult = trust_ctx.evaluate_url(current_url)
            if not trust_res.is_trusted:
                audit_logger.log_event(service_name, f"Domain trust violation at URL '{current_url}': {trust_res.reason}", level="ERROR")
                if on_step_callback:
                    await on_step_callback({
                        "step": step_idx,
                        "status": "DOMAIN_VIOLATION",
                        "message": f"Untrusted domain detected ({trust_res.registrable_domain}): {trust_res.reason}"
                    })
                return {
                    "status": "DOMAIN_VIOLATION",
                    "step": step_idx,
                    "reason": trust_res.reason,
                    "url": current_url
                }

            # 2. Check for MFA, CAPTCHA, or Security Challenges
            checkpoint = await self.interrupter.check_security_checkpoints(page, service_name)
            if checkpoint:
                if on_step_callback:
                    await on_step_callback({
                        "step": step_idx,
                        "status": "HUMAN_INTERVENTION_REQUIRED",
                        "challenge_type": checkpoint[0],
                        "message": f"Security Verification Required: {checkpoint[1]}"
                    })
                return {
                    "status": "HUMAN_INTERVENTION_REQUIRED",
                    "step": step_idx,
                    "challenge_type": checkpoint[0],
                    "details": checkpoint[1]
                }

            # 3. Check for unauthenticated login requirement
            is_auth, auth_conf, auth_reason = await self.auth_detector.detect_auth_state(page)
            if not is_auth:
                audit_logger.log_event(service_name, f"Login required before rotation: {auth_reason}", level="WARNING")
                if on_step_callback:
                    await on_step_callback({
                        "step": step_idx,
                        "status": "LOGIN_REQUIRED",
                        "message": "Please complete login manually in the browser."
                    })
                return {
                    "status": "LOGIN_REQUIRED",
                    "step": step_idx,
                    "reason": auth_reason
                }

            # 4. Inspect and sanitize DOM
            inspection, sanitized = await self.analyzer.analyze(page)

            # 5. AI Reasoning: Plan next action
            proposal: ActionProposal = await self.provider.plan_next_action(
                sanitized,
                goal="Navigate to account security settings, locate password change form, and prepare credential rotation."
            )

            # 6. Composite confidence evaluation
            is_cred_action = proposal.action in ("fill_secret", "prepare_password_change", "request_submission_approval", "submit")
            conf_eval = self.confidence_engine.calculate_confidence(
                ai_conf=proposal.confidence,
                dom_conf=0.95 if proposal.target_id in inspection.element_map else 0.50,
                semantic_conf=0.90,
                is_verified_domain=trust_res.is_trusted,
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
                return {
                    "status": "LOW_CONFIDENCE_HALT",
                    "step": step_idx,
                    "confidence": conf_eval.overall_confidence
                }

            # 7. Safety Policy Engine Validation
            is_approved, safety_reason = self.validator.validate_action(
                proposal.model_dump(),
                service_name=service_name,
                current_domain=trust_res.registrable_domain,
                has_user_approval=False
            )

            if not is_approved:
                audit_logger.log_event(service_name, f"Safety Policy Engine DENIED action: {safety_reason}", level="ERROR")
                return {
                    "status": "SAFETY_DENIED",
                    "step": step_idx,
                    "reason": safety_reason
                }

            # 8. Notify observer of approved step
            if on_step_callback:
                await on_step_callback({
                    "step": step_idx,
                    "action": proposal.action,
                    "target": proposal.target_id,
                    "reason": proposal.reason,
                    "confidence": conf_eval.overall_confidence,
                    "safety_status": "APPROVED"
                })

            # 9. Handle human intervention action
            if proposal.action == "request_human_intervention":
                return {
                    "status": "HUMAN_INTERVENTION_REQUIRED",
                    "step": step_idx,
                    "challenge_type": proposal.challenge_type or "MANUAL_GUIDANCE",
                    "details": proposal.reason
                }

            # 10. Handle submission approval request
            if proposal.action in ("request_submission_approval", "submit"):
                form_fp = await self.compute_form_fingerprint(page)
                audit_logger.log_event(service_name, f"AI reached password change form. Form fingerprint: {form_fp}. Awaiting user approval.")
                return {
                    "status": "READY_FOR_APPROVAL",
                    "step": step_idx,
                    "form_fingerprint": form_fp,
                    "target_id": proposal.target_id,
                    "reason": proposal.reason
                }

            # 11. Controlled Browser Execution for non-submission actions
            await self.executor.execute_action(
                page=page,
                action_payload=proposal.model_dump(),
                element_map=inspection.element_map,
                secret_boundary=secret_boundary
            )

            await asyncio.sleep(1.0)

        audit_logger.log_event(service_name, "AI Navigation loop reached maximum steps without completing preparation.", level="WARNING")
        return {
            "status": "FAILED",
            "step": max_steps,
            "reason": "Max navigation steps reached."
        }
