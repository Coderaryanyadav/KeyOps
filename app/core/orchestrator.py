import asyncio
import uuid
from typing import Dict, Any, Optional, Callable, Awaitable
from playwright.async_api import Page, BrowserContext

from app.core.workflow_state import WorkflowState, WorkflowPhase, WorkflowStateMachine
from app.core.password_generator import PasswordGenerator, PasswordPolicy
from app.safety.secret_boundary import SecretBoundary
from app.safety.domain_trust import DomainTrustContext
from app.safety.submission_approval import approval_manager, ApprovalToken
from app.browser.engine import BrowserAutomationEngine
from app.browser.success_verifier import password_change_verifier, VerificationOutcome
from app.browser.action_executor import ControlledActionExecutor
from app.ai.navigator import AINavigator
from app.adapters.registry import adapter_registry
from app.integrations.keychain import KeychainManager
from app.core.audit_logger import audit_logger

class PasswordRotationOrchestrator:
    """
    Master Workflow Orchestrator for KeyOps.
    Coordinates the safe, end-to-end AI-assisted password rotation lifecycle with
    authoritative human approval, deterministic DOM validation, and strict state transitions.
    """

    def __init__(self, browser_engine: Optional[BrowserAutomationEngine] = None):
        self.browser_engine = browser_engine or BrowserAutomationEngine()
        self.navigator = AINavigator()
        self.executor = ControlledActionExecutor()
        self.generator = PasswordGenerator()
        # Active in-memory workflow sessions: workflow_id -> WorkflowState
        self._active_workflows: Dict[str, WorkflowState] = {}
        # Active secret boundaries: workflow_id -> SecretBoundary
        self._secret_boundaries: Dict[str, SecretBoundary] = {}
        # Active page references: workflow_id -> Page
        self._active_pages: Dict[str, Page] = {}
        # Active browser contexts: workflow_id -> BrowserContext
        self._active_contexts: Dict[str, BrowserContext] = {}

    def get_workflow_state(self, workflow_id: str) -> Optional[WorkflowState]:
        return self._active_workflows.get(workflow_id)

    async def prepare_rotation_workflow(
        self,
        account_id: int,
        service: str,
        domain: str,
        username: str,
        current_password: Optional[str] = None,
        custom_policy: Optional[PasswordPolicy] = None,
        on_progress_callback: Optional[Callable[[Dict[str, Any]], Awaitable[None]]] = None
    ) -> Dict[str, Any]:
        """
        Phase 1: Initializes workflow state machine, opens official site in browser,
        runs AI navigation to locate and prepare password change fields, computes form fingerprint,
        and halts at READY_FOR_APPROVAL.
        """
        workflow_id = f"wf_{uuid.uuid4().hex[:12]}"
        session_id = f"sess_{uuid.uuid4().hex[:8]}"

        state = WorkflowState(
            workflow_id=workflow_id,
            account_id=account_id,
            service=service,
            expected_domain=domain,
            phase=WorkflowPhase.DISCOVERING_SERVICE
        )
        sm = WorkflowStateMachine(state)
        self._active_workflows[workflow_id] = state

        # Initialize local SecretBoundary
        secret_boundary = SecretBoundary()
        self._secret_boundaries[workflow_id] = secret_boundary

        # Determine password policy and generate secure password locally
        adapter = adapter_registry.get_adapter_for_service(service, domain)
        policy = custom_policy or adapter.get_password_policy()
        new_password = self.generator.generate(policy)
        secret_boundary.register_secrets(current_password=current_password, new_password=new_password)

        trust_ctx = DomainTrustContext(expected_service=service, allowed_explicit_domains=[domain])
        trust_ctx.register_on_domain_changed_callback(
            lambda old_d, new_d: approval_manager.invalidate_for_session(session_id, f"Domain changed from {old_d} to {new_d}")
        )

        async def emit_progress(phase: WorkflowPhase, message: str, confidence: float = 0.95, extra: Optional[Dict] = None):
            if on_progress_callback:
                payload = {
                    "workflow_id": workflow_id,
                    "account_id": account_id,
                    "service": service,
                    "phase": phase.value,
                    "message": message,
                    "confidence": confidence
                }
                if extra:
                    payload.update(extra)
                await on_progress_callback(payload)

        try:
            # 1. Domain Verification
            sm.transition_to(WorkflowPhase.VERIFYING_DOMAIN, "Verifying official domain registry.")
            await emit_progress(WorkflowPhase.VERIFYING_DOMAIN, f"Verifying official domain for {service}...")

            start_url = adapter.get_settings_url() if hasattr(adapter, 'get_settings_url') else f"https://{domain}"
            trust_eval = trust_ctx.evaluate_url(start_url)
            if not trust_eval.is_trusted:
                sm.transition_to(WorkflowPhase.DOMAIN_VIOLATION, trust_eval.reason)
                await emit_progress(WorkflowPhase.DOMAIN_VIOLATION, f"Untrusted domain: {trust_eval.reason}")
                return {"status": "DOMAIN_VIOLATION", "workflow_id": workflow_id, "reason": trust_eval.reason}

            # 2. Open Site
            sm.transition_to(WorkflowPhase.OPENING_SITE, f"Navigating to {start_url}")
            await emit_progress(WorkflowPhase.OPENING_SITE, f"Opening official portal: {start_url}")
            
            context = await self.browser_engine.create_context()
            self._active_contexts[workflow_id] = context
            page = await context.new_page()
            self._active_pages[workflow_id] = page

            await page.goto(start_url, wait_until="domcontentloaded")
            state.current_url = page.url

            # 3. AI Navigation loop
            sm.transition_to(WorkflowPhase.NAVIGATING, "AI actively discovering password change interface.")
            await emit_progress(WorkflowPhase.NAVIGATING, "AI analyzing page semantics to find Security & Credentials...")

            nav_result = await self.navigator.navigate_to_password_interface(
                page=page,
                service_name=service,
                domain=domain,
                secret_boundary=secret_boundary,
                domain_trust_context=trust_ctx,
                on_step_callback=on_progress_callback
            )

            nav_status = nav_result.get("status")

            if nav_status == "READY_FOR_APPROVAL":
                sm.transition_to(WorkflowPhase.PASSWORD_FORM_DETECTED, "Password form detected.")
                sm.transition_to(WorkflowPhase.PASSWORD_PREPARED, "Credentials prepared in DOM.")
                sm.transition_to(WorkflowPhase.READY_FOR_APPROVAL, "Awaiting explicit user submission authorization.")
                
                form_fp = nav_result.get("form_fingerprint", "fp_default")
                state.form_fingerprint = form_fp

                await emit_progress(
                    WorkflowPhase.READY_FOR_APPROVAL,
                    "Password change form ready for submission. User confirmation required.",
                    extra={"form_fingerprint": form_fp, "session_id": session_id}
                )

                return {
                    "status": "READY_FOR_APPROVAL",
                    "workflow_id": workflow_id,
                    "session_id": session_id,
                    "account_id": account_id,
                    "service": service,
                    "domain": domain,
                    "form_fingerprint": form_fp,
                    "generated_password": new_password,
                    "password_policy": policy.model_dump(),
                    "requires_approval": True
                }

            elif nav_status == "HUMAN_INTERVENTION_REQUIRED":
                challenge = nav_result.get("challenge_type", "SECURITY_CHALLENGE")
                sm.transition_to(WorkflowPhase.SECURITY_CHALLENGE, f"Challenge: {challenge}")
                sm.transition_to(WorkflowPhase.WAITING_FOR_HUMAN, "Paused for human takeover.")
                state.challenge_type = challenge

                await emit_progress(
                    WorkflowPhase.WAITING_FOR_HUMAN,
                    f"Action Required: Please complete {challenge} verification in the browser.",
                    extra={"challenge_type": challenge, "details": nav_result.get("details", "")}
                )
                return {
                    "status": "WAITING_FOR_HUMAN",
                    "workflow_id": workflow_id,
                    "session_id": session_id,
                    "challenge_type": challenge,
                    "message": "Complete the verification challenge in the open browser window, then click Resume."
                }

            elif nav_status == "LOGIN_REQUIRED":
                sm.transition_to(WorkflowPhase.AUTHENTICATION_REQUIRED, "User login required.")
                sm.transition_to(WorkflowPhase.WAITING_FOR_HUMAN, "Paused for manual user login.")
                state.challenge_type = "LOGIN_REQUIRED"

                await emit_progress(
                    WorkflowPhase.WAITING_FOR_HUMAN,
                    "Please log into your account in the browser to proceed.",
                    extra={"challenge_type": "LOGIN_REQUIRED"}
                )
                return {
                    "status": "WAITING_FOR_HUMAN",
                    "workflow_id": workflow_id,
                    "session_id": session_id,
                    "challenge_type": "LOGIN_REQUIRED",
                    "message": "Please complete login in the browser window, then click Resume."
                }

            else:
                sm.transition_to(WorkflowPhase.FAILED, f"AI navigation terminated: {nav_status}")
                await emit_progress(WorkflowPhase.FAILED, f"Preparation failed: {nav_result.get('reason', 'Unknown error')}")
                return {
                    "status": "FAILED",
                    "workflow_id": workflow_id,
                    "reason": nav_result.get("reason", "Preparation failed.")
                }

        except Exception as e:
            sm.transition_to(WorkflowPhase.FAILED, f"Exception: {str(e)}")
            await emit_progress(WorkflowPhase.FAILED, f"Error: {str(e)}")
            return {"status": "FAILED", "workflow_id": workflow_id, "reason": str(e)}

    async def execute_approved_submission(
        self,
        workflow_id: str,
        approval_token_id: str,
        session_id: str,
        save_to_keychain: bool = True,
        on_progress_callback: Optional[Callable[[Dict[str, Any]], Awaitable[None]]] = None
    ) -> Dict[str, Any]:
        """
        Phase 2: Verifies single-use approval token, transitions state to APPROVED -> SUBMITTING,
        executes submit, and verifies outcome using PasswordChangeVerifier.
        """
        state = self._active_workflows.get(workflow_id)
        if not state:
            return {"status": "FAILED", "message": "Workflow session not found or expired."}

        page = self._active_pages.get(workflow_id)
        secret_boundary = self._secret_boundaries.get(workflow_id)
        sm = WorkflowStateMachine(state)

        # Transition to APPROVED
        sm.transition_to(WorkflowPhase.APPROVED, "User explicitly confirmed password change.")

        # Re-verify live form fingerprint before submission
        current_fp = await self.navigator.compute_form_fingerprint(page) if page else ""

        approval_ctx = {
            "token_id": approval_token_id,
            "account_id": state.account_id,
            "service": state.service,
            "current_domain": state.expected_domain,
            "browser_session_id": session_id,
            "workflow_id": workflow_id,
            "form_fingerprint": current_fp
        }

        sm.transition_to(WorkflowPhase.SUBMITTING, "Submitting password update to server.")
        if on_progress_callback:
            await on_progress_callback({
                "workflow_id": workflow_id,
                "account_id": state.account_id,
                "phase": WorkflowPhase.SUBMITTING.value,
                "message": "Submitting password update..."
            })

        try:
            # Execute submit action through ControlledActionExecutor
            await self.executor.execute_action(
                page=page,
                action_payload={"action": "submit", "confidence": 1.0},
                element_map={},
                secret_boundary=secret_boundary,
                approval_context=approval_ctx
            )

            # Transition to VERIFYING_SUCCESS
            sm.transition_to(WorkflowPhase.VERIFYING_SUCCESS, "Inspecting post-submission outcome.")
            if on_progress_callback:
                await on_progress_callback({
                    "workflow_id": workflow_id,
                    "account_id": state.account_id,
                    "phase": WorkflowPhase.VERIFYING_SUCCESS.value,
                    "message": "Verifying server response..."
                })

            verification: VerificationOutcome = await password_change_verifier.verify(page)

            if verification.outcome == "SUCCESS":
                sm.transition_to(WorkflowPhase.SUCCESS, verification.details)
                
                # Save to macOS Keychain if requested
                if save_to_keychain and secret_boundary:
                    try:
                        new_pw = secret_boundary.resolve_secret("new_password")
                        KeychainManager.store_credential(state.service, f"account_{state.account_id}", new_pw)
                    except Exception as ke:
                        audit_logger.log_event(state.service, f"Keychain store notice: {str(ke)}", level="WARNING")

                if on_progress_callback:
                    await on_progress_callback({
                        "workflow_id": workflow_id,
                        "account_id": state.account_id,
                        "phase": WorkflowPhase.SUCCESS.value,
                        "message": f"Password rotation successfully confirmed! ({verification.details})"
                    })

                # Clear in-memory secret vault
                if secret_boundary:
                    secret_boundary.clear()

                return {
                    "status": "SUCCESS",
                    "workflow_id": workflow_id,
                    "account_id": state.account_id,
                    "details": verification.details
                }

            elif verification.outcome == "FAILED":
                sm.transition_to(WorkflowPhase.FAILED, verification.details)
                return {
                    "status": "FAILED",
                    "workflow_id": workflow_id,
                    "account_id": state.account_id,
                    "details": verification.details
                }
            else:
                sm.transition_to(WorkflowPhase.LOW_CONFIDENCE, "Ambiguous outcome. Manual verification advised.")
                return {
                    "status": "UNKNOWN",
                    "workflow_id": workflow_id,
                    "account_id": state.account_id,
                    "details": "Verification outcome was inconclusive. Please verify account in browser."
                }

        except Exception as e:
            sm.transition_to(WorkflowPhase.FAILED, f"Submission error: {str(e)}")
            return {"status": "FAILED", "workflow_id": workflow_id, "error": str(e)}

    async def resume_workflow_after_human(
        self,
        workflow_id: str,
        session_id: str,
        on_progress_callback: Optional[Callable[[Dict[str, Any]], Awaitable[None]]] = None
    ) -> Dict[str, Any]:
        """
        Resumes the exact same in-progress workflow after the user finishes solving MFA / CAPTCHA in the browser.
        """
        state = self._active_workflows.get(workflow_id)
        if not state:
            return {"status": "FAILED", "message": "Workflow session not found."}

        page = self._active_pages.get(workflow_id)
        secret_boundary = self._secret_boundaries.get(workflow_id)
        if not page or not secret_boundary:
            return {"status": "FAILED", "message": "Browser page or secret context lost."}

        sm = WorkflowStateMachine(state)
        trust_ctx = DomainTrustContext(expected_service=state.service, allowed_explicit_domains=[state.expected_domain])

        # Transition back to VERIFYING_DOMAIN & NAVIGATING
        sm.transition_to(WorkflowPhase.VERIFYING_DOMAIN, "Re-verifying domain after human intervention.")
        trust_eval = trust_ctx.evaluate_url(page.url)
        if not trust_eval.is_trusted:
            sm.transition_to(WorkflowPhase.DOMAIN_VIOLATION, trust_eval.reason)
            return {"status": "DOMAIN_VIOLATION", "reason": trust_eval.reason}

        sm.transition_to(WorkflowPhase.NAVIGATING, "Resuming AI navigation from current page state.")
        
        nav_result = await self.navigator.navigate_to_password_interface(
            page=page,
            service_name=state.service,
            domain=state.expected_domain,
            secret_boundary=secret_boundary,
            domain_trust_context=trust_ctx,
            on_step_callback=on_progress_callback
        )

        nav_status = nav_result.get("status")
        if nav_status == "READY_FOR_APPROVAL":
            sm.transition_to(WorkflowPhase.PASSWORD_FORM_DETECTED, "Form detected.")
            sm.transition_to(WorkflowPhase.PASSWORD_PREPARED, "Form filled.")
            sm.transition_to(WorkflowPhase.READY_FOR_APPROVAL, "Ready for user approval.")
            form_fp = nav_result.get("form_fingerprint", "fp_resumed")
            state.form_fingerprint = form_fp

            return {
                "status": "READY_FOR_APPROVAL",
                "workflow_id": workflow_id,
                "session_id": session_id,
                "account_id": state.account_id,
                "form_fingerprint": form_fp
            }
        
        return nav_result

# Singleton instance
orchestrator = PasswordRotationOrchestrator()
