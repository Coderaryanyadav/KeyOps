import asyncio
from typing import Dict, Any, Optional
from playwright.async_api import Page, ElementHandle
from app.safety.secret_boundary import SecretBoundary
from app.safety.submission_approval import approval_manager
from app.browser.credential_verifier import credential_verifier
from app.core.audit_logger import audit_logger

class ActionExecutionError(Exception):
    """Raised when an approved action fails during Playwright browser execution."""
    pass

class ControlledActionExecutor:
    """
    Executes safety-validated actions inside the Playwright browser.
    Resolves symbolic secret references using SecretBoundary ONLY after deterministic
    local verification by CredentialFieldVerifier.
    Enforces that submission requires a valid, active user approval token.
    """

    def __init__(self, custom_approval_manager: Optional[Any] = None):
        self._approval_manager = custom_approval_manager or approval_manager

    async def execute_action(
        self,
        page: Page,
        action_payload: Dict[str, Any],
        element_map: Dict[str, ElementHandle],
        secret_boundary: SecretBoundary,
        approval_context: Optional[Dict[str, Any]] = None
    ) -> bool:
        action = action_payload.get("action", "").lower().strip()
        target_id = action_payload.get("target_id") or action_payload.get("target")

        if action in ("click", "locate_password_interface", "locate_password_field"):
            if target_id not in element_map:
                raise ActionExecutionError(f"Element ID '{target_id}' not found in active element map.")
            el = element_map[target_id]
            await el.click()
            await page.wait_for_timeout(1500)
            return True

        elif action in ("fill_secret", "prepare_password_change"):
            if target_id not in element_map:
                raise ActionExecutionError(f"Field ID '{target_id}' not found in active element map.")
            
            secret_ref = action_payload.get("secret_reference", "").strip().lower()
            if not secret_ref:
                raise ActionExecutionError("Missing 'secret_reference' for credential fill action.")

            el = element_map[target_id]

            # Deterministic Local Field Verification
            expected_role = "current_password" if "current" in secret_ref or "old" in secret_ref else ("confirm_password" if "confirm" in secret_ref else "new_password")
            field_res = await credential_verifier.verify_field(el, expected_role=expected_role, page=page)
            
            if not field_res.is_valid:
                audit_logger.log_event(
                    "BROWSER_EXEC",
                    f"DENIED secret filling into element '{target_id}': {field_res.rejection_reason}",
                    level="ERROR"
                )
                raise ActionExecutionError(
                    f"Security Boundary Refusal: Field '{target_id}' rejected by local verifier: {field_res.rejection_reason}"
                )

            # Local verifier confirmed -> Resolve secret within local boundary
            raw_secret = secret_boundary.resolve_secret(secret_ref)
            await el.fill(raw_secret)
            audit_logger.log_event(
                "BROWSER_EXEC",
                f"Successfully filled verified credential field '{target_id}' (role={field_res.field_role}, confidence={field_res.confidence:.2f})."
            )
            return True

        elif action == "submit":
            # Submit MUST have valid approval token & matching context
            if not approval_context:
                raise ActionExecutionError("Submission DENIED: No user approval context provided.")

            token_id = approval_context.get("token_id", "")
            account_id = approval_context.get("account_id", 0)
            service = approval_context.get("service", "")
            expected_domain = approval_context.get("current_domain", "")
            session_id = approval_context.get("browser_session_id", "")
            workflow_id = approval_context.get("workflow_id", "")
            form_fingerprint = approval_context.get("form_fingerprint", "")

            # 1. Independent live browser URL inspection at the final submission boundary
            live_url = page.url
            if not live_url:
                raise ActionExecutionError("Submission DENIED: Live browser page URL is empty.")

            from app.safety.domain_trust import DomainTrustContext
            trust_ctx = DomainTrustContext(expected_service=service, allowed_explicit_domains=[expected_domain])
            trust_eval = trust_ctx.evaluate_url(live_url)
            if not trust_eval.is_trusted:
                audit_logger.log_event(
                    service or "BROWSER_EXEC",
                    f"Submission HALTED: Live page URL '{live_url}' failed domain trust: {trust_eval.reason}",
                    level="ERROR"
                )
                raise ActionExecutionError(
                    f"Submission DENIED: Live page URL '{live_url}' is not on trusted domain: {trust_eval.reason}"
                )

            # 2. Validate and atomically consume the approval token
            is_valid, reason = self._approval_manager.validate_and_consume_token(
                token_id=token_id,
                account_id=account_id,
                service=service,
                current_domain=expected_domain,
                browser_session_id=session_id,
                workflow_id=workflow_id,
                current_form_fingerprint=form_fingerprint
            )

            if not is_valid:
                raise ActionExecutionError(f"Submission DENIED by Approval Manager: {reason}")

            # 3. Execute submission via exact submit control (NO blind Enter keyboard fallback)
            if target_id and target_id in element_map:
                el = element_map[target_id]
                await el.click()
            else:
                submit_btn = await page.query_selector("button[type='submit'], input[type='submit']")
                if submit_btn:
                    await submit_btn.click()
                else:
                    raise ActionExecutionError(
                        "Submission DENIED: No verified submit button found on active password form. Blind Enter submission is prohibited."
                    )

            await page.wait_for_timeout(2500)
            audit_logger.log_event("BROWSER_EXEC", f"Password change form submitted with explicit user approval token '{token_id[:12]}...'.")
            return True

        elif action == "navigate":
            from urllib.parse import urlparse
            target_url = action_payload.get("target_url") or target_id
            if not target_url:
                raise ActionExecutionError("Navigation rejected: empty target URL.")
            
            parsed = urlparse(target_url)
            if parsed.scheme.lower() not in ("http", "https"):
                raise ActionExecutionError(f"Navigation rejected: unsafe scheme '{parsed.scheme}'. Only http/https allowed.")

            await page.goto(target_url, wait_until="domcontentloaded")
            return True

        elif action == "scroll":
            direction = action_payload.get("direction", "down").lower()
            delta = 400 if direction == "down" else -400
            await page.mouse.wheel(0, delta)
            await asyncio.sleep(0.5)
            return True

        elif action == "wait":
            seconds = min(10.0, float(action_payload.get("seconds", 2.0)))
            await asyncio.sleep(seconds)
            return True

        elif action in ("request_human_intervention", "request_submission_approval"):
            reason = action_payload.get("reason", "Human review requested.")
            audit_logger.log_event("BROWSER_EXEC", f"Flow pause triggered: {reason}", level="INFO")
            return True

        raise ActionExecutionError(f"Unsupported action '{action}'.")
