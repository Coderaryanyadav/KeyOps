import asyncio
from typing import Dict, Any, Optional
from playwright.async_api import Page, ElementHandle
from app.safety.secret_boundary import SecretBoundary
from app.core.audit_logger import audit_logger

class ActionExecutionError(Exception):
    """Raised when an approved action fails during Playwright browser execution."""
    pass

class ControlledActionExecutor:
    """
    Executes safety-validated actions inside the Playwright browser.
    Resolves symbolic secret references using SecretBoundary without exposing
    values to outside layers.
    """

    async def execute_action(
        self,
        page: Page,
        action_payload: Dict[str, Any],
        element_map: Dict[str, ElementHandle],
        secret_boundary: SecretBoundary
    ) -> bool:
        action = action_payload.get("action", "").lower().strip()
        target_id = action_payload.get("target_id") or action_payload.get("target")

        if action == "click":
            if target_id not in element_map:
                raise ActionExecutionError(f"Element ID '{target_id}' not found in active element map.")
            el = element_map[target_id]
            await el.click()
            await page.wait_for_timeout(1500)
            return True

        elif action == "fill_secret":
            if target_id not in element_map:
                raise ActionExecutionError(f"Field ID '{target_id}' not found in active element map.")
            secret_ref = action_payload.get("secret_reference", "")
            raw_secret = secret_boundary.resolve_secret(secret_ref)
            el = element_map[target_id]
            await el.fill(raw_secret)
            audit_logger.log_event("BROWSER_EXEC", f"Filled secret reference '{secret_ref}' into element '{target_id}'.")
            return True

        elif action == "navigate":
            target_url = action_payload.get("target_url") or target_id
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

        elif action == "request_human_intervention":
            reason = action_payload.get("reason", "Human intervention requested.")
            audit_logger.log_event("BROWSER_EXEC", f"Human intervention triggered: {reason}", level="WARNING")
            return True

        raise ActionExecutionError(f"Unsupported action '{action}'.")
