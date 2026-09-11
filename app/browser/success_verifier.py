import re
from typing import List, Optional
from playwright.async_api import Page
from pydantic import BaseModel, Field

class VerificationOutcome(BaseModel):
    outcome: str  # "SUCCESS", "FAILED", "UNKNOWN"
    confidence: float
    signals: List[str] = Field(default_factory=list)
    details: str = ""

class PasswordChangeVerifier:
    """
    Multi-signal post-submission outcome verifier.
    Never relies on mere button clicks. Scans the DOM, URL, and notification areas
    to establish genuine verification.
    """

    SUCCESS_PATTERNS = [
        re.compile(r"password\s+(has\s+been\s+)?(changed|updated|reset|saved)\b", re.IGNORECASE),
        re.compile(r"successfully\s+(updated|changed|saved)\b", re.IGNORECASE),
        re.compile(r"(your\s+)?changes\s+have\s+been\s+saved\b", re.IGNORECASE),
        re.compile(r"security\s+settings\s+updated\b", re.IGNORECASE),
        re.compile(r"new\s+password\s+activated\b", re.IGNORECASE),
        re.compile(r"\bpassword\s+saved\b", re.IGNORECASE),
        re.compile(r"\bsuccess\b", re.IGNORECASE)
    ]

    FAILURE_PATTERNS = [
        re.compile(r"(current|old)\s+password\s+(is\s+|was\s+)?(incorrect|wrong|invalid)\b", re.IGNORECASE),
        re.compile(r"password\s+(does\s+not\s+meet|must\s+contain|is\s+too\s+weak)\b", re.IGNORECASE),
        re.compile(r"passwords\s+do\s+not\s+match\b", re.IGNORECASE),
        re.compile(r"error\s+(changing|updating|saving)\s+password\b", re.IGNORECASE),
        re.compile(r"invalid\s+credentials\b", re.IGNORECASE),
        re.compile(r"something\s+went\s+wrong\b", re.IGNORECASE)
    ]

    async def verify(self, page: Page, timeout_ms: int = 5000) -> VerificationOutcome:
        """
        Inspects the post-submit DOM state to verify password change outcome.
        """
        signals: List[str] = []
        try:
            await page.wait_for_timeout(2000)
            
            # 1. Check all text and banner content on the page
            page_text = await page.evaluate("() => document.body ? document.body.innerText : ''")
            
            # Check for failure patterns first (explicit rejection)
            for pat in self.FAILURE_PATTERNS:
                match = pat.search(page_text)
                if match:
                    signals.append(f"Failure banner matched: '{match.group(0)}'")
                    return VerificationOutcome(
                        outcome="FAILED",
                        confidence=0.98,
                        signals=signals,
                        details=f"Server returned error message: '{match.group(0)}'"
                    )

            # Check for success patterns
            for pat in self.SUCCESS_PATTERNS:
                match = pat.search(page_text)
                if match:
                    signals.append(f"Success banner matched: '{match.group(0)}'")
                    return VerificationOutcome(
                        outcome="SUCCESS",
                        confidence=0.97,
                        signals=signals,
                        details=f"Verified success message: '{match.group(0)}'"
                    )

            # 2. Check if password form input fields disappeared (e.g. modal closed or page redirected)
            pw_fields = await page.query_selector_all("input[type='password']")
            if not pw_fields:
                signals.append("Password input fields no longer present in DOM.")
                return VerificationOutcome(
                    outcome="SUCCESS",
                    confidence=0.88,
                    signals=signals,
                    details="Password form closed and navigated away."
                )

            # 3. Check for specific alert elements or toasts
            alert_elems = await page.query_selector_all("[role='alert'], .alert, .toast, .notification, .flash-message")
            for alert in alert_elems:
                txt = (await alert.inner_text() or "").lower()
                if "success" in txt or "saved" in txt or "updated" in txt:
                    signals.append(f"Alert element indicated success: '{txt[:60]}'")
                    return VerificationOutcome(
                        outcome="SUCCESS",
                        confidence=0.95,
                        signals=signals,
                        details=f"Success alert confirmed: {txt[:60]}"
                    )
                elif "error" in txt or "fail" in txt or "invalid" in txt:
                    signals.append(f"Alert element indicated failure: '{txt[:60]}'")
                    return VerificationOutcome(
                        outcome="FAILED",
                        confidence=0.95,
                        signals=signals,
                        details=f"Error alert confirmed: {txt[:60]}"
                    )

            # If no conclusive signals found, fail safe with UNKNOWN
            return VerificationOutcome(
                outcome="UNKNOWN",
                confidence=0.50,
                signals=["No unambiguous success or failure banner detected."],
                details="Cannot conclusively confirm password modification. Human review required."
            )

        except Exception as e:
            return VerificationOutcome(
                outcome="UNKNOWN",
                confidence=0.0,
                signals=[f"Verification error: {str(e)}"],
                details=f"Verification exception: {str(e)}"
            )

password_change_verifier = PasswordChangeVerifier()
