import asyncio
import re
from typing import List, Optional
from urllib.parse import urlparse
from playwright.async_api import Page
from pydantic import BaseModel, Field

class VerificationOutcome(BaseModel):
    outcome: str  # "SUCCESS", "FAILED", "UNKNOWN"
    confidence: float
    signals: List[str] = Field(default_factory=list)
    details: str = ""

class PasswordChangeVerifier:
    """
    Multi-Signal Post-Submission Outcome Verifier.
    Priority 2: Rejects weak/generic body text alone (e.g., 'password changed' in body).
    Requires strong, independent structural signals (dedicated alert banners, role='alert',
    form disappearance, recognized post-change security URL) to confirm SUCCESS.
    Fails closed to UNKNOWN on ambiguous or unverified states.
    """

    SUCCESS_ALERT_SELECTORS = [
        "[role='alert']",
        ".alert-success",
        ".toast-success",
        ".notification-success",
        ".flash-success",
        ".banner-success",
        ".notice-success",
        "[data-status='success']",
        "[aria-live='polite']",
        ".alert"
    ]

    FAILURE_ALERT_SELECTORS = [
        "[role='alert']",
        ".alert-danger",
        ".alert-error",
        ".toast-error",
        ".notification-error",
        ".flash-error",
        ".banner-error",
        ".notice-error",
        "[data-status='error']",
        ".error-message",
        ".invalid-feedback"
    ]

    FAILURE_KEYWORDS = [
        re.compile(r"(current|old)\s+password\s+(is\s+|was\s+)?(incorrect|wrong|invalid)\b", re.IGNORECASE),
        re.compile(r"password\s+(does\s+not\s+meet|must\s+contain|is\s+too\s+weak)\b", re.IGNORECASE),
        re.compile(r"passwords\s+do\s+not\s+match\b", re.IGNORECASE),
        re.compile(r"error\s+(changing|updating|saving)\s+password\b", re.IGNORECASE),
        re.compile(r"invalid\s+credentials\b", re.IGNORECASE),
        re.compile(r"failed\s+to\s+update\s+password\b", re.IGNORECASE),
    ]

    SUCCESS_KEYWORDS = [
        re.compile(r"password\s+(?:has\s+been\s+)?(?:securely\s+|successfully\s+)?(?:changed|updated|reset|saved)\b", re.IGNORECASE),
        re.compile(r"(?:successfully|securely)\s+(?:updated|changed|saved|reset)\b", re.IGNORECASE),
        re.compile(r"(?:your\s+)?changes\s+(?:have\s+been\s+)?saved\b", re.IGNORECASE),
        re.compile(r"security\s+settings\s+updated\b", re.IGNORECASE),
        re.compile(r"new\s+password\s+activated\b", re.IGNORECASE),
    ]

    SUCCESS_PATTERNS = SUCCESS_KEYWORDS
    FAILURE_PATTERNS = FAILURE_KEYWORDS

    async def verify(
        self,
        page: Page,
        timeout_ms: int = 5000,
        expected_service: Optional[str] = None,
        expected_domain: Optional[str] = None
    ) -> VerificationOutcome:
        """
        Inspects the post-submit DOM state to verify password change outcome via multiple independent signals.
        Strict multi-signal requirement: Success alert alone or generic text alone returns UNKNOWN.
        Settings URL must be on a verified trusted domain to count as an independent structural signal.
        """
        signals: List[str] = []
        try:
            if hasattr(page, "wait_for_timeout"):
                try:
                    await page.wait_for_timeout(min(timeout_ms, 2000))
                except Exception:
                    pass

            # 1. Check for explicit error/rejection alerts first
            failure_elements = await page.query_selector_all(", ".join(self.FAILURE_ALERT_SELECTORS))
            for el in failure_elements:
                txt = (await el.inner_text() or "").strip()
                for pat in self.FAILURE_KEYWORDS:
                    if pat.search(txt):
                        signals.append(f"Explicit failure alert: '{txt[:80]}'")
                        return VerificationOutcome(
                            outcome="FAILED",
                            confidence=0.98,
                            signals=signals,
                            details=f"Server rejected password update: '{txt[:80]}'"
                        )

            # Check raw body text for explicit severe failure messages
            page_text = await page.evaluate("() => document.body ? document.body.innerText : ''")
            if not isinstance(page_text, str):
                page_text = str(page_text or "")

            for pat in self.FAILURE_KEYWORDS:
                match = pat.search(page_text)
                if match:
                    signals.append(f"Server rejection message detected in page: '{match.group(0)}'")
                    return VerificationOutcome(
                        outcome="FAILED",
                        confidence=0.95,
                        signals=signals,
                        details=f"Server returned failure: '{match.group(0)}'"
                    )

            # 2. Check for Strong Signal A: Dedicated success alert elements
            has_success_alert = False
            success_alert_text = ""
            success_elements = await page.query_selector_all(", ".join(self.SUCCESS_ALERT_SELECTORS))
            for el in success_elements:
                txt = (await el.inner_text() or "").strip()
                for pat in self.SUCCESS_KEYWORDS:
                    if pat.search(txt):
                        has_success_alert = True
                        success_alert_text = txt[:80]
                        signals.append(f"Dedicated success alert matched: '{success_alert_text}'")
                        break
                if has_success_alert:
                    break

            # 3. Check for Strong Signal B: Form disappearance or input clearing
            password_inputs = await page.query_selector_all("input[type='password']")
            form_disappeared_or_cleared = len(password_inputs) == 0

            # 4. Check for Strong Signal C: URL redirect to verified post-change settings/account area
            raw_url = getattr(page, "url", "")
            if isinstance(raw_url, str):
                current_url = raw_url
            elif callable(raw_url):
                try:
                    res = raw_url()
                    if asyncio.iscoroutine(res):
                        try:
                            current_url = str(await res)
                        except Exception:
                            current_url = ""
                    else:
                        current_url = str(res)
                except Exception:
                    current_url = ""
            else:
                current_url = ""

            is_settings_path = False
            if current_url and current_url != "about:blank":
                from app.safety.domain_trust import DomainTrustContext
                import tldextract
                ext = tldextract.extract(current_url)
                reg_d = f"{ext.domain}.{ext.suffix}".lower()
                
                svc = expected_service or ext.domain or "generic"
                allowed = [expected_domain] if expected_domain else ([reg_d] if reg_d else None)
                trust_ctx = DomainTrustContext(expected_service=svc, allowed_explicit_domains=allowed)
                trust_eval = trust_ctx.evaluate_url(current_url)
                if trust_eval.is_trusted:
                    parsed = urlparse(current_url)
                    is_settings_path = any(p in parsed.path.lower() for p in ["settings", "security", "account", "profile", "dashboard"])

            # Decision Matrix:
            # SUCCESS strictly requires at least 2 independent signals:
            # (Dedicated alert + form disappearance, or dedicated alert + verified settings URL)
            if has_success_alert and (form_disappeared_or_cleared or is_settings_path):
                signals.append("Multi-signal positive confirmation achieved (alert + structural DOM/URL state change).")
                return VerificationOutcome(
                    outcome="SUCCESS",
                    confidence=0.98,
                    signals=signals,
                    details=f"Password rotation confirmed: '{success_alert_text}'"
                )
            elif has_success_alert:
                signals.append("Single weak/isolated signal: dedicated success alert observed, but form is unchanged and URL is unverified.")
                return VerificationOutcome(
                    outcome="UNKNOWN",
                    confidence=0.50,
                    signals=signals,
                    details=f"Success alert '{success_alert_text}' found, but lacks independent structural confirmation (form disappearance or post-change settings URL). UNKNOWN."
                )

            # If only generic page text matched without a dedicated alert element -> WEAK SIGNAL -> UNKNOWN
            for pat in self.SUCCESS_KEYWORDS:
                if pat.search(page_text):
                    signals.append(f"Weak signal: generic body text matched '{pat.pattern}', but lacks structural confirmation alert.")
                    return VerificationOutcome(
                        outcome="UNKNOWN",
                        confidence=0.45,
                        signals=signals,
                        details="Generic page text contains success words, but no structural confirmation alert was detected. UNKNOWN."
                    )

            # Inconclusive outcome
            return VerificationOutcome(
                outcome="UNKNOWN",
                confidence=0.50,
                signals=["No positive success alert or conclusive state change detected."],
                details="Cannot conclusively confirm password modification. Human review required."
            )

        except Exception as e:
            return VerificationOutcome(
                outcome="UNKNOWN",
                confidence=0.0,
                signals=[f"Verification exception: {str(e)}"],
                details=f"Verification exception: {str(e)}"
            )

password_change_verifier = PasswordChangeVerifier()
