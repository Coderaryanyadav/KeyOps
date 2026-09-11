import asyncio
from typing import Optional, Tuple
from playwright.async_api import Page
from app.core.audit_logger import audit_logger

class HumanInterruptionRequired(Exception):
    """Raised when MFA, CAPTCHA, or bot protection requires human takeover."""
    def __init__(self, reason: str, challenge_type: str, service_name: str):
        self.reason = reason
        self.challenge_type = challenge_type
        self.service_name = service_name
        super().__init__(f"Human takeover required for {service_name}: {reason} ({challenge_type})")

class HumanInterrupter:
    """
    Comprehensive human interruption and safety boundary monitor.
    Detects MFA, 2FA, OTP, CAPTCHA, Passkey, Email/SMS, Device approval, and Suspicious login warnings.
    """

    MFA_KEYWORDS = [
        "two-factor", "2fa", "mfa", "authenticator", "verification code",
        "security code", "enter code", "text message", "push notification",
        "passkey", "security key", "recovery code", "otp", "one-time password",
        "security question", "approve on your device"
    ]

    CAPTCHA_KEYWORDS = [
        "g-recaptcha", "h-captcha", "cf-turnstile", "captcha", "robot",
        "verify you are human", "geetest", "arkoselabs"
    ]

    SUSPICIOUS_LOGIN_KEYWORDS = [
        "suspicious activity", "verify your identity", "we noticed an unusual login",
        "confirm your email", "check your email", "device confirmation"
    ]

    BOT_DETECTION_KEYWORDS = [
        "access denied", "rate limit", "unusual traffic", "blocked",
        "pardon our interruption", "cloudflare"
    ]

    async def check_security_checkpoints(self, page: Page, service_name: str) -> Optional[Tuple[str, str]]:
        """
        Scans current page for security checkpoints.
        Returns (challenge_type, explanation) if detected, or None if page is clear.
        """
        try:
            content = (await page.content()).lower()
            url = page.url.lower()

            # 1. CAPTCHA Check
            for kw in self.CAPTCHA_KEYWORDS:
                if kw in content:
                    audit_logger.log_event(service_name, f"CAPTCHA Challenge Detected ({kw}). Automation paused.", level="WARNING")
                    return "CAPTCHA", f"CAPTCHA Challenge Detected ({kw})"

            # 2. MFA / 2FA / OTP Check
            for kw in self.MFA_KEYWORDS:
                if kw in content or kw in url:
                    audit_logger.log_event(service_name, f"MFA / 2FA prompt detected ({kw}). Automation paused.", level="WARNING")
                    return "MFA", f"MFA / 2FA Prompt Detected ({kw})"

            # 3. Suspicious Login / Device Verification
            for kw in self.SUSPICIOUS_LOGIN_KEYWORDS:
                if kw in content:
                    audit_logger.log_event(service_name, f"Identity Verification / Suspicious Login prompt detected ({kw}). Automation paused.", level="WARNING")
                    return "VERIFICATION", f"Identity Verification Required ({kw})"

            # 4. Bot Detection / Rate Limit
            for kw in self.BOT_DETECTION_KEYWORDS:
                if kw in content:
                    audit_logger.log_event(service_name, f"Bot protection / Rate limit detected ({kw}). Automation paused.", level="WARNING")
                    return "SECURITY_BLOCK", f"Security Warning / Rate Limit Detected ({kw})"

            return None
        except Exception:
            return None

    async def wait_for_human_completion(
        self,
        page: Page,
        service_name: str,
        target_url_pattern: str,
        timeout_seconds: int = 300
    ) -> bool:
        """
        Pauses automation and polls page state until the user finishes manual verification
        and returns to the target destination.
        """
        audit_logger.log_event(service_name, f"Waiting for human verification on {page.url}...")
        start_time = asyncio.get_event_loop().time()

        while (asyncio.get_event_loop().time() - start_time) < timeout_seconds:
            await asyncio.sleep(2)
            check = await self.check_security_checkpoints(page, service_name)
            current_url = page.url
            
            if not check and (target_url_pattern in current_url or target_url_pattern == "*"):
                audit_logger.log_event(service_name, "Human verification completed successfully!")
                return True

        audit_logger.log_event(service_name, "Human verification timed out after 5 minutes.", level="ERROR")
        return False
