import re
from typing import Optional, Tuple
from playwright.async_api import Page
from app.core.password_generator import PasswordPolicy
from app.core.audit_logger import audit_logger

class PolicyDetector:
    """
    Detects visible password requirements on web forms and adjusts password policies.
    """

    MIN_LEN_REGEX = re.compile(r"(?:at least|minimum of|min)\s*(\d+)\s*(?:characters|chars)", re.IGNORECASE)
    MAX_LEN_REGEX = re.compile(r"(?:at most|maximum of|max|cannot exceed)\s*(\d+)\s*(?:characters|chars)", re.IGNORECASE)

    async def detect_policy(self, page: Page) -> Tuple[PasswordPolicy, float, str]:
        """
        Extracts password policy constraints from visible page text.
        Returns (policy, confidence, explanation).
        """
        try:
            content = await page.content()
            policy = PasswordPolicy(length=24)
            signals = []

            # 1. Detect minimum length
            min_match = self.MIN_LEN_REGEX.search(content)
            if min_match:
                min_len = int(min_match.group(1))
                if 8 <= min_len <= 128:
                    policy.length = max(min_len, 20)
                    signals.append(f"Min length: {min_len}")

            # 2. Detect maximum length
            max_match = self.MAX_LEN_REGEX.search(content)
            if max_match:
                max_len = int(max_match.group(1))
                if max_len < policy.length:
                    policy.length = max_len
                    signals.append(f"Max length: {max_len}")

            # 3. Check for symbol restrictions
            content_lower = content.lower()
            if "no special characters" in content_lower or "alphanumeric only" in content_lower:
                policy.use_symbols = False
                signals.append("No symbols allowed")
            elif "special character" in content_lower or "symbol" in content_lower:
                policy.use_symbols = True
                signals.append("Symbols required")

            if signals:
                explanation = "Detected policy: " + ", ".join(signals)
                return policy, 0.92, explanation

            return policy, 0.80, "Standard strong security policy applied (24 chars, uppercase, lowercase, numbers, symbols)."
        except Exception as e:
            return PasswordPolicy(), 0.50, f"Error detecting policy: {str(e)}"

    def adjust_policy_from_error(self, current_policy: PasswordPolicy, error_message: str) -> PasswordPolicy:
        """Adjusts policy dynamically when a website rejects a password submission."""
        new_policy = current_policy.model_copy()
        msg = error_message.lower()

        min_match = self.MIN_LEN_REGEX.search(msg)
        if min_match:
            new_policy.length = max(new_policy.length, int(min_match.group(1)))
        elif "too short" in msg or "minimum" in msg or "at least" in msg:
            new_policy.length = max(new_policy.length + 4, 20)

        max_match = self.MAX_LEN_REGEX.search(msg)
        if max_match:
            new_policy.length = min(new_policy.length, int(max_match.group(1)))

        if "special character" in msg or "symbol" in msg:
            new_policy.use_symbols = True
        if "no symbols" in msg or "letters and numbers only" in msg:
            new_policy.use_symbols = False

        audit_logger.log_event("POLICY_DETECTOR", f"Adjusted policy based on error '{error_message}': length={new_policy.length}, symbols={new_policy.use_symbols}")
        return new_policy
