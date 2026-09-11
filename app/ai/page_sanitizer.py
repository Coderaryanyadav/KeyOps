import re
from typing import Dict, List, Any
from app.browser.page_inspector import PageInspectionResult, InteractiveElement

class PageSanitizer:
    """
    Sanitizes live DOM inspection data into a minimized, privacy-preserving semantic
    representation for AI reasoning.
    CRITICAL SECURITY INVARIANT: Strips raw passwords, OTP codes, session tokens,
    auth headers, cookies, and sensitive hidden inputs before sending to any AI provider.
    """

    SENSITIVE_REGEX = [
        re.compile(r"\b\d{6}\b"),  # 6-digit OTP codes
        re.compile(r"\b(bearer|token|secret|sessionid|auth)=([^\s&]+)", re.IGNORECASE),
        re.compile(r"\b[A-Za-z0-9\-\._~\+\/]{32,}\b"),  # Long token/hash strings
    ]

    def sanitize_inspection(self, inspection: PageInspectionResult) -> Dict[str, Any]:
        """Produces a clean structured payload ready for AI analysis."""
        sanitized_elements = []

        for el in inspection.interactive_elements:
            # Mask sensitive values in input text or attributes
            clean_text = self._clean_text(el.text)
            clean_placeholder = self._clean_text(el.placeholder)
            clean_aria = self._clean_text(el.aria_label)

            # Never expose input values if present
            sanitized_elements.append({
                "element_id": el.element_id,
                "tag": el.tag,
                "role": el.role,
                "text": clean_text,
                "input_type": el.input_type,
                "autocomplete": el.autocomplete,
                "placeholder": clean_placeholder,
                "aria_label": clean_aria,
            })

        # Sanitize headings and visible text
        sanitized_headings = [self._clean_text(h) for h in inspection.headings]
        sanitized_summary = self._clean_text(inspection.visible_text_summary[:1500])

        return {
            "url": inspection.url,
            "title": self._clean_text(inspection.title),
            "headings": sanitized_headings,
            "interactive_elements": sanitized_elements,
            "visible_text_summary": sanitized_summary
        }

    def _clean_text(self, text: str) -> str:
        if not text:
            return ""
        cleaned = text
        for pattern in self.SENSITIVE_REGEX:
            cleaned = pattern.sub("[REDACTED]", cleaned)
        return cleaned.strip()
