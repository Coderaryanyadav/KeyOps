import re
from typing import Dict, List, Any
from urllib.parse import urlparse
from app.browser.page_inspector import PageInspectionResult, InteractiveElement

class PageSanitizer:
    """
    Sanitizes live DOM inspection data into a minimized, privacy-preserving semantic
    representation for AI reasoning.
    CRITICAL SECURITY INVARIANT: Strips raw passwords, OTP codes, session tokens,
    auth headers, cookies, sensitive query strings, userinfo, and sensitive hidden inputs
    before sending to any AI provider using an explicit allowlist model.
    """

    SENSITIVE_REGEX = [
        re.compile(r"\b\d{6}\b"),  # 6-digit OTP codes
        re.compile(r"\b(bearer|token|secret|sessionid|auth|password|key)=([^\s&]+)", re.IGNORECASE),
        re.compile(r"\b[A-Za-z0-9\-\._~\+\/]{32,}\b"),  # Long token/hash strings
        re.compile(r"Bearer\s+[A-Za-z0-9\-\._~\+\/]+", re.IGNORECASE),
    ]

    def sanitize_inspection(self, inspection: PageInspectionResult) -> Dict[str, Any]:
        """Produces a clean allowlisted structured payload ready for AI analysis."""
        sanitized_elements = []

        for el in inspection.interactive_elements:
            # Mask sensitive values in input text or attributes
            clean_text = self._clean_text(el.text)
            clean_placeholder = self._clean_text(el.placeholder)
            clean_aria = self._clean_text(el.aria_label)

            # Never expose input values if present - strictly allowlisted fields
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
            "url": self._sanitize_url(inspection.url),
            "title": self._clean_text(inspection.title),
            "headings": sanitized_headings,
            "interactive_elements": sanitized_elements,
            "visible_text_summary": sanitized_summary
        }

    def _sanitize_url(self, raw_url: str) -> str:
        """
        Strips username, password (userinfo), query parameters, tokens, OAuth states,
        and fragments from page URLs before passing to AI.
        """
        if not raw_url:
            return ""
        try:
            parsed = urlparse(raw_url)
            netloc = parsed.hostname or ""
            if parsed.port and parsed.port not in (80, 443):
                netloc = f"{netloc}:{parsed.port}"
            scheme = parsed.scheme if parsed.scheme in ("http", "https") else "https"
            clean_path = parsed.path
            return f"{scheme}://{netloc}{clean_path}"
        except Exception:
            return ""

    def _clean_text(self, text: str) -> str:
        if not text:
            return ""
        cleaned = text
        for pattern in self.SENSITIVE_REGEX:
            cleaned = pattern.sub("[REDACTED]", cleaned)
        return cleaned.strip()
