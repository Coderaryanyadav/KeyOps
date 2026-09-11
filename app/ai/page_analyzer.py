from typing import Dict, Any, Tuple
from playwright.async_api import Page
from app.browser.page_inspector import PageInspector, PageInspectionResult
from app.ai.page_sanitizer import PageSanitizer
from app.ai.base import PageUnderstanding

class PageAnalyzer:
    """
    Coordinates page inspection and privacy sanitization before AI reasoning.
    """

    def __init__(self):
        self.inspector = PageInspector()
        self.sanitizer = PageSanitizer()

    async def analyze(self, page: Page) -> Tuple[PageInspectionResult, Dict[str, Any]]:
        # 1. Raw inspection (contains handles for local execution)
        inspection = await self.inspector.inspect_page(page)

        # 2. Privacy-sanitized payload (safe for AI consumption)
        sanitized_payload = self.sanitizer.sanitize_inspection(inspection)

        return inspection, sanitized_payload
