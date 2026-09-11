from typing import Dict, Optional, Tuple, List, Any
from playwright.async_api import Page, ElementHandle
from pydantic import BaseModel, ConfigDict

class DetectedField(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    element: Optional[Any] = None
    confidence: float = 0.0
    signal: str = ""

class DetectedForm(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    current_password: Optional[Any] = None
    new_password: Optional[Any] = None
    confirm_password: Optional[Any] = None
    current_confidence: float = 0.0
    new_confidence: float = 0.0
    confirm_confidence: float = 0.0
    overall_confidence: float = 0.0
    explanation: str = ""

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def __setitem__(self, key: str, value: Any) -> None:
        setattr(self, key, value)

class FieldDetector:
    """
    Multi-signal password form detector with confidence scoring.
    Analyzes autocomplete, name, id, label, aria-label, placeholder, and form structure.
    """

    async def detect_password_fields(self, page: Page) -> DetectedForm:
        result = DetectedForm()
        
        # 1. Query all password inputs on the page
        inputs = await page.query_selector_all("input[type='password']")
        if not inputs:
            # Fallback to text inputs with password-related attributes
            inputs = await page.query_selector_all("input[name*='pass'], input[id*='pass'], input[autocomplete*='password']")

        if not inputs:
            result.explanation = "No password input fields detected on page."
            return result

        scored_fields: List[Dict[str, Any]] = []

        for inp in inputs:
            attrs = {
                "name": (await inp.get_attribute("name") or "").lower(),
                "id": (await inp.get_attribute("id") or "").lower(),
                "autocomplete": (await inp.get_attribute("autocomplete") or "").lower(),
                "placeholder": (await inp.get_attribute("placeholder") or "").lower(),
                "aria-label": (await inp.get_attribute("aria-label") or "").lower(),
            }

            role = "unknown"
            confidence = 0.50
            signal = "fallback"

            # Check autocomplete (strongest signal)
            if attrs["autocomplete"] == "current-password":
                role = "current_password"
                confidence = 0.99
                signal = "autocomplete='current-password'"
            elif attrs["autocomplete"] == "new-password":
                role = "new_password"
                confidence = 0.98
                signal = "autocomplete='new-password'"
            
            # Check name / id / label keywords
            combined_text = f"{attrs['name']} {attrs['id']} {attrs['placeholder']} {attrs['aria-label']}"

            if "old" in combined_text or "current" in combined_text or "curr" in combined_text:
                if role == "unknown" or confidence < 0.95:
                    role = "current_password"
                    confidence = 0.95
                    signal = "keyword 'old/current'"
            elif "confirm" in combined_text or "verify" in combined_text or "repeat" in combined_text or "reenter" in combined_text:
                role = "confirm_password"
                confidence = 0.96
                signal = "keyword 'confirm/verify/repeat'"
            elif "new" in combined_text or "password1" in combined_text:
                if role == "unknown" or confidence < 0.95:
                    role = "new_password"
                    confidence = 0.95
                    signal = "keyword 'new'"

            scored_fields.append({
                "element": inp,
                "role": role,
                "confidence": confidence,
                "signal": signal,
                "attrs": attrs
            })

        # Heuristic resolution based on form position if roles were ambiguous
        if len(scored_fields) == 1:
            result.new_password = scored_fields[0]["element"]
            result.new_confidence = 0.92
            result.explanation = "Single password field detected -> treated as new password."
        elif len(scored_fields) == 2:
            has_confirm = any(f["role"] == "confirm_password" for f in scored_fields)
            if has_confirm:
                result.new_password = scored_fields[0]["element"]
                result.new_confidence = 0.94
                result.confirm_password = scored_fields[1]["element"]
                result.confirm_confidence = 0.96
                result.explanation = "Two fields detected (new + confirmation)."
            else:
                result.current_password = scored_fields[0]["element"]
                result.current_confidence = 0.94
                result.new_password = scored_fields[1]["element"]
                result.new_confidence = 0.94
                result.explanation = "Two fields detected (current + new)."
        elif len(scored_fields) >= 3:
            result.current_password = scored_fields[0]["element"]
            result.current_confidence = scored_fields[0]["confidence"] if scored_fields[0]["role"] == "current_password" else 0.92
            result.new_password = scored_fields[1]["element"]
            result.new_confidence = scored_fields[1]["confidence"] if scored_fields[1]["role"] == "new_password" else 0.95
            result.confirm_password = scored_fields[2]["element"]
            result.confirm_confidence = scored_fields[2]["confidence"] if scored_fields[2]["role"] == "confirm_password" else 0.96
            result.explanation = "Standard 3-field password change form detected (current + new + confirm)."

        confidences = [c for c in [result.current_confidence, result.new_confidence, result.confirm_confidence] if c > 0]
        result.overall_confidence = sum(confidences) / len(confidences) if confidences else 0.0

        return result
