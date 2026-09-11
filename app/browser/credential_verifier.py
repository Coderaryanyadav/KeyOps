from typing import List, Dict, Any, Optional, Tuple
from playwright.async_api import ElementHandle, Page
from pydantic import BaseModel, Field

class FieldVerificationResult(BaseModel):
    is_valid: bool
    field_role: str  # "current_password", "new_password", "confirm_password", "unknown"
    confidence: float
    evidence: List[str] = Field(default_factory=list)
    rejection_reason: Optional[str] = None

class CredentialFieldVerifier:
    """
    Authoritative Local Credential Field Verifier.
    The AI only makes a semantic recommendation. This local verifier deterministically
    inspects the live DOM element to verify that it is genuinely a credential field
    matching the intended role before any secret can be resolved.
    """

    CONFIDENCE_THRESHOLD = 0.85

    async def verify_field(
        self,
        element: ElementHandle,
        expected_role: str,
        page: Optional[Page] = None
    ) -> FieldVerificationResult:
        """
        Deterministically evaluates DOM semantics and state of the target element.
        """
        evidence: List[str] = []
        score = 0.0

        try:
            # 1. Basic Element Validity & Visibility Checks
            tag_name = await element.evaluate("el => el.tagName.toLowerCase()")
            if tag_name != "input":
                return FieldVerificationResult(
                    is_valid=False,
                    field_role="invalid",
                    confidence=0.0,
                    rejection_reason=f"Target element is <{tag_name}>, not <input>."
                )

            is_visible = await element.is_visible()
            if not is_visible:
                return FieldVerificationResult(
                    is_valid=False,
                    field_role="hidden",
                    confidence=0.0,
                    rejection_reason="Target element is not visible on page."
                )

            is_enabled = await element.is_enabled()
            if not is_enabled:
                return FieldVerificationResult(
                    is_valid=False,
                    field_role="disabled",
                    confidence=0.0,
                    rejection_reason="Target element is disabled or readonly."
                )

            # 2. Extract DOM Attributes
            attrs: Dict[str, str] = await element.evaluate("""el => {
                const labelElem = el.labels && el.labels.length > 0 ? el.labels[0].innerText : '';
                return {
                    type: (el.getAttribute('type') || '').toLowerCase(),
                    name: (el.getAttribute('name') || '').toLowerCase(),
                    id: (el.getAttribute('id') || '').toLowerCase(),
                    autocomplete: (el.getAttribute('autocomplete') || '').toLowerCase(),
                    placeholder: (el.getAttribute('placeholder') || '').toLowerCase(),
                    aria_label: (el.getAttribute('aria-label') || '').toLowerCase(),
                    label_text: (labelElem || '').toLowerCase()
                };
            }""")

            inp_type = attrs["type"]
            autocomplete = attrs["autocomplete"]
            name = attrs["name"]
            el_id = attrs["id"]
            placeholder = attrs["placeholder"]
            aria_label = attrs["aria_label"]
            label_text = attrs["label_text"]

            # 3. Type Checking
            if inp_type == "password":
                score += 0.40
                evidence.append("type='password'")
            elif inp_type in ("text", ""):
                # Some sites use text inputs with masked styling or custom password controls
                score += 0.10
                evidence.append("type='text' (fallback evaluation)")
            else:
                return FieldVerificationResult(
                    is_valid=False,
                    field_role="invalid_type",
                    confidence=0.0,
                    rejection_reason=f"Prohibited input type '{inp_type}' for credential operation."
                )

            # 4. Autocomplete Semantics (Gold Standard)
            detected_role = "unknown"
            if autocomplete == "current-password":
                score += 0.55
                detected_role = "current_password"
                evidence.append("autocomplete='current-password'")
            elif autocomplete == "new-password":
                score += 0.55
                # New password could be new or confirm
                detected_role = "new_password"
                evidence.append("autocomplete='new-password'")
            elif "password" in autocomplete:
                score += 0.30
                evidence.append(f"autocomplete='{autocomplete}'")

            # 5. Text / Semantic Keywords Analysis
            combined_text = f"{name} {el_id} {placeholder} {aria_label} {label_text}"

            if any(k in combined_text for k in ["confirm", "verify", "repeat", "reenter", "re-enter", "confirm_password", "confirmpassword"]):
                detected_role = "confirm_password"
                score += 0.45
                evidence.append("keywords indicate confirmation field")
            elif any(k in combined_text for k in ["current", "old", "existing", "curr", "present", "oldpassword", "currentpassword"]):
                detected_role = "current_password"
                score += 0.45
                evidence.append("keywords indicate current/old password field")
            elif any(k in combined_text for k in ["new", "create", "newpassword", "passwd_new", "user_password"]):
                if detected_role != "confirm_password":
                    detected_role = "new_password"
                    score += 0.40
                    evidence.append("keywords indicate new password field")
            elif "password" in combined_text or "pass" in combined_text:
                score += 0.25
                evidence.append("generic password keywords present")

            final_confidence = min(1.0, score)

            # Check if detected role matches or is compatible with expected role
            role_matches = False
            if expected_role == detected_role:
                role_matches = True
            elif expected_role in ("new_password", "confirm_password") and detected_role in ("new_password", "confirm_password", "unknown") and final_confidence >= self.CONFIDENCE_THRESHOLD:
                # Accept new_password / confirm_password when confidence is high
                role_matches = True
            elif expected_role == "current_password" and (detected_role == "current_password" or (detected_role == "unknown" and final_confidence >= 0.70)):
                role_matches = True

            if final_confidence < 0.70:
                return FieldVerificationResult(
                    is_valid=False,
                    field_role=detected_role,
                    confidence=final_confidence,
                    evidence=evidence,
                    rejection_reason=f"Confidence {final_confidence:.2f} is below safety threshold."
                )

            if not role_matches:
                return FieldVerificationResult(
                    is_valid=False,
                    field_role=detected_role,
                    confidence=final_confidence,
                    evidence=evidence,
                    rejection_reason=f"Role mismatch: Expected '{expected_role}', detected '{detected_role}'."
                )

            return FieldVerificationResult(
                is_valid=True,
                field_role=detected_role if detected_role != "unknown" else expected_role,
                confidence=final_confidence,
                evidence=evidence
            )

        except Exception as e:
            return FieldVerificationResult(
                is_valid=False,
                field_role="error",
                confidence=0.0,
                rejection_reason=f"Element inspection error: {str(e)}"
            )

credential_verifier = CredentialFieldVerifier()
