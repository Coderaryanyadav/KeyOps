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
    Priority 3: Strictly deterministic local verifier.
    A password secret is ONLY resolved when deterministic DOM inspection positively
    confirms the exact intended credential role (current_password, new_password, confirm_password).
    Dangerous fallbacks (e.g. type=text, disabled, hidden, readonly, or generic keywords)
    are strictly rejected fail-closed.
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
                    rejection_reason="Target element is hidden/not visible on page."
                )

            is_enabled = await element.is_enabled()
            if not is_enabled:
                return FieldVerificationResult(
                    is_valid=False,
                    field_role="disabled",
                    confidence=0.0,
                    rejection_reason="Target element is disabled."
                )

            is_readonly = await element.evaluate("el => el.readOnly === true || el.hasAttribute('readonly')")
            if is_readonly:
                return FieldVerificationResult(
                    is_valid=False,
                    field_role="readonly",
                    confidence=0.0,
                    rejection_reason="Target element is readonly."
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

            # 3. Strict Type Checking (Password inputs mandatory for credential filling)
            if inp_type != "password":
                return FieldVerificationResult(
                    is_valid=False,
                    field_role="invalid_type",
                    confidence=0.0,
                    rejection_reason=f"Type mismatch: Prohibited input type '{inp_type}'. Real credentials require type='password'."
                )

            evidence.append("type='password'")

            combined_text = f"{name} {el_id} {placeholder} {aria_label} {label_text}".lower()
            detected_role = "unknown"
            score = 0.50  # Base score for type='password'

            # 4. Strict Role Classification
            is_confirm = any(k in combined_text for k in ["confirm", "verify", "repeat", "reenter", "re-enter", "confirmpassword", "confirm_password", "pass2", "pwd2", "password_confirmation"])
            is_current = any(k in combined_text for k in ["current", "old", "existing", "curr", "present", "oldpassword", "currentpassword", "old_password", "current_password"])
            is_new = any(k in combined_text for k in ["new", "create", "newpassword", "passwd_new", "user_password", "new_password", "set_password", "pass1", "pwd1"])

            if autocomplete == "current-password" or is_current:
                detected_role = "current_password"
                score += 0.45
                evidence.append("autocomplete/semantics indicate current password")
            elif is_confirm:
                detected_role = "confirm_password"
                score += 0.45
                evidence.append("semantics indicate confirmation password")
            elif autocomplete == "new-password" and not is_confirm:
                detected_role = "new_password"
                score += 0.45
                evidence.append("autocomplete='new-password'")
            elif is_new:
                detected_role = "new_password"
                score += 0.40
                evidence.append("semantics indicate new password")
            else:
                # Generic password input without role disambiguation
                detected_role = "unknown"

            # 5. Role Match Evaluation
            final_confidence = min(1.0, score)

            if detected_role == "unknown":
                return FieldVerificationResult(
                    is_valid=False,
                    field_role="unknown",
                    confidence=final_confidence,
                    evidence=evidence,
                    rejection_reason="Generic password field without explicit role semantics (current/new/confirm). REQUIRES_HUMAN."
                )

            if detected_role != expected_role:
                return FieldVerificationResult(
                    is_valid=False,
                    field_role=detected_role,
                    confidence=final_confidence,
                    evidence=evidence,
                    rejection_reason=f"Role mismatch: Expected '{expected_role}', detected '{detected_role}'."
                )

            return FieldVerificationResult(
                is_valid=True,
                field_role=detected_role,
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
