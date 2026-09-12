from typing import Any, Dict, Optional, List, Set, Union
from pydantic import BaseModel, Field

class SecretReference(BaseModel):
    reference_id: str  # e.g. "current_password", "new_password", "confirm_password"
    description: str

class SecretBoundaryViolation(Exception):
    """Raised when an attempt is made to pass raw credentials to AI or unauthorized layers."""
    pass

class SecretBoundary:
    """
    Unidirectional Isolation Boundary between AI reasoning layers and real credentials.
    The AI layer only receives and emits symbolic references (e.g., 'current_password').
    The SecretBoundary resolves these references to local secrets exclusively within
    the local browser automation layer.
    """

    def __init__(self):
        self._vault: Dict[str, str] = {}

    def register_secrets(self, current_password: Optional[str] = None, new_password: Optional[str] = None) -> None:
        """Stores credentials in memory for the active transaction only."""
        if current_password:
            self._vault["current_password"] = current_password
        if new_password:
            self._vault["new_password"] = new_password
            self._vault["confirm_password"] = new_password

    def resolve_secret(self, reference_id: str) -> str:
        """Resolves symbolic reference to actual secret for local browser field filling."""
        clean_ref = reference_id.strip().lower()
        if clean_ref not in self._vault:
            raise SecretBoundaryViolation(f"Unknown or unauthorized secret reference '{reference_id}'.")
        return self._vault[clean_ref]

    def clear(self) -> None:
        """Erases memory vault at the end of the transaction."""
        self._vault.clear()

    ALLOWED_AI_FIELDS = {
        "url", "title", "headings", "interactive_elements", "visible_text_summary",
        "element_id", "tag", "role", "text", "input_type", "autocomplete", "placeholder",
        "aria_label", "status", "target_id", "confidence", "reason", "action",
        "secret_reference", "challenge_type", "message", "direction", "seconds",
        "target_url", "elements", "form_fields", "field_name", "field_type", "field_role"
    }

    FORBIDDEN_VALUE_KEYWORDS = [
        "password", "secret", "token", "cookie", "otp", "bearer", "authorization",
        "sessionid", "private_key", "csrf", "recovery_code"
    ]

    @classmethod
    def sanitize_payload_for_ai(cls, payload: Any) -> Any:
        """
        Deep check ensuring no raw password strings or tokens leak into payloads prepared for AI.
        STRICT ALLOWLIST: Only explicitly approved semantic fields in ALLOWED_AI_FIELDS are kept.
        ALL unknown fields are completely dropped recursively.
        """
        if isinstance(payload, dict):
            sanitized = {}
            for k, v in payload.items():
                k_clean = str(k).strip()
                k_lower = k_clean.lower()

                # 1. Real Allowlist: If key is not in ALLOWED_AI_FIELDS, DROP IT!
                if k_lower not in cls.ALLOWED_AI_FIELDS:
                    continue

                # 2. Secret references must be purely symbolic
                if k_lower == "secret_reference":
                    if isinstance(v, str) and (v in ["current_password", "new_password", "confirm_password"] or v.startswith("ref_")):
                        sanitized[k_clean] = v
                    else:
                        sanitized[k_clean] = "[REDACTED_BY_SECRET_BOUNDARY]"
                    continue

                # 3. Recursively sanitize nested structures
                if isinstance(v, dict):
                    sanitized[k_clean] = cls.sanitize_payload_for_ai(v)
                elif isinstance(v, list):
                    sanitized[k_clean] = cls.sanitize_payload_for_ai(v)
                elif isinstance(v, str):
                    # Check for raw secrets embedded in text values of allowed fields
                    v_lower = v.lower()
                    if any(f"{kw}=" in v_lower or f"{kw}:" in v_lower for kw in ["password", "token", "secret", "bearer", "sessionid"]):
                        sanitized[k_clean] = "[REDACTED_BY_SECRET_BOUNDARY]"
                    else:
                        sanitized[k_clean] = v
                else:
                    sanitized[k_clean] = v
            return sanitized

        elif isinstance(payload, list):
            return [cls.sanitize_payload_for_ai(item) for item in payload]

        return payload
