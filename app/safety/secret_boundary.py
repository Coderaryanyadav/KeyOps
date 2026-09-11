from typing import Dict, Optional
from pydantic import BaseModel, Field

class SecretReference(BaseModel):
    reference_id: str  # e.g. "current_password", "new_password", "confirm_password"
    description: str

class SecretBoundaryViolation(Exception):
    """Raised when an attempt is made to pass raw credentials to AI or unauthorized layers."""
    pass

class SecretBoundary:
    """
    Absolute Isolation Boundary between AI reasoning layers and real credentials.
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

    @staticmethod
    def sanitize_payload_for_ai(payload: Dict) -> Dict:
        """
        Deep check ensuring no raw password strings or tokens leak into payloads prepared for AI.
        """
        sanitized = {}
        for k, v in payload.items():
            k_lower = str(k).lower()
            if any(forbidden in k_lower for forbidden in ["password", "secret", "token", "cookie", "otp", "key", "auth"]):
                if isinstance(v, str) and not v.startswith("ref_") and v not in ["current_password", "new_password", "confirm_password"]:
                    sanitized[k] = "[REDACTED_BY_SECRET_BOUNDARY]"
                    continue
            if isinstance(v, dict):
                sanitized[k] = SecretBoundary.sanitize_payload_for_ai(v)
            else:
                sanitized[k] = v
        return sanitized
