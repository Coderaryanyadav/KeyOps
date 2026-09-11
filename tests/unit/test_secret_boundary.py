import pytest
from app.safety.secret_boundary import SecretBoundary, SecretBoundaryViolation

def test_secret_boundary_isolation():
    boundary = SecretBoundary()
    boundary.register_secrets(current_password="OldPassword123!", new_password="NewSecretCSPRNG999!")

    # Resolve symbolic references locally
    assert boundary.resolve_secret("current_password") == "OldPassword123!"
    assert boundary.resolve_secret("new_password") == "NewSecretCSPRNG999!"
    assert boundary.resolve_secret("confirm_password") == "NewSecretCSPRNG999!"

    # Unauthorized reference rejection
    with pytest.raises(SecretBoundaryViolation):
        boundary.resolve_secret("master_key")

    boundary.clear()
    with pytest.raises(SecretBoundaryViolation):
        boundary.resolve_secret("current_password")

def test_secret_boundary_sanitize_ai_payload():
    payload = {
        "url": "https://example.com/settings",
        "username": "alice",
        "password": "RawPlaintextPassword!",
        "auth_token": "bearer_secret_123",
        "nested": {
            "session_cookie": "secret_cookie_val",
            "safe_field": "Account Settings"
        }
    }

    sanitized = SecretBoundary.sanitize_payload_for_ai(payload)

    assert sanitized["password"] == "[REDACTED_BY_SECRET_BOUNDARY]"
    assert sanitized["auth_token"] == "[REDACTED_BY_SECRET_BOUNDARY]"
    assert sanitized["nested"]["session_cookie"] == "[REDACTED_BY_SECRET_BOUNDARY]"
    assert sanitized["nested"]["safe_field"] == "Account Settings"
