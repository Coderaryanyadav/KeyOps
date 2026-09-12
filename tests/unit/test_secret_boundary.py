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
        "title": "Account Settings",
        "username": "alice",
        "password": "RawPlaintextPassword!",
        "auth_token": "bearer_secret_123",
        "database_dump": "SELECT * FROM users",
        "secret_reference": "new_password",
        "nested": {
            "session_cookie": "secret_cookie_val",
            "title": "Nested Security Modal",
            "unknown_internal_key": "sensitive_data"
        }
    }

    sanitized = SecretBoundary.sanitize_payload_for_ai(payload)

    # 1. Allowed fields are retained
    assert sanitized["url"] == "https://example.com/settings"
    assert sanitized["title"] == "Account Settings"
    assert sanitized["secret_reference"] == "new_password"

    # 2. Unknown & secret fields are dropped from top-level
    assert "password" not in sanitized
    assert "auth_token" not in sanitized
    assert "database_dump" not in sanitized
    assert "username" not in sanitized

    # 3. Unknown & secret fields are dropped from nested structures
    assert "nested" not in sanitized or "session_cookie" not in sanitized.get("nested", {})
    assert "unknown_internal_key" not in sanitized.get("nested", {})
    assert "RawPlaintextPassword!" not in str(sanitized)
    assert "bearer_secret_123" not in str(sanitized)
