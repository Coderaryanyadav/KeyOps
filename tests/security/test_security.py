import pytest
from app.core.audit_logger import sanitize_log_message
from app.core.domain_validator import DomainValidator, DomainValidationError
from app.core.password_generator import PasswordGenerator

def test_log_sanitization_redacts_passwords():
    raw_log = "GitHub | Password rotation started. password=SecretPassword123! token=bearer_xyz_789"
    sanitized = sanitize_log_message(raw_log)
    
    assert "SecretPassword123!" not in sanitized
    assert "bearer_xyz_789" not in sanitized
    assert "[REDACTED]" in sanitized

def test_domain_spoofing_defense():
    validator = DomainValidator()
    
    with pytest.raises(DomainValidationError):
        validator.validate_url("https://accounts.google.com.phishing.net/login", "Google")

def test_csprng_entropy():
    gen = PasswordGenerator()
    passwords = [gen.generate() for _ in range(100)]
    assert len(set(passwords)) == 100
