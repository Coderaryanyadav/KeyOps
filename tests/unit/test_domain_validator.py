import pytest
from app.core.domain_validator import DomainValidator, DomainValidationError

def test_official_domain_validation_valid():
    validator = DomainValidator()
    assert validator.validate_url("https://github.com/settings/security", "GitHub") is True
    assert validator.validate_url("https://accounts.google.com/signin", "Google") is True

def test_official_domain_validation_spoof_prevention():
    validator = DomainValidator()
    
    # Subdomain spoofing attack
    with pytest.raises(DomainValidationError):
        validator.validate_url("https://github.com.attacker.com/login", "GitHub")

    # Lookalike domain attack
    with pytest.raises(DomainValidationError):
        validator.validate_url("https://github-login.com", "GitHub")

    # Invalid scheme
    with pytest.raises(DomainValidationError):
        validator.validate_url("javascript:alert(1)", "GitHub")
