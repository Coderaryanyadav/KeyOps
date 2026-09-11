import pytest
from app.browser.success_verifier import PasswordChangeVerifier, VerificationOutcome

def test_success_verifier_patterns():
    verifier = PasswordChangeVerifier()

    # Success strings
    for s in ["Your password has been changed successfully.", "Password updated.", "Changes have been saved", "New password activated"]:
        matched = any(p.search(s) for p in verifier.SUCCESS_PATTERNS)
        assert matched is True, f"Failed to match success string: {s}"

    # Failure strings
    for f in ["Current password was incorrect", "Password does not meet requirements", "Passwords do not match", "Error updating password"]:
        matched = any(p.search(f) for p in verifier.FAILURE_PATTERNS)
        assert matched is True, f"Failed to match failure string: {f}"
