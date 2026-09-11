import pytest
from app.ai.page_sanitizer import PageSanitizer
from app.browser.page_inspector import PageInspectionResult, InteractiveElement

def test_page_sanitizer_removes_sensitive_data():
    sanitizer = PageSanitizer()
    
    inspection = PageInspectionResult(
        url="https://example.com/settings",
        title="Security Settings - auth=xyz123token999",
        headings=["Your 2FA Code is 123456", "Update Password"],
        interactive_elements=[
            InteractiveElement(
                element_id="elem_1",
                tag="input",
                role="textbox",
                text="Current Password: SuperSecret123",
                input_type="password",
                autocomplete="current-password",
                placeholder="Enter current password token=abc123456789012345678901234567890"
            )
        ],
        visible_text_summary="User email alice@example.com OTP code 654321 bearer=secret_token_12345"
    )

    sanitized = sanitizer.sanitize_inspection(inspection)

    assert "123456" not in sanitized["headings"][0]
    assert "[REDACTED]" in sanitized["headings"][0]
    assert "654321" not in sanitized["visible_text_summary"]
    assert "elem_1" in sanitized["interactive_elements"][0]["element_id"]
