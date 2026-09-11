import pytest
from playwright.async_api import async_playwright
from app.browser.credential_verifier import CredentialFieldVerifier, FieldVerificationResult

@pytest.mark.asyncio
async def test_credential_verifier_with_mock_dom():
    verifier = CredentialFieldVerifier()

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()

        html = """
        <html>
        <body>
            <form id="password-form">
                <input type="password" id="old-pwd" name="current_password" autocomplete="current-password" placeholder="Current Password">
                <input type="password" id="new-pwd" name="new_password" autocomplete="new-password" placeholder="Create New Password">
                <input type="password" id="confirm-pwd" name="confirm_password" placeholder="Confirm New Password">
                <input type="text" id="username" name="username" autocomplete="username">
            </form>
        </body>
        </html>
        """
        await page.set_content(html)

        # 1. Test current password verification
        old_input = await page.query_selector("#old-pwd")
        res_current = await verifier.verify_field(old_input, expected_role="current_password", page=page)
        assert res_current.is_valid is True
        assert res_current.field_role == "current_password"
        assert res_current.confidence >= 0.85

        # 2. Test new password verification
        new_input = await page.query_selector("#new-pwd")
        res_new = await verifier.verify_field(new_input, expected_role="new_password", page=page)
        assert res_new.is_valid is True
        assert res_new.field_role == "new_password"

        # 3. Test confirm password verification
        confirm_input = await page.query_selector("#confirm-pwd")
        res_confirm = await verifier.verify_field(confirm_input, expected_role="confirm_password", page=page)
        assert res_confirm.is_valid is True
        assert res_confirm.field_role == "confirm_password"

        # 4. Test non-password input rejection
        user_input = await page.query_selector("#username")
        res_user = await verifier.verify_field(user_input, expected_role="new_password", page=page)
        assert res_user.is_valid is False
        assert "mismatch" in (res_user.rejection_reason or "").lower() or "confidence" in (res_user.rejection_reason or "").lower()

        await browser.close()
