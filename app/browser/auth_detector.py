from typing import Tuple
from playwright.async_api import Page

class AuthenticationDetector:
    """
    Evaluates whether the user is currently authenticated in the browser context.
    Uses multi-signal heuristics (logout buttons, avatars, account menus, login forms).
    """

    async def detect_auth_state(self, page: Page) -> Tuple[bool, float, str]:
        """
        Returns (is_authenticated, confidence, reason).
        """
        try:
            content = (await page.content()).lower()
            url = page.url.lower()

            # 1. Check for logout / sign out elements
            logout_elements = await page.query_selector_all("a[href*='logout'], a[href*='signout'], a, button")
            for el in logout_elements:
                txt = (await el.text_content() or "").strip().lower()
                href = (await el.get_attribute("href") or "").lower()
                if any(w in txt for w in ["sign out", "log out", "logout", "signout"]) or "logout" in href or "signout" in href:
                    return True, 0.98, f"Detected authenticated logout element ('{txt or href}')."

            # 2. Check for user avatar or account navigation
            avatar = await page.query_selector(".avatar, [aria-label*='Account'], [aria-label*='Profile'], .user-nav, img[alt*='avatar']")
            if avatar:
                return True, 0.94, "Detected user avatar / account profile menu."

            # 3. Check for obvious login form
            login_form = await page.query_selector("form[action*='login'], form[action*='signin'], input[name='login'], input[name='identifier']")
            if login_form:
                return False, 0.95, "Detected unauthenticated login form."

            if "login" in url or "signin" in url or "auth" in url:
                return False, 0.85, f"URL indicates authentication page ('{url}')."

            return True, 0.80, "No login forms detected on current page."
        except Exception as e:
            return False, 0.50, f"Error inspecting auth state: {str(e)}"
