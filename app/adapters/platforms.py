from typing import Optional, Dict
from playwright.async_api import Page

class PlatformDetectionResult:
    def __init__(self, platform_name: str, confidence: float, hints: Dict[str, str]):
        self.platform_name = platform_name
        self.confidence = confidence
        self.hints = hints

class PlatformDetector:
    """
    Detects standard authentication/identity platforms (Auth0, Okta, Firebase, Clerk, WordPress, etc.)
    enabling platform-level workflow discovery across thousands of websites.
    """

    PLATFORM_SIGNATURES = {
        "Auth0": ["auth0", "auth0.com", "cdn.auth0.com", "auth0-js", "_auth0"],
        "Okta": ["okta", "okta.com", "oktacdn.com", "okta-sign-in"],
        "Firebase": ["firebase", "firebaseapp.com", "firebase.google.com", "firebase-auth"],
        "Clerk": ["clerk", "clerk.com", "clerk.dev", "__clerk_status"],
        "Supabase": ["supabase", "supabase.co", "gotrue"],
        "AWS Cognito": ["cognito", "amazoncognito.com", "cognito-idp"],
        "Keycloak": ["keycloak", "auth/realms"],
        "WordPress": ["wordpress", "wp-login.php", "wp-admin", "wp-content"],
        "Shopify": ["shopify", "myshopify.com", "cdn.shopify.com", "shopify-customer-account"]
    }

    async def detect_platform(self, page: Page) -> Optional[PlatformDetectionResult]:
        try:
            content = (await page.content()).lower()
            url = page.url.lower()

            for platform, sigs in self.PLATFORM_SIGNATURES.items():
                match_count = sum(1 for sig in sigs if sig in content or sig in url)
                if match_count > 0:
                    confidence = min(0.98, 0.70 + (0.15 * match_count))
                    return PlatformDetectionResult(
                        platform_name=platform,
                        confidence=confidence,
                        hints={"detected_signatures": f"{match_count} signatures matched for {platform}"}
                    )
            return None
        except Exception:
            return None
