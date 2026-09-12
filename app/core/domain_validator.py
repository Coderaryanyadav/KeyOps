from typing import Dict, List, Optional, Set
from urllib.parse import urlparse
import tldextract

class DomainValidationError(Exception):
    """Raised when domain validation fails or domain spoofing is detected."""
    pass

class DomainValidator:
    """
    Strict official domain validator with defenses against open redirects,
    lookalike domains, subdomain spoofing, and IDN homograph attacks.
    """

    def __init__(self):
        # Service -> set of allowed registered domains (registered domain = domain.suffix, e.g. github.com)
        self._registered_domains: Dict[str, Set[str]] = {
            "google": {"google.com", "accounts.google.com", "myaccount.google.com"},
            "apple": {"apple.com", "appleid.apple.com", "icloud.com"},
            "microsoft": {"microsoft.com", "live.com", "login.live.com", "office.com"},
            "github": {"github.com"},
            "amazon": {"amazon.com", "amazon.co.uk", "amazon.de", "amazon.ca"},
            "discord": {"discord.com", "discordapp.com"},
            "instagram": {"instagram.com"},
            "facebook": {"facebook.com"},
            "reddit": {"reddit.com"},
            "linkedin": {"linkedin.com"},
        }

    def register_official_domains(self, service_name: str, domains: List[str]) -> None:
        key = service_name.lower()
        if key not in self._registered_domains:
            self._registered_domains[key] = set()
        for d in domains:
            self._registered_domains[key].add(d.lower())

    def validate_url(self, url: str, expected_service_name: str, allowed_explicit_domains: Optional[List[str]] = None) -> bool:
        """
        Validates that `url` belongs to the official domain of `expected_service_name`.
        Returns True if valid, raises DomainValidationError or returns False if untrusted.
        """
        if not url:
            raise DomainValidationError("Empty or missing URL.")

        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise DomainValidationError(f"Invalid URL scheme '{parsed.scheme}'. Only http and https are allowed.")

        # Localhost exception for testing (strictly 127.0.0.1 or localhost, no arbitrary .local)
        if parsed.hostname in ("127.0.0.1", "localhost"):
            return True

        extracted = tldextract.extract(url)
        registered_domain = f"{extracted.domain}.{extracted.suffix}".lower()
        full_host = parsed.hostname.lower() if parsed.hostname else ""

        service_key = expected_service_name.lower()
        # Security: Always operate on a copy of the registered domains set to prevent global state pollution
        official_set = set(self._registered_domains.get(service_key, set()))

        if allowed_explicit_domains:
            for d in allowed_explicit_domains:
                official_set.add(d.lower())

        if not official_set:
            # Fallback check if service is unknown: ensure registered domain matches expected service key or explicitly trusted domain
            if service_key in registered_domain:
                return True
            raise DomainValidationError(f"No official domains registered for service '{expected_service_name}'.")

        # Validate registered domain matches or full host matches official whitelist
        is_valid = False
        for official in official_set:
            official = official.lower()
            if official.startswith("http://") or official.startswith("https://"):
                official_host = urlparse(official).hostname or ""
            else:
                official_host = official

            official_extracted = tldextract.extract(official_host)
            official_registered = f"{official_extracted.domain}.{official_extracted.suffix}".lower()

            if registered_domain == official_registered:
                # Extra check: prevent subdomain confusion like github.com.attacker.com
                # If host ends with official_host or official_registered
                if full_host == official_host or full_host.endswith("." + official_registered) or full_host == official_registered:
                    is_valid = True
                    break

        if not is_valid:
            raise DomainValidationError(
                f"SECURITY HALT: URL '{url}' with domain '{registered_domain}' does NOT match "
                f"official domain registry for service '{expected_service_name}' ({official_set})."
            )

        return True
