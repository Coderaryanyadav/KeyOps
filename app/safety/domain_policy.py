from typing import List, Optional
from urllib.parse import urlparse
import tldextract
from app.core.domain_validator import DomainValidator, DomainValidationError

class DomainPolicyEngine:
    """
    Authoritative domain safety policy.
    Ensures browser navigation remains strictly bounded within official registered domains.
    """

    def __init__(self):
        self.validator = DomainValidator()

    def validate_navigation(self, target_url: str, service_name: str, allowed_domains: Optional[List[str]] = None) -> bool:
        """
        Validates target URL before navigation.
        Raises DomainValidationError if target domain is untrusted.
        """
        if not target_url:
            raise DomainValidationError("Target URL cannot be empty.")

        parsed = urlparse(target_url)
        if parsed.scheme not in ("http", "https"):
            raise DomainValidationError(f"Invalid URL scheme '{parsed.scheme}'. Only http/https are permitted.")

        # Localhost testing exception
        if parsed.hostname in ("127.0.0.1", "localhost") or (parsed.hostname and parsed.hostname.endswith(".local")):
            return True

        return self.validator.validate_url(target_url, service_name, allowed_domains)
