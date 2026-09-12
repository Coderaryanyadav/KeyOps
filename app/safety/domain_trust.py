from typing import List, Optional, Set, Callable
from urllib.parse import urlparse
import tldextract
from pydantic import BaseModel
from app.core.domain_validator import DomainValidator, DomainValidationError
from app.core.audit_logger import audit_logger

class DomainTrustResult(BaseModel):
    is_trusted: bool
    current_url: str
    registrable_domain: str
    service_name: str
    is_https: bool
    reason: str

class DomainTrustContext:
    """
    Live runtime domain trust manager.
    Enforces strict domain verification on every single browser navigation, redirect,
    and credential operation.
    """

    def __init__(self, expected_service: str, allowed_explicit_domains: Optional[List[str]] = None):
        self.expected_service = expected_service.lower().strip()
        self.allowed_explicit_domains = [d.lower().strip() for d in (allowed_explicit_domains or [])]
        self.validator = DomainValidator()
        self.last_trusted_domain: Optional[str] = None
        self._on_domain_changed_callbacks: List[Callable[[str, str], None]] = []

    def register_on_domain_changed_callback(self, callback: Callable[[str, str], None]) -> None:
        """Registers a listener to be called when domain changes or becomes untrusted."""
        self._on_domain_changed_callbacks.append(callback)

    def evaluate_url(self, url: str) -> DomainTrustResult:
        """
        Evaluates domain trust for a given URL without throwing exceptions.
        """
        if not url:
            return DomainTrustResult(
                is_trusted=False,
                current_url="",
                registrable_domain="",
                service_name=self.expected_service,
                is_https=False,
                reason="URL is empty."
            )

        parsed = urlparse(url)
        is_https = parsed.scheme == "https"
        is_localhost = parsed.hostname in ("127.0.0.1", "localhost")

        # In production, require HTTPS
        if not is_https and not is_localhost:
            return DomainTrustResult(
                is_trusted=False,
                current_url=url,
                registrable_domain="",
                service_name=self.expected_service,
                is_https=False,
                reason=f"Insecure scheme '{parsed.scheme}'. HTTPS is mandatory."
            )

        # Punycode / Homograph attack check
        hostname = (parsed.hostname or "").lower()
        if "xn--" in hostname:
            audit_logger.log_event(self.expected_service, f"Homograph/IDN punycode detected in URL: {url}", level="ERROR")
            return DomainTrustResult(
                is_trusted=False,
                current_url=url,
                registrable_domain=hostname,
                service_name=self.expected_service,
                is_https=is_https,
                reason="IDN Punycode / Homograph domain detected."
            )

        if is_localhost:
            return DomainTrustResult(
                is_trusted=True,
                current_url=url,
                registrable_domain=hostname,
                service_name=self.expected_service,
                is_https=is_https,
                reason="Local test fixture / Localhost."
            )

        extracted = tldextract.extract(url)
        reg_domain = f"{extracted.domain}.{extracted.suffix}".lower()

        try:
            self.validator.validate_url(url, self.expected_service, self.allowed_explicit_domains)
            
            # Check for domain change
            if self.last_trusted_domain and self.last_trusted_domain != reg_domain:
                for cb in self._on_domain_changed_callbacks:
                    try:
                        cb(self.last_trusted_domain, reg_domain)
                    except Exception:
                        pass

            self.last_trusted_domain = reg_domain
            return DomainTrustResult(
                is_trusted=True,
                current_url=url,
                registrable_domain=reg_domain,
                service_name=self.expected_service,
                is_https=is_https,
                reason="Official verified domain."
            )
        except DomainValidationError as e:
            # Trigger domain change / invalidation
            for cb in self._on_domain_changed_callbacks:
                try:
                    cb(self.last_trusted_domain or "", reg_domain)
                except Exception:
                    pass
            return DomainTrustResult(
                is_trusted=False,
                current_url=url,
                registrable_domain=reg_domain,
                service_name=self.expected_service,
                is_https=is_https,
                reason=str(e)
            )
