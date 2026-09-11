from typing import Optional, Dict
from app.adapters.registry import adapter_registry
from app.core.domain_validator import DomainValidator

class URLDiscoveryPipeline:
    """
    Multi-Tier URL Discovery Pipeline for unknown and known services.
    Order of precedence:
    1. Existing verified account URL
    2. Trusted domain registry
    3. Known service adapter
    4. Known authentication platform
    5. Website internal navigation / AI navigation
    """

    def __init__(self):
        self.validator = DomainValidator()

    def discover_starting_url(self, service_name: str, domain: str, known_url: Optional[str] = None) -> str:
        # 1. Existing verified URL
        if known_url and (known_url.startswith("http://") or known_url.startswith("https://")):
            return known_url

        # 2. Check Adapter Registry
        adapter = adapter_registry.get_adapter_for_service(service_name, domain)
        if adapter and adapter.login_url:
            return adapter.login_url

        # 3. Clean domain fallback
        clean_domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
        if clean_domain.startswith("127.0.0.1") or clean_domain.startswith("localhost"):
            return f"http://{clean_domain}"
        
        return f"https://{clean_domain}"
