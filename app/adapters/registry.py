from typing import Dict, List, Type
from app.adapters.base import PasswordAdapter
from app.adapters.google import GoogleAdapter
from app.adapters.apple import AppleAdapter
from app.adapters.microsoft import MicrosoftAdapter
from app.adapters.github import GitHubAdapter
from app.adapters.amazon import AmazonAdapter
from app.adapters.discord import DiscordAdapter
from app.adapters.reddit import RedditAdapter
from app.adapters.generic import GenericAdapter

class AdapterRegistry:
    """
    Central registry for managing service adapters and resolving adapter instances by domain or service name.
    """

    def __init__(self):
        self._adapters: List[PasswordAdapter] = [
            GoogleAdapter(),
            AppleAdapter(),
            MicrosoftAdapter(),
            GitHubAdapter(),
            AmazonAdapter(),
            DiscordAdapter(),
            RedditAdapter(),
        ]

    def register_adapter(self, adapter: PasswordAdapter) -> None:
        self._adapters.append(adapter)

    def list_adapters(self) -> List[PasswordAdapter]:
        return list(self._adapters)

    def get_adapter_for_service(self, service_name: str, domain: str = "") -> PasswordAdapter:
        service_lower = service_name.lower()
        domain_lower = domain.lower()

        for adapter in self._adapters:
            if adapter.service_name.lower() == service_lower:
                return adapter
            if domain_lower and adapter.can_handle(domain_lower):
                return adapter

        return GenericAdapter(target_service_name=service_name, target_domain=domain)

adapter_registry = AdapterRegistry()
