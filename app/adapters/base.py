from abc import ABC, abstractmethod
from typing import Dict, List, Optional
from playwright.async_api import Page, ElementHandle
from app.core.password_generator import PasswordPolicy, PasswordGenerator

class PasswordAdapter(ABC):
    """
    Abstract base class for all Service Adapters.
    Defines official domains, URLs, navigation logic, field detection,
    MFA detection, CAPTCHA detection, and submission verification.
    """

    @property
    @abstractmethod
    def service_name(self) -> str:
        pass

    @property
    @abstractmethod
    def official_domains(self) -> List[str]:
        pass

    @property
    @abstractmethod
    def login_url(self) -> str:
        pass

    @property
    @abstractmethod
    def password_change_url(self) -> str:
        pass

    def get_password_policy(self) -> PasswordPolicy:
        """Returns site-specific password policy constraints."""
        return PasswordPolicy(length=24, use_uppercase=True, use_lowercase=True, use_digits=True, use_symbols=True)

    def can_handle(self, domain: str) -> bool:
        domain_lower = domain.lower()
        return any(d.lower() in domain_lower or domain_lower in d.lower() for d in self.official_domains)

    @abstractmethod
    async def navigate_to_security(self, page: Page) -> bool:
        pass

    @abstractmethod
    async def detect_password_fields(self, page: Page) -> Dict[str, Optional[ElementHandle]]:
        pass

    @abstractmethod
    async def fill_password(
        self,
        page: Page,
        fields: Dict[str, Optional[ElementHandle]],
        current_password: Optional[str],
        new_password: str
    ) -> bool:
        pass

    @abstractmethod
    async def submit_password_change(self, page: Page, dry_run: bool = False) -> bool:
        pass

    @abstractmethod
    async def detect_success(self, page: Page) -> bool:
        pass

    @abstractmethod
    async def detect_failure(self, page: Page) -> Optional[str]:
        pass
