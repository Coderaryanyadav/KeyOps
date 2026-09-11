from abc import ABC, abstractmethod
from typing import Dict, List, Optional
from playwright.async_api import Page, ElementHandle
from app.core.password_generator import PasswordPolicy
from app.safety.secret_boundary import SecretBoundaryViolation

class PasswordAdapter(ABC):
    """
    Abstract base class for all Service Adapters.
    Defines official domains, URLs, navigation logic, and password policies.
    CRITICAL ARCHITECTURAL INVARIANT: Adapters are declarative metadata and route providers.
    Adapters CANNOT directly fill or submit plaintext credentials without the central
    ControlledActionExecutor and SubmissionApprovalManager.
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

    async def fill_password(
        self,
        page: Page,
        fields: Dict[str, Optional[ElementHandle]],
        current_password: Optional[str],
        new_password: str
    ) -> bool:
        """
        SECURITY BOUNDARY ENFORCEMENT:
        Direct adapter secret filling is strictly blocked to prevent chokepoint bypass.
        All credential filling must route through ControlledActionExecutor with CredentialFieldVerifier.
        """
        raise SecretBoundaryViolation(
            "Direct adapter secret filling is prohibited. Credential operations must route through ControlledActionExecutor."
        )

    async def submit_password_change(self, page: Page, dry_run: bool = False) -> bool:
        """
        SECURITY BOUNDARY ENFORCEMENT:
        Direct adapter submission is strictly blocked to prevent approval bypass.
        All submissions must route through ControlledActionExecutor with a valid SubmissionApprovalToken.
        """
        raise SecretBoundaryViolation(
            "Direct adapter submission is prohibited. Submissions must route through ControlledActionExecutor with human approval token."
        )

    @abstractmethod
    async def detect_success(self, page: Page) -> bool:
        pass

    @abstractmethod
    async def detect_failure(self, page: Page) -> Optional[str]:
        pass
