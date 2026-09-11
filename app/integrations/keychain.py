import keyring
from typing import Optional
from app.core.audit_logger import audit_logger

SERVICE_NAMESPACE = "PasswordSecurityCenter"

class KeychainManager:
    """
    macOS Keychain integration via system keyring.
    Stores rotated credentials securely in macOS Keychain upon explicit user request.
    """

    @staticmethod
    def store_credential(service: str, username: str, secret: str) -> bool:
        try:
            keyring.set_password(f"{SERVICE_NAMESPACE}:{service}", username, secret)
            audit_logger.log_event(service, f"Credential successfully saved to macOS Keychain for account '{username}'.")
            return True
        except Exception as e:
            audit_logger.log_event(service, f"Failed to save credential to macOS Keychain: {str(e)}", level="ERROR")
            return False

    @staticmethod
    def retrieve_credential(service: str, username: str) -> Optional[str]:
        try:
            return keyring.get_password(f"{SERVICE_NAMESPACE}:{service}", username)
        except Exception:
            return None

    @staticmethod
    def delete_credential(service: str, username: str) -> bool:
        try:
            keyring.delete_password(f"{SERVICE_NAMESPACE}:{service}", username)
            return True
        except Exception:
            return False
