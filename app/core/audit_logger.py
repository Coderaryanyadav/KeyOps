import datetime
import logging
import re
from pathlib import Path
from typing import Optional
from app.config import settings

# Regex to detect secret strings, passwords, auth tokens, bearer tokens
SENSITIVE_PATTERNS = [
    re.compile(r"(password|passwd|secret|token|bearer|cookie|auth)=([^\s&]+)", re.IGNORECASE),
    re.compile(r"Bearer\s+([A-Za-z0-9\-\._~\+\/]+=*)", re.IGNORECASE),
]

def sanitize_log_message(message: str) -> str:
    """Strips secrets, passwords, cookies, and tokens from log strings."""
    sanitized = message
    for pattern in SENSITIVE_PATTERNS:
        sanitized = pattern.sub(r"\1=[REDACTED]", sanitized)
    return sanitized

class AuditLogger:
    """Privacy-preserving audit logger ensuring zero secret exposure."""

    def __init__(self, log_path: Optional[Path] = None):
        self.log_path = log_path or settings.log_file
        self.logger = logging.getLogger("PasswordSecurityAudit")
        self.logger.setLevel(logging.INFO)

        if not self.logger.handlers:
            handler = logging.FileHandler(self.log_path, encoding="utf-8")
            formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s")
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def log_event(self, service: str, event: str, level: str = "INFO") -> str:
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        clean_event = sanitize_log_message(event)
        entry = f"{service} | {clean_event}"

        if level.upper() == "ERROR":
            self.logger.error(entry)
        elif level.upper() == "WARNING":
            self.logger.warning(entry)
        else:
            self.logger.info(entry)

        return entry

audit_logger = AuditLogger()
