import os
import secrets
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv
from pydantic import BaseModel, Field

# Load local environment variables from .env if present
load_dotenv()

APP_DIR = Path(os.path.expanduser("~/.password_security_center"))
APP_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = APP_DIR / "security_center.db"
LOG_PATH = APP_DIR / "audit.log"

HIGH_VALUE_SERVICES = {
    "google",
    "apple",
    "microsoft",
    "1password",
    "bitwarden",
    "dashlane",
    "chase",
    "bankofamerica",
    "wells_fargo",
    "stripe",
    "aws",
    "gcp",
    "azure",
    "github",
}

class AppSettings(BaseModel):
    app_name: str = "Password Security Center"
    version: str = "1.0.0"
    db_url: str = f"sqlite:///{DB_PATH}"
    log_file: Path = LOG_PATH
    browser_headed: bool = True
    browser_slow_mo_ms: int = 250
    screenshot_on_error: bool = False
    telemetry_enabled: bool = False
    port: int = 8443
    host: str = "127.0.0.1"
    local_api_token: str = Field(default_factory=lambda: os.environ.get("KEYOPS_API_TOKEN", "") or secrets.token_urlsafe(32))

    # AI Reasoning Configuration
    ai_provider: str = "gemini"  # gemini, local, disabled
    ai_model: str = "gemini-2.5-flash"
    gemini_api_key: Optional[str] = Field(default_factory=lambda: os.environ.get("GEMINI_API_KEY", ""))
    ai_page_analysis_enabled: bool = True
    page_sanitization_enabled: bool = True
    sensitive_page_protection: bool = True

settings = AppSettings()
