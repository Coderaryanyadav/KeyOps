import csv
from io import StringIO
from typing import List, Dict, Any
from sqlalchemy.orm import Session
from app.database.models import Account
from app.core.risk_engine import RiskEngine
from app.core.audit_logger import audit_logger

class CSVAccountImporter:
    """Imports and validates accounts from CSV files or raw strings."""

    def __init__(self, db_session: Session):
        self.db = db_session
        self.risk_engine = RiskEngine()

    def import_from_csv_content(self, csv_text: str) -> List[Account]:
        reader = csv.DictReader(StringIO(csv_text))
        imported_accounts: List[Account] = []

        for row in reader:
            service = (row.get("service") or row.get("name") or row.get("Title") or "Unknown").strip()
            username = (row.get("username") or row.get("email") or row.get("login_username") or "user@example.com").strip()
            url_or_domain = (row.get("url") or row.get("domain") or row.get("login_uri") or f"{service.lower()}.com").strip()
            status = (row.get("status") or row.get("issue") or "Reused").strip()

            # Clean domain
            domain = url_or_domain.replace("https://", "").replace("http://", "").split("/")[0]

            risk_analysis = self.risk_engine.analyze_account(service, status)

            # Check if account already exists
            existing = self.db.query(Account).filter_by(service=service, username=username).first()
            if existing:
                existing.domain = domain
                existing.risk = risk_analysis.risk_level.value
                existing.issue = status
                imported_accounts.append(existing)
            else:
                account = Account(
                    service=service,
                    username=username,
                    domain=domain,
                    risk=risk_analysis.risk_level.value,
                    issue=status,
                    mfa_status=risk_analysis.is_high_value,
                    automation_support="FULL",
                    rotation_status="IDLE",
                )
                self.db.add(account)
                imported_accounts.append(account)

        self.db.commit()
        audit_logger.log_event("CSV_IMPORT", f"Successfully imported {len(imported_accounts)} accounts.")
        return imported_accounts
