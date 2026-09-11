from typing import List, Dict, Any
from pydantic import BaseModel

class SecurityOverview(BaseModel):
    score: int  # 0 to 100
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    total_accounts: int
    fixed_accounts: int
    remaining_accounts: int
    mfa_coverage_percent: float
    reused_count: int
    compromised_count: int

class SecurityScoreCalculator:
    """Calculates security metrics and 0-100 overall security score."""

    @staticmethod
    def calculate(accounts: List[Dict[str, Any]]) -> SecurityOverview:
        if not accounts:
            return SecurityOverview(
                score=100,
                critical_count=0,
                high_count=0,
                medium_count=0,
                low_count=0,
                total_accounts=0,
                fixed_accounts=0,
                remaining_accounts=0,
                mfa_coverage_percent=100.0,
                reused_count=0,
                compromised_count=0,
            )

        critical = 0
        high = 0
        medium = 0
        low = 0
        fixed = 0
        mfa_enabled = 0
        reused = 0
        compromised = 0

        for acc in accounts:
            risk = str(acc.get("risk", "LOW")).upper()
            status = str(acc.get("rotation_status", "")).lower()
            issue = str(acc.get("issue", "")).lower()

            if status == "success" or status == "fixed":
                fixed += 1
            else:
                if risk == "CRITICAL":
                    critical += 1
                elif risk == "HIGH":
                    high += 1
                elif risk == "MEDIUM":
                    medium += 1
                else:
                    low += 1

            if acc.get("mfa_status"):
                mfa_enabled += 1
            if "reused" in issue:
                reused += 1
            if "compromised" in issue:
                compromised += 1

        total = len(accounts)
        remaining = total - fixed

        # Score formula: Base 100, subtract penalties for unresolved risks
        penalty = (critical * 20) + (high * 10) + (medium * 5) + (low * 2)
        score = max(0, min(100, 100 - penalty))

        mfa_percent = round((mfa_enabled / total) * 100.0, 1) if total > 0 else 100.0

        return SecurityOverview(
            score=score,
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            low_count=low,
            total_accounts=total,
            fixed_accounts=fixed,
            remaining_accounts=remaining,
            mfa_coverage_percent=mfa_percent,
            reused_count=reused,
            compromised_count=compromised,
        )
