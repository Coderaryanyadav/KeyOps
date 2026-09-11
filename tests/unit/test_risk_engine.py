import pytest
from app.core.risk_engine import RiskEngine, RiskLevel

def test_risk_engine_critical_account():
    engine = RiskEngine()
    analysis = engine.analyze_account("Google", "Compromised", mfa_enabled=True)
    assert analysis.risk_level == RiskLevel.CRITICAL
    assert analysis.is_high_value is True

def test_risk_engine_reused_password():
    engine = RiskEngine()
    analysis = engine.analyze_account("Reddit", "Reused", mfa_enabled=False)
    assert analysis.risk_level == RiskLevel.HIGH
    assert "Reused" in analysis.reason
