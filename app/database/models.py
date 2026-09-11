from datetime import datetime, timezone
from sqlalchemy import String, Boolean, Integer, DateTime, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

class Base(DeclarativeBase):
    pass

class Account(Base):
    """
    Stores metadata for monitored accounts.
    SECURITY GUARANTEE: Never contains plaintext passwords or sensitive secrets.
    """
    __tablename__ = "accounts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    service: Mapped[str] = mapped_column(String(100), nullable=False)
    username: Mapped[str] = mapped_column(String(200), nullable=False)
    domain: Mapped[str] = mapped_column(String(200), nullable=False)
    risk: Mapped[str] = mapped_column(String(20), default="LOW")  # CRITICAL, HIGH, MEDIUM, LOW
    issue: Mapped[str] = mapped_column(String(200), default="None")
    mfa_status: Mapped[bool] = mapped_column(Boolean, default=False)
    automation_support: Mapped[str] = mapped_column(String(50), default="FULL")  # FULL, GENERIC, MANUAL
    last_checked: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_rotation: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    rotation_status: Mapped[str] = mapped_column(String(50), default="IDLE")  # IDLE, PENDING, IN_PROGRESS, SUCCESS, FAILED, PAUSED
    failure_reason: Mapped[str] = mapped_column(Text, nullable=True)

class AuditLog(Base):
    """
    Redacted audit log of system operations and user confirmations.
    """
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    service: Mapped[str] = mapped_column(String(100), nullable=False)
    event: Mapped[str] = mapped_column(Text, nullable=False)
    level: Mapped[str] = mapped_column(String(20), default="INFO")

class SecuritySetting(Base):
    """Local configuration preferences."""
    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)

class PersistedWorkflowState(Base):
    """
    Persisted non-sensitive workflow lifecycle tracking.
    CRITICAL SECURITY INVARIANT: NEVER stores passwords, keys, tokens, or raw credentials.
    """
    __tablename__ = "workflow_states"

    workflow_id: Mapped[str] = mapped_column(String(50), primary_key=True)
    account_id: Mapped[int] = mapped_column(Integer, nullable=False)
    service: Mapped[str] = mapped_column(String(100), nullable=False)
    domain: Mapped[str] = mapped_column(String(200), nullable=False)
    phase: Mapped[str] = mapped_column(String(50), nullable=False)
    last_safe_state: Mapped[str] = mapped_column(String(50), nullable=True)
    challenge_type: Mapped[str] = mapped_column(String(50), nullable=True)
    form_fingerprint: Mapped[str] = mapped_column(String(100), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
