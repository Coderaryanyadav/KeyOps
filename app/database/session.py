from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from app.config import settings
from app.database.models import Base, Account

engine = create_engine(
    settings.db_url,
    connect_args={"check_same_thread": False} if "sqlite" in settings.db_url else {},
    echo=False,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    """Creates database tables and seeds demo accounts if database is empty."""
    Base.metadata.create_all(bind=engine)
    
    db: Session = SessionLocal()
    try:
        if db.query(Account).count() == 0:
            seed_accounts = [
                Account(
                    service="Google",
                    username="user@example.com",
                    domain="accounts.google.com",
                    risk="CRITICAL",
                    issue="Compromised",
                    mfa_status=True,
                    automation_support="FULL",
                    rotation_status="IDLE",
                ),
                Account(
                    service="GitHub",
                    username="user@example.com",
                    domain="github.com",
                    risk="CRITICAL",
                    issue="Reused",
                    mfa_status=True,
                    automation_support="FULL",
                    rotation_status="IDLE",
                ),
                Account(
                    service="Amazon",
                    username="user@example.com",
                    domain="amazon.com",
                    risk="HIGH",
                    issue="Weak",
                    mfa_status=False,
                    automation_support="FULL",
                    rotation_status="IDLE",
                ),
                Account(
                    service="Discord",
                    username="user@example.com",
                    domain="discord.com",
                    risk="HIGH",
                    issue="Compromised",
                    mfa_status=False,
                    automation_support="FULL",
                    rotation_status="IDLE",
                ),
                Account(
                    service="Reddit",
                    username="user@example.com",
                    domain="reddit.com",
                    risk="MEDIUM",
                    issue="Reused",
                    mfa_status=False,
                    automation_support="FULL",
                    rotation_status="IDLE",
                ),
                Account(
                    service="Apple",
                    username="user@example.com",
                    domain="appleid.apple.com",
                    risk="MEDIUM",
                    issue="Old Password",
                    mfa_status=True,
                    automation_support="FULL",
                    rotation_status="IDLE",
                ),
                Account(
                    service="Microsoft",
                    username="user@example.com",
                    domain="login.live.com",
                    risk="LOW",
                    issue="None",
                    mfa_status=True,
                    automation_support="FULL",
                    rotation_status="IDLE",
                ),
            ]
            db.add_all(seed_accounts)
            db.commit()
    finally:
        db.close()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
