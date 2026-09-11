import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.database.models import Base, Account

def test_database_models_no_plaintext_passwords():
    # Verify DB model attributes strictly contain NO plaintext password fields
    columns = [c.name for c in Account.__table__.columns]
    assert "password" not in columns
    assert "plaintext_password" not in columns
    assert "secret" not in columns

def test_account_creation_in_sqlite():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    acc = Account(
        service="GitHub",
        username="testuser@example.com",
        domain="github.com",
        risk="CRITICAL",
        issue="Reused"
    )
    session.add(acc)
    session.commit()

    saved = session.query(Account).filter_by(service="GitHub").first()
    assert saved is not None
    assert saved.username == "testuser@example.com"
    assert saved.risk == "CRITICAL"
