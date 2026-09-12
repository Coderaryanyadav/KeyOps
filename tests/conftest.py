import pytest
from app.database.session import init_db

@pytest.fixture(scope="session", autouse=True)
def setup_test_database():
    """
    Ensure the test database schema exists and default tables/seed records
    are initialized before any tests or TestClient instances run.
    Guarantees clean, deterministic execution in fresh CI runners.
    """
    init_db()
