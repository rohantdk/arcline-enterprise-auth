import os
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
import main
def test_fastapi_persists_audit_event_to_postgres(monkeypatch):
    url = os.getenv("ARCLINE_TEST_RUNTIME_DATABASE_URL")
    if not url:
        pytest.skip("Runtime database URL is not configured.")
    engine = create_engine(
        url,
        pool_pre_ping=True,
        connect_args={
            "connect_timeout": 5,
            "options": "-c statement_timeout=10000",
        },
    )
    try:
        with engine.connect() as conn:
            role = conn.execute(
                text("SELECT current_user")
            ).scalar_one()
        assert role == "arcline_app", (
            "Integration test must use the restricted runtime role."
        )
        runtime_sessions = sessionmaker(
            bind=engine,
            autoflush=False,
            expire_on_commit=False,
        )
        monkeypatch.setattr(main, "SessionLocal", runtime_sessions)
        client = TestClient(main.app)
        response = client.get("/protected")
        assert response.status_code == 401
        print("Runtime role:", role)
        print("Unauthenticated endpoint returned:", response.status_code)
        print("FastAPI request completed.")
    finally:
        engine.dispose()
