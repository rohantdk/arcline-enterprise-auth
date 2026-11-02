import base64
import json
import os
import uuid
import pytest
from fastapi.testclient import TestClient
from itsdangerous import TimestampSigner
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
import main
@pytest.fixture
def postgres_audit():
    runtime_url = os.getenv("ARCLINE_TEST_RUNTIME_DATABASE_URL")
    admin_url = os.getenv("ARCLINE_TEST_ADMIN_DATABASE_URL")
    if not runtime_url or not admin_url:
        pytest.skip("Required PostgreSQL test URLs are not configured.")
    options = {
        "pool_pre_ping": True,
        "connect_args": {
            "connect_timeout": 5,
            "options": "-c statement_timeout=10000",
        },
    }
    runtime_engine = create_engine(runtime_url, **options)
    admin_engine = create_engine(admin_url, **options)
    with runtime_engine.connect() as conn:
        role = conn.execute(text("SELECT current_user")).scalar_one()
        assert role == "arcline_app"
    runtime_sessions = sessionmaker(
        bind=runtime_engine,
        autoflush=False,
        expire_on_commit=False,
    )
    original_sessions = main.SessionLocal
    main.SessionLocal = runtime_sessions
    try:
        yield admin_engine
    finally:
        main.SessionLocal = original_sessions
        runtime_engine.dispose()
        admin_engine.dispose()
def make_authenticated_client(user):
    session_data = {"user": user}
    encoded = base64.b64encode(
        json.dumps(session_data).encode("utf-8")
    )
    cookie = TimestampSigner(str(main.SESSION_SECRET)).sign(
        encoded
    ).decode("utf-8")
    client = TestClient(main.app, base_url="http://testserver.local")
    client.cookies.set(
        "session",
        cookie,
        domain="testserver.local",
        path="/",
    )
    return client
def find_audit_event(engine, actor_sub, event_type):
    with engine.connect() as conn:
        return conn.execute(
            text("""
                SELECT event_type, outcome, metadata
                FROM public.audit_events
                WHERE actor_sub = :actor_sub
                  AND event_type = :event_type
                ORDER BY id DESC
                LIMIT 1
            """),
            {
                "actor_sub": actor_sub,
                "event_type": event_type,
            },
        ).mappings().first()
def test_role_denial_is_persisted_to_postgres(postgres_audit):
    actor = "stage3-role-denial-" + uuid.uuid4().hex
    client = make_authenticated_client({
        "sub": actor,
        "preferred_username": "stage3_employee",
        "roles": ["employee"],
    })
    try:
        response = client.get("/admin")
        assert response.status_code == 403
    finally:
        client.close()
    event = find_audit_event(
        postgres_audit,
        actor,
        "role_authorization_denied",
    )
    assert event is not None, "Role-denial audit event was not persisted."
    assert event["outcome"] == "denied"
    assert event["metadata"]["required_role"] == "admin"
def test_logout_is_persisted_to_postgres(postgres_audit):
    actor = "stage3-logout-" + uuid.uuid4().hex
    client = make_authenticated_client({
        "sub": actor,
        "preferred_username": "stage3_admin",
        "roles": ["admin"],
    })
    try:
        response = client.post("/auth/logout")
        assert response.status_code == 200
    finally:
        client.close()
    event = find_audit_event(
        postgres_audit,
        actor,
        "logout_succeeded",
    )
    assert event is not None, "Logout audit event was not persisted."
    assert event["outcome"] == "success"
    assert event["metadata"]["reason"] == "user_initiated"
