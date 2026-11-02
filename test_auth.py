import os

# Configure test settings BEFORE importing main.
os.environ.setdefault("SESSION_SECRET", "test-only-session-secret")
os.environ.setdefault(
    "KEYCLOAK_ISSUER_URL",
    "http://localhost:8080/realms/arcline",
)
os.environ.setdefault("KEYCLOAK_CLIENT_ID", "arcline-auth-api")
os.environ.setdefault("KEYCLOAK_CLIENT_SECRET", "test-only-client-secret")
os.environ.setdefault("SCIM_BEARER_TOKEN", "test-only-scim-token")

# Use an isolated SQLite database for these unit tests.
os.environ["DATABASE_URL"] = "sqlite+pysqlite:///:memory:"

import base64
import json

import main
import pytest
from fastapi.testclient import TestClient
from itsdangerous import TimestampSigner
from sqlalchemy import delete

from main import SESSION_SECRET, app


def make_session_cookie(user: dict) -> str:
    """Create a signed Starlette session cookie for integration tests."""
    session_data = {"user": user}
    encoded_data = base64.b64encode(
        json.dumps(session_data).encode("utf-8")
    )
    signer = TimestampSigner(str(SESSION_SECRET))
    return signer.sign(encoded_data).decode("utf-8")


def make_authenticated_client(user: dict) -> TestClient:
    """Return a client carrying a valid signed application session."""
    client = TestClient(app, base_url="http://testserver.local")
    client.cookies.set(
        "session",
        make_session_cookie(user),
        domain="testserver.local",
        path="/",
    )
    return client


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def employee_client():
    test_client = make_authenticated_client(
        {
            "sub": "employee-test-id",
            "preferred_username": "employee1",
            "roles": ["employee"],
        }
    )
    try:
        yield test_client
    finally:
        test_client.close()


@pytest.fixture
def admin_client():
    test_client = make_authenticated_client(
        {
            "sub": "admin-test-id",
            "preferred_username": "admin1",
            "roles": ["admin"],
        }
    )
    try:
        yield test_client
    finally:
        test_client.close()


@pytest.fixture
def tenant_data():
    """Insert isolated organization, membership, and document records."""
    with main.SessionLocal() as db:
        db.execute(delete(main.Document))
        db.execute(delete(main.OrganizationMembership))
        db.execute(delete(main.Organization))

        db.add_all(
            [
                main.Organization(id="org-acme", name="Acme"),
                main.Organization(id="org-globex", name="Globex"),
            ]
        )

        db.add_all(
            [
                main.OrganizationMembership(
                    user_sub="employee-test-id",
                    organization_id="org-acme",
                    role="member",
                ),
                main.OrganizationMembership(
                    user_sub="employee-b-test-id",
                    organization_id="org-globex",
                    role="member",
                ),
            ]
        )

        db.add_all(
            [
                main.Document(
                    id="doc-acme-001",
                    organization_id="org-acme",
                    title="Acme handbook",
                    content="Acme-only content",
                ),
                main.Document(
                    id="doc-globex-001",
                    organization_id="org-globex",
                    title="Globex handbook",
                    content="Globex-only content",
                ),
            ]
        )
        db.commit()

    yield

    with main.SessionLocal() as db:
        db.execute(delete(main.Document))
        db.execute(delete(main.OrganizationMembership))
        db.execute(delete(main.Organization))
        db.commit()


# ---------------------------------------------------------------------
# Authentication tests
# ---------------------------------------------------------------------

def test_anonymous_user_cannot_access_current_user(client):
    response = client.get("/auth/me")
    assert response.status_code == 401


def test_anonymous_user_cannot_access_protected(client):
    response = client.get("/protected")
    assert response.status_code == 401


def test_authenticated_employee_can_access_current_user(employee_client):
    response = employee_client.get("/auth/me")
    assert response.status_code == 200
    assert response.json()["authenticated"] is True
    assert response.json()["user"]["preferred_username"] == "employee1"


def test_authenticated_employee_can_access_protected(employee_client):
    response = employee_client.get("/protected")
    assert response.status_code == 200
    assert response.json()["user"]["preferred_username"] == "employee1"


# ---------------------------------------------------------------------
# Role-based access control tests
# ---------------------------------------------------------------------

def test_employee_cannot_access_admin(employee_client):
    response = employee_client.get("/admin")
    assert response.status_code == 403


def test_admin_can_access_admin(admin_client):
    response = admin_client.get("/admin")
    assert response.status_code == 200
    assert response.json()["user"] == "admin1"


def test_anonymous_user_cannot_access_admin(client):
    response = client.get("/admin")
    assert response.status_code == 401


# ---------------------------------------------------------------------
# Regression tests for existing endpoints
# ---------------------------------------------------------------------

def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


def test_message_endpoint(client):
    response = client.post(
        "/message",
        json={"message": "Hello arcline"},
    )
    assert response.status_code == 200
    assert response.json() == {
        "received": True,
        "message": "Hello arcline",
    }


def test_message_endpoint_rejects_empty_body(client):
    response = client.post("/message", json={})
    assert response.status_code == 422


def test_logout_clears_application_session(admin_client):
    response = admin_client.post("/auth/logout")
    assert response.status_code == 200

    response = admin_client.get("/admin")
    assert response.status_code == 401


# ---------------------------------------------------------------------
# Organization membership and tenant-isolation tests
# ---------------------------------------------------------------------

def test_member_can_access_document_in_own_organization(
    employee_client,
    tenant_data,
):
    response = employee_client.get(
        "/organizations/org-acme/documents/doc-acme-001"
    )
    assert response.status_code == 200
    assert response.json()["organization_id"] == "org-acme"
    assert response.json()["content"] == "Acme-only content"


def test_member_cannot_request_another_organization(
    employee_client,
    tenant_data,
):
    response = employee_client.get(
        "/organizations/org-globex/documents/doc-globex-001"
    )
    assert response.status_code == 403


def test_member_cannot_read_foreign_document_even_if_they_know_its_id(
    employee_client,
    tenant_data,
):
    # Membership succeeds for Acme, but this document belongs to Globex.
    response = employee_client.get(
        "/organizations/org-acme/documents/doc-globex-001"
    )
    assert response.status_code == 404
    assert response.json()["detail"] == "Document not found."


def test_anonymous_user_cannot_access_organization_document(
    client,
    tenant_data,
):
    response = client.get(
        "/organizations/org-acme/documents/doc-acme-001"
    )
    assert response.status_code == 401


def test_authenticated_nonmember_cannot_access_organization_document(
    admin_client,
    tenant_data,
):
    # An application admin does not automatically have tenant membership.
    response = admin_client.get(
        "/organizations/org-acme/documents/doc-acme-001"
    )
    assert response.status_code == 403
