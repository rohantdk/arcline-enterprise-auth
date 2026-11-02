import os

# Configure non-secret test settings before importing the application module.
os.environ.setdefault("SESSION_SECRET", "test-only-session-secret")
os.environ.setdefault("SCIM_BEARER_TOKEN", "test-only-scim-token")
os.environ.setdefault("KEYCLOAK_ISSUER_URL", "http://localhost:8080/realms/arcline")
os.environ.setdefault("KEYCLOAK_CLIENT_ID", "arcline-auth-api")
os.environ.setdefault("KEYCLOAK_CLIENT_SECRET", "test-only-client-secret")
os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

import main
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, select

SCIM_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
SCIM_LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"


@pytest.fixture
def scim_client(monkeypatch):
    monkeypatch.setattr(main, "SCIM_BEARER_TOKEN", "test-only-scim-token")
    monkeypatch.setattr(main, "SCIM_ORGANIZATION_ID", "org-scim-test")
    monkeypatch.setattr(
        main,
        "verify_keycloak_subject",
        lambda subject: subject in {"kc-user-1", "kc-user-2", "kc-user-3"},
    )
    with main.SessionLocal() as db:
        db.execute(
            delete(main.OrganizationMembership).where(
                main.OrganizationMembership.organization_id == "org-scim-test"
            )
        )
        organization = db.get(main.Organization, "org-scim-test")
        if organization is None:
            db.add(main.Organization(id="org-scim-test", name="SCIM Test Org"))
        db.commit()

    with TestClient(main.app) as client:
        yield client

    with main.SessionLocal() as db:
        db.execute(
            delete(main.OrganizationMembership).where(
                main.OrganizationMembership.organization_id == "org-scim-test"
            )
        )
        organization = db.get(main.Organization, "org-scim-test")
        if organization is not None:
            db.delete(organization)
        db.commit()


def auth_headers():
    return {"Authorization": "Bearer test-only-scim-token"}


def user_payload(subject="kc-user-1", **extra):
    payload = {
        "schemas": [SCIM_USER_SCHEMA],
        "userName": subject,
        "externalId": subject,
    }
    payload.update(extra)
    return payload


def test_service_provider_config_requires_bearer_token(scim_client):
    response = scim_client.get("/scim/v2/ServiceProviderConfig")
    assert response.status_code == 401


def test_service_provider_config_accepts_bearer_token(scim_client):
    response = scim_client.get(
        "/scim/v2/ServiceProviderConfig", headers=auth_headers()
    )
    assert response.status_code == 200
    body = response.json()
    assert body["schemas"] == [
        "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
    ]


def test_provision_existing_keycloak_user_assigns_member_role(scim_client):
    response = scim_client.post(
        "/scim/v2/Users",
        headers=auth_headers(),
        json=user_payload(role="admin", roles=["admin"]),
    )
    assert response.status_code == 201
    body = response.json()
    assert body["id"] == "kc-user-1"
    assert body["userName"] == "kc-user-1"
    assert body["externalId"] == "kc-user-1"

    with main.SessionLocal() as db:
        membership = db.execute(
            select(main.OrganizationMembership).where(
                main.OrganizationMembership.user_sub == "kc-user-1",
                main.OrganizationMembership.organization_id == "org-scim-test",
            )
        ).scalar_one()
        assert membership.role == "member"


def test_duplicate_provisioning_returns_conflict(scim_client):
    first = scim_client.post(
        "/scim/v2/Users", headers=auth_headers(), json=user_payload()
    )
    second = scim_client.post(
        "/scim/v2/Users", headers=auth_headers(), json=user_payload()
    )
    assert first.status_code == 201
    assert second.status_code == 409
    assert second.json()["schemas"] == [
        "urn:ietf:params:scim:api:messages:2.0:Error"
    ]


def test_unknown_keycloak_user_is_not_provisioned(scim_client):
    response = scim_client.post(
        "/scim/v2/Users",
        headers=auth_headers(),
        json=user_payload("unknown-user"),
    )
    assert response.status_code == 404
    with main.SessionLocal() as db:
        membership = db.execute(
            select(main.OrganizationMembership).where(
                main.OrganizationMembership.user_sub == "unknown-user",
                main.OrganizationMembership.organization_id == "org-scim-test",
            )
        ).scalar_one_or_none()
        assert membership is None


def test_user_name_must_equal_external_id(scim_client):
    response = scim_client.post(
        "/scim/v2/Users",
        headers=auth_headers(),
        json={
            "schemas": [SCIM_USER_SCHEMA],
            "userName": "kc-user-1",
            "externalId": "different-id",
        },
    )
    assert response.status_code == 400
    assert response.json()["scimType"] == "invalidValue"


def test_missing_user_attributes_are_rejected(scim_client):
    response = scim_client.post(
        "/scim/v2/Users",
        headers=auth_headers(),
        json={"schemas": [SCIM_USER_SCHEMA]},
    )
    assert response.status_code == 400


def test_list_and_get_users_are_tenant_scoped(scim_client):
    for subject in ("kc-user-1", "kc-user-2"):
        response = scim_client.post(
            "/scim/v2/Users",
            headers=auth_headers(),
            json=user_payload(subject),
        )
        assert response.status_code == 201

    listed = scim_client.get("/scim/v2/Users?startIndex=1&count=1", headers=auth_headers())
    assert listed.status_code == 200
    body = listed.json()
    assert body["schemas"] == [SCIM_LIST_SCHEMA]
    assert body["totalResults"] == 2
    assert body["itemsPerPage"] == 1
    assert len(body["Resources"]) == 1

    retrieved = scim_client.get(
        "/scim/v2/Users/kc-user-2", headers=auth_headers()
    )
    assert retrieved.status_code == 200
    assert retrieved.json()["id"] == "kc-user-2"

    missing = scim_client.get(
        "/scim/v2/Users/not-provisioned", headers=auth_headers()
    )
    assert missing.status_code == 404


def test_invalid_bearer_token_is_rejected(scim_client):
    response = scim_client.get(
        "/scim/v2/Users", headers={"Authorization": "Bearer wrong-token"}
    )
    assert response.status_code == 401


def test_verifier_unavailable_returns_503_without_provisioning(
    scim_client, monkeypatch
):
    def unavailable(_subject):
        raise main.KeycloakVerificationUnavailable("private detail")

    monkeypatch.setattr(main, "verify_keycloak_subject", unavailable)
    response = scim_client.post(
        "/scim/v2/Users", headers=auth_headers(), json=user_payload()
    )
    assert response.status_code == 503
    assert "private detail" not in response.text
    with main.SessionLocal() as db:
        membership = db.execute(
            select(main.OrganizationMembership).where(
                main.OrganizationMembership.user_sub == "kc-user-1",
                main.OrganizationMembership.organization_id == "org-scim-test",
            )
        ).scalar_one_or_none()
        assert membership is None
