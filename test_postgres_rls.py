"""PostgreSQL RLS integration tests for arcline.

Configure these environment variables locally (never commit them):
  ARCLINE_TEST_ADMIN_DATABASE_URL   - privileged PostgreSQL URL for fixtures
  ARCLINE_TEST_RUNTIME_DATABASE_URL - URL authenticated as restricted arcline_app

These tests intentionally do not import main.py or modify DATABASE_URL.
"""
from __future__ import annotations

import os
from uuid import uuid4

import pytest
from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError

load_dotenv()

ADMIN_URL = os.getenv("ARCLINE_TEST_ADMIN_DATABASE_URL")
RUNTIME_URL = os.getenv("ARCLINE_TEST_RUNTIME_DATABASE_URL")

pytestmark = pytest.mark.skipif(
    not ADMIN_URL or not RUNTIME_URL,
    reason=(
        "Set ARCLINE_TEST_ADMIN_DATABASE_URL and "
        "ARCLINE_TEST_RUNTIME_DATABASE_URL to run PostgreSQL RLS tests."
    ),
)


@pytest.fixture(scope="module")
def engines():
    """Create separate privileged-fixture and restricted-runtime connections."""
    # Bound connection, lock, and query waits so a test fails with a useful
    # PostgreSQL error instead of hanging indefinitely.
    connect_args = {
        "connect_timeout": 5,
        "options": "-c statement_timeout=15000 -c lock_timeout=5000",
        "application_name": "arcline_rls_pytest",
    }
    admin_engine = create_engine(
        ADMIN_URL, pool_pre_ping=True, connect_args=connect_args
    )
    runtime_engine = create_engine(
        RUNTIME_URL, pool_pre_ping=True, connect_args=connect_args
    )
    try:
        with admin_engine.connect() as conn:
            role_info = conn.execute(
                text(
                    """
                    SELECT rolsuper, rolbypassrls
                    FROM pg_roles
                    WHERE rolname = current_user
                    """
                )
            ).one()
            if not (role_info.rolsuper or role_info.rolbypassrls):
                pytest.fail(
                    "ARCLINE_TEST_ADMIN_DATABASE_URL must use a PostgreSQL "
                    "role with SUPERUSER or BYPASSRLS for reliable test fixtures."
                )

        with runtime_engine.connect() as conn:
            runtime_role = conn.execute(text("SELECT current_user")).scalar_one()
            if runtime_role != "arcline_app":
                pytest.fail(
                    "ARCLINE_TEST_RUNTIME_DATABASE_URL must connect as "
                    f"'arcline_app', not {runtime_role!r}."
                )
            role_info = conn.execute(
                text(
                    """
                    SELECT rolsuper, rolbypassrls
                    FROM pg_roles
                    WHERE rolname = current_user
                    """
                )
            ).one()
            if role_info.rolsuper or role_info.rolbypassrls:
                pytest.fail("arcline_app must not be SUPERUSER or BYPASSRLS.")

        yield admin_engine, runtime_engine
    finally:
        runtime_engine.dispose()
        admin_engine.dispose()


@pytest.fixture
def tenant_data(engines):
    """Create isolated tenant fixtures using the privileged connection."""
    admin_engine, _ = engines
    suffix = uuid4().hex
    org_a = f"rls-a-{suffix}"
    org_b = f"rls-b-{suffix}"
    user_a = f"rls-user-a-{suffix}"
    doc_a = f"rls-doc-a-{suffix}"
    doc_b = f"rls-doc-b-{suffix}"

    print("[RLS setup] Creating isolated tenant fixtures...", flush=True)
    with admin_engine.begin() as conn:
        conn.execute(
            text("INSERT INTO organizations (id, name) VALUES (:id, :name)"),
            [{"id": org_a, "name": "RLS Test A"}, {"id": org_b, "name": "RLS Test B"}],
        )
        conn.execute(
            text(
                """
                INSERT INTO organization_memberships (user_sub, organization_id, role)
                VALUES (:user_sub, :organization_id, 'member')
                """
            ),
            {"user_sub": user_a, "organization_id": org_a},
        )
        conn.execute(
            text(
                """
                INSERT INTO documents (id, organization_id, title, content)
                VALUES (:id, :organization_id, :title, :content)
                """
            ),
            [
                {
                    "id": doc_a,
                    "organization_id": org_a,
                    "title": "Own tenant document",
                    "content": "tenant A",
                },
                {
                    "id": doc_b,
                    "organization_id": org_b,
                    "title": "Foreign tenant document",
                    "content": "tenant B",
                },
            ],
        )

    data = {
        "org_a": org_a,
        "org_b": org_b,
        "user_a": user_a,
        "doc_a": doc_a,
        "doc_b": doc_b,
    }
    try:
        yield data
    finally:
        print("[RLS cleanup] Removing isolated tenant fixtures...", flush=True)
        with admin_engine.begin() as conn:
            conn.execute(
                text("DELETE FROM organizations WHERE id IN (:org_a, :org_b)"),
                {"org_a": org_a, "org_b": org_b},
            )


def _set_context(conn, user_sub: str, organization_id: str) -> None:
    """Set RLS variables transaction-locally on the same connection as the query."""
    conn.execute(
        text("SELECT set_config('app.current_user_sub', :value, true)"),
        {"value": user_sub},
    )
    conn.execute(
        text("SELECT set_config('app.current_organization_id', :value, true)"),
        {"value": organization_id},
    )


def test_member_can_read_own_organization_document(engines, tenant_data):
    _, runtime_engine = engines
    print("[RLS test] Checking own-organization document visibility...", flush=True)
    with runtime_engine.begin() as conn:
        _set_context(conn, tenant_data["user_a"], tenant_data["org_a"])
        rows = conn.execute(
            text("SELECT id FROM documents WHERE id = :id"),
            {"id": tenant_data["doc_a"]},
        ).all()
        assert [row.id for row in rows] == [tenant_data["doc_a"]]


def test_member_cannot_read_foreign_organization_document(engines, tenant_data):
    _, runtime_engine = engines
    with runtime_engine.begin() as conn:
        _set_context(conn, tenant_data["user_a"], tenant_data["org_a"])
        rows = conn.execute(
            text("SELECT id FROM documents WHERE id = :id"),
            {"id": tenant_data["doc_b"]},
        ).all()
        assert rows == []


def test_missing_security_context_exposes_no_documents(engines, tenant_data):
    _, runtime_engine = engines
    with runtime_engine.begin() as conn:
        rows = conn.execute(
            text("SELECT id FROM documents WHERE id IN (:doc_a, :doc_b)"),
            {"doc_a": tenant_data["doc_a"], "doc_b": tenant_data["doc_b"]},
        ).all()
        assert rows == []


def test_non_member_cannot_read_documents_even_with_tenant_context(engines, tenant_data):
    _, runtime_engine = engines
    with runtime_engine.begin() as conn:
        _set_context(conn, "not-a-member", tenant_data["org_a"])
        rows = conn.execute(
            text("SELECT id FROM documents WHERE id = :id"),
            {"id": tenant_data["doc_a"]},
        ).all()
        assert rows == []


def test_runtime_role_cannot_insert_documents(engines, tenant_data):
    _, runtime_engine = engines
    with runtime_engine.connect() as conn:
        transaction = conn.begin()
        try:
            _set_context(conn, tenant_data["user_a"], tenant_data["org_a"])
            with pytest.raises(SQLAlchemyError):
                conn.execute(
                    text(
                        """
                        INSERT INTO documents (id, organization_id, title, content)
                        VALUES (:id, :organization_id, 'must be denied', 'test')
                        """
                    ),
                    {
                        "id": f"rls-write-{uuid4().hex}",
                        "organization_id": tenant_data["org_a"],
                    },
                )
        finally:
            transaction.rollback()
