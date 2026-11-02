"""Focused Stage 3 audit logging tests for arcline.

These tests use an isolated SQLite database and do not touch PostgreSQL or .env
credentials. Run with: python -m pytest -q test_audit_stage3.py
"""
from __future__ import annotations

import logging

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import main


@pytest.fixture
def audit_db(monkeypatch):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    main.Base.metadata.create_all(bind=engine)
    test_session_local = sessionmaker(
        bind=engine, autoflush=False, expire_on_commit=False
    )
    monkeypatch.setattr(main, "SessionLocal", test_session_local)
    try:
        yield test_session_local
    finally:
        engine.dispose()


def test_audit_event_is_persisted_and_unapproved_metadata_is_dropped(audit_db):
    main._record_audit_event(
        "document_access_denied",
        "denied",
        actor_sub="test-user-sub",
        organization_id="test-org",
        metadata={
            "reason": "membership_required",
            "resource": "document",
            "secret": "must-not-be-stored",
            "document_content": "private document body",
        },
    )

    with audit_db() as db:
        event = db.execute(select(main.AuditEvent)).scalar_one()
        assert event.actor_sub == "test-user-sub"
        assert event.event_type == "document_access_denied"
        assert event.outcome == "denied"
        assert event.organization_id == "test-org"
        assert event.metadata_json == {
            "reason": "membership_required",
            "resource": "document",
        }
        assert "must-not-be-stored" not in str(event.metadata_json)
        assert "private document body" not in str(event.metadata_json)


def test_unauthenticated_protected_request_is_audited(audit_db):
    client = TestClient(main.app)

    response = client.get("/protected")

    assert response.status_code == 401
    with audit_db() as db:
        events = db.execute(select(main.AuditEvent)).scalars().all()
    assert any(
        event.event_type == "authentication_denied"
        and event.outcome == "denied"
        and event.metadata_json.get("reason") == "missing_session"
        for event in events
    )


def test_audit_storage_failure_does_not_expose_error_to_client(monkeypatch, caplog):
    def broken_session_factory():
        raise RuntimeError("private database connection details")

    monkeypatch.setattr(main, "SessionLocal", broken_session_factory)
    with caplog.at_level(logging.WARNING, logger="arcline.audit"):
        # Audit failure must not turn an authorization denial into a 500 or
        # put connection details into application logs.
        main._record_audit_event(
            "authentication_denied", "denied",
            metadata={"reason": "missing_session", "status_code": 401},
        )

    assert "private database connection details" not in caplog.text
    assert "Audit event persistence failed" in caplog.text
