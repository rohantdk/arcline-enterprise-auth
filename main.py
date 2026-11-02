from __future__ import annotations
import secrets
import logging
import os
import json
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Generator

from authlib.integrations.starlette_client import OAuth
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String, Text, create_engine, select, text
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.middleware.sessions import SessionMiddleware

# --------------------------------------------------
# 1. Configuration
# --------------------------------------------------
load_dotenv()
app = FastAPI(title="arcline Enterprise Auth Bridge")
logger = logging.getLogger("arcline.audit")

SESSION_SECRET = os.getenv("SESSION_SECRET")
KEYCLOAK_ISSUER_URL = os.getenv("KEYCLOAK_ISSUER_URL")
KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID")
KEYCLOAK_CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET")
DATABASE_URL = os.getenv("DATABASE_URL")
SCIM_BEARER_TOKEN = os.getenv("SCIM_BEARER_TOKEN")
SCIM_ORGANIZATION_ID = os.getenv("SCIM_ORGANIZATION_ID")
KEYCLOAK_SCIM_CLIENT_ID = os.getenv("KEYCLOAK_SCIM_CLIENT_ID")
KEYCLOAK_SCIM_CLIENT_SECRET = os.getenv("KEYCLOAK_SCIM_CLIENT_SECRET")

required_settings = {
    "SESSION_SECRET": SESSION_SECRET,
    "SCIM_BEARER_TOKEN": SCIM_BEARER_TOKEN,
    "KEYCLOAK_ISSUER_URL": KEYCLOAK_ISSUER_URL,
    "KEYCLOAK_CLIENT_ID": KEYCLOAK_CLIENT_ID,
    "KEYCLOAK_CLIENT_SECRET": KEYCLOAK_CLIENT_SECRET,
    "DATABASE_URL": DATABASE_URL,
}
missing_settings = [
    name for name, value in required_settings.items()
    if not value or not value.strip()
]
if missing_settings:
    raise RuntimeError(
        f"Missing required environment settings: {', '.join(missing_settings)}"
    )

app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    same_site="lax",
    # Local HTTP development only; production must use HTTPS.
    https_only=False,
)

# --------------------------------------------------
# 2. Database models and connection
# --------------------------------------------------


class Base(DeclarativeBase):
    pass


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)


class OrganizationMembership(Base):
    __tablename__ = "organization_memberships"

    user_sub: Mapped[str] = mapped_column(String(255), primary_key=True)
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), primary_key=True
    )
    role: Mapped[str] = mapped_column(
        String(50), nullable=False, default="member")


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, autoincrement=True)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    actor_sub: Mapped[str | None] = mapped_column(String(255), nullable=True)
    event_type: Mapped[str] = mapped_column(String(80), nullable=False)
    outcome: Mapped[str] = mapped_column(String(20), nullable=False)
    organization_id: Mapped[str | None] = mapped_column(
        String(100), nullable=True)
    metadata_json: Mapped[dict] = mapped_column(
        "metadata", JSON, nullable=False, default=dict)


class Document(Base):
    __tablename__ = "documents"

    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)


engine_options: dict = {"pool_pre_ping": True}
if DATABASE_URL.startswith("sqlite"):
    engine_options["connect_args"] = {"check_same_thread": False}
    if DATABASE_URL.endswith(":memory:") or DATABASE_URL.endswith("///"):
        engine_options["poolclass"] = StaticPool
engine = create_engine(DATABASE_URL, **engine_options)
SessionLocal = sessionmaker(
    bind=engine, autoflush=False, expire_on_commit=False)

# Create tables automatically only for the isolated SQLite test database.
# PostgreSQL schema and RLS policies must be installed by the database migration
# role via schema.sql; the runtime application role should not own/create tables.
if engine.dialect.name == "sqlite":
    Base.metadata.create_all(bind=engine)


# Only explicitly approved, non-sensitive metadata may enter the audit log.
_AUDIT_EVENT_TYPES = {
    "login_succeeded",
    "login_failed",
    "logout_succeeded",
    "authentication_denied",
    "role_authorization_denied",
    "tenant_access_denied",
    "document_access_succeeded",
    "document_access_denied",
    "scim_user_provisioned",
    "scim_user_provisioning_denied",
}
_AUDIT_OUTCOMES = {"success", "failure", "denied"}
_AUDIT_METADATA_KEYS = {"reason", "required_role", "resource", "status_code"}


def _record_audit_event(
    event_type: str,
    outcome: str,
    *,
    actor_sub: str | None = None,
    organization_id: str | None = None,
    metadata: dict | None = None,
    db_session: Session | None = None,
) -> None:
    """Persist a minimal audit event without exposing persistence errors to clients."""
    if event_type not in _AUDIT_EVENT_TYPES or outcome not in _AUDIT_OUTCOMES:
        logger.warning("Rejected invalid audit event classification")
        return

    safe_metadata: dict[str, str | int] = {}
    for key, value in (metadata or {}).items():
        if key not in _AUDIT_METADATA_KEYS or not isinstance(value, (str, int)):
            continue
        safe_metadata[key] = str(value)[:120] if isinstance(
            value, str) else value

    db = db_session
    owns_session = db is None
    try:
        if db is None:
            db = SessionLocal()
        if db.get_bind().dialect.name == "postgresql":
            import json

            db.execute(
                text(
                    "SELECT public.record_audit_event("
                    ":actor_sub, :event_type, :outcome, :organization_id, "
                    "CAST(:metadata AS jsonb))"
                ),
                {
                    "actor_sub": actor_sub,
                    "event_type": event_type,
                    "outcome": outcome,
                    "organization_id": organization_id,
                    "metadata": json.dumps(safe_metadata),
                },
            )
        else:
            db.add(
                AuditEvent(
                    actor_sub=actor_sub,
                    event_type=event_type,
                    outcome=outcome,
                    organization_id=organization_id,
                    metadata_json=safe_metadata,
                )
            )
        db.commit()
    except Exception:
        if db is not None:
            db.rollback()
        # Avoid exception details: they can contain SQL or deployment information.
        logger.warning(
            "Audit event persistence failed (event_type=%s)", event_type)
    finally:
        if owns_session and db is not None:
            db.close()


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def require_scim_token(request: Request) -> None:
    authorization = request.headers.get("Authorization", "")
    scheme, separator, token = authorization.partition(" ")

    if (
        not separator
        or scheme.lower() != "bearer"
        or not token
        or not SCIM_BEARER_TOKEN
        or not secrets.compare_digest(token, SCIM_BEARER_TOKEN)
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing SCIM bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )


# --------------------------------------------------
# SCIM 2.0 — Service Provider Configuration
# --------------------------------------------------

@app.get("/scim/v2/ServiceProviderConfig")
def scim_service_provider_config(
    _: None = Depends(require_scim_token),
):
    return {
        "schemas": [
            "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
        ],
        "documentationUri": None,
        "patch": {"supported": False},
        "bulk": {
            "supported": False,
            "maxOperations": 0,
            "maxPayloadSize": 0,
        },
        "filter": {
            "supported": False,
            "maxResults": 0,
        },
        "changePassword": {"supported": False},
        "sort": {"supported": False},
        "etag": {"supported": False},
        "authenticationSchemes": [
            {
                "type": "oauthbearertoken",
                "name": "Bearer Token",
                "description": "Dedicated bearer token for SCIM provisioning.",
                "specUri": (
                    "https://www.rfc-editor.org/rfc/rfc6750"
                ),
                "primary": True,
            }
        ],
    }


# --------------------------------------------------
# SCIM 2.0 — User resources and provisioning
# --------------------------------------------------

SCIM_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
SCIM_LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
SCIM_ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"


class SCIMError(Exception):
    def __init__(self, status_code: int, detail: str, scim_type: str | None = None):
        self.status_code = status_code
        self.detail = detail
        self.scim_type = scim_type


@app.exception_handler(SCIMError)
async def scim_error_handler(request: Request, exc: SCIMError):
    body = {
        "schemas": [SCIM_ERROR_SCHEMA],
        "detail": exc.detail,
        "status": str(exc.status_code),
    }
    if exc.scim_type:
        body["scimType"] = exc.scim_type
    return JSONResponse(status_code=exc.status_code, content=body)


class KeycloakVerificationUnavailable(Exception):
    """Raised when Keycloak cannot reliably verify a subject."""


def _scim_organization_id() -> str:
    organization_id = (SCIM_ORGANIZATION_ID or "").strip()
    if not organization_id:
        raise SCIMError(
            503,
            "SCIM provisioning is not configured for an organization.",
        )
    return organization_id


def verify_keycloak_subject(subject: str) -> bool:
    """
    Verify an existing Keycloak user using a dedicated client-credentials client.
    This function deliberately does not create users in Keycloak.
    """
    client_id = (KEYCLOAK_SCIM_CLIENT_ID or "").strip()
    client_secret = (KEYCLOAK_SCIM_CLIENT_SECRET or "").strip()
    issuer = (KEYCLOAK_ISSUER_URL or "").rstrip("/")
    if not client_id or not client_secret or not issuer:
        raise KeycloakVerificationUnavailable(
            "The Keycloak SCIM verifier client is not configured."
        )

    parsed_issuer = urllib.parse.urlparse(issuer)
    path_parts = [part for part in parsed_issuer.path.split("/") if part]
    try:
        realms_index = path_parts.index("realms")
        realm = path_parts[realms_index + 1]
    except (ValueError, IndexError):
        raise KeycloakVerificationUnavailable(
            "The configured Keycloak issuer URL is invalid."
        ) from None

    origin = f"{parsed_issuer.scheme}://{parsed_issuer.netloc}"
    token_url = f"{issuer}/protocol/openid-connect/token"
    token_body = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
    }).encode("utf-8")
    token_request = urllib.request.Request(
        token_url,
        data=token_body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(token_request, timeout=5) as response:
            token_payload = json.loads(response.read().decode("utf-8"))
        access_token = token_payload.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise KeycloakVerificationUnavailable(
                "Keycloak did not return an access token."
            )
    except KeycloakVerificationUnavailable:
        raise
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError, ValueError):
        # Do not expose Keycloak response bodies or credentials to callers/logs.
        raise KeycloakVerificationUnavailable(
            "Keycloak user verification is temporarily unavailable."
        ) from None

    encoded_subject = urllib.parse.quote(subject, safe="")
    user_url = (
        f"{origin}/admin/realms/{urllib.parse.quote(realm, safe='')}"
        f"/users/{encoded_subject}"
    )
    user_request = urllib.request.Request(
        user_url,
        headers={"Authorization": f"Bearer {access_token}"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(user_request, timeout=5) as response:
            user_payload = json.loads(response.read().decode("utf-8"))
        return isinstance(user_payload, dict) and user_payload.get("id") == subject
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return False
        raise KeycloakVerificationUnavailable(
            "Keycloak could not verify the requested user."
        ) from None
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        raise KeycloakVerificationUnavailable(
            "Keycloak user verification is temporarily unavailable."
        ) from None


def _scim_user_resource(user_sub: str) -> dict:
    # This MVP intentionally has no separate profile mapping table.
    return {
        "schemas": [SCIM_USER_SCHEMA],
        "id": user_sub,
        "externalId": user_sub,
        "userName": user_sub,
        "active": True,
        "meta": {"resourceType": "User"},
    }


def _scim_membership_list(
    db: Session, organization_id: str, start_index: int, count: int
) -> tuple[list[dict], int]:
    if db.get_bind().dialect.name == "postgresql":
        # The SECURITY DEFINER function applies a narrowly scoped RLS context.
        rows = db.execute(
            text(
                "SELECT user_sub, role FROM public.scim_list_users("
                ":organization_id, :offset, :count)"
            ),
            {
                "organization_id": organization_id,
                "offset": start_index - 1,
                "count": count,
            },
        ).mappings().all()
        total = db.execute(
            text("SELECT public.scim_count_users(:organization_id)"),
            {"organization_id": organization_id},
        ).scalar_one()
        return [dict(row) for row in rows], int(total)

    total = db.execute(
        select(OrganizationMembership).where(
            OrganizationMembership.organization_id == organization_id
        )
    ).scalars().all()
    page = sorted(total, key=lambda membership: membership.user_sub)[
        start_index - 1:start_index - 1 + count
    ]
    return [
        {"user_sub": membership.user_sub, "role": membership.role}
        for membership in page
    ], len(total)


def _scim_get_membership(
    db: Session, organization_id: str, user_sub: str
) -> dict | None:
    if db.get_bind().dialect.name == "postgresql":
        row = db.execute(
            text(
                "SELECT user_sub, role FROM public.scim_get_user("
                ":organization_id, :user_sub)"
            ),
            {"organization_id": organization_id, "user_sub": user_sub},
        ).mappings().first()
        return dict(row) if row else None

    membership = db.execute(
        select(OrganizationMembership).where(
            OrganizationMembership.organization_id == organization_id,
            OrganizationMembership.user_sub == user_sub,
        )
    ).scalar_one_or_none()
    if membership is None:
        return None
    return {"user_sub": membership.user_sub, "role": membership.role}


@app.get("/scim/v2/Users")
def scim_list_users(
    start_index: int = Query(1, alias="startIndex", ge=1),
    count: int = Query(100, ge=0, le=100),
    _: None = Depends(require_scim_token),
    db: Session = Depends(get_db),
):
    organization_id = _scim_organization_id()
    rows, total = _scim_membership_list(db, organization_id, start_index, count)
    resources = [_scim_user_resource(row["user_sub"]) for row in rows]
    return {
        "schemas": [SCIM_LIST_SCHEMA],
        "totalResults": total,
        "startIndex": start_index,
        "itemsPerPage": len(resources),
        "Resources": resources,
    }


@app.get("/scim/v2/Users/{user_id}")
def scim_get_user(
    user_id: str,
    _: None = Depends(require_scim_token),
    db: Session = Depends(get_db),
):
    organization_id = _scim_organization_id()
    membership = _scim_get_membership(db, organization_id, user_id)
    if membership is None:
        raise SCIMError(404, "User not found.")
    return _scim_user_resource(membership["user_sub"])


@app.post("/scim/v2/Users", status_code=201)
def scim_provision_user(
    payload: dict,
    _: None = Depends(require_scim_token),
    db: Session = Depends(get_db),
):
    organization_id = _scim_organization_id()
    schemas = payload.get("schemas")
    user_name = payload.get("userName")
    external_id = payload.get("externalId")

    if not isinstance(schemas, list) or SCIM_USER_SCHEMA not in schemas:
        raise SCIMError(400, "A valid SCIM User schema is required.", "invalidSyntax")
    if (
        not isinstance(user_name, str)
        or not user_name.strip()
        or len(user_name) > 255
        or not isinstance(external_id, str)
        or not external_id.strip()
        or len(external_id) > 255
    ):
        raise SCIMError(
            400,
            "Both userName and externalId must be non-empty strings of at most 255 characters.",
            "invalidValue",
        )
    user_name = user_name.strip()
    external_id = external_id.strip()
    if user_name != external_id:
        raise SCIMError(
            400,
            "For this MVP, userName must equal externalId and both must be the Keycloak subject.",
            "invalidValue",
        )

    try:
        exists_in_keycloak = verify_keycloak_subject(user_name)
    except KeycloakVerificationUnavailable:
        raise SCIMError(
            503, "Identity verification is temporarily unavailable."
        ) from None

    if not exists_in_keycloak:
        _record_audit_event(
            "scim_user_provisioning_denied",
            "denied",
            actor_sub=user_name,
            organization_id=organization_id,
            metadata={"reason": "keycloak_user_not_found", "status_code": 404},
            db_session=db,
        )
        raise SCIMError(404, "The specified Keycloak user does not exist.")

    if db.get_bind().dialect.name == "postgresql":
        try:
            inserted = db.execute(
                text(
                    "SELECT public.scim_provision_membership("
                    ":user_sub, :organization_id)"
                ),
                {"user_sub": user_name, "organization_id": organization_id},
            ).scalar_one()
            db.commit()
        except Exception:
            db.rollback()
            logger.warning("SCIM membership provisioning failed")
            raise SCIMError(
                500, "The organization membership could not be provisioned."
            ) from None
        if not inserted:
            _record_audit_event(
                "scim_user_provisioning_denied",
                "denied",
                actor_sub=user_name,
                organization_id=organization_id,
                metadata={"reason": "duplicate_membership", "status_code": 409},
                db_session=db,
            )
            raise SCIMError(409, "The user is already provisioned.")
    else:
        existing = db.execute(
            select(OrganizationMembership).where(
                OrganizationMembership.user_sub == user_name,
                OrganizationMembership.organization_id == organization_id,
            )
        ).scalar_one_or_none()
        if existing is not None:
            _record_audit_event(
                "scim_user_provisioning_denied",
                "denied",
                actor_sub=user_name,
                organization_id=organization_id,
                metadata={"reason": "duplicate_membership", "status_code": 409},
                db_session=db,
            )
            raise SCIMError(409, "The user is already provisioned.")

        try:
            # Role is server-controlled; SCIM input cannot set admin.
            db.add(
                OrganizationMembership(
                    user_sub=user_name,
                    organization_id=organization_id,
                    role="member",
                )
            )
            db.commit()
        except Exception:
            db.rollback()
            logger.warning("SCIM membership provisioning failed")
            raise SCIMError(
                500, "The organization membership could not be provisioned."
            ) from None

    _record_audit_event(
        "scim_user_provisioned",
        "success",
        actor_sub=user_name,
        organization_id=organization_id,
        metadata={"resource": "user", "status_code": 201},
        db_session=db,
    )
    return _scim_user_resource(user_name)


def set_postgres_security_context(
    db: Session, user_sub: str, organization_id: str
) -> None:
    """Set transaction-local identity/tenant values consumed by PostgreSQL RLS."""
    if db.get_bind().dialect.name == "postgresql":
        db.execute(
            text("SELECT set_config('app.current_user_sub', :value, true)"),
            {"value": user_sub},
        )
        db.execute(
            text("SELECT set_config('app.current_organization_id', :value, true)"),
            {"value": organization_id},
        )


# --------------------------------------------------
# 3. Keycloak OIDC configuration
# --------------------------------------------------
oauth = OAuth()
oauth.register(
    name="keycloak",
    client_id=KEYCLOAK_CLIENT_ID,
    client_secret=KEYCLOAK_CLIENT_SECRET,
    server_metadata_url=(
        f"{KEYCLOAK_ISSUER_URL.rstrip('/')}/.well-known/openid-configuration"
    ),
    client_kwargs={
        "scope": "openid profile email",
        "code_challenge_method": "S256",
    },
)

# --------------------------------------------------
# 4. Basic endpoints
# --------------------------------------------------


@app.get("/")
def home():
    return {
        "company": "arcline",
        "application": "arcline ace",
        "agent": "arcline actor",
        "project": "Enterprise SSO & RBAC Bridge",
        "status": "running",
    }


@app.get("/health")
def health_check():
    return {"status": "healthy"}


class MessageRequest(BaseModel):
    message: str


@app.post("/message")
def receive_message(request: MessageRequest):
    return {"received": True, "message": request.message}

# --------------------------------------------------
# 5. Login and OIDC callback
# --------------------------------------------------


@app.get("/auth/login")
async def auth_login(request: Request):
    keycloak = oauth.create_client("keycloak")
    redirect_uri = request.url_for("auth_callback")
    return await keycloak.authorize_redirect(request, redirect_uri)


@app.get("/auth/callback", name="auth_callback")
async def auth_callback(request: Request, db: Session = Depends(get_db)):
    keycloak = oauth.create_client("keycloak")
    try:
        token = await keycloak.authorize_access_token(request)
        user = token.get("userinfo")
        if not user or not user.get("sub"):
            _record_audit_event(
                "login_failed",
                "failure",
                metadata={"reason": "identity_verification"},
                db_session=db,
            )
            raise HTTPException(
                status_code=401, detail="Identity verification failed"
            )
    except HTTPException:
        raise
    except Exception:
        _record_audit_event(
            "login_failed",
            "failure",
            metadata={"reason": "identity_provider_error"},
            db_session=db,
        )
        raise HTTPException(
            status_code=401, detail="Sign-in could not be completed"
        ) from None

    roles = user.get("realm_access", {}).get("roles", [])
    # Tenant membership is read from the database, never accepted from browser
    # parameters or inferred from global application roles.
    request.session["user"] = {
        "sub": user["sub"],
        "email": user.get("email"),
        "preferred_username": user.get("preferred_username"),
        "roles": roles,
    }
    _record_audit_event(
        "login_succeeded", "success", actor_sub=user["sub"], db_session=db
    )
    return {"message": "Login successful", "user": request.session["user"]}

# --------------------------------------------------
# 6. Authentication and role authorization
# --------------------------------------------------


def get_current_user(request: Request, db: Session = Depends(get_db)) -> dict:
    user = request.session.get("user")
    if not user:
        _record_audit_event(
            "authentication_denied",
            "denied",
            metadata={"reason": "missing_session", "status_code": 401},
            db_session=db,
        )
        raise HTTPException(
            status_code=401, detail="Not authenticated. Please sign in."
        )
    return user


def require_role(required_role: str):
    def role_checker(
        user: dict = Depends(get_current_user),
        db: Session = Depends(get_db),
    ) -> dict:
        if required_role not in user.get("roles", []):
            _record_audit_event(
                "role_authorization_denied",
                "denied",
                actor_sub=user.get("sub"),
                metadata={"required_role": required_role, "status_code": 403},
                db_session=db,
            )
            raise HTTPException(
                status_code=403, detail=f"Forbidden. Required role: {required_role}."
            )
        return user
    return role_checker


def require_organization_member(organization_id: str):
    """Authorize using OIDC subject + persisted membership, not URL input alone."""
    def membership_checker(
        user: dict = Depends(get_current_user),
        db: Session = Depends(get_db),
    ) -> dict:
        subject = user.get("sub")
        if not subject:
            raise HTTPException(
                status_code=401, detail="Verified user identity required.")
        set_postgres_security_context(db, subject, organization_id)
        membership = db.execute(
            select(OrganizationMembership).where(
                OrganizationMembership.user_sub == subject,
                OrganizationMembership.organization_id == organization_id,
            )
        ).scalar_one_or_none()
        if membership is None:
            _record_audit_event(
                "tenant_access_denied",
                "denied",
                actor_sub=subject,
                organization_id=organization_id,
                metadata={"reason": "membership_required", "status_code": 403},
                db_session=db,
            )
            raise HTTPException(
                status_code=403, detail="Forbidden. Organization membership required."
            )
        return user
    return membership_checker

# --------------------------------------------------
# 7. Current user and protected endpoints
# --------------------------------------------------


@app.get("/auth/me")
def auth_me(user: dict = Depends(get_current_user)):
    return {"authenticated": True, "user": user}


@app.get("/protected")
def protected_route(user: dict = Depends(get_current_user)):
    return {"message": "Welcome to the protected arcline resource!", "user": user}

# --------------------------------------------------
# 8. Tenant-scoped document access
# --------------------------------------------------


@app.get("/organizations/{organization_id}/documents/{document_id}")
def get_organization_document(
    organization_id: str,
    document_id: str,
    user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    subject = user.get("sub")
    if not subject:
        raise HTTPException(
            status_code=401, detail="Verified user identity required.")

    # Establish the PostgreSQL RLS context before any tenant data query.
    set_postgres_security_context(db, subject, organization_id)
    membership = db.execute(
        select(OrganizationMembership).where(
            OrganizationMembership.user_sub == subject,
            OrganizationMembership.organization_id == organization_id,
        )
    ).scalar_one_or_none()
    if membership is None:
        _record_audit_event(
            "tenant_access_denied",
            "denied",
            actor_sub=subject,
            organization_id=organization_id,
            metadata={"reason": "membership_required", "status_code": 403},
            db_session=db,
        )
        raise HTTPException(
            status_code=403, detail="Forbidden. Organization membership required."
        )

    # Filter by BOTH IDs. Even if a caller knows a foreign document ID, it is
    # never returned unless it belongs to the authorized organization.
    document = db.execute(
        select(Document).where(
            Document.id == document_id,
            Document.organization_id == organization_id,
        )
    ).scalar_one_or_none()
    if document is None:
        _record_audit_event(
            "document_access_denied",
            "denied",
            actor_sub=subject,
            organization_id=organization_id,
            metadata={"reason": "resource_not_found",
                      "resource": "document", "status_code": 404},
            db_session=db,
        )
        raise HTTPException(status_code=404, detail="Document not found.")

    _record_audit_event(
        "document_access_succeeded",
        "success",
        actor_sub=subject,
        organization_id=organization_id,
        metadata={"resource": "document", "status_code": 200},
        db_session=db,
    )
    return {
        "id": document.id,
        "organization_id": document.organization_id,
        "title": document.title,
        "content": document.content,
    }

# --------------------------------------------------
# 9. Logout and admin-only endpoint
# --------------------------------------------------


@app.post("/auth/logout")
async def auth_logout(request: Request, db: Session = Depends(get_db)):
    user = request.session.get("user") or {}
    _record_audit_event(
        "logout_succeeded",
        "success",
        actor_sub=user.get("sub"),
        metadata={"reason": "user_initiated"},
        db_session=db,
    )
    request.session.clear()
    return {"message": "Logged out successfully"}


@app.get("/admin")
def admin_dashboard(user: dict = Depends(require_role("admin"))):
    return {
        "message": "Welcome to the arcline admin dashboard!",
        "user": user.get("preferred_username"),
        "roles": user.get("roles", []),
    }
