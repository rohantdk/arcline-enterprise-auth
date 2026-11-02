# arcline Enterprise SSO & RBAC Bridge

A FastAPI service that puts enterprise login, role checks, tenant isolation,
SCIM provisioning and audit logging in front of the arcline AI stack
(arcline ace / arcline actor).

Local development only — Keycloak `start-dev`, plain HTTP, dev secrets.

## Request flow

```
Browser ──/auth/login──► Keycloak (OIDC, code + PKCE) ──► /auth/callback
                                                         │ signed session cookie
                                                         ▼  {sub, email, roles}
Browser ──/admin──────────► require_role("admin")       (Keycloak realm role)
Browser ──/organizations/{org}/documents/{id}
          ├─ 1. app check: membership row for (sub, org)?      → 403 if not
          ├─ 2. app filter: WHERE id = :id AND organization_id = :org
          └─ 3. PostgreSQL RLS: policies read app.current_user_sub /
                app.current_organization_id set per transaction
IdP ──Bearer token──► /scim/v2/Users  → verify user exists in Keycloak
                                      → scim_provision_membership() (role = member)
Every allow/deny ──► record_audit_event() → audit_events (insert-only)
```

## Files

| File | Purpose |
|---|---|
| `main.py` | The whole app: config, models, OIDC, RBAC, tenant docs, SCIM, audit |
| `schema.sql` | **Migration 1** — tables, roles, RLS policies |
| `audit_stage3_migration_least_privilege.sql` | **Migration 2** — `audit_events` + insert-only writer function |
| `scim_provisioning_migration.sql` | **Migration 3** — SCIM functions, `arcline_scim_writer`, `scim_configuration` |
| `test_auth.py` | Login/session/RBAC/tenant tests (SQLite) |
| `test_scim_mvp.py` | SCIM tests, Keycloak mocked (SQLite) |
| `test_audit_stage3.py` | Audit filtering / failure-handling tests (SQLite) |
| `test_postgres_rls.py` | Real two-tenant RLS tests against PostgreSQL |
| `test_audit_postgres_*.py` | Audit rows really land in PostgreSQL |
| `check_db_connections.py` | Quick "can I connect with each DB URL" check |
| `_archive/` | Earlier versions kept for reference; not used |

Apply migrations in order 1 → 2 → 3, as `arcline_admin`, never as `arcline_app`.

## PostgreSQL roles

| Role | Login | Purpose |
|---|---|---|
| `arcline_admin` | yes | Migrations / test fixtures. Bypasses RLS — never the app's role |
| `arcline_app` | yes | Runtime app. No BYPASSRLS; SELECT only + EXECUTE on functions |
| `arcline_audit_writer` | no | Owns `record_audit_event()`; INSERT-only on `audit_events` |
| `arcline_scim_writer` | no | Owns `scim_*()` functions; SELECT/INSERT on memberships |

## Running

```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn main:app --reload            # needs Keycloak + Postgres containers running
python -m pytest -q test_auth.py test_scim_mvp.py test_audit_stage3.py   # SQLite only
python -m pytest -q                  # all, needs Docker Desktop + arcline-postgres
```

`.env` keys: `KEYCLOAK_ISSUER_URL`, `KEYCLOAK_CLIENT_ID`, `KEYCLOAK_CLIENT_SECRET`,
`SESSION_SECRET`, `DATABASE_URL`, `SCIM_BEARER_TOKEN`, `SCIM_ORGANIZATION_ID`,
`KEYCLOAK_SCIM_CLIENT_ID`, `KEYCLOAK_SCIM_CLIENT_SECRET`,
`ARCLINE_TEST_ADMIN_DATABASE_URL`, `ARCLINE_TEST_RUNTIME_DATABASE_URL`.

## Status against the original brief

| Brief item | Status |
|---|---|
| OIDC SSO | Done with Keycloak. Okta / Entra ID not connected yet (Keycloak can broker to them) |
| SAML | Not started |
| RBAC | Done — global Keycloak realm roles (`admin`) |
| Row-level data scoping | Done (app checks + RLS). Two-tenant PostgreSQL tests pass as `arcline_app` (2026-10-28) |
| SCIM provisioning | MVP: create-membership only. No PATCH/DELETE → no deprovisioning |
| Audit logging | Done; verified `arcline_app` has no direct privileges on `audit_events` (insert only via function) |
| Connect to AI stack | Not started — ace/actor don't call this service yet |
