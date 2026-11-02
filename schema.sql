-- PostgreSQL schema for arcline tenant isolation.
-- Apply with a PostgreSQL migration/admin role. The runtime role `arcline_app`
-- must not be a superuser, table owner, or have BYPASSRLS. Create it first if
-- needed, and set its password interactively with psql's \password arcline_app.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'arcline_app') THEN
        CREATE ROLE arcline_app LOGIN;
    END IF;
END
$$;

CREATE TABLE IF NOT EXISTS organizations (
    id VARCHAR(100) PRIMARY KEY,
    name VARCHAR(200) NOT NULL
);

CREATE TABLE IF NOT EXISTS organization_memberships (
    user_sub VARCHAR(255) NOT NULL,
    organization_id VARCHAR(100) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    role VARCHAR(50) NOT NULL DEFAULT 'member',
    PRIMARY KEY (user_sub, organization_id)
);

CREATE TABLE IF NOT EXISTS documents (
    id VARCHAR(100) PRIMARY KEY,
    organization_id VARCHAR(100) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    title VARCHAR(300) NOT NULL,
    content TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_documents_organization_id ON documents(organization_id);

ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizations FORCE ROW LEVEL SECURITY;
ALTER TABLE organization_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE organization_memberships FORCE ROW LEVEL SECURITY;
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE documents FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS organization_member_select ON organization_memberships;
CREATE POLICY organization_member_select ON organization_memberships
    FOR SELECT
    USING (user_sub = NULLIF(current_setting('app.current_user_sub', true), ''));

DROP POLICY IF EXISTS organization_visible_to_member ON organizations;
CREATE POLICY organization_visible_to_member ON organizations
    FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM organization_memberships m
            WHERE m.organization_id = organizations.id
              AND m.user_sub = NULLIF(current_setting('app.current_user_sub', true), '')
        )
    );

DROP POLICY IF EXISTS document_visible_to_member ON documents;
CREATE POLICY document_visible_to_member ON documents
    FOR SELECT
    USING (
        organization_id = NULLIF(current_setting('app.current_organization_id', true), '')
        AND EXISTS (
            SELECT 1 FROM organization_memberships m
            WHERE m.organization_id = documents.organization_id
              AND m.user_sub = NULLIF(current_setting('app.current_user_sub', true), '')
        )
    );

-- Provisioning/write operations should use a separate trusted path or receive
-- explicit INSERT/UPDATE/DELETE policies after their authorization rules are designed.

GRANT USAGE ON SCHEMA public TO arcline_app;
GRANT SELECT ON organizations, organization_memberships, documents TO arcline_app;
