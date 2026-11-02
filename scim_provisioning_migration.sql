-- SCIM MVP provisioning migration for arcline.
-- Apply only with trusted migration role arcline_admin, never arcline_app.
-- Restricts all SCIM functions to the database-controlled arcline-default tenant.
-- Confirm a current backup exists before applying.

BEGIN;

ALTER TABLE public.audit_events
    DROP CONSTRAINT IF EXISTS audit_events_event_type_check;
ALTER TABLE public.audit_events
    ADD CONSTRAINT audit_events_event_type_check CHECK (event_type IN (
        'login_succeeded', 'login_failed', 'logout_succeeded',
        'authentication_denied', 'role_authorization_denied',
        'tenant_access_denied', 'document_access_succeeded',
        'document_access_denied', 'scim_user_provisioned',
        'scim_user_provisioning_denied'
    ));

CREATE OR REPLACE FUNCTION public.record_audit_event(
    p_actor_sub TEXT, p_event_type TEXT, p_outcome TEXT,
    p_organization_id TEXT, p_metadata JSONB
)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    safe_metadata JSONB := COALESCE(p_metadata, '{}'::jsonb);
BEGIN
    IF p_event_type IS NULL OR p_event_type NOT IN (
        'login_succeeded', 'login_failed', 'logout_succeeded',
        'authentication_denied', 'role_authorization_denied',
        'tenant_access_denied', 'document_access_succeeded',
        'document_access_denied', 'scim_user_provisioned',
        'scim_user_provisioning_denied'
    ) OR p_outcome IS NULL OR p_outcome NOT IN ('success', 'failure', 'denied') THEN
        RAISE EXCEPTION 'Invalid audit event classification';
    END IF;
    IF jsonb_typeof(safe_metadata) <> 'object' THEN
        RAISE EXCEPTION 'Audit metadata must be a JSON object';
    END IF;
    IF EXISTS (
        SELECT 1 FROM jsonb_object_keys(safe_metadata) AS item(key)
        WHERE key NOT IN ('reason', 'required_role', 'resource', 'status_code')
    ) THEN
        RAISE EXCEPTION 'Audit metadata contains an unsupported key';
    END IF;
    INSERT INTO public.audit_events
        (actor_sub, event_type, outcome, organization_id, metadata)
    VALUES (p_actor_sub, p_event_type, p_outcome, p_organization_id, safe_metadata);
END;
$$;
ALTER FUNCTION public.record_audit_event(TEXT, TEXT, TEXT, TEXT, JSONB)
    OWNER TO arcline_audit_writer;
REVOKE ALL ON FUNCTION public.record_audit_event(TEXT, TEXT, TEXT, TEXT, JSONB) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.record_audit_event(TEXT, TEXT, TEXT, TEXT, JSONB) TO arcline_app;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'arcline_scim_writer') THEN
        EXECUTE 'CREATE ROLE arcline_scim_writer NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS';
    END IF;
END
$$;
ALTER ROLE arcline_scim_writer
    NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
GRANT USAGE ON SCHEMA public TO arcline_scim_writer;
GRANT SELECT, INSERT ON TABLE public.organization_memberships TO arcline_scim_writer;

-- Only trusted administrators can change this tenant configuration.
CREATE TABLE IF NOT EXISTS public.scim_configuration (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton IS TRUE),
    organization_id VARCHAR(100) NOT NULL
        REFERENCES public.organizations(id) ON DELETE RESTRICT
);
REVOKE ALL ON TABLE public.scim_configuration FROM PUBLIC;
REVOKE ALL ON TABLE public.scim_configuration FROM arcline_app;
GRANT SELECT ON TABLE public.scim_configuration TO arcline_scim_writer;
INSERT INTO public.scim_configuration (singleton, organization_id)
VALUES (TRUE, 'arcline-default')
ON CONFLICT (singleton) DO UPDATE SET organization_id = EXCLUDED.organization_id;

DROP POLICY IF EXISTS organization_memberships_scim_select ON public.organization_memberships;
CREATE POLICY organization_memberships_scim_select
    ON public.organization_memberships FOR SELECT TO arcline_scim_writer
    USING (organization_id = pg_catalog.current_setting('app.current_organization_id', true));
DROP POLICY IF EXISTS organization_memberships_scim_insert ON public.organization_memberships;
CREATE POLICY organization_memberships_scim_insert
    ON public.organization_memberships FOR INSERT TO arcline_scim_writer
    WITH CHECK (organization_id = pg_catalog.current_setting('app.current_organization_id', true));

CREATE OR REPLACE FUNCTION public.scim_list_users(
    p_organization_id TEXT, p_offset INTEGER, p_count INTEGER
)
RETURNS TABLE(user_sub TEXT, role TEXT)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF p_organization_id IS NULL OR NOT EXISTS (
        SELECT 1 FROM public.scim_configuration c
        WHERE c.singleton IS TRUE AND c.organization_id = p_organization_id
    ) THEN RAISE EXCEPTION 'Organization is not configured for SCIM'; END IF;
    PERFORM pg_catalog.set_config('app.current_organization_id', p_organization_id, true);
    RETURN QUERY
    SELECT m.user_sub::TEXT, m.role::TEXT FROM public.organization_memberships AS m
    WHERE m.organization_id = p_organization_id
    ORDER BY m.user_sub
    OFFSET GREATEST(COALESCE(p_offset, 0), 0)
    LIMIT LEAST(GREATEST(COALESCE(p_count, 0), 0), 100);
END;
$$;

CREATE OR REPLACE FUNCTION public.scim_count_users(p_organization_id TEXT)
RETURNS BIGINT
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE result_count BIGINT;
BEGIN
    IF p_organization_id IS NULL OR NOT EXISTS (
        SELECT 1 FROM public.scim_configuration c
        WHERE c.singleton IS TRUE AND c.organization_id = p_organization_id
    ) THEN RAISE EXCEPTION 'Organization is not configured for SCIM'; END IF;
    PERFORM pg_catalog.set_config('app.current_organization_id', p_organization_id, true);
    SELECT count(*) INTO result_count FROM public.organization_memberships AS m
    WHERE m.organization_id = p_organization_id;
    RETURN result_count;
END;
$$;

CREATE OR REPLACE FUNCTION public.scim_get_user(p_organization_id TEXT, p_user_sub TEXT)
RETURNS TABLE(user_sub TEXT, role TEXT)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF p_organization_id IS NULL OR NOT EXISTS (
        SELECT 1 FROM public.scim_configuration c
        WHERE c.singleton IS TRUE AND c.organization_id = p_organization_id
    ) THEN RAISE EXCEPTION 'Organization is not configured for SCIM'; END IF;
    PERFORM pg_catalog.set_config('app.current_organization_id', p_organization_id, true);
    RETURN QUERY
    SELECT m.user_sub::TEXT, m.role::TEXT FROM public.organization_memberships AS m
    WHERE m.organization_id = p_organization_id AND m.user_sub = p_user_sub;
END;
$$;

CREATE OR REPLACE FUNCTION public.scim_provision_membership(p_user_sub TEXT, p_organization_id TEXT)
RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE inserted_rows INTEGER;
BEGIN
    IF p_user_sub IS NULL OR length(p_user_sub) = 0 THEN
        RAISE EXCEPTION 'User is required';
    END IF;
    IF p_organization_id IS NULL OR NOT EXISTS (
        SELECT 1 FROM public.scim_configuration c
        WHERE c.singleton IS TRUE AND c.organization_id = p_organization_id
    ) THEN RAISE EXCEPTION 'Organization is not configured for SCIM'; END IF;
    PERFORM pg_catalog.set_config('app.current_organization_id', p_organization_id, true);
    INSERT INTO public.organization_memberships (user_sub, organization_id, role)
    VALUES (p_user_sub, p_organization_id, 'member')
    ON CONFLICT (user_sub, organization_id) DO NOTHING;
    GET DIAGNOSTICS inserted_rows = ROW_COUNT;
    RETURN inserted_rows = 1;
END;
$$;

GRANT CREATE ON SCHEMA public TO arcline_scim_writer;
ALTER FUNCTION public.scim_list_users(TEXT, INTEGER, INTEGER) OWNER TO arcline_scim_writer;
ALTER FUNCTION public.scim_count_users(TEXT) OWNER TO arcline_scim_writer;
ALTER FUNCTION public.scim_get_user(TEXT, TEXT) OWNER TO arcline_scim_writer;
ALTER FUNCTION public.scim_provision_membership(TEXT, TEXT) OWNER TO arcline_scim_writer;
REVOKE CREATE ON SCHEMA public FROM arcline_scim_writer;

REVOKE ALL ON FUNCTION public.scim_list_users(TEXT, INTEGER, INTEGER) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.scim_count_users(TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.scim_get_user(TEXT, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.scim_provision_membership(TEXT, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.scim_list_users(TEXT, INTEGER, INTEGER) TO arcline_app;
GRANT EXECUTE ON FUNCTION public.scim_count_users(TEXT) TO arcline_app;
GRANT EXECUTE ON FUNCTION public.scim_get_user(TEXT, TEXT) TO arcline_app;
GRANT EXECUTE ON FUNCTION public.scim_provision_membership(TEXT, TEXT) TO arcline_app;

COMMIT;
