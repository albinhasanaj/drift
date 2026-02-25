-- Phase D Prerequisite: Base cloud tables
-- These tables are normally created by Phase 1 (Cloud Infrastructure).
-- Created here as prerequisites so Phase D can run independently.

-- ── Tenants (Phase 1 / P1-07) ──
CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    plan TEXT NOT NULL DEFAULT 'free'
        CHECK (plan IN ('free', 'pro', 'team', 'enterprise')),
    owner_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
CREATE POLICY tenants_isolation ON tenants
    USING (id = current_setting('app.tenant_id', true)::UUID);

-- ── User-Tenant Mappings (Phase 1 / P1-07) ──
CREATE TABLE IF NOT EXISTS user_tenant_mappings (
    user_id UUID NOT NULL,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    role TEXT NOT NULL DEFAULT 'member'
        CHECK (role IN ('owner', 'admin', 'member', 'viewer')),
    active BOOLEAN NOT NULL DEFAULT true,
    scim_external_id TEXT,
    deprovisioned_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, tenant_id)
);
ALTER TABLE user_tenant_mappings ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_tenant_mappings FORCE ROW LEVEL SECURITY;
CREATE POLICY utm_isolation ON user_tenant_mappings
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);

-- ── Projects (Phase 1 / P1-07) ──
CREATE TABLE IF NOT EXISTS projects (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE projects FORCE ROW LEVEL SECURITY;
CREATE POLICY projects_isolation ON projects
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);

-- ── API Keys (Phase 1 / P1-07) ──
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    key_hash TEXT NOT NULL,
    name TEXT NOT NULL,
    scopes TEXT[] NOT NULL DEFAULT '{}',
    created_by UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ
);
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY api_keys_isolation ON api_keys
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);

-- ── Tenant context helper function ──
CREATE OR REPLACE FUNCTION set_tenant_context(p_tenant_id UUID)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    PERFORM set_config('app.tenant_id', p_tenant_id::text, true);
END;
$$;
