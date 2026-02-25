-- Phase D placeholders for Phase F tables
-- Phase D's /Groups endpoint needs teams + team_memberships.
-- Phase D's audit logging needs cloud_audit_log.
-- Phase F will ALTER these with additional columns/constraints.

-- ── Teams (Phase F / CP0-F-07 — placeholder) ──
CREATE TABLE IF NOT EXISTS teams (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    scim_external_id TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);
ALTER TABLE teams ENABLE ROW LEVEL SECURITY;
ALTER TABLE teams FORCE ROW LEVEL SECURITY;
CREATE POLICY teams_isolation ON teams
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);

-- ── Team Memberships (Phase F / CP0-F-07 — placeholder) ──
CREATE TABLE IF NOT EXISTS team_memberships (
    team_id UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id UUID NOT NULL,
    role TEXT NOT NULL DEFAULT 'member'
        CHECK (role IN ('lead', 'member')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (team_id, user_id)
);
ALTER TABLE team_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE team_memberships FORCE ROW LEVEL SECURITY;
CREATE POLICY team_memberships_isolation ON team_memberships
    USING (team_id IN (
        SELECT id FROM teams WHERE tenant_id = current_setting('app.tenant_id', true)::UUID
    ));

-- ── Cloud Audit Log (Phase F / CP0-F-01 — placeholder) ──
CREATE TABLE IF NOT EXISTS cloud_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    actor_id UUID NOT NULL,
    actor_email TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT,
    metadata JSONB,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE cloud_audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_audit_log FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_tenant_isolation ON cloud_audit_log
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE POLICY audit_no_update ON cloud_audit_log FOR UPDATE USING (false);
CREATE POLICY audit_no_delete ON cloud_audit_log FOR DELETE USING (false);
