-- Phase D: SCIM group-to-role mapping
-- Maps IdP group names to Drift roles for automatic role assignment.

CREATE TABLE IF NOT EXISTS scim_group_mappings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    idp_group_name TEXT NOT NULL,
    drift_role TEXT NOT NULL DEFAULT 'member'
        CHECK (drift_role IN ('owner', 'admin', 'member', 'viewer')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, idp_group_name)
);

ALTER TABLE scim_group_mappings ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_group_mappings FORCE ROW LEVEL SECURITY;

CREATE POLICY scim_group_mappings_tenant_isolation ON scim_group_mappings
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
