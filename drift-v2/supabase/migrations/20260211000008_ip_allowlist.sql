-- Phase F3: IP Allowlisting (CP0-F-14)
-- Per-tenant CIDR-based access control using Postgres native INET type.

CREATE TABLE IF NOT EXISTS ip_allowlist (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    cidr INET NOT NULL,
    description TEXT DEFAULT '',
    expires_at TIMESTAMPTZ,
    created_by UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE ip_allowlist ENABLE ROW LEVEL SECURITY;
ALTER TABLE ip_allowlist FORCE ROW LEVEL SECURITY;
CREATE POLICY ip_allowlist_tenant_isolation ON ip_allowlist
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_ip_allowlist_tenant ON ip_allowlist(tenant_id);

-- ── CIDR matching function (CP0-F-16) ──
-- Uses Postgres inet <<= operator for proper CIDR matching.
CREATE OR REPLACE FUNCTION check_ip_allowlist(p_tenant_id UUID, p_client_ip TEXT)
RETURNS TABLE(id UUID)
LANGUAGE sql
SECURITY DEFINER
STABLE
AS $$
    SELECT id FROM ip_allowlist
    WHERE tenant_id = p_tenant_id
    AND p_client_ip::inet <<= cidr
    AND (expires_at IS NULL OR expires_at > now());
$$;
