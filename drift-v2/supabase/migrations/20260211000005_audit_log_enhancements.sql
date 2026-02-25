-- Phase F1: Audit Log Enhancements (CP0-F-01, CP0-F-06)
-- Adds performance indexes to cloud_audit_log (created in 20260211000003).
-- Verifies immutability policies exist. Enables Realtime.

-- ── Performance indexes (idempotent) ──
CREATE INDEX IF NOT EXISTS idx_audit_tenant_created ON cloud_audit_log(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_tenant_actor ON cloud_audit_log(tenant_id, actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_tenant_action ON cloud_audit_log(tenant_id, action);
CREATE INDEX IF NOT EXISTS idx_audit_tenant_resource ON cloud_audit_log(tenant_id, resource_type);

-- ── Verify immutability policies exist (from Phase D placeholder) ──
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE tablename = 'cloud_audit_log' AND policyname = 'audit_no_update'
    ) THEN
        EXECUTE 'CREATE POLICY audit_no_update ON cloud_audit_log FOR UPDATE USING (false)';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE tablename = 'cloud_audit_log' AND policyname = 'audit_no_delete'
    ) THEN
        EXECUTE 'CREATE POLICY audit_no_delete ON cloud_audit_log FOR DELETE USING (false)';
    END IF;
END
$$;

-- ── Enable Realtime on cloud_audit_log (CP0-F-06) ──
-- Enterprise tenants subscribe to audit:{tenant_id} Realtime channel.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_publication_tables
        WHERE pubname = 'supabase_realtime' AND tablename = 'cloud_audit_log'
    ) THEN
        ALTER PUBLICATION supabase_realtime ADD TABLE cloud_audit_log;
    END IF;
END
$$;
