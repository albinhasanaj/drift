-- Phase F1: Audit Retention (CP0-F-05)
-- Plan-based retention: Free=30d, Pro=1y, Team=2y, Enterprise=no auto cleanup.
-- Runs via pg_cron daily at 3 AM if available.

CREATE OR REPLACE FUNCTION cleanup_expired_audit_logs()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    -- Free: 30 days
    DELETE FROM cloud_audit_log
    WHERE created_at < now() - interval '30 days'
    AND tenant_id IN (SELECT id FROM tenants WHERE plan = 'free');

    -- Pro: 1 year
    DELETE FROM cloud_audit_log
    WHERE created_at < now() - interval '1 year'
    AND tenant_id IN (SELECT id FROM tenants WHERE plan = 'pro');

    -- Team: 2 years
    DELETE FROM cloud_audit_log
    WHERE created_at < now() - interval '2 years'
    AND tenant_id IN (SELECT id FROM tenants WHERE plan = 'team');

    -- Enterprise: no automatic cleanup (custom retention)
END;
$$;

-- Schedule daily cleanup via pg_cron (if available)
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_cron') THEN
        PERFORM cron.schedule(
            'audit-log-retention',
            '0 3 * * *',
            'SELECT cleanup_expired_audit_logs()'
        );
    END IF;
END
$$;
