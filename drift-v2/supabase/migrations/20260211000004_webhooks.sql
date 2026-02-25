-- Phase E: Webhook & Event Notification System (CP0-E-01)
-- Tables: webhook_event_types, webhook_endpoints, webhook_deliveries
-- All tables have RLS enabled + forced with tenant isolation policies.

-- ── Reference table: supported event types ──
CREATE TABLE IF NOT EXISTS webhook_event_types (
    event_type TEXT PRIMARY KEY,
    description TEXT NOT NULL,
    payload_schema JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO webhook_event_types (event_type, description) VALUES
    ('scan.completed', 'Scan finished with summary statistics'),
    ('gate.failed', 'Quality gate failed'),
    ('violation.new', 'New critical/high violation detected'),
    ('grounding.degraded', 'Memory grounding score dropped below threshold'),
    ('apikey.expiring', 'API key approaching expiration'),
    ('sync.failed', 'Cloud sync failed after retries'),
    ('project.created', 'New project registered'),
    ('project.deleted', 'Project deleted'),
    ('ping', 'Test event for webhook verification')
ON CONFLICT (event_type) DO NOTHING;

-- ── Webhook endpoints ──
CREATE TABLE IF NOT EXISTS webhook_endpoints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    secret_hash TEXT NOT NULL,
    secret_hash_new TEXT,
    secret_rotated_at TIMESTAMPTZ,
    events TEXT[] NOT NULL,
    description TEXT DEFAULT '',
    active BOOLEAN NOT NULL DEFAULT true,
    consecutive_failures INT NOT NULL DEFAULT 0,
    created_by UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE webhook_endpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_endpoints FORCE ROW LEVEL SECURITY;
CREATE POLICY webhook_endpoints_tenant_isolation ON webhook_endpoints
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_webhook_endpoints_tenant ON webhook_endpoints(tenant_id);
CREATE INDEX idx_webhook_endpoints_active ON webhook_endpoints(tenant_id, active) WHERE active = true;

-- ── Webhook deliveries ──
CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id UUID NOT NULL REFERENCES webhook_endpoints(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL,
    event_type TEXT NOT NULL,
    payload JSONB NOT NULL,
    idempotency_key UUID NOT NULL DEFAULT gen_random_uuid(),
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'delivered', 'failed', 'dead_letter')),
    status_code INT,
    response_body TEXT,
    attempt INT NOT NULL DEFAULT 0,
    max_attempts INT NOT NULL DEFAULT 5,
    next_retry_at TIMESTAMPTZ,
    delivered_at TIMESTAMPTZ,
    latency_ms INT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE webhook_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_deliveries FORCE ROW LEVEL SECURITY;
CREATE POLICY webhook_deliveries_tenant_isolation ON webhook_deliveries
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_webhook_deliveries_endpoint ON webhook_deliveries(endpoint_id);
CREATE INDEX idx_webhook_deliveries_retry ON webhook_deliveries(next_retry_at)
    WHERE status = 'pending' AND next_retry_at IS NOT NULL;
CREATE INDEX idx_webhook_deliveries_tenant_created ON webhook_deliveries(tenant_id, created_at DESC);

-- ── pg_cron job for secret rotation cleanup (runs hourly) ──
-- Promotes secret_hash_new → secret_hash after 24h rotation window.
-- NOTE: pg_cron must be enabled in the Supabase project settings.
-- If pg_cron is not available, this can be run manually or via a scheduled Edge Function.
DO $outer$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_cron') THEN
        PERFORM cron.schedule(
            'webhook-secret-rotation-cleanup',
            '0 * * * *',
            $cron$
            UPDATE webhook_endpoints
            SET secret_hash = secret_hash_new,
                secret_hash_new = NULL,
                secret_rotated_at = NULL,
                updated_at = now()
            WHERE secret_hash_new IS NOT NULL
              AND secret_rotated_at < now() - interval '24 hours';
            $cron$
        );
    END IF;
END $outer$;
