-- Phase D: SCIM bearer token infrastructure
-- Tokens are SHA-256 hashed; raw tokens are NEVER stored.

CREATE TABLE IF NOT EXISTS scim_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL,           -- SHA-256 of bearer token
    description TEXT DEFAULT '',
    created_by UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ,            -- NULL = active
    last_used_at TIMESTAMPTZ,
    UNIQUE (tenant_id, token_hash)
);

ALTER TABLE scim_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_tokens FORCE ROW LEVEL SECURITY;

CREATE POLICY scim_tokens_tenant_isolation ON scim_tokens
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);

CREATE INDEX idx_scim_tokens_lookup
    ON scim_tokens (token_hash)
    WHERE revoked_at IS NULL;
