-- Phase F2: Team Enhancements + New Tables (CP0-F-07)
-- Phase D placeholders created teams + team_memberships (20260211000003).
-- This migration adds team_projects, invitations, subscriptions.

-- ── Team Projects (NEW) ──
CREATE TABLE IF NOT EXISTS team_projects (
    team_id UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    assigned_by UUID NOT NULL,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (team_id, project_id)
);
ALTER TABLE team_projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE team_projects FORCE ROW LEVEL SECURITY;
CREATE POLICY team_projects_isolation ON team_projects
    USING (team_id IN (
        SELECT id FROM teams WHERE tenant_id = current_setting('app.tenant_id', true)::UUID
    ));

-- ── Invitations (NEW) ──
CREATE TABLE IF NOT EXISTS invitations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'member'
        CHECK (role IN ('admin', 'member', 'viewer')),
    team_id UUID REFERENCES teams(id) ON DELETE SET NULL,
    invited_by UUID NOT NULL,
    token TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL DEFAULT now() + interval '7 days',
    accepted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE invitations ENABLE ROW LEVEL SECURITY;
ALTER TABLE invitations FORCE ROW LEVEL SECURITY;
CREATE POLICY invitations_tenant_isolation ON invitations
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_invitations_token ON invitations(token);
CREATE INDEX idx_invitations_tenant ON invitations(tenant_id);

-- ── Subscriptions (for seat limits) ──
CREATE TABLE IF NOT EXISTS subscriptions (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    plan TEXT NOT NULL DEFAULT 'free'
        CHECK (plan IN ('free', 'pro', 'team', 'enterprise')),
    seat_limit INT NOT NULL DEFAULT 5,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE subscriptions FORCE ROW LEVEL SECURITY;
CREATE POLICY subscriptions_isolation ON subscriptions
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
