-- Cloud Data Pipeline: Tier 3 — Future Features (12 tables)
--
-- Multi-agent (6 from cortex.db), reclassification (2 from cortex.db),
-- temporal snapshots (1 from cortex.db), migration tracking (3 from drift.db).

-- ════════════════════════════════════════════════════════════════════════════
-- MULTI-AGENT (6 from cortex.db)
-- ════════════════════════════════════════════════════════════════════════════

-- ── cloud_agent_registry (from cortex.db agent_registry) ──
CREATE TABLE cloud_agent_registry (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      TEXT NOT NULL,        -- agent_id
    name          TEXT NOT NULL,
    namespace_id  TEXT NOT NULL,
    capabilities  TEXT,
    parent_agent  TEXT,
    registered_at TEXT NOT NULL,
    last_active   TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'active',
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_agent_registry ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_agent_registry FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_agent_registry_isolation ON cloud_agent_registry
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_agent_registry_project ON cloud_agent_registry(project_id);
CREATE INDEX idx_cloud_agent_registry_status ON cloud_agent_registry(status);

-- ── cloud_memory_namespaces (from cortex.db memory_namespaces) ──
CREATE TABLE cloud_memory_namespaces (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      TEXT NOT NULL,        -- namespace_id
    scope         TEXT NOT NULL,
    owner_agent   TEXT,
    created_at    TEXT NOT NULL,
    metadata      TEXT,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_memory_namespaces ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_memory_namespaces FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_memory_namespaces_isolation ON cloud_memory_namespaces
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_memory_namespaces_project ON cloud_memory_namespaces(project_id);

-- ── cloud_namespace_permissions (from cortex.db namespace_permissions) ──
CREATE TABLE cloud_namespace_permissions (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    namespace_id  TEXT NOT NULL,
    agent_id      TEXT NOT NULL,
    permissions   TEXT NOT NULL,
    granted_at    TEXT NOT NULL,
    granted_by    TEXT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, namespace_id, agent_id)
);
ALTER TABLE cloud_namespace_permissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_namespace_permissions FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_namespace_permissions_isolation ON cloud_namespace_permissions
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_namespace_permissions_project ON cloud_namespace_permissions(project_id);

-- ── cloud_memory_projections (from cortex.db memory_projections) ──
CREATE TABLE cloud_memory_projections (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      TEXT NOT NULL,        -- projection_id
    source_namespace TEXT NOT NULL,
    target_namespace TEXT NOT NULL,
    filter_json   TEXT NOT NULL,
    compression_level BIGINT NOT NULL DEFAULT 0,
    live          BOOLEAN NOT NULL DEFAULT false,
    created_at    TEXT NOT NULL,
    created_by    TEXT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_memory_projections ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_memory_projections FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_memory_projections_isolation ON cloud_memory_projections
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_memory_projections_project ON cloud_memory_projections(project_id);

-- ── cloud_provenance_log (from cortex.db provenance_log) ──
CREATE TABLE cloud_provenance_log (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      BIGINT NOT NULL,
    memory_id     TEXT NOT NULL,
    hop_index     BIGINT NOT NULL,
    agent_id      TEXT NOT NULL,
    action        TEXT NOT NULL,
    timestamp     TEXT NOT NULL,
    confidence_delta DOUBLE PRECISION DEFAULT 0.0,
    details       TEXT,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_provenance_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_provenance_log FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_provenance_log_isolation ON cloud_provenance_log
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_provenance_log_project ON cloud_provenance_log(project_id);
CREATE INDEX idx_cloud_provenance_log_memory ON cloud_provenance_log(memory_id);

-- ── cloud_agent_trust (from cortex.db agent_trust) ──
CREATE TABLE cloud_agent_trust (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    agent_id      TEXT NOT NULL,
    target_agent  TEXT NOT NULL,
    overall_trust DOUBLE PRECISION NOT NULL DEFAULT 0.5,
    domain_trust  TEXT,
    evidence      TEXT NOT NULL,
    last_updated  TEXT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, agent_id, target_agent)
);
ALTER TABLE cloud_agent_trust ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_agent_trust FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_agent_trust_isolation ON cloud_agent_trust
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_agent_trust_project ON cloud_agent_trust(project_id);

-- ════════════════════════════════════════════════════════════════════════════
-- TEMPORAL & RECLASSIFICATION (3 from cortex.db)
-- ════════════════════════════════════════════════════════════════════════════

-- ── cloud_reclassification_history (from cortex.db reclassification_history) ──
CREATE TABLE cloud_reclassification_history (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      BIGINT NOT NULL,
    memory_id     TEXT NOT NULL,
    old_type      TEXT NOT NULL,
    new_type      TEXT NOT NULL,
    reason        TEXT NOT NULL DEFAULT '',
    confidence    DOUBLE PRECISION NOT NULL DEFAULT 1.0,
    reclassified_at TEXT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_reclassification_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_reclassification_history FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_reclassification_history_isolation ON cloud_reclassification_history
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_reclassification_history_project ON cloud_reclassification_history(project_id);
CREATE INDEX idx_cloud_reclassification_history_memory ON cloud_reclassification_history(memory_id);

-- ── cloud_reclassification_signals (from cortex.db reclassification_signals) ──
CREATE TABLE cloud_reclassification_signals (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      BIGINT NOT NULL,
    memory_id     TEXT NOT NULL,
    signal_type   TEXT NOT NULL,
    signal_data   TEXT NOT NULL DEFAULT '{}',
    strength      DOUBLE PRECISION NOT NULL DEFAULT 0.5,
    created_at    TEXT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_reclassification_signals ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_reclassification_signals FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_reclassification_signals_isolation ON cloud_reclassification_signals
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_reclassification_signals_project ON cloud_reclassification_signals(project_id);

-- ── cloud_drift_snapshots (from cortex.db drift_snapshots) ──
CREATE TABLE cloud_drift_snapshots (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      BIGINT NOT NULL,     -- snapshot_id
    timestamp     TEXT NOT NULL,
    window_seconds BIGINT NOT NULL,
    metrics       TEXT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_drift_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_drift_snapshots FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_drift_snapshots_isolation ON cloud_drift_snapshots
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_drift_snapshots_project ON cloud_drift_snapshots(project_id);

-- ════════════════════════════════════════════════════════════════════════════
-- MIGRATION TRACKING (3 from drift.db)
-- ════════════════════════════════════════════════════════════════════════════

-- ── cloud_migration_projects (from drift.db migration_projects) ──
CREATE TABLE cloud_migration_projects (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      BIGINT NOT NULL,
    name          TEXT NOT NULL,
    source_language TEXT NOT NULL,
    target_language TEXT NOT NULL,
    source_framework TEXT,
    target_framework TEXT,
    status        TEXT NOT NULL DEFAULT 'active',
    created_at    BIGINT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_migration_projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_migration_projects FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_migration_projects_isolation ON cloud_migration_projects
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_migration_projects_project ON cloud_migration_projects(project_id);

-- ── cloud_migration_modules (from drift.db migration_modules) ──
CREATE TABLE cloud_migration_modules (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      BIGINT NOT NULL,
    migration_project_id BIGINT NOT NULL,
    module_name   TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'pending',
    spec_content  TEXT,
    created_at    BIGINT NOT NULL,
    updated_at    BIGINT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_migration_modules ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_migration_modules FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_migration_modules_isolation ON cloud_migration_modules
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_migration_modules_project ON cloud_migration_modules(project_id);

-- ── cloud_migration_corrections (from drift.db migration_corrections) ──
CREATE TABLE cloud_migration_corrections (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      BIGINT NOT NULL,
    module_id     BIGINT NOT NULL,
    section       TEXT NOT NULL,
    original_text TEXT NOT NULL,
    corrected_text TEXT NOT NULL,
    reason        TEXT,
    created_at    BIGINT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_migration_corrections ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_migration_corrections FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_migration_corrections_isolation ON cloud_migration_corrections
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_migration_corrections_project ON cloud_migration_corrections(project_id);
