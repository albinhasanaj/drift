-- Cloud Data Pipeline: Tier 2 — Complete Cortex (19 tables)
--
-- Mirrors local SQLite tables from cortex.db (16 tables) and drift.db (3 tables)
-- into Postgres with tenant_id, project_id, RLS.
--
-- cortex.db uses ISO-8601 TEXT timestamps (not unix epochs like drift.db).
-- We store them as TEXT in cloud too, keeping fidelity with the source.

-- ════════════════════════════════════════════════════════════════════════════
-- CORE MEMORY SYSTEM (16 from cortex.db)
-- ════════════════════════════════════════════════════════════════════════════

-- ── cloud_memories (from cortex.db memories) ──
CREATE TABLE cloud_memories (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      TEXT NOT NULL,        -- memory id
    memory_type   TEXT NOT NULL,
    content       TEXT NOT NULL,
    summary       TEXT NOT NULL DEFAULT '',
    transaction_time TEXT NOT NULL,
    valid_time    TEXT NOT NULL,
    valid_until   TEXT,
    confidence    DOUBLE PRECISION NOT NULL DEFAULT 1.0,
    importance    TEXT NOT NULL DEFAULT 'normal',
    last_accessed TEXT NOT NULL,
    access_count  BIGINT NOT NULL DEFAULT 0,
    tags          TEXT NOT NULL DEFAULT '[]',
    archived      BOOLEAN NOT NULL DEFAULT false,
    superseded_by TEXT,
    supersedes    TEXT,
    content_hash  TEXT NOT NULL,
    namespace_id  TEXT DEFAULT 'agent://default/',
    source_agent  TEXT DEFAULT 'default',
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_memories ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_memories FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_memories_isolation ON cloud_memories
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_memories_project ON cloud_memories(project_id);
CREATE INDEX idx_cloud_memories_type ON cloud_memories(memory_type);
CREATE INDEX idx_cloud_memories_confidence ON cloud_memories(confidence);
CREATE INDEX idx_cloud_memories_archived ON cloud_memories(archived);

-- ── cloud_memory_relationships (from cortex.db memory_relationships) ──
CREATE TABLE cloud_memory_relationships (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    source_id     TEXT NOT NULL,
    target_id     TEXT NOT NULL,
    relationship_type TEXT NOT NULL,
    strength      DOUBLE PRECISION NOT NULL DEFAULT 1.0,
    evidence      TEXT NOT NULL DEFAULT '[]',
    created_at    TEXT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, source_id, target_id, relationship_type)
);
ALTER TABLE cloud_memory_relationships ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_memory_relationships FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_memory_relationships_isolation ON cloud_memory_relationships
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_memory_relationships_project ON cloud_memory_relationships(project_id);
CREATE INDEX idx_cloud_memory_relationships_source ON cloud_memory_relationships(source_id);
CREATE INDEX idx_cloud_memory_relationships_target ON cloud_memory_relationships(target_id);

-- ── cloud_memory_patterns (from cortex.db memory_patterns) ──
CREATE TABLE cloud_memory_patterns (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    memory_id     TEXT NOT NULL,
    pattern_id    TEXT NOT NULL,
    pattern_name  TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, memory_id, pattern_id)
);
ALTER TABLE cloud_memory_patterns ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_memory_patterns FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_memory_patterns_isolation ON cloud_memory_patterns
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_memory_patterns_project ON cloud_memory_patterns(project_id);

-- ── cloud_memory_constraints (from cortex.db memory_constraints) ──
CREATE TABLE cloud_memory_constraints (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    memory_id     TEXT NOT NULL,
    constraint_id TEXT NOT NULL,
    constraint_name TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, memory_id, constraint_id)
);
ALTER TABLE cloud_memory_constraints ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_memory_constraints FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_memory_constraints_isolation ON cloud_memory_constraints
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_memory_constraints_project ON cloud_memory_constraints(project_id);

-- ── cloud_memory_files (from cortex.db memory_files) ® REDACT: file_path ──
CREATE TABLE cloud_memory_files (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    memory_id     TEXT NOT NULL,
    file_path     TEXT NOT NULL,        -- relativized
    line_start    BIGINT,
    line_end      BIGINT,
    content_hash  TEXT,
    created_at    TEXT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, memory_id, file_path)
);
ALTER TABLE cloud_memory_files ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_memory_files FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_memory_files_isolation ON cloud_memory_files
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_memory_files_project ON cloud_memory_files(project_id);
CREATE INDEX idx_cloud_memory_files_path ON cloud_memory_files(file_path);

-- ── cloud_memory_functions (from cortex.db memory_functions) ® REDACT: file_path ──
CREATE TABLE cloud_memory_functions (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    memory_id     TEXT NOT NULL,
    function_name TEXT NOT NULL,
    file_path     TEXT NOT NULL,        -- relativized
    signature     TEXT,
    created_at    TEXT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, memory_id, function_name, file_path)
);
ALTER TABLE cloud_memory_functions ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_memory_functions FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_memory_functions_isolation ON cloud_memory_functions
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_memory_functions_project ON cloud_memory_functions(project_id);

-- ── cloud_causal_edges (from cortex.db causal_edges) ──
CREATE TABLE cloud_causal_edges (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    source_id     TEXT NOT NULL,
    target_id     TEXT NOT NULL,
    relation      TEXT NOT NULL,
    strength      DOUBLE PRECISION NOT NULL DEFAULT 1.0,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, source_id, target_id)
);
ALTER TABLE cloud_causal_edges ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_causal_edges FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_causal_edges_isolation ON cloud_causal_edges
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_causal_edges_project ON cloud_causal_edges(project_id);
CREATE INDEX idx_cloud_causal_edges_source ON cloud_causal_edges(source_id);
CREATE INDEX idx_cloud_causal_edges_target ON cloud_causal_edges(target_id);

-- ── cloud_causal_evidence (from cortex.db causal_evidence) ──
CREATE TABLE cloud_causal_evidence (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      BIGINT NOT NULL,
    source_id     TEXT NOT NULL,
    target_id     TEXT NOT NULL,
    description   TEXT NOT NULL,
    source        TEXT NOT NULL DEFAULT 'system',
    timestamp     TEXT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_causal_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_causal_evidence FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_causal_evidence_isolation ON cloud_causal_evidence
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_causal_evidence_project ON cloud_causal_evidence(project_id);
CREATE INDEX idx_cloud_causal_evidence_edge ON cloud_causal_evidence(source_id, target_id);

-- ── cloud_memory_audit_log (from cortex.db memory_audit_log) ──
CREATE TABLE cloud_memory_audit_log (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      BIGINT NOT NULL,
    memory_id     TEXT NOT NULL,
    operation     TEXT NOT NULL,
    details       TEXT NOT NULL DEFAULT '{}',
    actor         TEXT NOT NULL DEFAULT 'system',
    timestamp     TEXT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_memory_audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_memory_audit_log FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_memory_audit_log_isolation ON cloud_memory_audit_log
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_memory_audit_log_project ON cloud_memory_audit_log(project_id);
CREATE INDEX idx_cloud_memory_audit_log_memory ON cloud_memory_audit_log(memory_id);

-- ── cloud_consolidation_metrics (from cortex.db consolidation_metrics) ──
CREATE TABLE cloud_consolidation_metrics (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      BIGINT NOT NULL,
    run_id        TEXT NOT NULL,
    precision_score DOUBLE PRECISION,
    compression_ratio DOUBLE PRECISION,
    lift          DOUBLE PRECISION,
    stability     DOUBLE PRECISION,
    memories_created BIGINT NOT NULL DEFAULT 0,
    memories_archived BIGINT NOT NULL DEFAULT 0,
    timestamp     TEXT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_consolidation_metrics ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_consolidation_metrics FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_consolidation_metrics_isolation ON cloud_consolidation_metrics
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_consolidation_metrics_project ON cloud_consolidation_metrics(project_id);

-- ── cloud_cortex_degradation_log (from cortex.db degradation_log) ──
CREATE TABLE cloud_cortex_degradation_log (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      BIGINT NOT NULL,
    component     TEXT NOT NULL,
    failure       TEXT NOT NULL,
    fallback      TEXT NOT NULL,
    details       TEXT NOT NULL DEFAULT '{}',
    timestamp     TEXT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_cortex_degradation_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_cortex_degradation_log FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_cortex_degradation_log_isolation ON cloud_cortex_degradation_log
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_cortex_degradation_log_project ON cloud_cortex_degradation_log(project_id);
CREATE INDEX idx_cloud_cortex_degradation_log_component ON cloud_cortex_degradation_log(component);

-- ── cloud_memory_validation (from cortex.db memory_validation_history) ──
CREATE TABLE cloud_memory_validation (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      BIGINT NOT NULL,
    memory_id     TEXT NOT NULL,
    dimension     TEXT NOT NULL,
    score         DOUBLE PRECISION NOT NULL,
    healing_action TEXT,
    validated_at  TEXT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_memory_validation ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_memory_validation FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_memory_validation_isolation ON cloud_memory_validation
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_memory_validation_project ON cloud_memory_validation(project_id);
CREATE INDEX idx_cloud_memory_validation_memory ON cloud_memory_validation(memory_id);

-- ── cloud_memory_contradictions (from cortex.db memory_contradictions) ──
CREATE TABLE cloud_memory_contradictions (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      BIGINT NOT NULL,
    memory_id_a   TEXT NOT NULL,
    memory_id_b   TEXT NOT NULL,
    contradiction_type TEXT NOT NULL,
    confidence_delta DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    resolved      BOOLEAN NOT NULL DEFAULT false,
    detected_at   TEXT NOT NULL,
    resolved_at   TEXT,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_memory_contradictions ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_memory_contradictions FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_memory_contradictions_isolation ON cloud_memory_contradictions
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_memory_contradictions_project ON cloud_memory_contradictions(project_id);

-- ── cloud_memory_versions (from cortex.db memory_versions) ──
CREATE TABLE cloud_memory_versions (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      BIGINT NOT NULL,
    memory_id     TEXT NOT NULL,
    version       BIGINT NOT NULL,
    content       TEXT NOT NULL,
    summary       TEXT NOT NULL DEFAULT '',
    confidence    DOUBLE PRECISION NOT NULL,
    changed_by    TEXT NOT NULL DEFAULT 'system',
    reason        TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_memory_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_memory_versions FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_memory_versions_isolation ON cloud_memory_versions
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_memory_versions_project ON cloud_memory_versions(project_id);
CREATE INDEX idx_cloud_memory_versions_memory ON cloud_memory_versions(memory_id);

-- ── cloud_memory_events (from cortex.db memory_events) ──
CREATE TABLE cloud_memory_events (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      BIGINT NOT NULL,     -- event_id
    memory_id     TEXT NOT NULL,
    recorded_at   TEXT NOT NULL,
    event_type    TEXT NOT NULL,
    delta         TEXT NOT NULL,
    actor_type    TEXT NOT NULL,
    actor_id      TEXT NOT NULL,
    caused_by     TEXT,
    schema_version BIGINT NOT NULL DEFAULT 1,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_memory_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_memory_events FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_memory_events_isolation ON cloud_memory_events
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_memory_events_project ON cloud_memory_events(project_id);
CREATE INDEX idx_cloud_memory_events_memory ON cloud_memory_events(memory_id);
CREATE INDEX idx_cloud_memory_events_type ON cloud_memory_events(event_type);

-- ── cloud_memory_snapshots (from cortex.db memory_snapshots) ──
-- Note: state BLOB in SQLite → we store hex-encoded or base64 in cloud
CREATE TABLE cloud_memory_snapshots (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      BIGINT NOT NULL,     -- snapshot_id
    memory_id     TEXT NOT NULL,
    snapshot_at   TEXT NOT NULL,
    state         TEXT NOT NULL,        -- base64-encoded BLOB
    event_id      BIGINT NOT NULL,
    reason        TEXT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_memory_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_memory_snapshots FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_memory_snapshots_isolation ON cloud_memory_snapshots
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_memory_snapshots_project ON cloud_memory_snapshots(project_id);
CREATE INDEX idx_cloud_memory_snapshots_memory ON cloud_memory_snapshots(memory_id);

-- ════════════════════════════════════════════════════════════════════════════
-- ADVANCED (3 from drift.db)
-- ════════════════════════════════════════════════════════════════════════════

-- ── cloud_simulations (from drift.db simulations) ──
CREATE TABLE cloud_simulations (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      BIGINT NOT NULL,
    task_category TEXT NOT NULL,
    task_description TEXT NOT NULL,
    approach_count BIGINT NOT NULL,
    recommended_approach TEXT,
    p10_effort    DOUBLE PRECISION NOT NULL,
    p50_effort    DOUBLE PRECISION NOT NULL,
    p90_effort    DOUBLE PRECISION NOT NULL,
    created_at    BIGINT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_simulations ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_simulations FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_simulations_isolation ON cloud_simulations
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_simulations_project ON cloud_simulations(project_id);
CREATE INDEX idx_cloud_simulations_category ON cloud_simulations(task_category);

-- ── cloud_decisions (from drift.db decisions) ──
CREATE TABLE cloud_decisions (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      BIGINT NOT NULL,
    category      TEXT NOT NULL,
    description   TEXT NOT NULL,
    commit_sha    TEXT,
    confidence    DOUBLE PRECISION NOT NULL,
    related_patterns TEXT,
    author        TEXT,
    files_changed TEXT,
    created_at    BIGINT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_decisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_decisions FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_decisions_isolation ON cloud_decisions
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_decisions_project ON cloud_decisions(project_id);
CREATE INDEX idx_cloud_decisions_category ON cloud_decisions(category);

-- ── cloud_embedding_models (from cortex.db embedding_model_info) ──
CREATE TABLE cloud_embedding_models (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      BIGINT NOT NULL,
    model_name    TEXT NOT NULL,
    dimensions    BIGINT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'active',
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_embedding_models ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_embedding_models FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_embedding_models_isolation ON cloud_embedding_models
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_embedding_models_project ON cloud_embedding_models(project_id);
