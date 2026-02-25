-- Cloud Data Pipeline: Tier 1 — Dashboard Essentials (42 tables)
--
-- Mirrors local SQLite tables from drift.db (37 tables) and bridge.db (5 tables)
-- into Postgres with tenant_id, project_id, RLS, and cloud-safe column types.
--
-- Design rules:
--   1. Every table gets tenant_id UUID + project_id UUID (FK to tenants/projects)
--   2. Every table gets RLS: USING (tenant_id = current_setting('app.tenant_id', true)::UUID)
--   3. Local INTEGER PK → cloud local_id (non-unique, scoped to project). Cloud PK is UUID.
--   4. Local TEXT PK → cloud local_id TEXT (same pattern)
--   5. synced_at TIMESTAMPTZ DEFAULT now() on every row
--   6. SQLite INTEGER → BIGINT, REAL → DOUBLE PRECISION, TEXT → TEXT
--   7. REDACT tables: file paths stripped to relative, code/snippet/matched_text → NULL before sync

-- ════════════════════════════════════════════════════════════════════════════
-- Helper: creates a standard RLS policy for a cloud table
-- ════════════════════════════════════════════════════════════════════════════

-- We'll apply RLS inline per table below.

-- ════════════════════════════════════════════════════════════════════════════
-- SCAN & FILES (3 tables)
-- ════════════════════════════════════════════════════════════════════════════

-- ── cloud_scan_history (from drift.db scan_history) ® REDACT: root_path ──
CREATE TABLE cloud_scan_history (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      BIGINT NOT NULL,
    started_at    BIGINT NOT NULL,
    completed_at  BIGINT,
    root_path     TEXT,              -- redacted to relative or stripped
    total_files   BIGINT,
    added_files   BIGINT,
    modified_files BIGINT,
    removed_files BIGINT,
    unchanged_files BIGINT,
    duration_ms   BIGINT,
    status        TEXT NOT NULL DEFAULT 'running',
    error         TEXT,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_scan_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_scan_history FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_scan_history_isolation ON cloud_scan_history
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_scan_history_project ON cloud_scan_history(project_id);
CREATE INDEX idx_cloud_scan_history_started ON cloud_scan_history(started_at DESC);

-- ── cloud_file_stats (from drift.db file_metadata) ® REDACT: path ──
CREATE TABLE cloud_file_stats (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      TEXT NOT NULL,       -- original path (relativized)
    language      TEXT,
    file_size     BIGINT NOT NULL,
    content_hash  TEXT NOT NULL,        -- hex-encoded, not raw BLOB
    mtime_secs    BIGINT NOT NULL,
    mtime_nanos   BIGINT NOT NULL,
    last_scanned_at BIGINT NOT NULL,
    scan_duration_us BIGINT,
    pattern_count BIGINT DEFAULT 0,
    function_count BIGINT DEFAULT 0,
    error_count   BIGINT DEFAULT 0,
    error         TEXT,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_file_stats ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_file_stats FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_file_stats_isolation ON cloud_file_stats
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_file_stats_project ON cloud_file_stats(project_id);
CREATE INDEX idx_cloud_file_stats_language ON cloud_file_stats(language);

-- ── cloud_functions (from drift.db functions) ® REDACT: file ──
CREATE TABLE cloud_functions (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      BIGINT NOT NULL,
    file          TEXT NOT NULL,        -- relativized
    name          TEXT NOT NULL,
    qualified_name TEXT,
    language      TEXT NOT NULL,
    line          BIGINT NOT NULL,
    end_line      BIGINT NOT NULL,
    parameter_count BIGINT NOT NULL DEFAULT 0,
    return_type   TEXT,
    is_exported   BOOLEAN NOT NULL DEFAULT false,
    is_async      BOOLEAN NOT NULL DEFAULT false,
    body_hash     TEXT,                 -- hex-encoded
    signature_hash TEXT,                -- hex-encoded
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_functions ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_functions FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_functions_isolation ON cloud_functions
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_functions_project ON cloud_functions(project_id);
CREATE INDEX idx_cloud_functions_file ON cloud_functions(file);
CREATE INDEX idx_cloud_functions_name ON cloud_functions(name);

-- ════════════════════════════════════════════════════════════════════════════
-- ANALYSIS & PATTERNS (7 tables)
-- ════════════════════════════════════════════════════════════════════════════

-- ── cloud_call_edges (from drift.db call_edges) ──
CREATE TABLE cloud_call_edges (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    caller_id     BIGINT NOT NULL,
    callee_id     BIGINT NOT NULL,
    resolution    TEXT NOT NULL,
    confidence    DOUBLE PRECISION NOT NULL,
    call_site_line BIGINT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, caller_id, callee_id, call_site_line)
);
ALTER TABLE cloud_call_edges ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_call_edges FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_call_edges_isolation ON cloud_call_edges
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_call_edges_project ON cloud_call_edges(project_id);
CREATE INDEX idx_cloud_call_edges_caller ON cloud_call_edges(caller_id);
CREATE INDEX idx_cloud_call_edges_callee ON cloud_call_edges(callee_id);

-- ── cloud_data_access (from drift.db data_access) ──
CREATE TABLE cloud_data_access (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    function_id   BIGINT NOT NULL,
    table_name    TEXT NOT NULL,
    operation     TEXT NOT NULL,
    framework     TEXT,
    line          BIGINT NOT NULL,
    confidence    DOUBLE PRECISION NOT NULL DEFAULT 0.8,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, function_id, table_name, operation, line)
);
ALTER TABLE cloud_data_access ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_data_access FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_data_access_isolation ON cloud_data_access
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_data_access_project ON cloud_data_access(project_id);

-- ── cloud_detections (from drift.db detections) ® REDACT: file, matched_text ──
CREATE TABLE cloud_detections (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      BIGINT NOT NULL,
    file          TEXT NOT NULL,        -- relativized
    line          BIGINT NOT NULL,
    column_num    BIGINT NOT NULL,
    pattern_id    TEXT NOT NULL,
    category      TEXT NOT NULL,
    confidence    DOUBLE PRECISION NOT NULL,
    detection_method TEXT NOT NULL,
    cwe_ids       TEXT,
    owasp         TEXT,
    matched_text  TEXT,                 -- redacted to NULL before sync
    created_at    BIGINT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_detections ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_detections FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_detections_isolation ON cloud_detections
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_detections_project ON cloud_detections(project_id);
CREATE INDEX idx_cloud_detections_category ON cloud_detections(category);
CREATE INDEX idx_cloud_detections_pattern ON cloud_detections(pattern_id);

-- ── cloud_boundaries (from drift.db boundaries) ® REDACT: file ──
CREATE TABLE cloud_boundaries (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      BIGINT NOT NULL,
    file          TEXT NOT NULL,        -- relativized
    framework     TEXT NOT NULL,
    model_name    TEXT NOT NULL,
    table_name    TEXT,
    field_name    TEXT,
    sensitivity   TEXT,
    confidence    DOUBLE PRECISION NOT NULL,
    created_at    BIGINT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_boundaries ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_boundaries FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_boundaries_isolation ON cloud_boundaries
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_boundaries_project ON cloud_boundaries(project_id);
CREATE INDEX idx_cloud_boundaries_framework ON cloud_boundaries(framework);

-- ── cloud_pattern_confidence (from drift.db pattern_confidence) ──
CREATE TABLE cloud_pattern_confidence (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      TEXT NOT NULL,        -- pattern_id
    alpha         DOUBLE PRECISION NOT NULL,
    beta          DOUBLE PRECISION NOT NULL,
    posterior_mean DOUBLE PRECISION NOT NULL,
    credible_interval_low DOUBLE PRECISION NOT NULL,
    credible_interval_high DOUBLE PRECISION NOT NULL,
    tier          TEXT NOT NULL,
    momentum      TEXT NOT NULL DEFAULT 'Stable',
    last_updated  BIGINT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_pattern_confidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_pattern_confidence FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_pattern_confidence_isolation ON cloud_pattern_confidence
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_pattern_confidence_project ON cloud_pattern_confidence(project_id);

-- ── cloud_outliers (from drift.db outliers) ® REDACT: file ──
CREATE TABLE cloud_outliers (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      BIGINT NOT NULL,
    pattern_id    TEXT NOT NULL,
    file          TEXT NOT NULL,        -- relativized
    line          BIGINT NOT NULL,
    deviation_score DOUBLE PRECISION NOT NULL,
    significance  TEXT NOT NULL,
    method        TEXT NOT NULL,
    created_at    BIGINT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_outliers ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_outliers FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_outliers_isolation ON cloud_outliers
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_outliers_project ON cloud_outliers(project_id);
CREATE INDEX idx_cloud_outliers_pattern ON cloud_outliers(pattern_id);

-- ── cloud_conventions (from drift.db conventions) ──
CREATE TABLE cloud_conventions (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      BIGINT NOT NULL,
    pattern_id    TEXT NOT NULL,
    category      TEXT NOT NULL,
    scope         TEXT NOT NULL,
    dominance_ratio DOUBLE PRECISION NOT NULL,
    promotion_status TEXT NOT NULL DEFAULT 'discovered',
    discovered_at BIGINT NOT NULL,
    last_seen     BIGINT NOT NULL,
    expires_at    BIGINT,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_conventions ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_conventions FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_conventions_isolation ON cloud_conventions
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_conventions_project ON cloud_conventions(project_id);
CREATE INDEX idx_cloud_conventions_category ON cloud_conventions(category);

-- ════════════════════════════════════════════════════════════════════════════
-- GRAPH INTELLIGENCE (5 tables)
-- ════════════════════════════════════════════════════════════════════════════

-- ── cloud_taint_flows (from drift.db taint_flows) ® REDACT: source_file, sink_file ──
CREATE TABLE cloud_taint_flows (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      BIGINT NOT NULL,
    source_file   TEXT NOT NULL,        -- relativized
    source_line   BIGINT NOT NULL,
    source_type   TEXT NOT NULL,
    sink_file     TEXT NOT NULL,        -- relativized
    sink_line     BIGINT NOT NULL,
    sink_type     TEXT NOT NULL,
    cwe_id        BIGINT,
    is_sanitized  BOOLEAN NOT NULL DEFAULT false,
    path          TEXT NOT NULL,
    confidence    DOUBLE PRECISION NOT NULL,
    created_at    BIGINT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_taint_flows ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_taint_flows FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_taint_flows_isolation ON cloud_taint_flows
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_taint_flows_project ON cloud_taint_flows(project_id);
CREATE INDEX idx_cloud_taint_flows_cwe ON cloud_taint_flows(cwe_id);

-- ── cloud_error_gaps (from drift.db error_gaps) ® REDACT: file ──
CREATE TABLE cloud_error_gaps (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      BIGINT NOT NULL,
    file          TEXT NOT NULL,        -- relativized
    function_id   TEXT NOT NULL,
    gap_type      TEXT NOT NULL,
    error_type    TEXT,
    propagation_chain TEXT,
    framework     TEXT,
    cwe_id        BIGINT,
    severity      TEXT NOT NULL,
    created_at    BIGINT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_error_gaps ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_error_gaps FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_error_gaps_isolation ON cloud_error_gaps
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_error_gaps_project ON cloud_error_gaps(project_id);
CREATE INDEX idx_cloud_error_gaps_severity ON cloud_error_gaps(severity);

-- ── cloud_impact_scores (from drift.db impact_scores) ──
CREATE TABLE cloud_impact_scores (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      TEXT NOT NULL,        -- function_id
    blast_radius  BIGINT NOT NULL,
    risk_score    DOUBLE PRECISION NOT NULL,
    is_dead_code  BOOLEAN NOT NULL DEFAULT false,
    dead_code_reason TEXT,
    exclusion_category TEXT,
    updated_at    BIGINT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_impact_scores ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_impact_scores FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_impact_scores_isolation ON cloud_impact_scores
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_impact_scores_project ON cloud_impact_scores(project_id);

-- ── cloud_test_coverage (from drift.db test_coverage) ──
CREATE TABLE cloud_test_coverage (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    test_function_id TEXT NOT NULL,
    source_function_id TEXT NOT NULL,
    coverage_type TEXT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, test_function_id, source_function_id)
);
ALTER TABLE cloud_test_coverage ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_test_coverage FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_test_coverage_isolation ON cloud_test_coverage
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_test_coverage_project ON cloud_test_coverage(project_id);
CREATE INDEX idx_cloud_test_coverage_source ON cloud_test_coverage(source_function_id);

-- ── cloud_test_quality (from drift.db test_quality) ──
CREATE TABLE cloud_test_quality (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      TEXT NOT NULL,        -- function_id
    coverage_breadth DOUBLE PRECISION,
    coverage_depth DOUBLE PRECISION,
    assertion_density DOUBLE PRECISION,
    mock_ratio    DOUBLE PRECISION,
    isolation     DOUBLE PRECISION,
    freshness     DOUBLE PRECISION,
    stability     DOUBLE PRECISION,
    overall_score DOUBLE PRECISION NOT NULL,
    smells        TEXT,
    updated_at    BIGINT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_test_quality ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_test_quality FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_test_quality_isolation ON cloud_test_quality
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_test_quality_project ON cloud_test_quality(project_id);

-- ════════════════════════════════════════════════════════════════════════════
-- STRUCTURAL INTELLIGENCE (15 tables)
-- ════════════════════════════════════════════════════════════════════════════

-- ── cloud_coupling_metrics (from drift.db coupling_metrics) ──
CREATE TABLE cloud_coupling_metrics (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      TEXT NOT NULL,        -- module
    ce            BIGINT NOT NULL,
    ca            BIGINT NOT NULL,
    instability   DOUBLE PRECISION NOT NULL,
    abstractness  DOUBLE PRECISION NOT NULL,
    distance      DOUBLE PRECISION NOT NULL,
    zone          TEXT NOT NULL,
    updated_at    BIGINT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_coupling_metrics ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_coupling_metrics FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_coupling_metrics_isolation ON cloud_coupling_metrics
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_coupling_metrics_project ON cloud_coupling_metrics(project_id);
CREATE INDEX idx_cloud_coupling_metrics_zone ON cloud_coupling_metrics(zone);

-- ── cloud_coupling_cycles (from drift.db coupling_cycles) ──
CREATE TABLE cloud_coupling_cycles (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      BIGINT NOT NULL,
    members       TEXT NOT NULL,
    break_suggestions TEXT NOT NULL,
    created_at    BIGINT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_coupling_cycles ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_coupling_cycles FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_coupling_cycles_isolation ON cloud_coupling_cycles
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_coupling_cycles_project ON cloud_coupling_cycles(project_id);

-- ── cloud_constraints (from drift.db constraints) ──
CREATE TABLE cloud_constraints (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      TEXT NOT NULL,
    description   TEXT NOT NULL,
    invariant_type TEXT NOT NULL,
    target        TEXT NOT NULL,
    scope         TEXT,
    source        TEXT NOT NULL,
    enabled       BOOLEAN NOT NULL DEFAULT true,
    created_at    BIGINT NOT NULL,
    updated_at    BIGINT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_constraints ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_constraints FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_constraints_isolation ON cloud_constraints
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_constraints_project ON cloud_constraints(project_id);
CREATE INDEX idx_cloud_constraints_type ON cloud_constraints(invariant_type);

-- ── cloud_constraint_results (from drift.db constraint_verifications) ──
CREATE TABLE cloud_constraint_results (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      BIGINT NOT NULL,
    constraint_id TEXT NOT NULL,
    passed        BOOLEAN NOT NULL,
    violations    TEXT NOT NULL,
    verified_at   BIGINT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_constraint_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_constraint_results FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_constraint_results_isolation ON cloud_constraint_results
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_constraint_results_project ON cloud_constraint_results(project_id);

-- ── cloud_contracts (from drift.db contracts) ® REDACT: source_file ──
CREATE TABLE cloud_contracts (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      TEXT NOT NULL,
    paradigm      TEXT NOT NULL,
    source_file   TEXT NOT NULL,        -- relativized
    framework     TEXT NOT NULL,
    confidence    DOUBLE PRECISION NOT NULL,
    endpoints     TEXT NOT NULL,
    created_at    BIGINT NOT NULL,
    updated_at    BIGINT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_contracts ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_contracts FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_contracts_isolation ON cloud_contracts
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_contracts_project ON cloud_contracts(project_id);
CREATE INDEX idx_cloud_contracts_paradigm ON cloud_contracts(paradigm);

-- ── cloud_contract_mismatches (from drift.db contract_mismatches) ──
CREATE TABLE cloud_contract_mismatches (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      BIGINT NOT NULL,
    backend_endpoint TEXT NOT NULL,
    frontend_call TEXT NOT NULL,
    mismatch_type TEXT NOT NULL,
    severity      TEXT NOT NULL,
    message       TEXT NOT NULL,
    created_at    BIGINT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_contract_mismatches ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_contract_mismatches FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_contract_mismatches_isolation ON cloud_contract_mismatches
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_contract_mismatches_project ON cloud_contract_mismatches(project_id);
CREATE INDEX idx_cloud_contract_mismatches_type ON cloud_contract_mismatches(mismatch_type);

-- ── cloud_constants (from drift.db constants) ® REDACT: file ──
CREATE TABLE cloud_constants (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      BIGINT NOT NULL,
    name          TEXT NOT NULL,
    value         TEXT NOT NULL,
    file          TEXT NOT NULL,        -- relativized
    line          BIGINT NOT NULL,
    is_used       BOOLEAN NOT NULL DEFAULT true,
    language      TEXT NOT NULL,
    is_named      BOOLEAN NOT NULL DEFAULT true,
    created_at    BIGINT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_constants ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_constants FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_constants_isolation ON cloud_constants
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_constants_project ON cloud_constants(project_id);

-- ── cloud_secrets (from drift.db secrets) ® REDACT: file, redacted_value ──
CREATE TABLE cloud_secrets (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      BIGINT NOT NULL,
    pattern_name  TEXT NOT NULL,
    redacted_value TEXT NOT NULL,       -- already redacted locally; double-redact to [REDACTED]
    file          TEXT NOT NULL,        -- relativized
    line          BIGINT NOT NULL,
    severity      TEXT NOT NULL,
    entropy       DOUBLE PRECISION NOT NULL,
    confidence    DOUBLE PRECISION NOT NULL,
    cwe_ids       TEXT NOT NULL,
    created_at    BIGINT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_secrets FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_secrets_isolation ON cloud_secrets
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_secrets_project ON cloud_secrets(project_id);
CREATE INDEX idx_cloud_secrets_severity ON cloud_secrets(severity);

-- ── cloud_env_variables (from drift.db env_variables) ® REDACT: file ──
CREATE TABLE cloud_env_variables (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      BIGINT NOT NULL,
    name          TEXT NOT NULL,
    file          TEXT NOT NULL,        -- relativized
    line          BIGINT NOT NULL,
    access_method TEXT NOT NULL,
    has_default   BOOLEAN NOT NULL DEFAULT false,
    defined_in_env BOOLEAN NOT NULL DEFAULT false,
    framework_prefix TEXT,
    created_at    BIGINT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_env_variables ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_env_variables FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_env_variables_isolation ON cloud_env_variables
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_env_variables_project ON cloud_env_variables(project_id);
CREATE INDEX idx_cloud_env_variables_name ON cloud_env_variables(name);

-- ── cloud_wrappers (from drift.db wrappers) ® REDACT: file ──
CREATE TABLE cloud_wrappers (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      BIGINT NOT NULL,
    name          TEXT NOT NULL,
    file          TEXT NOT NULL,        -- relativized
    line          BIGINT NOT NULL,
    category      TEXT NOT NULL,
    wrapped_primitives TEXT NOT NULL,
    framework     TEXT NOT NULL,
    confidence    DOUBLE PRECISION NOT NULL,
    is_multi_primitive BOOLEAN NOT NULL DEFAULT false,
    is_exported   BOOLEAN NOT NULL DEFAULT false,
    usage_count   BIGINT NOT NULL DEFAULT 0,
    created_at    BIGINT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_wrappers ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_wrappers FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_wrappers_isolation ON cloud_wrappers
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_wrappers_project ON cloud_wrappers(project_id);
CREATE INDEX idx_cloud_wrappers_category ON cloud_wrappers(category);

-- ── cloud_dna_genes (from drift.db dna_genes) ──
CREATE TABLE cloud_dna_genes (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      TEXT NOT NULL,        -- gene_id
    name          TEXT NOT NULL,
    description   TEXT NOT NULL,
    dominant_allele TEXT,
    alleles       TEXT NOT NULL,
    confidence    DOUBLE PRECISION NOT NULL,
    consistency   DOUBLE PRECISION NOT NULL,
    exemplars     TEXT NOT NULL,
    updated_at    BIGINT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_dna_genes ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_dna_genes FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_dna_genes_isolation ON cloud_dna_genes
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_dna_genes_project ON cloud_dna_genes(project_id);

-- ── cloud_dna_mutations (from drift.db dna_mutations) ® REDACT: file, code ──
CREATE TABLE cloud_dna_mutations (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      TEXT NOT NULL,
    file          TEXT NOT NULL,        -- relativized
    line          BIGINT NOT NULL,
    gene_id       TEXT NOT NULL,
    expected      TEXT NOT NULL,
    actual        TEXT NOT NULL,
    impact        TEXT NOT NULL,
    code          TEXT,                 -- redacted to NULL before sync
    suggestion    TEXT NOT NULL,
    detected_at   BIGINT NOT NULL,
    resolved      BOOLEAN NOT NULL DEFAULT false,
    resolved_at   BIGINT,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_dna_mutations ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_dna_mutations FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_dna_mutations_isolation ON cloud_dna_mutations
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_dna_mutations_project ON cloud_dna_mutations(project_id);
CREATE INDEX idx_cloud_dna_mutations_gene ON cloud_dna_mutations(gene_id);

-- ── cloud_crypto_findings (from drift.db crypto_findings) ® REDACT: file, code ──
CREATE TABLE cloud_crypto_findings (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      BIGINT NOT NULL,
    file          TEXT NOT NULL,        -- relativized
    line          BIGINT NOT NULL,
    category      TEXT NOT NULL,
    description   TEXT NOT NULL,
    code          TEXT,                 -- redacted to NULL before sync
    confidence    DOUBLE PRECISION NOT NULL,
    cwe_id        BIGINT NOT NULL,
    owasp         TEXT NOT NULL,
    remediation   TEXT NOT NULL,
    language      TEXT NOT NULL,
    created_at    BIGINT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_crypto_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_crypto_findings FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_crypto_findings_isolation ON cloud_crypto_findings
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_crypto_findings_project ON cloud_crypto_findings(project_id);
CREATE INDEX idx_cloud_crypto_findings_cwe ON cloud_crypto_findings(cwe_id);

-- ── cloud_owasp_findings (from drift.db owasp_findings) ® REDACT: file ──
CREATE TABLE cloud_owasp_findings (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      TEXT NOT NULL,
    detector      TEXT NOT NULL,
    file          TEXT NOT NULL,        -- relativized
    line          BIGINT NOT NULL,
    description   TEXT NOT NULL,
    severity      DOUBLE PRECISION NOT NULL,
    cwes          TEXT NOT NULL,
    owasp_categories TEXT NOT NULL,
    confidence    DOUBLE PRECISION NOT NULL,
    remediation   TEXT,
    created_at    BIGINT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_owasp_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_owasp_findings FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_owasp_findings_isolation ON cloud_owasp_findings
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_owasp_findings_project ON cloud_owasp_findings(project_id);
CREATE INDEX idx_cloud_owasp_findings_detector ON cloud_owasp_findings(detector);

-- ── cloud_decomposition_decisions (from drift.db decomposition_decisions) ──
CREATE TABLE cloud_decomposition_decisions (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      BIGINT NOT NULL,
    dna_profile_hash TEXT NOT NULL,
    adjustment    TEXT NOT NULL,
    confidence    DOUBLE PRECISION NOT NULL,
    dna_similarity DOUBLE PRECISION NOT NULL,
    narrative     TEXT NOT NULL,
    source_dna_hash TEXT NOT NULL,
    applied_weight DOUBLE PRECISION NOT NULL,
    created_at    BIGINT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_decomposition_decisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_decomposition_decisions FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_decomposition_decisions_isolation ON cloud_decomposition_decisions
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_decomposition_decisions_project ON cloud_decomposition_decisions(project_id);

-- ════════════════════════════════════════════════════════════════════════════
-- ENFORCEMENT (7 tables)
-- ════════════════════════════════════════════════════════════════════════════

-- ── cloud_violations (from drift.db violations) ® REDACT: file ──
CREATE TABLE cloud_violations (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      TEXT NOT NULL,
    file          TEXT NOT NULL,        -- relativized
    line          BIGINT NOT NULL,
    column_num    BIGINT,
    end_line      BIGINT,
    end_column    BIGINT,
    severity      TEXT NOT NULL,
    pattern_id    TEXT NOT NULL,
    rule_id       TEXT NOT NULL,
    message       TEXT NOT NULL,
    quick_fix_strategy TEXT,
    quick_fix_description TEXT,
    cwe_id        BIGINT,
    owasp_category TEXT,
    suppressed    BOOLEAN NOT NULL DEFAULT false,
    is_new        BOOLEAN NOT NULL DEFAULT false,
    created_at    BIGINT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_violations ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_violations FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_violations_isolation ON cloud_violations
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_violations_project ON cloud_violations(project_id);
CREATE INDEX idx_cloud_violations_severity ON cloud_violations(severity);
CREATE INDEX idx_cloud_violations_pattern ON cloud_violations(pattern_id);
CREATE INDEX idx_cloud_violations_rule ON cloud_violations(rule_id);

-- ── cloud_gate_results (from drift.db gate_results) ──
CREATE TABLE cloud_gate_results (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      BIGINT NOT NULL,
    gate_id       TEXT NOT NULL,
    status        TEXT NOT NULL,
    passed        BOOLEAN NOT NULL,
    score         DOUBLE PRECISION NOT NULL,
    summary       TEXT NOT NULL,
    violation_count BIGINT NOT NULL DEFAULT 0,
    warning_count BIGINT NOT NULL DEFAULT 0,
    execution_time_ms BIGINT NOT NULL DEFAULT 0,
    details       TEXT,
    error         TEXT,
    run_at        BIGINT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_gate_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_gate_results FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_gate_results_isolation ON cloud_gate_results
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_gate_results_project ON cloud_gate_results(project_id);
CREATE INDEX idx_cloud_gate_results_gate ON cloud_gate_results(gate_id);
CREATE INDEX idx_cloud_gate_results_run ON cloud_gate_results(run_at);

-- ── cloud_audit_snapshots (from drift.db audit_snapshots) ──
CREATE TABLE cloud_audit_snapshots (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      BIGINT NOT NULL,
    health_score  DOUBLE PRECISION NOT NULL,
    avg_confidence DOUBLE PRECISION NOT NULL,
    approval_ratio DOUBLE PRECISION NOT NULL,
    compliance_rate DOUBLE PRECISION NOT NULL,
    cross_validation_rate DOUBLE PRECISION NOT NULL,
    duplicate_free_rate DOUBLE PRECISION NOT NULL,
    pattern_count BIGINT NOT NULL DEFAULT 0,
    category_scores TEXT,
    created_at    BIGINT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_audit_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_audit_snapshots FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_audit_snapshots_isolation ON cloud_audit_snapshots
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_audit_snapshots_project ON cloud_audit_snapshots(project_id);

-- ── cloud_health_trends (from drift.db health_trends) ──
CREATE TABLE cloud_health_trends (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      BIGINT NOT NULL,
    metric_name   TEXT NOT NULL,
    metric_value  DOUBLE PRECISION NOT NULL,
    recorded_at   BIGINT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_health_trends ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_health_trends FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_health_trends_isolation ON cloud_health_trends
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_health_trends_project ON cloud_health_trends(project_id);
CREATE INDEX idx_cloud_health_trends_metric ON cloud_health_trends(metric_name);

-- ── cloud_feedback (from drift.db feedback) ──
CREATE TABLE cloud_feedback (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      BIGINT NOT NULL,
    violation_id  TEXT NOT NULL,
    pattern_id    TEXT NOT NULL,
    detector_id   TEXT NOT NULL,
    action        TEXT NOT NULL,
    dismissal_reason TEXT,
    reason        TEXT,
    author        TEXT,
    created_at    BIGINT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_feedback ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_feedback FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_feedback_isolation ON cloud_feedback
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_feedback_project ON cloud_feedback(project_id);
CREATE INDEX idx_cloud_feedback_pattern ON cloud_feedback(pattern_id);

-- ── cloud_policy_results (from drift.db policy_results) ──
CREATE TABLE cloud_policy_results (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      BIGINT NOT NULL,
    policy_name   TEXT NOT NULL,
    aggregation_mode TEXT NOT NULL,
    overall_passed BOOLEAN NOT NULL,
    overall_score DOUBLE PRECISION NOT NULL,
    gate_count    BIGINT NOT NULL,
    gates_passed  BIGINT NOT NULL,
    gates_failed  BIGINT NOT NULL,
    details       TEXT,
    run_at        BIGINT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_policy_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_policy_results FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_policy_results_isolation ON cloud_policy_results
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_policy_results_project ON cloud_policy_results(project_id);

-- ── cloud_degradation_alerts (from drift.db degradation_alerts) ──
CREATE TABLE cloud_degradation_alerts (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      BIGINT NOT NULL,
    alert_type    TEXT NOT NULL,
    severity      TEXT NOT NULL,
    message       TEXT NOT NULL,
    current_value DOUBLE PRECISION NOT NULL,
    previous_value DOUBLE PRECISION NOT NULL,
    delta         DOUBLE PRECISION NOT NULL,
    created_at    BIGINT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_degradation_alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_degradation_alerts FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_degradation_alerts_isolation ON cloud_degradation_alerts
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_degradation_alerts_project ON cloud_degradation_alerts(project_id);
CREATE INDEX idx_cloud_degradation_alerts_type ON cloud_degradation_alerts(alert_type);

-- ════════════════════════════════════════════════════════════════════════════
-- BRIDGE (5 tables)
-- ════════════════════════════════════════════════════════════════════════════

-- ── cloud_bridge_memories (from bridge.db bridge_memories) ──
CREATE TABLE cloud_bridge_memories (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      TEXT NOT NULL,        -- memory id
    memory_type   TEXT NOT NULL,
    content       TEXT NOT NULL,
    summary       TEXT NOT NULL,
    confidence    DOUBLE PRECISION NOT NULL,
    importance    TEXT NOT NULL,
    tags          TEXT NOT NULL DEFAULT '[]',
    linked_patterns TEXT NOT NULL DEFAULT '[]',
    created_at    BIGINT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_bridge_memories ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_bridge_memories FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_bridge_memories_isolation ON cloud_bridge_memories
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_bridge_memories_project ON cloud_bridge_memories(project_id);
CREATE INDEX idx_cloud_bridge_memories_type ON cloud_bridge_memories(memory_type);

-- ── cloud_grounding_results (from bridge.db bridge_grounding_results) ──
CREATE TABLE cloud_grounding_results (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      BIGINT NOT NULL,
    memory_id     TEXT NOT NULL,
    grounding_score DOUBLE PRECISION NOT NULL,
    classification TEXT NOT NULL,
    evidence      TEXT NOT NULL,
    created_at    BIGINT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_grounding_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_grounding_results FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_grounding_results_isolation ON cloud_grounding_results
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_grounding_results_project ON cloud_grounding_results(project_id);
CREATE INDEX idx_cloud_grounding_results_memory ON cloud_grounding_results(memory_id);

-- ── cloud_grounding_snapshots (from bridge.db bridge_grounding_snapshots) ──
CREATE TABLE cloud_grounding_snapshots (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      BIGINT NOT NULL,
    total_memories BIGINT NOT NULL,
    grounded_count BIGINT NOT NULL,
    validated_count BIGINT NOT NULL,
    partial_count BIGINT NOT NULL,
    weak_count    BIGINT NOT NULL,
    invalidated_count BIGINT NOT NULL,
    avg_score     DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    error_count   BIGINT NOT NULL DEFAULT 0,
    trigger_type  TEXT,
    created_at    BIGINT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_grounding_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_grounding_snapshots FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_grounding_snapshots_isolation ON cloud_grounding_snapshots
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_grounding_snapshots_project ON cloud_grounding_snapshots(project_id);

-- ── cloud_bridge_events (from bridge.db bridge_event_log) ──
CREATE TABLE cloud_bridge_events (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      BIGINT NOT NULL,
    event_type    TEXT NOT NULL,
    memory_type   TEXT,
    memory_id     TEXT,
    confidence    DOUBLE PRECISION,
    created_at    BIGINT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_bridge_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_bridge_events FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_bridge_events_isolation ON cloud_bridge_events
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_bridge_events_project ON cloud_bridge_events(project_id);
CREATE INDEX idx_cloud_bridge_events_type ON cloud_bridge_events(event_type);

-- ── cloud_bridge_metrics (from bridge.db bridge_metrics) ──
CREATE TABLE cloud_bridge_metrics (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id      BIGINT NOT NULL,
    metric_name   TEXT NOT NULL,
    metric_value  DOUBLE PRECISION NOT NULL,
    recorded_at   BIGINT NOT NULL,
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, local_id)
);
ALTER TABLE cloud_bridge_metrics ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_bridge_metrics FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_bridge_metrics_isolation ON cloud_bridge_metrics
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_bridge_metrics_project ON cloud_bridge_metrics(project_id);
CREATE INDEX idx_cloud_bridge_metrics_name ON cloud_bridge_metrics(metric_name);
