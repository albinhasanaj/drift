# Agent Prompt: Cloud Data Pipeline — Local SQLite → Hosted Supabase Sync

## Your Mission

Build the complete data pipeline connecting Drift's 3 local SQLite databases to hosted Supabase/Postgres. **This is the missing foundation** between storage traits (Phases A-C, done) and enterprise features (Phases D-F, parked).

**92 local tables** audited. **73 syncable** (metadata only). **19 LOCAL-ONLY**. You will build:

1. **Cloud Postgres schema** — 73 `cloud_*` tables with `tenant_id`, `project_id`, RLS
2. **Redaction layer** — pure functions stripping paths, secrets, source code
3. **NAPI sync export** — new Rust functions extracting raw rows with delta cursors
4. **TypeScript sync client** — NAPI → redact → PostgREST upsert
5. **CLI commands** — `drift cloud login/push/status/logout`
6. **Dashboard views** — Postgres aggregation views for GUI
7. **Cortex stub wiring** — existing `cortexCloudSync()` stubs produce real results

**Source code never leaves the developer's machine. Only metadata syncs.**

---

## Documents You MUST Read Before Writing Any Code

1. **`docs/v2-research/CLOUD-DATA-PIPELINE-PLAN.md`** — Verified plan: 92 tables, sync classification, tier assignments (T1:42, T2:19, T3:12), redaction rules.
2. **`supabase/migrations/20260211000000_base_cloud_tables.sql`** — Existing `tenants`, `projects`, `set_tenant_context()` with RLS.
3. **`supabase/functions/sync/index.ts`** — Sync stub. Stores NOTHING. You bypass it via PostgREST.
4. **`crates/drift/drift-napi/src/runtime.rs`** — `DriftRuntime` with `storage: Arc<DriftStorageEngine>`, `bridge_store`.
5. **`crates/drift/drift-napi/src/bindings/`** — 10 binding modules. Study `rt.storage().with_reader()` pattern.
6. **`packages/cortex/src/bridge/client.ts`** — `CortexClient` with `cloudSync()`, `cloudStatus()`, `cloudResolveConflict()` stubs.
7. **`packages/cortex/src/cli/cloud.ts`** — CLI `sync/status/resolve` subcommands calling CortexClient stubs.
8. **`crates/drift/drift-storage/src/migrations/`** — v001-v007 defining all 45 drift.db tables.

**Comprehension questions (must answer all before coding):**
- Total tables across 3 DBs? (**92**: 45 drift + 6 bridge + 41 cortex)
- Tables syncing to cloud? (**73**: 42 drift + 5 bridge + 26 cortex)
- LOCAL-ONLY count? (**19**: 3 drift + 1 bridge + 15 cortex)
- Tables needing REDACT? (**19**: 17 drift + 2 cortex)
- Why PostgREST not Edge Functions? (Auto-generated REST, RLS enforced, zero server code)

---

## Phase Execution Order

### Sub-Phase P1: Cloud Postgres Schema (73 tables, 3 migrations)

**Goal:** Create cloud-side tables with `tenant_id`, `project_id`, RLS, indexes.

**Files to create:**
- `supabase/migrations/20260212000000_cloud_tier1_tables.sql` — 42 tables
- `supabase/migrations/20260212000001_cloud_tier2_tables.sql` — 19 tables
- `supabase/migrations/20260212000002_cloud_tier3_tables.sql` — 12 tables

**Design Rules:**
1. Every table: `tenant_id UUID NOT NULL REFERENCES tenants(id)`, `project_id UUID NOT NULL REFERENCES projects(id)`
2. Every table: `ENABLE ROW LEVEL SECURITY` + `FORCE ROW LEVEL SECURITY` + tenant policy
3. Cloud PK: `id UUID PRIMARY KEY DEFAULT gen_random_uuid()`
4. Local PK → `local_id` column with `UNIQUE(project_id, local_id)`
5. Every row: `synced_at TIMESTAMPTZ NOT NULL DEFAULT now()`
6. Types: SQLite INTEGER→BIGINT, REAL→DOUBLE PRECISION, TEXT→TEXT

**Representative pattern (all 73 follow this):**

```sql
CREATE TABLE IF NOT EXISTS cloud_violations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    local_id TEXT NOT NULL,
    file TEXT, line INT, column_num INT, end_line INT, end_column INT,
    severity TEXT NOT NULL, pattern_id TEXT, rule_id TEXT NOT NULL,
    message TEXT NOT NULL, cwe_id INT, owasp_category TEXT,
    suppressed BOOLEAN NOT NULL DEFAULT false,
    is_new BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ, synced_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(project_id, local_id)
);
ALTER TABLE cloud_violations ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_violations FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_violations_tenant_isolation ON cloud_violations
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_cloud_violations_tenant ON cloud_violations(tenant_id);
CREATE INDEX idx_cloud_violations_project ON cloud_violations(project_id);
```

**Tier 1 (42 tables):** `cloud_scan_history`, `cloud_file_stats`, `cloud_functions`, `cloud_call_edges`, `cloud_data_access`, `cloud_detections`, `cloud_boundaries`, `cloud_pattern_confidence`, `cloud_outliers`, `cloud_conventions`, `cloud_taint_flows`, `cloud_error_gaps`, `cloud_impact_scores`, `cloud_test_coverage`, `cloud_test_quality`, `cloud_coupling_metrics`, `cloud_coupling_cycles`, `cloud_constraints`, `cloud_constraint_results`, `cloud_contracts`, `cloud_contract_mismatches`, `cloud_constants`, `cloud_secrets`, `cloud_env_variables`, `cloud_wrappers`, `cloud_dna_genes`, `cloud_dna_mutations`, `cloud_crypto_findings`, `cloud_owasp_findings`, `cloud_decomposition_decisions`, `cloud_violations`, `cloud_gate_results`, `cloud_audit_snapshots`, `cloud_health_trends`, `cloud_feedback`, `cloud_policy_results`, `cloud_degradation_alerts`, `cloud_bridge_memories`, `cloud_grounding_results`, `cloud_grounding_snapshots`, `cloud_bridge_events`, `cloud_bridge_metrics`

**Tier 2 (19 tables):** `cloud_memories`, `cloud_memory_relationships`, `cloud_memory_patterns`, `cloud_memory_constraints`, `cloud_memory_files`, `cloud_memory_functions`, `cloud_causal_edges`, `cloud_causal_evidence`, `cloud_memory_audit_log`, `cloud_consolidation_metrics`, `cloud_cortex_degradation_log`, `cloud_memory_validation`, `cloud_memory_contradictions`, `cloud_memory_versions`, `cloud_memory_events`, `cloud_memory_snapshots`, `cloud_simulations`, `cloud_decisions`, `cloud_embedding_models`

**Tier 3 (12 tables):** `cloud_agent_registry`, `cloud_memory_namespaces`, `cloud_namespace_permissions`, `cloud_memory_projections`, `cloud_provenance_log`, `cloud_agent_trust`, `cloud_reclassification_history`, `cloud_reclassification_signals`, `cloud_drift_snapshots`, `cloud_migration_projects`, `cloud_migration_modules`, `cloud_migration_corrections`

**Gate:** `supabase db reset` succeeds. Cloud table count = **73**. RLS forced on all.

---

### Sub-Phase P2: Redaction Layer

**Goal:** Pure-function TS module transforming local rows into cloud-safe rows.

**File to create:** `packages/drift/src/cloud/redact.ts`

**19 REDACT tables with field rules:**

| Field Pattern | Rule | Tables |
|---|---|---|
| `file`, `path`, `source_file`, `sink_file`, `file_path` | `path.relative(projectRoot, abs)` | file_metadata, functions, scan_history, detections, boundaries, outliers, taint_flows, error_gaps, contracts, constants, secrets, env_variables, wrappers, dna_mutations, crypto_findings, owasp_findings, violations, memory_files, memory_functions |
| `root_path` | Strip → `""` | scan_history |
| `code`, `snippet`, `matched_text` | Set → `null` | detections, dna_mutations, crypto_findings, memory_files |
| `body_hash`, `signature_hash`, `content_hash` | Delete field | file_metadata, functions |

**Implementation:** `redactRow(table, row, config)` applies per-table rules. SYNC tables pass unchanged. `redactBatch(table, rows, config)` maps over array.

**Gate:** Unit tests for path relativization, code stripping, hash dropping, passthrough.

---

### Sub-Phase P3: Sync Client + NAPI Export

#### P3a: NAPI Export (Rust)

**Files:**
- `crates/drift/drift-napi/src/bindings/sync_export.rs` (NEW)
- `crates/drift/drift-napi/src/bindings/mod.rs` — add `pub mod sync_export;`

**Design:**

```rust
/// Hardcoded allowlist — 42 drift.db syncable tables
static DRIFT_SYNCABLE: &[&str] = &[
    "file_metadata", "functions", "scan_history",
    "call_edges", "data_access", "detections", "boundaries",
    "pattern_confidence", "outliers", "conventions",
    "taint_flows", "error_gaps", "impact_scores", "test_coverage", "test_quality",
    "coupling_metrics", "coupling_cycles", "constraints", "constraint_verifications",
    "contracts", "contract_mismatches", "constants", "secrets", "env_variables",
    "wrappers", "dna_genes", "dna_mutations", "crypto_findings", "owasp_findings",
    "decomposition_decisions",
    "violations", "gate_results", "audit_snapshots", "health_trends",
    "feedback", "policy_results", "degradation_alerts",
    "simulations", "decisions", "migration_projects", "migration_modules",
    "migration_corrections",
];

/// 5 bridge.db syncable tables
static BRIDGE_SYNCABLE: &[&str] = &[
    "bridge_grounding_results", "bridge_grounding_snapshots",
    "bridge_event_log", "bridge_metrics", "bridge_memories",
];

#[napi]
pub fn drift_sync_export(table: String, after_rowid: Option<i64>, limit: Option<u32>)
    -> napi::Result<String> {
    // 1. Validate against DRIFT_SYNCABLE (reject if not found)
    // 2. rt.storage().with_reader(|conn| SELECT * FROM {table} WHERE rowid > ? LIMIT ?)
    // 3. Return JSON: { rows: [...], cursor: max_rowid, has_more: bool }
}

#[napi]
pub fn bridge_sync_export(table: String, after_rowid: Option<i64>, limit: Option<u32>)
    -> napi::Result<String> {
    // Same pattern for bridge.db
}
```

**For cortex.db (26 tables):** Add `cortex_sync_export` to cortex NAPI or through CortexClient.

**Critical:** Table name validated against hardcoded allowlist. SQL injection impossible. Batch capped at 1000. Delta via SQLite rowid.

#### P3b: TypeScript Sync Client

**Files:**
- `packages/drift/src/cloud/config.ts` — cloud config types
- `packages/drift/src/cloud/auth.ts` — login (browser OAuth), token management, logout
- `packages/drift/src/cloud/sync-client.ts` — NAPI export → redact → PostgREST upsert

**Sync protocol per table:**
1. Export batch via NAPI (`drift_sync_export(table, cursor, 1000)`)
2. Redact via `redactBatch()`
3. Add `tenant_id` + `project_id` + map `local_id`
4. Upsert via PostgREST: `supabase.from(cloudTable).upsert(rows, { onConflict: "project_id,local_id" })`
5. Update cursor, loop if `has_more`

**Credentials:** `~/.drift/cloud-credentials.json` (supabaseUrl, tokens, tenantId, projectId).

**Gate:** `SyncClient.push()` uploads rows. Delta sync only uploads new rows.

---

### Sub-Phase P4: CLI Wiring

**File to create:** `packages/drift-cli/src/commands/cloud.ts`
**File to modify:** `packages/drift-cli/src/commands/index.ts`

| Command | Description |
|---|---|
| `drift cloud login` | Browser OAuth → store JWT |
| `drift cloud push` | Sync pipeline with progress bar |
| `drift cloud push --full` | Ignore cursors, re-upload all |
| `drift cloud status` | Last sync time, rows, project info |
| `drift cloud logout` | Clear credentials |

**Gate:** Round-trip: login → push → status → logout.

---

### Sub-Phase P5: Dashboard Views

**File to create:** `supabase/migrations/20260212000003_dashboard_views.sql`

| View | Purpose |
|---|---|
| `v_project_health` | violation count, gate pass rate, confidence, DNA health |
| `v_trend_violations` | Daily violation count, 30 days |
| `v_top_violations` | Most frequent rules |
| `v_security_posture` | OWASP + CWE + taint + crypto counts |
| `v_pattern_summary` | Pattern count, confidence, conventions, outliers |
| `v_coupling_overview` | Modules, cycles, instability, zone of pain |

**Gate:** `GET /rest/v1/v_project_health` returns data via PostgREST.

---

### Sub-Phase P6: Wire Cortex Stubs

**Files to modify:**
- `packages/cortex/src/bridge/client.ts` — `cloudSync()` → `SyncClient.push()`
- `packages/cortex/src/cli/cloud.ts` — wire to real sync
- `packages/cortex/src/tools/system/drift_cloud_sync.ts` — wire MCP tool
- `packages/cortex/src/tools/system/drift_cloud_status.ts` — wire MCP tool

**10 stubs:** 3 NAPI, 3 CortexClient methods, 1 CLI command group, 3 MCP tools.

**Gate:** `drift cortex cloud sync` pushes real data.

---

## Tests (18 total)

### Schema Tests (`supabase/tests/cloud-schema.test.ts`)

| ID | Test | Proves |
|---|---|---|
| CDP-01 | `supabase db reset` → 73 cloud tables exist | Schema created |
| CDP-02 | Insert as tenant A → query as tenant B → 0 rows | RLS isolation |
| CDP-03 | Insert without tenant_id → error | NOT NULL enforced |
| CDP-04 | Duplicate `(project_id, local_id)` → upsert | Unique constraint |

### Redaction Tests (`packages/drift/tests/cloud/redact.test.ts`)

| ID | Test | Proves |
|---|---|---|
| CDP-05 | `/Users/x/proj/src/a.ts` → `src/a.ts` | Path relativization |
| CDP-06 | `matched_text: "const x"` → `null` | Code stripping |
| CDP-07 | `root_path: "/Users/x/proj"` → `""` | Root stripped |
| CDP-08 | SYNC table row → unchanged | Passthrough |
| CDP-09 | `body_hash` + `content_hash` → deleted | Hash dropping |

### NAPI Export Tests (`crates/drift/drift-napi/tests/sync_export_test.rs`)

| ID | Test | Proves |
|---|---|---|
| CDP-10 | `drift_sync_export("violations", None, Some(10))` → valid JSON | Export works |
| CDP-11 | `drift_sync_export("parse_cache", ...)` → error | Allowlist enforced |
| CDP-12 | Insert 5, export after_rowid=3 → 2 rows | Delta cursor |
| CDP-13 | `bridge_sync_export("bridge_memories", ...)` → valid JSON | Bridge export |

### Sync Client Tests (`packages/drift/tests/cloud/sync-client.test.ts`)

| ID | Test | Proves |
|---|---|---|
| CDP-14 | `push()` → rows in cloud table | End-to-end |
| CDP-15 | Push → modify → push → only new rows | Delta sync |
| CDP-16 | Abs paths → relative in cloud | Redaction pipeline |
| CDP-17 | Code fields → null in cloud | Code stripping |

### CLI Test (`packages/drift-cli/tests/cloud.test.ts`)

| ID | Test | Proves |
|---|---|---|
| CDP-18 | `drift cloud` has login/push/status/logout | CLI wired |

---

## Architecture Constraints

1. **Source code NEVER syncs.** `matched_text`, `code`, `snippet` → `null`.
2. **Absolute paths NEVER sync.** All relativized. Grep `/Users/` or `/home/` = 0.
3. **RLS on EVERY cloud table.** ENABLE + FORCE + tenant policy. No exceptions.
4. **Push-only (v1).** Local = source of truth. No pull. `cloudResolveConflict()` stays no-op.
5. **PostgREST for data, NOT Edge Functions.** Sync stub stays for webhooks only.
6. **NAPI allowlist is hardcoded.** No dynamic table names. SQL injection impossible.
7. **Credentials in `~/.drift/cloud-credentials.json`.** Not project dir.
8. **Batch cap: 1000 rows per request.** Loop with cursor pagination.
9. **Delta via SQLite rowid.** Cursors in cortex.db `sync_state` (v010 migration).
10. **Do NOT change existing NAPI signatures.** Only ADD new functions.
11. **Do NOT modify Rust analysis code.** Only add sync_export.rs.
12. **Do NOT modify existing Supabase migrations** (000000-000008).

---

## Forbidden Actions

1. **Do NOT sync source code.** No `code`/`snippet`/`matched_text`/`body_hash` in cloud.
2. **Do NOT sync absolute paths.** Must relativize all.
3. **Do NOT create tables without RLS.**
4. **Do NOT accept arbitrary table names in NAPI.** Allowlist only.
5. **Do NOT store credentials in project directory.**
6. **Do NOT use `service_role` key in sync client.** User JWT + RLS only.
7. **Do NOT modify existing NAPI function signatures.**
8. **Do NOT sync LOCAL-ONLY tables** (19: parse_cache, reachability_cache, context_cache, memory_embeddings, memory_embedding_link, memory_fts, session_contexts, session_analytics, sync_state, sync_log, conflict_log, metric_snapshots, query_performance_log, memory_events_archive, materialized_views, delta_queue, peer_clocks, bridge_schema_version, schema_version).
9. **Do NOT auto-sync after analyze.** Sync is always explicit.
10. **Do NOT create custom sync Edge Function for data.** PostgREST handles data.

---

## Effort Estimate

| Sub-Phase | Effort | Risk |
|---|---|---|
| P1: Schema (3 migrations, 73 tables) | 2-3d | Mechanical, large |
| P2: Redaction (1 TS module) | 0.5d | Must cover 19 tables |
| P3: Sync + NAPI (2 Rust + 3 TS) | 3-4d | NAPI serialization |
| P4: CLI (1 TS module) | 1-2d | OAuth flow |
| P5: Views (1 migration) | 0.5d | Aggregation SQL |
| P6: Stubs (4 modifications) | 0.5-1d | 10 stubs |
| Tests (18 tests) | 1-2d | Need Supabase |
| **Total** | **8.5-13d** | |

---

## Subsystems That Are Clean (do NOT modify)

- `drift-analysis/` — analysis algorithms
- `drift-storage/src/queries/` — SQL query functions
- `drift-storage/src/migrations/` — SQLite schema
- `drift-storage/src/engine.rs` — Phase B engine
- `cortex-drift-bridge/src/storage/` — Phase C engine
- `supabase/functions/scim-*/` — Phase D
- `supabase/functions/webhooks/` — Phase E
- `supabase/functions/teams/` — Phase F
- `supabase/migrations/20260211000000-000008` — frozen
- Existing NAPI binding files — add sync_export.rs only

---

## Verification Commands

```bash
# 73 cloud tables:
psql "$SUPABASE_DB_URL" -c \
  "SELECT count(*) FROM information_schema.tables WHERE table_name LIKE 'cloud_%';"

# RLS forced on all:
psql "$SUPABASE_DB_URL" -c \
  "SELECT count(*) FROM pg_class WHERE relname LIKE 'cloud_%' AND relforcerowsecurity = true;"

# Zero absolute paths:
psql "$SUPABASE_DB_URL" -c \
  "SELECT count(*) FROM cloud_violations WHERE file LIKE '/Users/%' OR file LIKE '/home/%';"

# Zero source code:
psql "$SUPABASE_DB_URL" -c \
  "SELECT count(*) FROM cloud_detections WHERE matched_text IS NOT NULL;"

# CLI registered:
npx drift cloud --help

# No existing bindings modified:
git diff --name-only crates/drift/drift-napi/src/bindings/ \
  | grep -v sync_export | grep -v mod.rs
```

---

## Quality Gate (QG-CDP) — All Must Pass

- [ ] 73 `cloud_*` tables with RLS enabled + forced
- [ ] `UNIQUE(project_id, local_id)` on all 73
- [ ] Redaction covers 19 REDACT tables
- [ ] `drift_sync_export` with 42-table allowlist
- [ ] `bridge_sync_export` with 5-table allowlist
- [ ] Cortex sync covers 26 tables
- [ ] `SyncClient.push()` uploads to 73 cloud tables
- [ ] Delta sync works (only new rows)
- [ ] Zero absolute paths in cloud (SQL verified)
- [ ] Zero source code in cloud (SQL verified)
- [ ] `drift cloud login/push/status/logout` work
- [ ] 6 dashboard views queryable
- [ ] 10 cortex stubs wired
- [ ] Sync Edge Function not broken
- [ ] 18 tests pass
- [ ] `cargo clippy -p drift-napi -- -D warnings` clean
- [ ] `tsc --noEmit` clean
- [ ] 19 LOCAL-ONLY tables not exported

---

## Appendix A: Source → Cloud Table Mapping (73 entries)

### drift.db → Cloud (42 tables)

| # | Source Table | Cloud Table | Tier | Type |
|---|---|---|---|---|
| 1 | `file_metadata` | `cloud_file_stats` | T1 | REDACT |
| 2 | `functions` | `cloud_functions` | T1 | REDACT |
| 3 | `scan_history` | `cloud_scan_history` | T1 | REDACT |
| 4 | `call_edges` | `cloud_call_edges` | T1 | SYNC |
| 5 | `data_access` | `cloud_data_access` | T1 | SYNC |
| 6 | `detections` | `cloud_detections` | T1 | REDACT |
| 7 | `boundaries` | `cloud_boundaries` | T1 | REDACT |
| 8 | `pattern_confidence` | `cloud_pattern_confidence` | T1 | SYNC |
| 9 | `outliers` | `cloud_outliers` | T1 | REDACT |
| 10 | `conventions` | `cloud_conventions` | T1 | SYNC |
| 11 | `taint_flows` | `cloud_taint_flows` | T1 | REDACT |
| 12 | `error_gaps` | `cloud_error_gaps` | T1 | REDACT |
| 13 | `impact_scores` | `cloud_impact_scores` | T1 | SYNC |
| 14 | `test_coverage` | `cloud_test_coverage` | T1 | SYNC |
| 15 | `test_quality` | `cloud_test_quality` | T1 | SYNC |
| 16 | `coupling_metrics` | `cloud_coupling_metrics` | T1 | SYNC |
| 17 | `coupling_cycles` | `cloud_coupling_cycles` | T1 | SYNC |
| 18 | `constraints` | `cloud_constraints` | T1 | SYNC |
| 19 | `constraint_verifications` | `cloud_constraint_results` | T1 | SYNC |
| 20 | `contracts` | `cloud_contracts` | T1 | REDACT |
| 21 | `contract_mismatches` | `cloud_contract_mismatches` | T1 | SYNC |
| 22 | `constants` | `cloud_constants` | T1 | REDACT |
| 23 | `secrets` | `cloud_secrets` | T1 | REDACT |
| 24 | `env_variables` | `cloud_env_variables` | T1 | REDACT |
| 25 | `wrappers` | `cloud_wrappers` | T1 | REDACT |
| 26 | `dna_genes` | `cloud_dna_genes` | T1 | SYNC |
| 27 | `dna_mutations` | `cloud_dna_mutations` | T1 | REDACT |
| 28 | `crypto_findings` | `cloud_crypto_findings` | T1 | REDACT |
| 29 | `owasp_findings` | `cloud_owasp_findings` | T1 | REDACT |
| 30 | `decomposition_decisions` | `cloud_decomposition_decisions` | T1 | SYNC |
| 31 | `violations` | `cloud_violations` | T1 | REDACT |
| 32 | `gate_results` | `cloud_gate_results` | T1 | SYNC |
| 33 | `audit_snapshots` | `cloud_audit_snapshots` | T1 | SYNC |
| 34 | `health_trends` | `cloud_health_trends` | T1 | SYNC |
| 35 | `feedback` | `cloud_feedback` | T1 | SYNC |
| 36 | `policy_results` | `cloud_policy_results` | T1 | SYNC |
| 37 | `degradation_alerts` | `cloud_degradation_alerts` | T1 | SYNC |
| 38 | `simulations` | `cloud_simulations` | T2 | SYNC |
| 39 | `decisions` | `cloud_decisions` | T2 | SYNC |
| 40 | `migration_projects` | `cloud_migration_projects` | T3 | SYNC |
| 41 | `migration_modules` | `cloud_migration_modules` | T3 | SYNC |
| 42 | `migration_corrections` | `cloud_migration_corrections` | T3 | SYNC |

### bridge.db → Cloud (5 tables)

| # | Source Table | Cloud Table | Tier | Type |
|---|---|---|---|---|
| 43 | `bridge_grounding_results` | `cloud_grounding_results` | T1 | SYNC |
| 44 | `bridge_grounding_snapshots` | `cloud_grounding_snapshots` | T1 | SYNC |
| 45 | `bridge_event_log` | `cloud_bridge_events` | T1 | SYNC |
| 46 | `bridge_metrics` | `cloud_bridge_metrics` | T1 | SYNC |
| 47 | `bridge_memories` | `cloud_bridge_memories` | T1 | SYNC |

### cortex.db → Cloud (26 tables)

| # | Source Table | Cloud Table | Tier | Type |
|---|---|---|---|---|
| 48 | `memories` | `cloud_memories` | T2 | SYNC |
| 49 | `memory_relationships` | `cloud_memory_relationships` | T2 | SYNC |
| 50 | `memory_patterns` | `cloud_memory_patterns` | T2 | SYNC |
| 51 | `memory_constraints` | `cloud_memory_constraints` | T2 | SYNC |
| 52 | `memory_files` | `cloud_memory_files` | T2 | REDACT |
| 53 | `memory_functions` | `cloud_memory_functions` | T2 | REDACT |
| 54 | `causal_edges` | `cloud_causal_edges` | T2 | SYNC |
| 55 | `causal_evidence` | `cloud_causal_evidence` | T2 | SYNC |
| 56 | `memory_audit_log` | `cloud_memory_audit_log` | T2 | SYNC |
| 57 | `consolidation_metrics` | `cloud_consolidation_metrics` | T2 | SYNC |
| 58 | `degradation_log` | `cloud_cortex_degradation_log` | T2 | SYNC |
| 59 | `memory_validation_history` | `cloud_memory_validation` | T2 | SYNC |
| 60 | `memory_contradictions` | `cloud_memory_contradictions` | T2 | SYNC |
| 61 | `memory_versions` | `cloud_memory_versions` | T2 | SYNC |
| 62 | `memory_events` | `cloud_memory_events` | T2 | SYNC |
| 63 | `memory_snapshots` | `cloud_memory_snapshots` | T2 | SYNC |
| 64 | `embedding_model_info` | `cloud_embedding_models` | T2 | SYNC |
| 65 | `reclassification_history` | `cloud_reclassification_history` | T3 | SYNC |
| 66 | `reclassification_signals` | `cloud_reclassification_signals` | T3 | SYNC |
| 67 | `drift_snapshots` | `cloud_drift_snapshots` | T3 | SYNC |
| 68 | `agent_registry` | `cloud_agent_registry` | T3 | SYNC |
| 69 | `memory_namespaces` | `cloud_memory_namespaces` | T3 | SYNC |
| 70 | `namespace_permissions` | `cloud_namespace_permissions` | T3 | SYNC |
| 71 | `memory_projections` | `cloud_memory_projections` | T3 | SYNC |
| 72 | `provenance_log` | `cloud_provenance_log` | T3 | SYNC |
| 73 | `agent_trust` | `cloud_agent_trust` | T3 | SYNC |

**Tier totals:** T1: 37 drift + 5 bridge = 42 ✓ | T2: 17 cortex + 2 drift = 19 ✓ | T3: 9 cortex + 3 drift = 12 ✓

---

## Appendix B: 19 LOCAL-ONLY Tables (never sync)

| # | Table | DB | Reason |
|---|---|---|---|
| 1 | `parse_cache` | drift.db | Content cache, recomputable |
| 2 | `reachability_cache` | drift.db | Graph cache, recomputable |
| 3 | `context_cache` | drift.db | Session-scoped, ephemeral |
| 4 | `memory_embeddings` | cortex.db | BLOB data, recomputable |
| 5 | `memory_embedding_link` | cortex.db | Depends on local embeddings |
| 6 | `memory_fts` | cortex.db | FTS5 virtual table |
| 7 | `session_contexts` | cortex.db | Local session data |
| 8 | `session_analytics` | cortex.db | Local session data |
| 9 | `sync_state` | cortex.db | Sync cursor tracking (local infra) |
| 10 | `sync_log` | cortex.db | Sync history (local infra) |
| 11 | `conflict_log` | cortex.db | Conflict tracking (local infra) |
| 12 | `metric_snapshots` | cortex.db | Performance metrics |
| 13 | `query_performance_log` | cortex.db | Performance metrics |
| 14 | `memory_events_archive` | cortex.db | Archived copy, recomputable |
| 15 | `materialized_views` | cortex.db | Materialized cache |
| 16 | `delta_queue` | cortex.db | CRDT sync queue (local infra) |
| 17 | `peer_clocks` | cortex.db | Vector clocks (local infra) |
| 18 | `bridge_schema_version` | bridge.db | Internal versioning |
| 19 | `schema_version` | cortex.db | Internal versioning |

---

## Appendix C: Cross-Phase Dependency Map

```
Phase A-C (Storage Traits) ← COMPLETE
│
├── DriftStorageEngine.with_reader() ← P3a reads drift.db
├── BridgeStorageEngine.with_reader() ← P3a reads bridge.db
└── IDriftReader trait ← not modified

Phase D-F (Enterprise) ← PARKED
│
├── tenants, projects tables ← P1 references via FK
├── set_tenant_context() ← RLS uses this
└── webhook dispatch ← sync stub fires webhooks

Cloud Data Pipeline (THIS PHASE)
│
├── P1: Schema ──────┐
│                     ├── P5: Views (after P1)
├── P2: Redaction ────┤
│                     ├── P3: Sync Client ── P4: CLI ── P6: Stubs
└─────────────────────┘
```

**Final coverage: 73 SYNC/REDACT + 19 LOCAL-ONLY = 92 total ✓**
**Tier check: T1(42) + T2(19) + T3(12) = 73 ✓**
**Stubs: 10 wired ✓**
