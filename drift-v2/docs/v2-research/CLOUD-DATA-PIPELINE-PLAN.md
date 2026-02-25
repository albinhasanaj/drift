# Drift Cloud Data Pipeline — Implementation Plan

> **Date:** Feb 11, 2026 (Updated: 100% verified audit — 92 tables across 3 DBs)
> **Scope:** Connect Drift's 3 local SQLite databases to hosted Supabase via a metadata-only sync pipeline. This is the missing foundation between the storage traits (Phases A-C, done) and the enterprise features (Phases D-F, parked).
> **Principle:** Source code never leaves the developer's machine. Only metadata syncs to cloud.
> **Constraint:** No local Supabase Docker required. All testing targets hosted Supabase project.
> **Verified:** 92 total tables (45 drift.db + 6 bridge.db + 41 cortex.db) → **73 SYNC/REDACT + 19 LOCAL-ONLY**

---

## Architecture Overview

```
Developer Machine                          Hosted Supabase
┌──────────────────────┐                  ┌──────────────────────────┐
│  drift scan/analyze  │                  │  Postgres (RLS)          │
│         │            │                  │  ┌────────────────────┐  │
│         ▼            │                  │  │ 73 cloud_* tables  │  │
│  ┌─────────────┐     │   delta sync    │  │ (tenant_id + RLS)  │  │
│  │  drift.db   │─────┼────────────────►│  │                    │  │
│  │  (45 tables)│     │   PostgREST     │  │  T1: 42 (core)     │  │
│  └─────────────┘     │   upsert        │  │  T2: 19 (cortex)   │  │
│  ┌─────────────┐     │                  │  │  T3: 12 (future)   │  │
│  │  bridge.db  │─────┼────────────────►│  │                    │  │
│  │  (6 tables) │     │                  │  └────────────────────┘  │
│  └─────────────┘     │                  │                          │
│  ┌─────────────┐     │                  │  PostgREST API ──► GUI  │
│  │  cortex.db  │─────┼────────────────►│                          │
│  │  (41 tables)│     │                  └──────────────────────────┘
│  └─────────────┘     │
│                      │
│  DriftStorageEngine  │
│  BridgeStorageEngine │  (Phase A-C traits)
│  CortexStorageEngine │
└──────────────────────┘
```

---

## Current State Inventory

### What exists and works (the data sources)

**drift.db — 45 tables across 7 migrations (42 SYNC + 3 LOCAL-ONLY):**

| Migration | SYNC/REDACT Tables | LOCAL-ONLY Tables |
|---|---|---|
| v001_initial (4) | `file_metadata` ®, `functions` ®, `scan_history` ® | `parse_cache` |
| v002_analysis (4) | `call_edges`, `data_access`, `detections` ®, `boundaries` ® | — |
| v003_patterns (3) | `pattern_confidence`, `outliers` ®, `conventions` | — |
| v004_graph (6) | `taint_flows` ®, `error_gaps` ®, `impact_scores`, `test_coverage`, `test_quality` | `reachability_cache` |
| v005_structural (15) | `coupling_metrics`, `coupling_cycles`, `constraints`, `constraint_verifications`, `contracts` ®, `contract_mismatches`, `constants` ®, `secrets` ®, `env_variables` ®, `wrappers` ®, `dna_genes`, `dna_mutations` ®, `crypto_findings` ®, `owasp_findings` ®, `decomposition_decisions` | — |
| v006_enforcement (7) | `violations` ®, `gate_results`, `audit_snapshots`, `health_trends`, `feedback`, `policy_results`, `degradation_alerts` | — |
| v007_advanced (6) | `simulations`, `decisions`, `migration_projects`, `migration_modules`, `migration_corrections` | `context_cache` |

> ® = REDACT (has file paths or source code fields that must be stripped/relativized before sync)

**bridge.db — 6 tables (5 SYNC + 1 LOCAL-ONLY):**

| Table | Sync | Notes |
|---|---|---|
| `bridge_grounding_results` | SYNC | memory_id, score, classification, evidence JSON |
| `bridge_grounding_snapshots` | SYNC | totals, avg_score, trigger_type |
| `bridge_event_log` | SYNC | event_type, memory_type, confidence |
| `bridge_metrics` | SYNC | metric_name, metric_value |
| `bridge_memories` | SYNC | memory_type, content, summary, confidence, tags, linked_patterns |
| `bridge_schema_version` | LOCAL-ONLY | Internal versioning |

**cortex.db — 41 tables across 15 migrations (26 SYNC + 15 LOCAL-ONLY):**

| Migration | SYNC/REDACT Tables | LOCAL-ONLY Tables |
|---|---|---|
| v001_initial (7) | `memories`, `memory_relationships`, `memory_patterns`, `memory_constraints`, `memory_files` ®, `memory_functions` ® | `schema_version` |
| v002_vector (2) | — | `memory_embeddings`, `memory_embedding_link` |
| v003_fts5 (1) | — | `memory_fts` (virtual) |
| v004_causal (2) | `causal_edges`, `causal_evidence` | — |
| v005_session (2) | — | `session_contexts`, `session_analytics` |
| v006_audit (3) | `memory_audit_log`, `consolidation_metrics`, `degradation_log` | — |
| v007_validation (2) | `memory_validation_history`, `memory_contradictions` | — |
| v008_versioning (1) | `memory_versions` | — |
| v009_embedding (1) | `embedding_model_info` | — |
| v010_cloud_sync (3) | — | `sync_state`, `sync_log`, `conflict_log` |
| v011_reclass (2) | `reclassification_history`, `reclassification_signals` | — |
| v012_observability (2) | — | `metric_snapshots`, `query_performance_log` |
| v013_placeholder (0) | — | — |
| v014_temporal (5) | `memory_events`, `memory_snapshots`, `drift_snapshots` | `memory_events_archive`, `materialized_views` |
| v015_multiagent (7+1) | `agent_registry`, `memory_namespaces`, `namespace_permissions`, `memory_projections`, `provenance_log`, `agent_trust` | `delta_queue`, `peer_clocks` |

### What exists as stubs

- **Cortex NAPI**: `cortexCloudSync()`, `cortexCloudGetStatus()`, `cortexCloudResolveConflict()` — wired in Rust but implementation is a no-op
- **Cortex TS**: `CortexClient.cloudSync()`, `.cloudStatus()`, `.cloudResolveConflict()` — calls NAPI stubs
- **Cortex CLI**: `drift cortex cloud sync/status/resolve` — calls CortexClient
- **Cortex MCP tools**: `drift_cloud_sync`, `drift_cloud_status`, `drift_cloud_resolve` — calls CortexClient
- **Sync Edge Function**: `supabase/functions/sync/index.ts` — accepts POST body, fires webhooks, but stores NOTHING to Postgres

### What does NOT exist (the gaps this plan fills)

1. **Cloud Postgres schema** — no cloud tables exist for analysis data
2. **Sync client** — no code reads from DriftStorageEngine and POSTs to Supabase
3. **Redaction layer** — no code strips paths/secrets before upload
4. **Auth flow** — no `drift cloud login` to get a Supabase JWT
5. **Delta sync** — no cursor-based incremental sync
6. **Dashboard API** — no read endpoints for the GUI to consume

---

## Sync Classification Summary (verified)

| Category | Count | Rule |
|---|---|---|
| **SYNC** | 54 tables | Metadata syncs as-is (no file paths, no source code) |
| **REDACT** | 19 tables | Has file paths → strip to relative. Has `code`/`snippet`/`matched_text` → null (17 drift.db + 2 cortex.db) |
| **LOCAL-ONLY** | 19 tables | Caches, embeddings/BLOB, FTS virtual, sessions, sync cursors, perf logs, materialized views |

### Sync Tiers

| Tier | Tables | Description |
|---|---|---|
| **T1 — Dashboard Essentials** | 42 | All drift.db analysis (37) + all bridge.db (5). Powers the dashboard MVP. |
| **T2 — Complete Cortex** | 19 | Core memory system (16 cortex) + simulations/decisions/embedding_models (3 drift). Full intelligence picture. |
| **T3 — Future Features** | 12 | Multi-agent (6 cortex) + reclassification (2 cortex) + temporal snapshots (1 cortex) + migration tracking (3 drift). |
| **Total SYNC/REDACT** | **73** | |

---

## Phase 1: Cloud Postgres Schema (Supabase Migration DDL)

> **Goal:** Create the cloud-side tables that mirror the syncable local tables, with `tenant_id`, `project_id`, and RLS on every table.
> **Where:** `supabase/migrations/20260212000000_cloud_data_tables.sql`
> **Depends on:** Existing migration 000000 (tenants, projects tables already exist)

### Design Rules

1. Every cloud table gets `tenant_id UUID NOT NULL REFERENCES tenants(id)` + `project_id UUID NOT NULL REFERENCES projects(id)`
2. Every cloud table gets RLS: `USING (tenant_id = current_setting('app.tenant_id', true)::UUID)`
3. Local INTEGER PRIMARY KEY → cloud `local_id` (non-unique, scoped to project). Cloud PK is UUID.
4. Local TEXT PRIMARY KEY → cloud `local_id TEXT` (same pattern)
5. `synced_at TIMESTAMPTZ NOT NULL DEFAULT now()` on every row
6. SQLite `INTEGER` → Postgres `BIGINT`, SQLite `REAL` → Postgres `DOUBLE PRECISION`, SQLite `TEXT` → Postgres `TEXT`

### Tier 1 — Dashboard Essentials (42 cloud tables)

**Scan & Files (3):**
`cloud_scan_history`, `cloud_file_stats`, `cloud_functions`

**Analysis & Patterns (7):**
`cloud_call_edges`, `cloud_data_access`, `cloud_detections`, `cloud_boundaries`, `cloud_pattern_confidence`, `cloud_outliers`, `cloud_conventions`

**Graph Intelligence (5):**
`cloud_taint_flows`, `cloud_error_gaps`, `cloud_impact_scores`, `cloud_test_coverage`, `cloud_test_quality`

**Structural Intelligence (15):**
`cloud_coupling_metrics`, `cloud_coupling_cycles`, `cloud_constraints`, `cloud_constraint_results`, `cloud_contracts`, `cloud_contract_mismatches`, `cloud_constants`, `cloud_secrets`, `cloud_env_variables`, `cloud_wrappers`, `cloud_dna_genes`, `cloud_dna_mutations`, `cloud_crypto_findings`, `cloud_owasp_findings`, `cloud_decomposition_decisions`

**Enforcement (7):**
`cloud_violations`, `cloud_gate_results`, `cloud_audit_snapshots`, `cloud_health_trends`, `cloud_feedback`, `cloud_policy_results`, `cloud_degradation_alerts`

**Bridge (5):**
`cloud_bridge_memories`, `cloud_grounding_results`, `cloud_grounding_snapshots`, `cloud_bridge_events`, `cloud_bridge_metrics`

### Tier 2 — Complete Cortex (19 cloud tables)

**Core Memory System (16 from cortex.db):**
`cloud_memories`, `cloud_memory_relationships`, `cloud_memory_patterns`, `cloud_memory_constraints`, `cloud_memory_files`, `cloud_memory_functions`, `cloud_causal_edges`, `cloud_causal_evidence`, `cloud_memory_audit_log`, `cloud_consolidation_metrics`, `cloud_cortex_degradation_log`, `cloud_memory_validation`, `cloud_memory_contradictions`, `cloud_memory_versions`, `cloud_memory_events`, `cloud_memory_snapshots`

**Advanced (3 from drift.db):**
`cloud_simulations`, `cloud_decisions`, `cloud_embedding_models`

### Tier 3 — Future Features (12 cloud tables)

**Multi-Agent (6 from cortex.db):**
`cloud_agent_registry`, `cloud_memory_namespaces`, `cloud_namespace_permissions`, `cloud_memory_projections`, `cloud_provenance_log`, `cloud_agent_trust`

**Temporal & Reclassification (3 from cortex.db):**
`cloud_reclassification_history`, `cloud_reclassification_signals`, `cloud_drift_snapshots`

**Migration Tracking (3 from drift.db):**
`cloud_migration_projects`, `cloud_migration_modules`, `cloud_migration_corrections`

### 19 LOCAL-ONLY Tables (never sync)

`parse_cache`, `reachability_cache`, `context_cache`, `memory_embeddings`, `memory_embedding_link`, `memory_fts`, `session_contexts`, `session_analytics`, `sync_state`, `sync_log`, `conflict_log`, `metric_snapshots`, `query_performance_log`, `memory_events_archive`, `materialized_views`, `delta_queue`, `peer_clocks`, `bridge_schema_version`, `schema_version`

**Total: 73 cloud tables (T1: 42 + T2: 19 + T3: 12)**

### Phase 1 Tasks

| ID | Task | Type |
|---|---|---|
| CP1-01 | Write `20260212000000_cloud_data_tables.sql` — T1 (42 tables) with tenant_id, project_id, RLS, indexes | impl |
| CP1-01b | Write `20260212000001_cloud_cortex_tables.sql` — T2 (19 tables) for cortex memory system | impl |
| CP1-01c | Write `20260212000002_cloud_future_tables.sql` — T3 (12 tables) for multi-agent + migration | impl |
| CP1-02 | Apply migration to hosted Supabase via `supabase db push` or manual SQL | impl |
| CP1-03 | Verify RLS: create 2 test tenants → insert data → verify tenant A can't see tenant B's rows | test |

**Estimated effort:** 2-3 days (T1 on day 1-2, T2+T3 on day 2-3)

---

## Phase 2: Redaction Layer

> **Goal:** A pure-function module that transforms local rows into cloud-safe rows — stripping absolute paths, redacting secrets, removing source code.
> **Where:** `packages/drift/src/cloud/redact.ts` (new)
> **Depends on:** Nothing (pure functions)

### Redaction Rules

| Field Type | Rule | Example |
|---|---|---|
| File paths | Strip to project-relative | `/Users/geoff/myapp/src/index.ts` → `src/index.ts` |
| Root paths | Strip entirely | `/Users/geoff/myapp` → `` |
| Secret values | Replace with `[REDACTED]` | `AKIAIOSFODNN7EXAMPLE` → `[REDACTED]` |
| Source code snippets | Strip entirely | Any `code` or `snippet` field → `null` |
| Environment variable values | Strip | Keep name, remove value |

### Phase 2 Tasks

| ID | Task | Type |
|---|---|---|
| CP2-01 | Create `packages/drift/src/cloud/redact.ts` — `redactPath(abs, projectRoot) → relative`, `redactRow(table, row, projectRoot) → cloudRow` | impl |
| CP2-02 | Create table-specific redaction configs: which fields are paths, which are secrets, which are source | impl |
| CP2-03 | Unit tests: path redaction, secret redaction, source stripping, passthrough for safe fields | test |

**Estimated effort:** 0.5 days

---

## Phase 3: Sync Client

> **Goal:** TypeScript module that reads from NAPI bindings, applies redaction, and POSTs delta payloads to Supabase.
> **Where:** `packages/drift/src/cloud/sync-client.ts` (new)
> **Depends on:** Phase 1 (tables exist), Phase 2 (redaction)

### Sync Protocol

1. **Login** — User runs `drift cloud login`. Opens browser for Supabase Auth. Stores JWT + refresh token in `~/.drift/cloud-credentials.json`.
2. **Push** — User runs `drift cloud push` (or it runs after `drift analyze`):
   - Read `sync_state` from local cortex.db (last sync cursor)
   - For each syncable table, query rows `WHERE rowid > last_sync_cursor` (delta)
   - Apply redaction
   - Batch into JSON payload (max 1000 rows per request)
   - POST to `https://<project>.supabase.co/rest/v1/cloud_<table>` (PostgREST)
   - Update local `sync_state` cursor
3. **Conflict resolution** — Cloud is append-only for now. Local is source of truth. No pull needed in v1.

### Why PostgREST (not Edge Functions)

Supabase auto-generates a REST API for every table. We don't need a custom sync Edge Function — we just POST rows directly via PostgREST with the user's JWT. RLS enforces tenant isolation. This is simpler, faster, and needs zero server-side code.

### Phase 3 Tasks

| ID | Task | Type |
|---|---|---|
| CP3-01 | Create `packages/drift/src/cloud/config.ts` — cloud config types (supabase URL, project ref, auth tokens) | impl |
| CP3-02 | Create `packages/drift/src/cloud/auth.ts` — `login()` (browser OAuth flow), `getToken()` (read cached JWT), `refreshToken()`, `logout()` | impl |
| CP3-03 | Create `packages/drift/src/cloud/sync-client.ts` — `SyncClient` class: `constructor(config, napi)`, `push()`, `status()` | impl |
| CP3-04 | Implement `push()` — for each syncable table group: read via NAPI → redact → batch → POST to PostgREST | impl |
| CP3-05 | Implement delta tracking — use `scan_history.id` as sync cursor for drift.db, `bridge_event_log.id` for bridge.db, `memory_events.event_id` for cortex.db | impl |
| CP3-06 | Implement batch upload — chunk rows into 1000-row batches, POST with `Prefer: resolution=merge-duplicates` header (upsert) | impl |
| CP3-07 | Error handling — retry on 5xx (3 attempts, exponential backoff), fail on 4xx, report to user | impl |
| CP3-08 | Integration test: push real scan data → verify rows in cloud table via PostgREST GET | test |
| CP3-09 | Delta test: push → modify local → push again → verify only new rows uploaded | test |

**Estimated effort:** 3-4 days

---

## Phase 4: CLI Wiring

> **Goal:** `drift cloud login`, `drift cloud push`, `drift cloud status`, `drift cloud logout`
> **Where:** `packages/drift-cli/src/commands/cloud.ts` (new)
> **Depends on:** Phase 3 (sync client)

### Commands

| Command | Description |
|---|---|
| `drift cloud login` | Opens browser for Supabase OAuth. Stores JWT. |
| `drift cloud push` | Runs sync client push. Shows progress bar + summary. |
| `drift cloud push --full` | Forces full sync (ignores cursor, re-uploads everything). |
| `drift cloud status` | Shows last sync time, rows synced, cloud project info. |
| `drift cloud logout` | Clears stored credentials. |

### Phase 4 Tasks

| ID | Task | Type |
|---|---|---|
| CP4-01 | Create `packages/drift-cli/src/commands/cloud.ts` — register `drift cloud` subcommand with login/push/status/logout | impl |
| CP4-02 | Implement `login` — open browser, handle OAuth callback, store tokens | impl |
| CP4-03 | Implement `push` — instantiate SyncClient, call push(), render progress + summary | impl |
| CP4-04 | Implement `status` — read local sync_state + cloud project info, display | impl |
| CP4-05 | Register in `packages/drift-cli/src/commands/index.ts` | impl |
| CP4-06 | Test: login → push → status → logout round-trip | test |

**Estimated effort:** 1-2 days

---

## Phase 5: Dashboard Read API

> **Goal:** Supabase PostgREST endpoints the GUI can call to display synced data. No Edge Functions needed — PostgREST auto-exposes all tables with RLS.
> **Where:** Supabase RLS policies + optional Postgres views
> **Depends on:** Phase 1 (tables exist)

### What PostgREST gives for free

Every `cloud_*` table is automatically available at:
```
GET https://<project>.supabase.co/rest/v1/cloud_violations?select=*&order=created_at.desc&limit=50
GET https://<project>.supabase.co/rest/v1/cloud_gate_results?select=*&passed=eq.false
GET https://<project>.supabase.co/rest/v1/cloud_coupling_metrics?select=*&zone=eq.zone_of_pain
```

All filtered by RLS (tenant can only see their own data).

### Dashboard Views (optional Postgres views for complex queries)

| View | Purpose |
|---|---|
| `v_project_health` | Aggregates: violation count, gate pass rate, avg confidence, DNA health |
| `v_trend_violations` | Daily violation count over last 30 days per project |
| `v_top_violations` | Most frequent violation rules across project |
| `v_security_posture` | OWASP + CWE coverage, taint flow count, crypto finding count |

### Phase 5 Tasks

| ID | Task | Type |
|---|---|---|
| CP5-01 | Create `20260212000001_dashboard_views.sql` — 4 Postgres views for dashboard aggregations | impl |
| CP5-02 | Verify PostgREST access: authenticated user can query all cloud_* tables and views | test |
| CP5-03 | Document API surface — list all queryable endpoints for frontend team | impl |

**Estimated effort:** 1 day

---

## Phase 6: Wire into Existing Cortex Cloud Stubs

> **Goal:** Connect the new sync client to the existing NAPI stubs so `cortexCloudSync()` actually works.
> **Where:** Cortex NAPI + TS bridge
> **Depends on:** Phase 3

The existing cortex stubs (`cortexCloudSync`, `cortexCloudGetStatus`, `cortexCloudResolveConflict`) are already wired end-to-end (NAPI → TS bridge → CLI → MCP tools). They just need real implementations.

### Phase 6 Tasks

| ID | Task | Type |
|---|---|---|
| CP6-01 | Implement `cortexCloudSync` in Rust — call into sync client or set a flag that TS picks up | impl |
| CP6-02 | Wire `drift cortex cloud sync` to use the new SyncClient from Phase 3 | impl |
| CP6-03 | Wire MCP tool `drift_cloud_sync` to use SyncClient | impl |
| CP6-04 | Test: `drift cortex cloud sync` actually pushes data | test |

**Estimated effort:** 1 day

---

## Dependency Graph

```
Phase 1 (Cloud Schema)
  │
  ├──► Phase 5 (Dashboard Views) — can start immediately after schema applied
  │
  ▼
Phase 2 (Redaction) ← no dependencies, can start Day 1
  │
  ▼
Phase 3 (Sync Client) ← needs Phase 1 + 2
  │
  ├──► Phase 4 (CLI Wiring)
  └──► Phase 6 (Wire Cortex Stubs)
```

**Critical path:** Phase 1 (1d) → Phase 2 (0.5d) → Phase 3 (3-4d) → Phase 4 (1-2d) = **5.5-7.5 days**

**Parallel:** Phase 5 can start after Phase 1. Phase 2 can start Day 1.

---

## What This Unlocks

Once this pipeline is done:

1. **`drift analyze && drift cloud push`** — scan locally, push metadata to cloud in one command
2. **Dashboard** — frontend queries PostgREST to show violations, gates, patterns, DNA, coupling across all projects
3. **Enterprise features (parked D/E/F)** — SCIM, webhooks, teams, audit now have actual data to operate on
4. **CI integration** — `drift-ci` can push results to cloud after every PR scan

---

## Summary

| Phase | What | Effort | Output |
|---|---|---|---|
| 1 | Cloud Postgres schema (73 tables in 3 tiers + RLS) | 2-3 days | Tables ready in hosted Supabase |
| 2 | Redaction layer (24 REDACT tables: path stripping, code/secret masking) | 0.5 days | Pure TS module |
| 3 | Sync client (new NAPI export fn → redact → PostgREST upsert) | 3-4 days | Working push pipeline |
| 4 | CLI wiring (drift cloud login/push/status) | 1-2 days | User-facing commands |
| 5 | Dashboard views (Postgres aggregation views) | 1 day | GUI-ready API |
| 6 | Wire cortex stubs | 1 day | Existing tools work |
| **Total** | | **8.5-11.5 days** | **End-to-end local → cloud pipeline** |

## Verification Checklist

- [x] **drift.db**: 45 tables verified (7 migrations read line-by-line)
- [x] **bridge.db**: 6 tables verified (schema.rs + migrations.rs read)
- [x] **cortex.db**: 41 tables verified (15 migrations read line-by-line)
- [x] **NAPI bindings**: 10 binding modules verified (scanner, analysis, patterns, graph, structural, enforcement, feedback, advanced, lifecycle, bridge)
- [x] **Existing stubs**: 10 stubs verified (3 NAPI, 3 CortexClient, 1 CLI, 3 MCP tools)
- [x] **Sync Edge Function**: Verified — stores nothing, just fires webhooks
- [x] **Every table classified**: 73 SYNC/REDACT + 19 LOCAL-ONLY = 92 total ✓
- [x] **Tier assignment**: T1(42) + T2(19) + T3(12) = 73 ✓
