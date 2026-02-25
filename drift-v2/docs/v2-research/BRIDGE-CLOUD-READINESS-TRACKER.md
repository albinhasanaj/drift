# Drift Cloud Readiness: Full-System Cloud Migration Plan

> **Status:** Created Feb 11, 2026. Comprehensive cloud migration plan for all 3 databases.
> **Purpose:** Enterprise-grade plan to migrate Drift's local SQLite storage to a multi-tenant cloud architecture, enabling users to push metadata (never source code) to a cloud GUI/FE dashboard.
> **Constraint:** Shared infrastructure (no per-user cloud accounts for now). Metadata only — zero source code leaves the developer's machine. Cloud is 100% opt-in — offline-only users experience zero degradation.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Current Architecture Inventory](#2-current-architecture-inventory)
3. [Cloud Database Architecture](#3-cloud-database-architecture)
4. [Schema Migration Strategy — All 3 Databases](#4-schema-migration-strategy--all-3-databases)
5. [Security, Authentication & Compliance](#5-security-authentication--compliance)
6. [Sync Protocol & API Layer](#6-sync-protocol--api-layer)
7. [FE/GUI Data Contract](#7-fegui-data-contract)
8. [Implementation Phases & Task Tables](#8-implementation-phases--task-tables)
9. [Cost Estimation & Infrastructure](#9-cost-estimation--infrastructure)
10. [Risk Register](#10-risk-register)
11. [Enterprise Readiness Gap Analysis](#11-enterprise-readiness-gap-analysis)
12. [Appendix A: Bridge Storage Layer Mapping (Original Audit)](#appendix-a-bridge-storage-layer-mapping-original-audit)

---

## 1. Executive Summary

### What We're Building

A **multi-tenant cloud platform** that lets Drift users push their **metadata only** (never source code) to a centralized cloud store, then visualize it through a web-based GUI/FE dashboard. The local CLI/MCP/CI workflow remains unchanged — the cloud layer is additive.

### The Data Flow

```
Developer's Machine (LOCAL)              Cloud (Supabase)               Browser (FE)
┌─────────────────────────┐    push     ┌──────────────────────┐       ┌──────────────┐
│ drift scan              │───────────→│ Supabase Edge Fns    │       │              │
│ drift analyze           │  metadata  │   ↓                  │       │  Drift       │
│                         │   only     │ PostgREST / custom   │──────→│  Dashboard   │
│ .drift/drift.db    ←────│───────────←│   ↓                  │  REST │              │
│ .drift/bridge.db        │   sync     │ Supabase Postgres    │  or   │  (React)     │
│ .drift/cortex.db        │           │ (shared, RLS)        │  GQL  │              │
└─────────────────────────┘            └──────────────────────┘       └──────────────┘
```

### Key Decisions

| Decision | Choice | Why |
|---|---|---|
| **Multi-tenant model** | Shared DB, shared schema + PostgreSQL Row-Level Security (RLS) | Bytebase + Supabase best practice for SaaS. Lowest ops cost. Pool model with `tenant_id` on every table. |
| **Cloud database** | Supabase (managed Postgres) | Built-in RLS, Auth, Edge Functions, Realtime, Storage. Generous free tier. Native PostgREST API. |
| **Source code policy** | **NEVER** leaves the machine | Only metadata rows (patterns, scores, violations, memories, etc.) are synced. `parse_cache`, `file_metadata.content_hash`, raw source — all stay local. |
| **Sync direction** | Bi-directional, offline-first | Local SQLite is always the source of truth. Cloud is a secondary replica. User can work fully offline. |
| **Auth** | Supabase Auth (GoTrue) + JWT | Built-in email/password, OAuth, SSO/SAML for enterprise. Token-based API access. |
| **Encryption** | AES-256 at rest (Supabase default) + TLS 1.3 in transit | SOC 2 / ISO 27001 compliant. |
| **Tenant isolation** | RLS + JWT `tenant_id` claim | Database enforces isolation — app bugs can't leak data. |
| **Offline mode** | 100% opt-in cloud, zero degradation offline | No cloud config = no cloud code runs. Every feature works identically without cloud. |

### What Syncs vs. What Stays Local

| Syncs to Cloud (metadata) | Stays Local (never leaves) |
|---|---|
| Patterns, conventions, confidence scores | Source code, file contents |
| Violations, gate results, audit snapshots | `parse_cache` (contains parsed ASTs) |
| Functions (name, file, line — not body) | `file_metadata.content_hash` (BLOB) |
| Boundaries, contracts, coupling metrics | `.driftignore`, local config |
| Bridge memories, grounding results | Raw detection `matched_text` |
| Cortex memories (summary, tags, links) | Cortex memory `content` field (may contain code snippets) |
| DNA genes, mutations, crypto/OWASP findings | Embedding vectors (cortex) |
| Taint flows, error gaps, impact scores | Secret values (even redacted) |
| Scan history (counts, timing, status) | Context cache content |
| Health trends, degradation alerts | Provenance details |

### Offline-First Guarantee — Cloud is 100% Opt-In

**Users who never configure cloud experience ZERO changes.** This is a hard architectural requirement, not a soft goal.

| Guarantee | How It's Enforced |
|---|---|
| **No cloud code runs unless opted in** | All sync/cloud code is gated behind `if config.cloud.enabled`. No `.drift/cloud.json` = cloud module never loads. |
| **No new dependencies for offline users** | Cloud client (`@supabase/supabase-js`) is a lazy import — not loaded unless `drift cloud login` has been run. |
| **No network calls unless opted in** | Zero HTTP requests to any external service during `drift scan`, `drift analyze`, `drift check`, or any existing command. |
| **No degraded behavior offline** | Every feature — scanning, analysis, patterns, violations, grounding, causal, MCP tools, CI agent — works identically with or without cloud. |
| **No required account** | `drift` CLI works out of the box with zero registration, zero login, zero config. Cloud is a separate `drift cloud` subcommand group. |
| **Local SQLite is always the source of truth** | Even cloud-enabled users keep local databases. Cloud is a read-replica for the dashboard. If cloud is down, local workflow is unaffected. |
| **Cloud can be disabled at any time** | `drift cloud unlink` removes cloud config. Local data is untouched. Cloud data can be deleted via `drift cloud export` then account deletion. |
| **No telemetry without consent** | No usage analytics, no crash reporting, no phone-home unless user explicitly enables cloud. |

**Implementation pattern:**

```typescript
// In drift-cli/src/commands/index.ts — cloud commands are lazy-registered
if (cloudConfigExists()) {
  const { registerCloudCommands } = await import('./cloud.js');
  registerCloudCommands(program);
}

// In drift-napi runtime.rs — sync hook is a no-op without cloud config
pub fn post_analyze_hook(&self) {
    if self.cloud_config.is_none() {
        return; // No cloud = no sync = no network = no latency
    }
    // ... optional auto-push
}
```

**Test enforcement:** CI includes a dedicated test that runs the full `drift scan → analyze → check` pipeline **with no network access** (e.g., `unshare --net` on Linux, sandbox on macOS) to prove zero external dependencies.

---

## 2. Current Architecture Inventory

### 2a. The Three Databases

Drift currently uses **3 independent SQLite databases** per project, all stored in `.drift/`:

| Database | File | Crate | Tables | Migration Versions | Purpose |
|---|---|---|---|---|---|
| **drift.db** | `.drift/drift.db` | `drift-storage` | ~44 tables | v001–v007 | Analysis results: files, functions, patterns, detections, call graph, enforcement, structural, advanced |
| **bridge.db** | `.drift/bridge.db` | `cortex-drift-bridge` | 5 tables + 1 version | v1 | Memory grounding, causal intelligence, event log, metrics |
| **cortex.db** | `.drift/cortex.db` | `cortex-storage` | ~35 tables | v001–v015 | AI memory system: memories, relationships, embeddings, causal graph, sessions, audit, cloud sync, multi-agent |

**Total: ~84 tables across 3 databases.**

### 2b. drift.db — Complete Table Inventory (44 tables)

**v001 — Core scanning:**
- `file_metadata` (path PK, language, size, content_hash BLOB, mtime, scan stats)
- `parse_cache` (content_hash PK, language, parse_result_json) — **LOCAL ONLY, never syncs**
- `functions` (id, file, name, qualified_name, language, line, params, return_type, is_exported, is_async, body_hash, signature_hash)
- `scan_history` (id, started_at, root_path, file counts, duration, status)

**v002 — Analysis:**
- `call_edges` (caller_id, callee_id, resolution, confidence, call_site_line)
- `data_access` (function_id, table_name, operation, framework, line)
- `detections` (id, file, line, pattern_id, category, confidence, detection_method, cwe/owasp)
- `boundaries` (id, file, framework, model_name, table_name, field_name, sensitivity)

**v003 — Pattern intelligence:**
- `pattern_confidence` (pattern_id PK, alpha, beta, posterior_mean, credible_interval, tier, momentum)
- `outliers` (id, pattern_id, file, line, deviation_score, significance, method)
- `conventions` (id, pattern_id, category, scope, dominance_ratio, promotion_status)

**v004 — Graph intelligence:**
- `reachability_cache` (source_node, direction, reachable_set, sensitivity)
- `taint_flows` (id, source_file/line/type, sink_file/line/type, cwe_id, path, confidence)
- `error_gaps` (id, file, function_id, gap_type, severity, cwe_id)
- `impact_scores` (function_id PK, blast_radius, risk_score, is_dead_code)
- `test_coverage` (test_function_id, source_function_id, coverage_type)
- `test_quality` (function_id PK, coverage_breadth/depth, assertion_density, overall_score)

**v005 — Structural:**
- `coupling_metrics` (module PK, Ce, Ca, instability, abstractness, distance, zone)
- `coupling_cycles` (id, members, break_suggestions)
- `constraints` (id, description, invariant_type, target, scope, source)
- `constraint_verifications` (id, constraint_id FK, passed, violations, verified_at)
- `contracts` (id, paradigm, source_file, framework, confidence, endpoints)
- `contract_mismatches` (id, backend_endpoint, frontend_call, mismatch_type, severity)
- `constants` (id, name, value, file, line, language)
- `secrets` (id, pattern_name, redacted_value, file, line, severity, entropy) — **Redacted values only, never raw**
- `env_variables` (id, name, file, line, access_method, has_default)
- `wrappers` (id, name, file, line, category, wrapped_primitives, framework)
- `dna_genes` (gene_id PK, name, dominant_allele, alleles, confidence, consistency)
- `dna_mutations` (id, file, line, gene_id, expected, actual, impact, suggestion)
- `crypto_findings` (id, file, line, category, cwe_id, owasp, remediation)
- `owasp_findings` (id, detector, file, line, severity, cwes, owasp_categories)
- `decomposition_decisions` (id, dna_profile_hash, adjustment, confidence, narrative)

**v006 — Enforcement:**
- `violations` (id, file, line, severity, pattern_id, rule_id, message, cwe_id, is_new)
- `gate_results` (id, gate_id, status, passed, score, summary, violation_count)
- `audit_snapshots` (id, health_score, avg_confidence, compliance_rate, pattern_count)
- `health_trends` (id, metric_name, metric_value, recorded_at)
- `feedback` (id, violation_id, pattern_id, action, dismissal_reason, author)
- `policy_results` (id, policy_name, aggregation_mode, overall_passed/score, gate counts)
- `degradation_alerts` (id, alert_type, severity, message, current/previous_value, delta)

**v007 — Advanced:**
- `simulations` (id, task_category, description, p10/p50/p90_effort)
- `decisions` (id, category, description, commit_sha, confidence, author)
- `context_cache` (id, session_id, intent, depth, token_count) — **LOCAL ONLY**
- `migration_projects` (id, name, source/target_language/framework)
- `migration_modules` (id, project_id FK, module_name, status, spec_content)
- `migration_corrections` (id, module_id FK, section, original_text, corrected_text)

### 2c. bridge.db — Complete Table Inventory (5+1 tables)

- `bridge_memories` (id PK, memory_type, content, summary, confidence, importance, tags JSON, linked_patterns JSON)
- `bridge_grounding_results` (id AUTO, memory_id, grounding_score, classification, evidence JSON)
- `bridge_grounding_snapshots` (id AUTO, total/grounded/validated/partial/weak/invalidated counts, avg_score, trigger_type)
- `bridge_event_log` (id AUTO, event_type, memory_type, memory_id, confidence)
- `bridge_metrics` (id AUTO, metric_name, metric_value, recorded_at)
- `bridge_schema_version` (version) — single-row, immune to retention

### 2d. cortex.db — Complete Table Inventory (~35 tables)

**v001 — Core memory:**
- `schema_version` (version PK, applied_at)
- `memories` (id PK, memory_type, content, summary, transaction_time, valid_time, confidence, importance, tags JSON, content_hash, namespace_id, source_agent)
- `memory_relationships` (source_id, target_id, relationship_type, strength, evidence)
- `memory_patterns` (memory_id, pattern_id, pattern_name)
- `memory_constraints` (memory_id, constraint_id, constraint_name)
- `memory_files` (memory_id, file_path, line_start, line_end, content_hash)
- `memory_functions` (memory_id, function_name, file_path, signature)

**v002 — Vectors:**
- `embeddings` (memory_id PK, vector BLOB, model TEXT, dimensions INT) — **LOCAL ONLY (vectors stay local)**

**v003 — FTS5:**
- `memories_fts` (FTS5 virtual table) — **LOCAL ONLY (SQLite-specific)**

**v004 — Causal:**
- `causal_edges` (source_id, target_id PK, relation, strength)
- `causal_evidence` (id, source_id, target_id, description, source)

**v005 — Sessions:**
- `sessions` (session_id PK, agent_id, started_at, ended_at, token counts, status)

**v006 — Audit:**
- `audit_log` (id, memory_id, action, actor, details, timestamp)

**v007 — Validation:**
- `validation_results` (id, memory_id, dimension, score, details)

**v008 — Versioning:**
- `version_history` (id, memory_id, version, snapshot BLOB, created_at)
- `version_snapshots` (id, memory_id, snapshot_at, state)

**v010 — Cloud sync (already exists!):**
- `sync_state` (id=1, last_sync_at, last_sync_token, status) — **Foundation for cloud sync**
- `sync_log` (id, direction, memory_id, operation, status, details)
- `conflict_log` (id, memory_id, local_version, remote_version, resolution)

**v012 — Observability:**
- `metrics_log` / `query_log` (observability tables)

**v014 — Temporal:**
- `memory_events` (event_id, memory_id, recorded_at, event_type, delta, actor)
- `memory_events_archive` (archived events)
- `memory_snapshots` (snapshot_id, memory_id, snapshot_at, state BLOB)
- `drift_snapshots` (snapshot_id, timestamp, window_seconds, metrics)
- `materialized_views` (view_id, label, timestamp, memory_count, snapshot_ids)

**v015 — Multi-agent:**
- `agent_registry` (agent_id PK, name, namespace_id, capabilities, parent_agent, status)
- `memory_namespaces` (namespace_id PK, scope, owner_agent)
- `namespace_permissions` (namespace_id, agent_id PK, permissions, granted_by)
- `memory_projections` (projection_id PK, source/target_namespace, filter_json, live)
- `provenance_log` (id, memory_id, hop_index, agent_id, action, confidence_delta)
- `agent_trust` (agent_id, target_agent PK, overall_trust, domain_trust, evidence)
- `delta_queue` (delta_id, source/target_agent, memory_id, delta_json, vector_clock)

---

## 3. Cloud Database Architecture

### 3a. Why Shared DB + Shared Schema (Pool Model)

Per Bytebase and Supabase guidance, there are 3 multi-tenant patterns:

| Pattern | Isolation | Cost | Ops Complexity | Our Choice |
|---|---|---|---|---|
| **Database per tenant (Silo)** | Maximum | Highest | Very high — N databases to manage | ❌ Not for now (no per-user cloud storage) |
| **Shared DB, separate schemas (Bridge)** | Medium | Medium | High — N schema migrations | ❌ Worst of both worlds per Bytebase |
| **Shared DB, shared schema (Pool)** | Via RLS | Lowest | Lowest — single DB, single migration | ✅ **Our choice** |

**Key rationale:** No per-user cloud storage for now. Pool model with PostgreSQL Row-Level Security (RLS) gives us enterprise-grade tenant isolation at the lowest operational cost. Supabase has native RLS support built into its dashboard and client libraries. We can upgrade individual tenants to dedicated Supabase projects later if needed.

### 3b. PostgreSQL RLS — How It Works for Drift

Every cloud table gets a `tenant_id UUID NOT NULL` column. RLS policies enforce isolation at the database level:

```sql
-- Example: cloud version of pattern_confidence
CREATE TABLE cloud.pattern_confidence (
    tenant_id    UUID NOT NULL,
    project_id   UUID NOT NULL,
    pattern_id   TEXT NOT NULL,
    alpha        REAL NOT NULL,
    beta         REAL NOT NULL,
    posterior_mean REAL NOT NULL,
    credible_interval_low  REAL NOT NULL,
    credible_interval_high REAL NOT NULL,
    tier         TEXT NOT NULL,
    momentum     TEXT NOT NULL DEFAULT 'Stable',
    last_updated TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, project_id, pattern_id)
);

-- Enable RLS
ALTER TABLE cloud.pattern_confidence ENABLE ROW LEVEL SECURITY;

-- Policy: users can only see their own tenant's data
CREATE POLICY tenant_isolation ON cloud.pattern_confidence
    USING (tenant_id = current_setting('app.tenant_id')::UUID);

-- Force RLS even for table owners
ALTER TABLE cloud.pattern_confidence FORCE ROW LEVEL SECURITY;
```

Supabase automatically extracts the user's JWT claims and makes them available via `auth.uid()` and `auth.jwt()`. The RLS policy uses these directly — no manual `SET LOCAL` needed when using the Supabase client. For direct Postgres access (Edge Functions), we set `SET LOCAL app.tenant_id = '<uuid>'` per transaction. **Even if app code has a bug and omits a WHERE clause, RLS prevents cross-tenant data leaks.**

### 3c. Cloud Schema Design — Shared Postgres Instance

```
Supabase Postgres (managed)
├── Schema: public (Supabase default)
│   ├── tenants (id, name, email, plan, created_at)
│   ├── projects (id, tenant_id, name, repo_url_hash, created_at)
│   │
│   ├── ── drift.db tables (syncable subset) ──
│   ├── functions (tenant_id, project_id, id, file, name, ...)
│   ├── scan_history (tenant_id, project_id, id, ...)
│   ├── detections (tenant_id, project_id, id, ...)
│   ├── pattern_confidence (tenant_id, project_id, ...)
│   ├── violations (tenant_id, project_id, ...)
│   ├── gate_results (tenant_id, project_id, ...)
│   ├── ... (30+ syncable drift tables)
│   │
│   ├── ── bridge.db tables ──
│   ├── bridge_memories (tenant_id, project_id, ...)
│   ├── bridge_grounding_results (tenant_id, project_id, ...)
│   ├── bridge_grounding_snapshots (tenant_id, project_id, ...)
│   ├── bridge_event_log (tenant_id, project_id, ...)
│   ├── bridge_metrics (tenant_id, project_id, ...)
│   │
│   ├── ── cortex.db tables (syncable subset) ──
│   ├── memories (tenant_id, project_id, id, memory_type, summary, ...)
│   ├── memory_relationships (tenant_id, project_id, ...)
│   ├── causal_edges (tenant_id, project_id, ...)
│   ├── audit_log (tenant_id, project_id, ...)
│   ├── sessions (tenant_id, project_id, ...)
│   ├── ... (15+ syncable cortex tables)
│   │
│   └── ── Cloud-only tables ──
│       ├── sync_cursors (tenant_id, project_id, db_name, last_sync_at, cursor_token)
│       ├── api_keys (tenant_id, key_hash, name, scopes, expires_at)
│       └── usage_billing (tenant_id, month, sync_count, storage_bytes)
│
├── Schema: auth (managed by Supabase Auth — GoTrue)
│   └── users, sessions, identities (auto-managed)
│   └── user_tenant_mappings (user_id, tenant_id, role) — custom table
│
└── Supabase Read Replicas (Pro plan, for dashboard queries)
```

### 3d. Table Sync Classification — What Goes to Cloud

| Classification | Tables | Count | Rationale |
|---|---|---|---|
| **SYNC** — push to cloud | Most drift.db analysis tables, all bridge.db tables, cortex summaries | ~60 | Metadata needed for dashboard visualization |
| **LOCAL-ONLY** — never syncs | `parse_cache`, `file_metadata`, `context_cache`, `embeddings`, `memories_fts`, `reachability_cache` | ~8 | Contains source code, ASTs, vectors, or SQLite-specific features |
| **REDACT-ON-SYNC** — syncs with field filtering | `secrets` (drop redacted_value), `detections` (drop matched_text), `memories` (drop content field) | ~3 | Fields may contain code snippets or sensitive values |
| **CLOUD-ONLY** — exists only in cloud | `tenants`, `projects`, `api_keys`, `sync_cursors`, `usage_billing` | ~5 | Multi-tenancy infrastructure |

### 3e. SQLite-to-PostgreSQL Type Mapping

| SQLite Type | PostgreSQL Type | Notes |
|---|---|---|
| `TEXT` | `TEXT` | Direct mapping |
| `INTEGER` (boolean) | `BOOLEAN` | SQLite uses 0/1, Postgres has native bool |
| `INTEGER` (unix epoch) | `TIMESTAMPTZ` | Convert `unixepoch()` → `now()`, store as proper timestamps |
| `INTEGER` (autoincrement) | `BIGSERIAL` | Postgres sequences |
| `REAL` | `DOUBLE PRECISION` | Direct mapping |
| `BLOB` | `BYTEA` | For content_hash, body_hash — but these stay LOCAL |
| `TEXT` (JSON) | `JSONB` | Postgres-native JSON with indexing. Tags, evidence, alleles, etc. |
| `TEXT PRIMARY KEY` (UUIDs) | `UUID` | Native UUID type in Postgres |
| SQLite `STRICT` mode | PostgreSQL type system | Postgres is always strict |
| `json_extract()` | `->>`/`@>` operators | JSONB operators replace SQLite json functions |
| `unixepoch()` default | `now()` default | Proper timestamp handling |

---

## 4. Schema Migration Strategy — All 3 Databases

### 4a. Migration Approach

Each of the ~84 SQLite tables needs a cloud counterpart. Strategy:

1. **Generate Postgres DDL** from existing SQLite migration SQL (mechanical translation)
2. **Add `tenant_id` + `project_id`** to every table's primary key
3. **Convert types** per the mapping in Section 3e
4. **Add RLS policies** to every table
5. **Use Postgres migrations** (e.g., `sqlx migrate` or `refinery`) — NOT `PRAGMA user_version`

### 4b. drift.db Cloud Migration — Per-Table Decision

| Table | Sync? | Cloud PK | Notes |
|---|---|---|---|
| `file_metadata` | ❌ LOCAL | — | Contains content_hash BLOB, local scan state |
| `parse_cache` | ❌ LOCAL | — | Contains parsed ASTs |
| `functions` | ✅ SYNC | `(tenant_id, project_id, id)` | Drop `body_hash`, `signature_hash` BLOBs |
| `scan_history` | ✅ SYNC | `(tenant_id, project_id, id)` | Counts + timing only |
| `call_edges` | ✅ SYNC | `(tenant_id, project_id, caller_id, callee_id, call_site_line)` | Graph structure |
| `detections` | ⚠️ REDACT | `(tenant_id, project_id, id)` | Drop `matched_text` column |
| `pattern_confidence` | ✅ SYNC | `(tenant_id, project_id, pattern_id)` | Core dashboard metric |
| `violations` | ✅ SYNC | `(tenant_id, project_id, id)` | Core dashboard metric |
| `gate_results` | ✅ SYNC | `(tenant_id, project_id, id)` | Core dashboard metric |
| `secrets` | ⚠️ REDACT | `(tenant_id, project_id, id)` | Drop `redacted_value` |
| `context_cache` | ❌ LOCAL | — | Session-local data |
| *All other tables* | ✅ SYNC | `(tenant_id, project_id, <original_pk>)` | Standard metadata |

### 4c. bridge.db Cloud Migration

All 5 bridge tables sync to cloud. No redaction needed — bridge stores summaries, not code.

### 4d. cortex.db Cloud Migration

| Table | Sync? | Notes |
|---|---|---|
| `memories` | ⚠️ REDACT | Sync summary/tags/confidence, drop `content` (may contain code) |
| `memory_relationships` | ✅ SYNC | Graph structure |
| `embeddings` | ❌ LOCAL | Binary vectors, model-specific |
| `memories_fts` | ❌ LOCAL | SQLite FTS5 virtual table |
| `causal_edges/evidence` | ✅ SYNC | Causal graph metadata |
| `sync_state/log/conflict_log` | ✅ SYNC | Already designed for cloud! |
| `agent_registry` + multi-agent tables | ✅ SYNC | Multi-agent coordination |
| *All other tables* | ✅ SYNC | Standard metadata |

---

## 5. Security, Authentication & Compliance

### 5a. Authentication Architecture

```
User (CLI/MCP)          Supabase                                        Browser (FE)
     │                       │                                                │
     │── drift cloud login ─→│  GoTrue Auth                                    │
     │   (opens browser)     │   ↓                                             │
     │←── JWT (Supabase) ───│  JWT with user_id + tenant_id claims             │
     │                       │                                                │
     │── drift cloud push ──→│  Edge Function / PostgREST                      │
     │   Authorization:      │   ↓  JWT auto-verified                        │
     │   Bearer <jwt>        │   Postgres (RLS enforced via auth.uid())       │
     │                       │   ↓  INSERT/SELECT with tenant isolation        │
     │←── 200 OK ────────────│                                                │
```

**Components:**

| Component | Technology | Purpose |
|---|---|---|
| **Identity Provider** | Supabase Auth (GoTrue) | User registration, login, MFA, password policy. Built into Supabase. |
| **SSO/SAML** | Supabase SSO (Pro plan) | Enterprise SSO (Okta, Azure AD, Google Workspace) via SAML 2.0 |
| **OAuth** | Supabase OAuth providers | GitHub, Google, GitLab — ideal for developer sign-up |
| **API Auth** | JWT Bearer tokens | Stateless auth for every API call. Supabase JWTs auto-verified by PostgREST. |
| **API Keys** | SHA-256 hashed, stored in `api_keys` table | CI/CD automation (no browser login needed) |
| **Token Refresh** | Supabase refresh tokens | Silent re-auth without re-login |
| **RBAC** | Custom claims in JWT + `user_tenant_mappings` table | `owner`, `admin`, `member`, `viewer` roles per tenant |

### 5b. Encryption

| Layer | Standard | Implementation |
|---|---|---|
| **At rest** | AES-256 | Supabase Postgres encryption at rest (managed by platform) |
| **In transit (API)** | TLS 1.3 | Supabase enforces HTTPS-only on all endpoints |
| **In transit (DB)** | TLS 1.2+ | Supabase Postgres SSL enforced by default |
| **API keys** | SHA-256 + salt | Keys hashed before storage, raw key shown once at creation |
| **Secrets in metadata** | Field-level redaction | `secrets.redacted_value` stripped before sync; `detections.matched_text` stripped |
| **JWT signing** | HS256 (Supabase default) | Supabase JWT secret, configurable per project |

### 5c. Tenant Isolation — Defense in Depth

| Layer | Mechanism | What It Prevents |
|---|---|---|
| **L1: Network** | Supabase managed networking | Postgres not directly exposed; access via PostgREST/Edge Functions only |
| **L2: API** | JWT `tenant_id` claim validation | Requests without valid tenant context rejected by Supabase Auth |
| **L3: Application** | `auth.uid()` / `auth.jwt()` in RLS policies | Every DB query scoped to tenant via Supabase's built-in JWT context |
| **L4: Database** | PostgreSQL RLS policies on every table | Even if app omits WHERE, RLS blocks cross-tenant reads |
| **L5: Audit** | Supabase logs + custom `audit_log` table | Every data access logged with tenant + user + timestamp |

### 5d. SOC 2 Type II Readiness Checklist

| Control | Requirement | Our Implementation | Status |
|---|---|---|---|
| **CC6.1** | Logical access controls | Supabase Auth + RBAC + RLS | ✅ Designed |
| **CC6.2** | Authentication mechanisms | MFA, SSO/SAML, JWT | ✅ Designed |
| **CC6.3** | Access authorization | Role-based claims, API key scopes | ✅ Designed |
| **CC6.6** | Encryption in transit | TLS 1.3 (API), TLS 1.2+ (DB) | ✅ Designed |
| **CC6.7** | Encryption at rest | AES-256 (Supabase managed) | ✅ Designed |
| **CC7.1** | Monitoring & detection | Supabase dashboard logs + custom audit_log | ✅ Designed |
| **CC7.2** | Incident response | Automated alerts, runbook | 📋 TODO |
| **CC8.1** | Change management | GitHub Actions CI, migration versioning | ✅ Existing |
| **A1.2** | Availability monitoring | Supabase managed availability + health checks | ✅ Designed |
| **PI1.1** | Data integrity | Postgres constraints + RLS + checksums | ✅ Designed |

### 5e. Data Residency & GDPR

| Concern | Solution |
|---|---|
| **Data location** | Supabase project deployed in selected region. Default: US East. EU customers: EU West (Frankfurt). Supabase supports 12+ regions. |
| **Right to erasure (GDPR Art. 17)** | `DELETE FROM cloud.* WHERE tenant_id = ?` — single SQL deletes all tenant data |
| **Data portability (GDPR Art. 20)** | `drift cloud export` CLI command dumps all cloud data as JSON |
| **Data processing agreement** | Standard DPA template for enterprise customers |
| **No source code processing** | Architecturally guaranteed — source code never leaves the machine |

---

## 6. Sync Protocol & API Layer

### 6a. Sync Architecture — Offline-First

The local SQLite databases remain the source of truth. Cloud sync is **additive** — the user can always work fully offline. Sync happens on explicit `drift cloud push` or automatically after `drift analyze` (if configured).

```
Local SQLite                    Supabase                      Supabase PG
┌──────────┐                    ┌──────────┐                  ┌──────────┐
│ drift.db │──── delta ────────→│ Edge Fn  │──── upsert ────→│ public.* │
│ bridge.db│    extraction      │ /sync    │   with RLS      │ tables   │
│ cortex.db│                    │          │                  │          │
│          │←── ack + cursor ──│ 200 OK   │                  │          │
│ .drift/  │    (sync_token)   │          │                  │          │
│ sync.json│                    └──────────┘                  └──────────┘
└──────────┘
```

### 6b. Sync Protocol — Cursor-Based Delta Sync

**NOT** a full dump every time. Uses cursor-based incremental sync:

1. **Client reads local cursor** from `.drift/sync.json` — `{ last_sync_at: "2026-02-11T12:00:00Z", cursor_token: "abc123" }`
2. **Client queries local SQLite** for rows with `created_at > last_sync_at` or `updated_at > last_sync_at`
3. **Client applies redaction rules** — strips `matched_text`, `content`, `redacted_value`, BLOBs
4. **Client batches rows** into a sync payload (max 1000 rows per batch, ~500KB max)
5. **Client POSTs to `/api/v1/sync`** with JWT auth
6. **Supabase Edge Function validates JWT** (automatic), extracts `tenant_id` from `auth.jwt()`
7. **Server upserts rows** — `INSERT ... ON CONFLICT (tenant_id, project_id, <pk>) DO UPDATE`
8. **Server returns new cursor** — client stores it for next sync
9. **Conflict resolution**: Last-write-wins (LWW) based on `updated_at` timestamp. Cortex already has `conflict_log` table for auditing.

### 6c. Sync Payload Format

```json
{
  "project_id": "uuid",
  "db": "drift",
  "cursor": "2026-02-11T12:00:00Z",
  "tables": {
    "pattern_confidence": {
      "upserts": [
        { "pattern_id": "auth_check", "alpha": 3.5, "beta": 1.2, "posterior_mean": 0.745, ... }
      ],
      "deletes": ["old_pattern_id"]
    },
    "violations": {
      "upserts": [...],
      "deletes": [...]
    }
  }
}
```

### 6d. API Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/api/v1/auth/login` | Public | Exchange Supabase Auth code for session |
| `POST` | `/api/v1/auth/apikey` | JWT | Create API key for CI/CD |
| `POST` | `/api/v1/sync` | JWT or API Key | Push delta sync payload |
| `GET` | `/api/v1/sync/status` | JWT | Get last sync time, cursor, stats |
| `GET` | `/api/v1/projects` | JWT | List projects for tenant |
| `POST` | `/api/v1/projects` | JWT | Register new project |
| `GET` | `/api/v1/projects/:id/summary` | JWT | Dashboard summary (FE reads) |
| `GET` | `/api/v1/projects/:id/patterns` | JWT | Pattern confidence list |
| `GET` | `/api/v1/projects/:id/violations` | JWT | Violations list with filters |
| `GET` | `/api/v1/projects/:id/gates` | JWT | Gate results timeline |
| `GET` | `/api/v1/projects/:id/health` | JWT | Health score + trends |
| `GET` | `/api/v1/projects/:id/memories` | JWT | Bridge + cortex memory overview |
| `GET` | `/api/v1/projects/:id/dna` | JWT | DNA genes + mutations |
| `GET` | `/api/v1/projects/:id/security` | JWT | Crypto, OWASP, taint findings |
| `GET` | `/api/v1/projects/:id/contracts` | JWT | API contracts + mismatches |
| `GET` | `/api/v1/projects/:id/graph` | JWT | Call graph + coupling data |
| `DELETE` | `/api/v1/projects/:id` | JWT (owner) | Delete project + all data |
| `DELETE` | `/api/v1/account` | JWT (owner) | Delete tenant + all data (GDPR) |

### 6e. API Technology Stack

| Component | Technology | Why |
|---|---|---|
| **API Runtime** | Supabase Edge Functions (Deno) | Built-in, zero infra management, auto-deployed, low latency |
| **API Framework** | Hono (on Deno) or direct PostgREST | Hono for custom sync logic; PostgREST for standard CRUD reads (dashboard) |
| **Auth** | Supabase Auth (GoTrue) | JWT verification built-in, auto-injected into RLS context |
| **DB Client** | `@supabase/supabase-js` or direct `postgres` driver | Supabase client for auth-aware queries; raw driver for Edge Functions |
| **Validation** | Zod | Runtime schema validation for sync payloads |
| **Rate Limiting** | Edge Function logic + per-tenant quotas in DB | Prevent abuse, enforce plan limits |
| **Realtime** (future) | Supabase Realtime | Live dashboard updates via Postgres CDC — built into Supabase |

### 6f. CLI Commands — New `drift cloud` Subgroup

```
drift cloud login          # Open browser → Supabase Auth login → store JWT locally
drift cloud logout         # Clear local credentials
drift cloud push           # Sync local metadata to cloud (delta)
drift cloud push --full    # Force full re-sync (no cursor)
drift cloud status         # Show sync status, last push time, cursor
drift cloud projects       # List cloud projects for this tenant
drift cloud link <name>    # Link current directory to a cloud project
drift cloud unlink         # Unlink current directory
drift cloud export         # Download all cloud data as JSON (GDPR portability)
drift cloud apikey create  # Create API key for CI/CD
drift cloud apikey list    # List active API keys
drift cloud apikey revoke  # Revoke an API key
```

---

## 7. FE/GUI Data Contract

### 7a. Dashboard Views — What the FE Needs

The FE dashboard will consume the cloud API (Section 6d) to render these views:

| View | Primary Data Source | Key Metrics |
|---|---|---|
| **Project Overview** | `scan_history`, `audit_snapshots`, `health_trends` | Health score, scan count, last scan time, trend sparkline |
| **Pattern Intelligence** | `pattern_confidence`, `conventions`, `outliers` | Bayesian confidence, tier distribution, momentum trends |
| **Violations & Gates** | `violations`, `gate_results`, `policy_results` | Violation count by severity, gate pass/fail rate, policy compliance |
| **Security Dashboard** | `crypto_findings`, `owasp_findings`, `taint_flows`, `secrets` | CWE distribution, OWASP category heatmap, taint flow graph |
| **Architecture DNA** | `dna_genes`, `dna_mutations`, `coupling_metrics`, `coupling_cycles` | Gene consistency, mutation rate, coupling zones |
| **API Contracts** | `contracts`, `contract_mismatches` | Endpoint count, mismatch types, FE↔BE alignment |
| **Memory & Grounding** | `bridge_memories`, `bridge_grounding_results`, `causal_edges` | Memory count, avg grounding score, causal graph |
| **Call Graph** | `call_edges`, `impact_scores`, `test_coverage` | Dead code %, blast radius, coverage gaps |
| **Team Activity** | `scan_history`, `feedback`, `decisions` | Scans/week, feedback actions, decision log |

### 7b. API Response Shapes (examples)

**GET /api/v1/projects/:id/summary**
```json
{
  "project": { "id": "uuid", "name": "my-app", "last_scan": "2026-02-11T12:00:00Z" },
  "health_score": 0.82,
  "scan_count": 47,
  "violation_summary": { "critical": 2, "high": 8, "medium": 23, "low": 41 },
  "pattern_summary": { "total": 156, "established": 89, "emerging": 42, "declining": 25 },
  "gate_pass_rate": 0.91,
  "memory_count": 312,
  "avg_grounding_score": 0.67
}
```

### 7c. Data Freshness

| Data Type | Freshness Guarantee | Mechanism |
|---|---|---|
| **After `drift cloud push`** | Immediate | Sync is synchronous, API returns after DB commit |
| **Dashboard reads** | Read replica lag (~100ms) | Dashboard queries go to Supabase read replica |
| **Aggregate metrics** | 5-minute materialization | Pre-computed views for expensive aggregations |

---

## 8. Implementation Phases & Task Tables

### Phase 0: Build Proper Storage Layers for Drift & Bridge (Prerequisite — 12-17 days)

Cortex already has a proper storage abstraction: `cortex-core` defines traits (`IMemoryStorage`, `ICausalStorage`), and `cortex-storage` provides a `StorageEngine` that implements them with `ConnectionPool`, `with_reader`/`with_writer` separation, audit logging, and versioning. **Drift and Bridge have no equivalent.** This phase builds them.

> **Audit note (Feb 11, 2026):** Phase 0 underwent a thorough code-level audit against the actual codebase. The original estimates were significantly revised upward after discovering the true scope of query functions (149 in drift-storage), connection instances (7-8 in bridge, not 4), and downstream rewiring (107 NAPI call sites, 15+ evidence collector files). All gaps are documented inline below with **[AUDIT]** tags.

**Current state:**

| Crate | Storage Abstraction | Connection Management | Queries |
|---|---|---|---|
| **cortex-storage** ✅ | `StorageEngine` implements `IMemoryStorage` + `ICausalStorage` traits | `ConnectionPool` (`Arc<WriteConnection>` + `Arc<ReadPool>`) | Organized in `queries/` module, called through trait methods |
| **drift-storage** ⚠️ | `DatabaseManager` — closure-based, passes raw `&Connection` | `ReadPool` (round-robin, read-only flags) + `Mutex<Connection>` writer | 149 public functions across 15 query modules — no trait |
| **cortex-drift-bridge** ❌ | None — **7-8 separate `Mutex<Connection>` scattered across files** (not 4 as originally estimated) | No pool, no engine, raw locks at NAPI boundary | Inline SQL in `storage/tables.rs`, `query/` — all take `&Connection` |

**[AUDIT] Connection instance inventory — bridge (corrected):**

| Location | Field | Purpose |
|---|---|---|
| `DriftRuntime.bridge_db` | `Option<Mutex<Connection>>` | Main bridge.db — NAPI bridge bindings |
| `DriftRuntime.drift_db_for_bridge` | `Option<Mutex<Connection>>` | Read-only drift.db — evidence queries |
| `BridgeEventHandler.cortex_db` | `Option<Mutex<Connection>>` | bridge.db (misnamed) — event→memory writes |
| `BridgeWeightProvider.cortex_db` | `Option<Mutex<Connection>>` | bridge.db (misnamed) — Skill memory reads |
| `BridgeDecompositionPriorProvider.cortex_db` | `Option<Mutex<Connection>>` | bridge.db (misnamed) — DecisionContext reads |
| `BridgeRuntime.drift_db` | `Option<Mutex<Connection>>` | Standalone runtime — never used from NAPI |
| `BridgeRuntime.cortex_db` | `Option<Mutex<Connection>>` | Standalone runtime — never used from NAPI |
| `BridgeRuntime.bridge_db` | `Option<Mutex<Connection>>` | Standalone runtime — never used from NAPI |

**[AUDIT] Dual-runtime problem:** `BridgeRuntime` (in `cortex-drift-bridge/src/lib.rs`) and `DriftRuntime` (in `drift-napi/src/runtime.rs`) both manage bridge connections independently. `BridgeRuntime.initialize()` is **never called from `DriftRuntime`** — it exists only for standalone/test use. Phase 0b must decide: merge, delete, or keep both. Recommendation: `BridgeStorageEngine` replaces `BridgeRuntime`'s storage role; `BridgeRuntime` becomes a thin wrapper or is deprecated.

**Target state (following cortex pattern):**

```
drift-core/src/traits/
  ├── mod.rs
  ├── drift_files.rs      → trait IDriftFiles { ... }         # ~5 methods (file_metadata)
  ├── drift_analysis.rs   → trait IDriftAnalysis { ... }      # ~25 methods (detections, functions, patterns, boundaries, call_edges)
  ├── drift_structural.rs → trait IDriftStructural { ... }    # ~37 methods (coupling, constraints, contracts, DNA, crypto, secrets, etc.)
  ├── drift_enforcement.rs→ trait IDriftEnforcement { ... }   # ~21 methods (violations, gates, audit, feedback, policy, degradation)
  ├── drift_advanced.rs   → trait IDriftAdvanced { ... }      # ~9 methods (simulations, decisions, context, migration)
  ├── drift_reader.rs     → trait IDriftReader { ... }        # ~14 read-only methods (bridge evidence queries)
  └── drift_batch.rs      → trait IDriftBatchWriter { ... }   # ~5 methods (send, flush, flush_sync, stats, shutdown)

drift-storage/src/
  ├── engine.rs           → DriftStorageEngine implements all 6 IDrift* traits
  │                         Owns DatabaseManager + BatchWriter, routes through with_reader/with_writer
  ├── connection/         → (existing) DatabaseManager, ReadPool, pragmas
  ├── queries/            → (existing) 149 free fns across 15 modules, now called from engine.rs
  ├── batch/              → (existing) BatchWriter with 21 BatchCommand variants
  ├── materialized.rs     → (existing) aggregation views — wired into engine lifecycle
  ├── retention.rs        → (existing) data retention cleanup — called on engine init
  └── pagination.rs       → (existing) keyset pagination — exposed through engine for cloud sync

cortex-drift-bridge/src/
  ├── storage/
  │   ├── engine.rs       → BridgeStorageEngine implements IBridgeStorage
  │   │                     Owns ConnectionPool (new), replaces all 7-8 raw Mutex<Connection>
  │   ├── pool.rs         → ConnectionPool (write + read pool, like cortex)
  │   ├── tables.rs       → (existing) INSERT/UPDATE fns, now called from engine
  │   └── schema.rs       → (existing) DDL
  ├── query/              → (existing) read queries, now called from engine
  │   └── cross_db.rs     → ATTACH pattern replaced with trait-based data passing (cloud-compatible)
  └── traits.rs           → trait IBridgeStorage { ... }     # ~23 methods
```

**[AUDIT] Key design decisions required before implementation:**

1. **Trait splitting vs. monolithic:** Cortex uses 2 traits (IMemoryStorage: 22 methods, ICausalStorage: 10 methods) for 32 total. Drift has **149 query functions** across 15 modules. A single `IDriftStorage` with ~100 methods is unwieldy. Recommendation: **6 focused sub-traits** (files, analysis, structural, enforcement, advanced, batch) plus `IDriftReader` for bridge. Each sub-trait maps to 1-3 query modules.
2. **`Arc<T>` blanket impl:** Cortex has `impl<T: IMemoryStorage> IMemoryStorage for Arc<T>` allowing `Arc<StorageEngine>` to be used as `&dyn IMemoryStorage`. All drift traits need this pattern for `Arc<DriftStorageEngine>` sharing across NAPI threads.
3. **`Send + Sync` bounds:** All traits must have `: Send + Sync` (like cortex) since `Arc<DriftStorageEngine>` is shared across NAPI worker threads.
4. **Transaction support:** Some operations need atomicity (enforcement writes, batch inserts). Each trait should expose a `with_transaction()` method, or all individual trait methods should be individually atomic (like cortex's approach).
5. **Error type unification:** drift-storage uses `StorageError`, cortex-storage uses `CortexResult`, bridge uses `BridgeResult`. `IDriftReader` will be consumed by bridge code — need `From<StorageError> for BridgeError` or a shared error type.
6. **ATTACH pattern replacement:** `query/cross_db.rs` uses `ATTACH DATABASE drift.db` for cross-DB reads. This is SQLite-specific and won't work with Postgres. The `IDriftReader` trait replaces this — bridge calls trait methods to get data, never ATTACHes.

#### Phase 0a: Drift Storage Engine (8.5-10.5 days)

| ID | Task | Est. | Details |
|---|---|---|---|
| P0-01 | Design and define drift storage traits in `drift-core` | 2-3d | **[AUDIT] Revised from 1d.** 6 sub-traits covering 149 existing query functions: `IDriftFiles` (~5), `IDriftAnalysis` (~25: detections, functions, patterns, boundaries, call_edges, scan_history), `IDriftStructural` (~37: coupling, constraints, contracts, DNA, crypto, secrets, wrappers, OWASP, decomposition, constants, env_vars, data_access), `IDriftEnforcement` (~21: violations, gates, audit, feedback, policy, degradation, health_trends), `IDriftAdvanced` (~9: simulations, decisions, context, migration), `IDriftBatchWriter` (~5: send, flush, flush_sync, stats, shutdown). All traits need `Send + Sync` bounds and `Arc<T>` blanket impls. Follow cortex pattern: `&self` receiver, `Result<T, StorageError>` return. |
| P0-02 | Define `IDriftReader` trait in `drift-core` | 0.5d | ~14 read-only methods used by bridge evidence collectors: `pattern_confidence()`, `pattern_occurrence_rate()`, `false_positive_rate()`, `constraint_verified()`, `coupling_metric()`, `dna_health()`, `test_coverage()`, `error_handling_gaps()`, `decision_evidence()`, `boundary_data()`, `taint_flow_risk()`, `call_graph_coverage()`, `count_matching_patterns()`, `latest_scan_timestamp()`. These match `query/drift_queries.rs` 1:1. |
| P0-03 | Build `DriftStorageEngine` in `drift-storage/src/engine.rs` | 2-3d | **[AUDIT] Revised from 1.5d.** Implements all 6 `IDrift*` traits. Owns `DatabaseManager` + `BatchWriter`. Routes writes through `with_writer`, reads through `with_reader`. Batch commands route through `BatchWriter`. Must also integrate: `materialized.rs` (aggregation views), `retention.rs` (cleanup on init, like bridge does in INF-04), `pagination.rs` (keyset pagination for cloud sync cursor extraction). `open()` and `open_in_memory()` constructors mirroring cortex. |
| P0-04 | Implement `IDriftReader` on `DriftStorageEngine` | 0.5d | Read-only subset routing through `with_reader`. Bridge crate depends on `drift-core` for the trait, receives `Arc<dyn IDriftReader>` instead of raw `&Connection`. |
| P0-05 | Rewire `drift-napi` to use `DriftStorageEngine` | 1-1.5d | **[AUDIT] Revised from 0.5d.** `DriftRuntime` holds `Arc<DriftStorageEngine>` instead of raw `DatabaseManager` + `BatchWriter`. There are **107 call sites** across **9 NAPI binding files** (`analysis.rs`: 48, `structural.rs`: 16, `enforcement.rs`: 12, `bridge.rs`: 10, `graph.rs`: 6, `scanner.rs`: 6, `patterns.rs`: 4, `feedback.rs`: 3, `lifecycle.rs`: 2) that currently call `rt.db.with_writer(\|conn\| ...)` or `rt.db.with_reader(\|conn\| ...)` — all must switch to trait method calls. |
| P0-06 | Update drift-storage tests | 0.5d | Existing tests should mostly work since the engine delegates to the same query functions. Add engine-level integration tests for `open_in_memory()`, read/write routing, batch writer integration, retention-on-init, and pagination. |
| P0-15 | Define `IWorkspaceStorage` trait in `drift-core` | 0.5d | **[AUDIT-2] NEW — discovered during Feb 11 connection audit.** `drift-core/src/workspace/` has **12 files with ~30+ direct `Connection::open()` calls** that bypass `DatabaseManager` entirely. These perform workspace-level operations: init, backup, export/import, integrity checks, GC, status, project management, monorepo support, destructive resets. Trait needs ~10 methods: `initialize()`, `status()`, `project_info()`, `workspace_context()`, `gc()`, `backup()`, `export()`, `import()`, `integrity_check()`, `schema_version()`. Some operations (backup via SQLite Backup API, `VACUUM INTO`, `PRAGMA integrity_check`) are inherently SQLite-specific — trait methods can return `NotSupported` for cloud backends. `Send + Sync` bounds + `Arc<T>` blanket impl. |
| P0-16 | Refactor workspace module to use `IWorkspaceStorage` trait | 1-1.5d | **[AUDIT-2] NEW.** 12 files in `drift-core/src/workspace/`: `init.rs` (3× `Connection::open`), `backup.rs` (5× `Connection::open*` — backup source/dest, integrity check, retention, registry), `export.rs` (2× `Connection::open*` — VACUUM INTO, import integrity), `integrity.rs` (1× `Connection::open_with_flags`), `context.rs` (`&Connection` for workspace_context CRUD), `migration.rs` (`&Connection` for workspace schema), `project.rs` (`&Connection` for project queries), `status.rs` (`&Connection` for status queries), `gc.rs` (`&Connection` for garbage collection), `destructive.rs` (`&Connection` for reset/destroy), `monorepo.rs` (`&Connection` for monorepo queries). Route all through `IWorkspaceStorage`. Backup/export can remain SQLite-only (local operations by nature) but `status()`, `project_info()`, `gc()`, `workspace_context()` must work against the engine for cloud parity. |
| P0-17 | Update drift-core workspace tests | 0.5d | **[AUDIT-2] NEW.** 7 existing test files in `drift-core/tests/` (workspace_test.rs, hardening_workspace_test.rs, etc.) use `Connection::open_in_memory()` directly. Switch to `IWorkspaceStorage` test doubles or engine's in-memory mode. |

#### Phase 0b: Bridge Storage Engine (6-9 days)

| ID | Task | Est. | Details |
|---|---|---|---|
| P0-07 | Define `IBridgeStorage` trait | 1d | ~23 methods: 7 writes (insert_memory, insert_grounding_result, insert_snapshot, insert_event, insert_metric, upsert_weight, upsert_decomposition_prior), 7 reads (get_memory, query_memories_by_type, get_grounding_history, get_snapshots, get_events, get_metrics, get_schema_version), 3 formalized ad-hoc queries (query_all_memories_for_grounding, search_memories_by_tag, get_weight_adjustments), 4 lifecycle (initialize, migrate, health_check, shutdown), 2 usage (count_memories, storage_stats). Must have `Send + Sync` bounds + `Arc<T>` blanket impl. |
| P0-08 | Build `ConnectionPool` for bridge | 0.5d | Modeled after cortex-storage's pool. Write connection + 2-4 read connections. WAL mode. Currently bridge has zero pooling. |
| P0-09 | Build `BridgeStorageEngine` | 2-3d | **[AUDIT] Revised from 1.5d.** Implements `IBridgeStorage`. Owns `ConnectionPool`. Routes existing `storage/tables.rs` writes and `query/` reads through the engine. Must replace **all 7-8 `Mutex<Connection>` instances** (not 4 as originally estimated — see inventory above). Must also resolve the dual-runtime problem: `BridgeRuntime` in `lib.rs` should either be merged into the engine or deprecated to a thin wrapper. |
| P0-10 | Rewire bridge consumers (5+ structs/modules) | 1-2d | **[AUDIT] Revised from 0.5d — 5+ consumers, not 3.** Replace `Option<Mutex<Connection>>` with `Arc<dyn IBridgeStorage>` in: (1) `BridgeEventHandler` (`event_mapping/mapper.rs`), (2) `BridgeWeightProvider` (`specification/weight_provider.rs`), (3) `BridgeDecompositionPriorProvider` (`specification/decomposition_provider.rs`), (4) `specification/events.rs` — 3 functions (`on_spec_corrected`, `on_contract_verified`, `on_decomposition_adjusted`) take raw `bridge_db: Option<&Connection>`, (5) `grounding/contradiction.rs` — `generate_contradiction()` takes `bridge_db: Option<&Connection>`. |
| P0-11 | Rewire `DriftRuntime` bridge wiring | 0.5d | `DriftRuntime.bridge_db` → `bridge_store: Arc<BridgeStorageEngine>`. `drift_db_for_bridge` → `drift_reader: Arc<dyn IDriftReader>`. NAPI bridge bindings call trait methods. `bridge_deduplicator` stays in `DriftRuntime` (in-memory only). |
| P0-12 | Rewire evidence collectors + ad-hoc SQL queries | 1d | **[AUDIT] Revised from 0.5d.** The grounding evidence system has **~15 files** that take raw `&Connection`: 12 collector functions in `grounding/evidence/collector.rs`, composite runners in `grounding/evidence/composite.rs`, the loop runner in `grounding/loop_runner.rs`, plus the 12 query functions in `query/drift_queries.rs`. All currently receive `&Connection` to drift.db — must be rewired to call `Arc<dyn IDriftReader>` trait methods instead. Also includes `query/cross_db.rs` ATTACH-based queries — the ATTACH pattern must be replaced with trait-based data passing (bridge calls `IDriftReader` methods, never ATTACHes drift.db directly). |
| P0-13 | Rewire `tools/` directory consumers | 0.5d | `tools/drift_health.rs` (`handle_drift_health()`) and `tools/drift_grounding_check.rs` (`handle_drift_grounding_check()`) take `Option<&Mutex<Connection>>` — rewire to use engine. |
| P0-14 | Update ~20+ bridge test files | 1-1.5d | **[AUDIT] Revised from 0.5d.** 20+ test files in `cortex-drift-bridge/tests/` each create their own `Connection::open_in_memory()` and build mock schemas manually. All must switch to `BridgeStorageEngine::open_in_memory()`. Additionally, ~10 test files with mock `drift_db` setups (evidence collector tests, grounding tests) need `IDriftReader` test doubles or the engine's in-memory mode. |

#### Phase 0 Summary

| Subsystem | Trait | Engine | Est. Total |
|---|---|---|---|
| **Drift** | 6 sub-traits (~100 total methods) + `IDriftReader` (~14 methods) + `IWorkspaceStorage` (~10 methods) | `DriftStorageEngine` + workspace refactor | 8.5-10.5 days |
| **Bridge** | `IBridgeStorage` (~23 methods) | `BridgeStorageEngine` | 6-9 days |
| **Cortex** | ✅ Already done (`IMemoryStorage` + `ICausalStorage`) | ✅ `StorageEngine` exists | 0 days |
| **Total Phase 0** | | | **14.5-19.5 days** |
| **With 2 engineers (0a ‖ 0b)** | | | **9.5-11.5 days** |

> **Why this matters for cloud:** Without these traits, there's no seam to inject a Supabase/Postgres backend. The traits are the swap point — `SqliteDriftStorage` for local, `SupabaseDriftStorage` for cloud. Cortex can already do this because it has the traits. Drift and bridge cannot.
>
> **[AUDIT] Additional rationale:** The trait boundary also eliminates the SQLite-specific `ATTACH DATABASE` pattern used by bridge for cross-DB queries. Cloud Postgres uses a single shared database with RLS — no ATTACH needed. The `IDriftReader` trait makes this transparent: bridge code calls `reader.pattern_confidence(id)` regardless of whether the backing store is local SQLite or cloud Postgres.

### Phase 1: Cloud Infrastructure (5-7 days)

| ID | Task | Est. |
|---|---|---|
| P1-01 | Create Supabase project (Pro plan for read replicas + SSO) | 0.5d |
| P1-02 | Generate Postgres DDL from all SQLite migrations (~60 syncable tables) | 1d |
| P1-03 | Add `tenant_id` + `project_id` to all tables, add RLS policies | 1d |
| P1-04 | Configure Supabase Auth (email/password, GitHub OAuth, MFA) | 0.5d |
| P1-05 | Create Edge Functions project structure + deploy pipeline | 0.5d |
| P1-06 | Configure Supabase network restrictions + API key scopes | 0.5d |
| P1-07 | Create `tenants`, `projects`, `api_keys`, `sync_cursors`, `usage_billing` cloud-only tables | 0.5d |
| P1-08 | Enable Supabase read replicas (Pro plan) for dashboard queries | 0.5d |
| P1-09 | Write Postgres migration runner (Supabase CLI `supabase db push` or raw SQL) | 0.5d |
| P1-10 | CI/CD pipeline for infrastructure (GitHub Actions) | 0.5d |

### Phase 2: Sync Engine (4-5 days)

| ID | Task | Est. |
|---|---|---|
| P2-01 | Implement delta extraction from local SQLite (cursor-based) | 1d |
| P2-02 | Implement redaction layer (strip `matched_text`, `content`, BLOBs) | 0.5d |
| P2-03 | Implement sync payload serialization (JSON batches) | 0.5d |
| P2-04 | Implement cloud sync API handler (`POST /api/v1/sync`) | 1d |
| P2-05 | Implement upsert logic with Supabase RLS context (`auth.uid()`) | 0.5d |
| P2-06 | Implement cursor management (`.drift/sync.json`) | 0.5d |
| P2-07 | Implement conflict resolution (LWW + conflict_log) | 0.5d |
| P2-08 | Integration test: full sync cycle (local → cloud → verify) | 0.5d |

### Phase 3: API Layer (3-4 days)

| ID | Task | Est. |
|---|---|---|
| P3-01 | Implement auth endpoints (login, apikey CRUD) | 0.5d |
| P3-02 | Implement project CRUD endpoints | 0.5d |
| P3-03 | Implement dashboard read endpoints (summary, patterns, violations, etc.) | 1.5d |
| P3-04 | Implement GDPR endpoints (export, delete account) | 0.5d |
| P3-05 | Rate limiting + per-tenant quotas | 0.5d |
| P3-06 | API integration tests | 0.5d |

### Phase 4: CLI Integration (2-3 days)

| ID | Task | Est. |
|---|---|---|
| P4-01 | Implement `drift cloud login/logout` (Supabase Auth PKCE flow) | 0.5d |
| P4-02 | Implement `drift cloud push` (delta sync) | 0.5d |
| P4-03 | Implement `drift cloud status/projects/link/unlink` | 0.5d |
| P4-04 | Implement `drift cloud export` (GDPR) | 0.5d |
| P4-05 | Implement `drift cloud apikey` subcommands | 0.5d |
| P4-06 | Auto-push after `drift analyze` (opt-in config) | 0.5d |

### Phase 5: Hardening & Compliance (2-3 days)

| ID | Task | Est. |
|---|---|---|
| P5-01 | Penetration testing: RLS bypass attempts | 0.5d |
| P5-02 | Verify encryption at rest (Supabase) and in transit (TLS) | 0.5d |
| P5-03 | Set up Supabase dashboard monitoring + custom audit_log queries | 0.5d |
| P5-04 | Write SOC 2 evidence documentation | 0.5d |
| P5-05 | Load test: 100 concurrent tenants syncing | 0.5d |
| P5-06 | Disaster recovery test: Supabase point-in-time recovery | 0.5d |

### Phase 6: Enterprise P0 Features (8-10 days)

Implements the 5 P0 gaps identified in Section 11a. These block enterprise sales.

#### Phase 6a: SCIM Provisioning (GAP-01, 2-3 days)

| ID | Task | Est. | Details |
|---|---|---|---|
| P6-01 | Evaluate WorkOS vs. hand-rolled SCIM | 0.5d | WorkOS provides unified SSO+SCIM. If cost-effective, use it for Enterprise tier and keep Supabase Auth for Free/Pro. Decision gate. |
| P6-02 | Implement SCIM `/Users` endpoint (Edge Function) | 1d | `POST/GET/PATCH/DELETE /scim/v2/Users`. Maps IdP user to Supabase Auth user + `user_tenant_mappings`. Bearer token auth (separate from user JWT). |
| P6-03 | Implement SCIM `/Groups` endpoint | 0.5d | `POST/GET/PATCH/DELETE /scim/v2/Groups`. Maps IdP groups to Drift teams (Phase 6c). Group membership → team membership. |
| P6-04 | SCIM deprovisioning: user deactivation | 0.5d | When IdP sends `active: false`, disable Supabase Auth user + revoke all API keys + log audit event. Data preserved, access revoked. |
| P6-05 | SCIM integration tests (Okta, Azure AD) | 0.5d | Test with Okta SCIM test harness + Azure AD SCIM validator. Verify create/update/deactivate/delete lifecycle. |

#### Phase 6b: Webhook System (GAP-02, 2-3 days)

| ID | Task | Est. | Details |
|---|---|---|---|
| P6-06 | Create `webhook_endpoints` + `webhook_deliveries` tables | 0.5d | DDL from GAP-02 spec. RLS policies. Indexes on `tenant_id`, `endpoint_id`. |
| P6-07 | Implement webhook registration API | 0.5d | `POST/GET/PATCH/DELETE /api/v1/webhooks`. Validate URL (HTTPS only), generate shared secret, store hashed. |
| P6-08 | Implement webhook dispatch engine | 1d | Edge Function or Supabase Queue. On trigger event: serialize payload, sign with HMAC-SHA256, POST to registered URLs. Retry with exponential backoff (1s→2s→4s→8s→16s, max 5 retries). |
| P6-09 | Wire sync/gate/violation events to webhook dispatch | 0.5d | After `POST /api/v1/sync` succeeds, fire `scan.completed`. After gate results upserted, fire `gate.failed` for failing gates. After new critical violations, fire `violation.new`. |
| P6-10 | Webhook delivery logs + test endpoint | 0.5d | `GET /api/v1/webhooks/:id/deliveries` (paginated). `POST /api/v1/webhooks/:id/test` sends a `ping` event. |

#### Phase 6c: Team & Org Management (GAP-04, 2 days)

| ID | Task | Est. | Details |
|---|---|---|---|
| P6-11 | Create `teams`, `team_memberships`, `team_projects`, `invitations` tables | 0.5d | DDL from GAP-04 spec. RLS policies. Indexes. |
| P6-12 | Implement team CRUD API | 0.5d | `POST/GET/PATCH/DELETE /api/v1/teams`. Only org admins can create/delete teams. |
| P6-13 | Implement invitation flow | 0.5d | `POST /api/v1/invitations` (sends email via Resend/Postmark). `POST /api/v1/invitations/:token/accept`. Expiry after 7 days. Resend capability. |
| P6-14 | Implement seat management + member list | 0.5d | `GET /api/v1/members` (paginated). Enforce `seat_limit` from `subscriptions` table. Return 402 if seat limit reached on invite. |

#### Phase 6d: Audit Log API + IP Allowlisting (GAP-03 + GAP-05, 2 days)

| ID | Task | Est. | Details |
|---|---|---|---|
| P6-15 | Create `cloud_audit_log` table with immutability policies | 0.5d | DDL from GAP-03 spec. RLS + no-update/no-delete policies. |
| P6-16 | Wire audit events into all mutating API endpoints | 0.5d | Every `POST/PATCH/DELETE` logs to `cloud_audit_log` with actor, action, resource, IP, user agent. Use Postgres trigger or Edge Function middleware. |
| P6-17 | Implement audit query API | 0.5d | `GET /api/v1/audit` with cursor pagination + filters (actor, action, resource_type, time range). `GET /api/v1/audit/export` returns JSON Lines for SIEM. |
| P6-18 | Create `ip_allowlist` table + enforcement middleware | 0.5d | DDL from GAP-05 spec. Edge Function middleware checks client IP against tenant's allowlist. If allowlist is empty, all IPs allowed (default open). CIDR matching via `inet` type. |

### Phase 7: Operational Readiness (5-7 days)

Implements the P1 operational gaps from Section 11b. Expected during enterprise evaluation.

#### Phase 7a: API Design Hardening (GAP-06 + GAP-07 + GAP-08 + GAP-09 + GAP-14, 3-4 days)

| ID | Task | Est. | Details |
|---|---|---|---|
| P7-01 | Add cursor-based pagination to all list endpoints | 1d | Refactor all `GET /api/v1/projects/:id/*` endpoints. Base64 cursor (keyset pagination on `id`). Response envelope: `{ data, pagination: { cursor, has_more, total } }`. Default limit 50, max 200. |
| P7-02 | Add filter + sort parameters to list endpoints | 0.5d | Per-endpoint filters (severity, file, category, since/before). Sort by any indexed column. Validate against allowlist (prevent SQL injection via sort param). |
| P7-03 | Implement rate limiting middleware | 0.5d | Sliding window counter per tenant. Per-plan limits from GAP-07. Rate limit headers on every response. 429 with `retry_after` on exceeded. |
| P7-04 | Write OpenAPI 3.1 spec | 0.5d | Hand-write or generate from Hono routes. Publish at `/api/v1/openapi.json`. Include all request/response schemas, error codes, auth requirements. |
| P7-05 | Generate TypeScript SDK from OpenAPI | 0.5d | `@drift/cloud-sdk` npm package. Auto-generated via `openapi-typescript-codegen`. Publish to npm. |
| P7-06 | Implement idempotency keys | 0.5d | `idempotency_keys` table from GAP-14. Middleware checks `Idempotency-Key` header on all `POST` endpoints. pg_cron cleanup of expired keys. |
| P7-07 | Document API versioning + deprecation policy | 0.5d | Add to docs site. 12-month sunset minimum. Sunset + Deprecation headers on deprecated endpoints. |

#### Phase 7b: Health, SLA & Observability (GAP-10 + GAP-11 + GAP-12 + GAP-13, 2-3 days)

| ID | Task | Est. | Details |
|---|---|---|---|
| P7-08 | Implement `/health` and `/ready` endpoints | 0.5d | Edge Functions. `/health` = shallow (200 OK). `/ready` = deep (DB ping, auth check, read replica lag). |
| P7-09 | Set up external uptime monitoring | 0.5d | BetterUptime or Checkly hitting `/health` every 30s. Alert to PagerDuty/OpsGenie on failure. |
| P7-10 | Create public status page | 0.5d | Instatus or Statuspage.io. Components: API, Auth, Database, Sync Engine, Dashboard. RSS feed. Email subscribers for incidents. |
| P7-11 | Define SLA tiers + incident severity definitions | 0.5d | Document per GAP-11 spec. Publish on website + include in enterprise contracts. SLA credit policy. |
| P7-12 | Set up platform observability | 0.5d | Supabase Logs Dashboard + Grafana Cloud (or Datadog). Dashboards for: sync latency p50/p95/p99, API error rate, Edge Function cold starts, per-tenant sync frequency. |
| P7-13 | Configure alerting rules | 0.5d | Per GAP-12: sync error >5% → P2, API p99 >5s → P3, DB pool exhaustion → P1, replica lag >5s → P2. Route to PagerDuty. |
| P7-14 | Define RPO/RTO + DR runbook | 0.5d | Document per GAP-13. Schedule quarterly DR drill. Set up cross-region backup for Team/Enterprise plans. |

### Total Estimated Timeline

| Phase | Duration | Depends On |
|---|---|---|
| Phase 0: Storage Engines (Drift + Bridge + Workspace) | **14.5-19.5 days** _(revised from 12-17 after Feb 11 workspace audit)_ | Nothing (start immediately) |
| Phase 1: Cloud Infrastructure | 5-7 days | Phase 0 (traits needed to build Supabase impls) |
| Phase 2: Sync Engine | 4-5 days | Phase 0 + Phase 1 |
| Phase 3: API Layer | 3-4 days | Phase 1 |
| Phase 4: CLI Integration | 2-3 days | Phase 2 + Phase 3 |
| Phase 5: Hardening | 2-3 days | Phase 4 |
| Phase 6: Enterprise P0 Features | 8-10 days | Phase 3 (API layer exists) |
| Phase 7: Operational Readiness | 5-7 days | Phase 3 + Phase 5 |
| **Total (MVP cloud)** | **30.5-42 days** _(revised from 28-39 after Feb 11 workspace audit)_ | Phases 0-5 only — cloud works but not enterprise-ready |
| **Total (enterprise-ready)** | **43.5-59 days** _(revised from 41-56)_ | All 8 phases — full enterprise feature set |
| **Critical path (MVP)** | **~21.5-28 days** _(revised from ~20-26)_ | 2 engineers: Phase 0a‖0b (9.5-11.5d), then Phase 1‖3 |
| **Critical path (enterprise)** | **~29.5-38 days** _(revised from ~28-36)_ | 2 engineers: Phase 6a‖6b‖6c‖6d parallel, Phase 7a‖7b parallel |

**Parallelization opportunities:**
- Phase 0a (drift) ‖ Phase 0b (bridge) — independent codebases
- Phase 1 ‖ Phase 3 — infra vs. API can overlap after Phase 0
- Phase 6a (SCIM) ‖ Phase 6b (webhooks) ‖ Phase 6c (teams) ‖ Phase 6d (audit/IP) — all independent
- Phase 7a (API hardening) ‖ Phase 7b (observability) — independent concerns
- P2 features (Phase 8, not yet scoped) can follow Phase 7 or run in parallel with later Phase 6 tasks

---

## 9. Cost Estimation & Infrastructure

### 9a. Supabase Monthly Cost Estimate

| Supabase Plan | Included | Est. Monthly Cost | When to Use |
|---|---|---|---|
| **Free** | 500MB DB, 50K Auth MAU, 500K Edge Function invocations, 1GB bandwidth | **$0** | Development, testing, early alpha |
| **Pro** | 8GB DB, 100K Auth MAU, 2M Edge Function invocations, 250GB bandwidth, read replicas, daily backups, SSO/SAML | **$25/mo** | Production launch, <500 tenants |
| **Team** | Same as Pro + SOC 2 compliance, priority support, org-level billing | **$599/mo** | When SOC 2 is required |
| **Enterprise** | Custom limits, dedicated Postgres, SLA, BAA for HIPAA | **Custom** | >1000 tenants, enterprise contracts |

**Add-ons (Pro plan):**

| Add-on | Pricing | When Needed |
|---|---|---|
| **Additional DB storage** | $0.125/GB/mo | When > 8GB DB |
| **Additional bandwidth** | $0.09/GB | Heavy sync traffic |
| **Point-in-time recovery** | $100/mo (Pro), included (Team) | Production disaster recovery |
| **Read replicas** | $0.016/hr per replica | Dashboard read scaling |
| **Custom domain** | Included in Pro | `api.drift.dev` instead of `*.supabase.co` |

**Realistic cost trajectory:**

| Stage | Tenants | Plan | Est. Monthly |
|---|---|---|---|
| Alpha / dev | 1–10 | Free | **$0** |
| Beta launch | 10–100 | Pro | **$25–$50** |
| Production | 100–500 | Pro + add-ons | **$50–$150** |
| Growth | 500–2000 | Team | **$599–$800** |
| Enterprise | 2000+ | Enterprise | **Custom** |

> **Key advantage:** Supabase Free tier lets us develop and test the entire cloud layer at **$0**. Self-managed Postgres (Aurora etc.) starts at ~$45/mo even idle. This is ideal for iterating before launch.

### 9b. Scaling Triggers

| Metric | Threshold | Action |
|---|---|---|
| DB size > 8GB | Pro plan limit | Purchase additional storage ($0.125/GB) |
| Edge Function timeouts | > 1% of sync requests | Optimize batch sizes, consider splitting payloads |
| Read replica lag > 1s | Dashboard slowness | Add second read replica |
| Auth MAU > 100K | Pro plan limit | Upgrade to Team or Enterprise |
| > 2K tenants | RLS query plan degradation | Add `tenant_id` partitioning, upgrade to dedicated Postgres |
| Bandwidth > 250GB/mo | Pro plan limit | Purchase additional bandwidth or upgrade plan |

---

## 10. Risk Register

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| R1 | **RLS performance degradation** at scale (>10K tenants) | Low | High | Monitor query plans with `EXPLAIN ANALYZE`. Add `tenant_id` as leading index column on all tables. Partition large tables by `tenant_id`. |
| R2 | **Data leak via application bug** | Medium | Critical | Defense in depth: RLS (L4) is the safety net even if L3 (app) fails. Penetration test RLS bypass quarterly. |
| R3 | **Sync payload too large** for Edge Function (2MB body limit) | Medium | Medium | Batch into 500KB chunks. Implement streaming for large projects. Split across multiple Edge Function calls. |
| R4 | **Source code accidentally synced** | Low | Critical | Redaction layer is a hard filter — `parse_cache`, `file_metadata`, `matched_text`, `content` fields all blocked at extraction. Unit tests verify redaction. |
| R5 | **Supabase token expiry during CI/CD** | Medium | Low | API keys (non-expiring, scoped) for CI. `drift cloud apikey create --scope sync` for automation. |
| R6 | **Supabase project pausing** (Free tier only) | Low | Low | Free tier pauses after 1 week inactivity. Pro plan ($25/mo) never pauses. Production always on Pro+. |
| R7 | **Migration breaks existing local workflow** | Low | High | Cloud is purely additive. Local SQLite workflow unchanged. `drift cloud push` is opt-in. No local behavior changes without `drift cloud link`. **Offline guarantee enforced by CI network-isolation test.** |
| R8 | **GDPR right-to-erasure incomplete** | Low | High | Single `DELETE WHERE tenant_id = ?` with CASCADE. Automated verification job confirms zero rows post-deletion. |
| R9 | **Schema drift between SQLite and Postgres** | Medium | Medium | Single source of truth for schemas. Generate Postgres DDL from SQLite migrations. CI validates both schemas match. |
| R10 | **Cortex v010 sync tables conflict with new design** | Low | Medium | v010 tables (`sync_state`, `sync_log`, `conflict_log`) are a subset of what we need. Extend, don't replace. Add cloud-specific columns via new migration. |
| R11 | **SCIM provider lock-in** (WorkOS vs. hand-rolled) | Medium | Medium | If we choose WorkOS: single vendor dependency for enterprise auth. Mitigation: abstract behind `IIdentityProvider` trait. If hand-rolled: more work but full control. Decision gate in P6-01. |
| R12 | **Webhook delivery reliability** at scale | Medium | Medium | Webhook targets may be slow/down. Mitigation: async dispatch queue (Supabase Queues or pg_cron + outbox table), circuit breaker per endpoint, dead letter queue. Never block sync on webhook delivery. |
| R13 | **Rate limiting bypass** via multiple API keys | Low | Medium | Single tenant creates N API keys to circumvent per-key rate limits. Mitigation: rate limits are per-tenant, not per-key. Tenant ID extracted from JWT/API key, not from the key itself. |
| R14 | **Audit log storage growth** (immutable, never deleted) | Medium | Low | `cloud_audit_log` is append-only. At scale (>1M events/month), storage grows fast. Mitigation: archive old events to cold storage (S3/GCS) after retention period. Keep hot table small. Partitioning by month. |
| R15 | **IP allowlist locks out admin** | Low | High | Admin accidentally sets overly restrictive IP allowlist, locking themselves out. Mitigation: Supabase dashboard access is separate from API allowlist. Always allow Supabase dashboard IP. `drift cloud ip-allowlist reset` CLI command as escape hatch. |
| R16 | **Webhook secret rotation** | Low | Medium | Rotating webhook secrets requires coordinating with all registered endpoints simultaneously. Mitigation: support dual-secret validation during rotation window (old + new secret both valid for 24h). |
| R17 | **SLA credit abuse** | Low | Low | Tenants claiming SLA credits for self-inflicted issues (e.g., misconfigured IP allowlist). Mitigation: SLA excludes issues caused by customer configuration. Incident reports distinguish platform vs. customer-caused outages. |

---

## 11. Enterprise Readiness Gap Analysis

> **Source:** Cross-referenced against the [EnterpriseReady](https://www.enterpriseready.io/) framework (12 categories), SOC 2 Type II controls, and feature parity with SonarCloud, Snyk, Datadog, and GitHub Enterprise Cloud. Assessed Feb 2026.
>
> **Verdict:** The architecture (multi-tenant RLS, encryption, sync protocol, offline-first) is solid. The biggest gaps are in **operational readiness** — the things enterprise IT, security, and procurement teams check before signing.

---

### 11a. P0 — Blocks Enterprise Sales

These are table-stakes. Enterprise procurement will reject the product without them.

#### GAP-01: SCIM Provisioning (User Lifecycle Automation)

SSO/SAML is designed (Section 5a) but **SCIM is completely absent**. Enterprise IT requires automated user provisioning/deprovisioning from their IdP (Okta, Azure AD, OneLogin). When an employee is terminated, their Drift access must be revoked automatically — not manually. Without SCIM, you fail most enterprise security questionnaires.

**What's missing:**
- SCIM 2.0 `/Users` and `/Groups` endpoints (RFC 7644)
- IdP-initiated provisioning (create/update/deactivate/delete users)
- Group-to-role mapping (IdP group → Drift tenant role)
- SCIM event webhook delivery for provisioning changes
- SCIM bearer token auth (separate from user JWT)

**Implementation notes:**
- Supabase Auth does **not** have built-in SCIM. Requires a custom Edge Function or external SCIM adapter (e.g., WorkOS, Stytch, or hand-rolled).
- WorkOS provides SCIM + SSO as a unified service — may be worth evaluating as an alternative to raw Supabase Auth for enterprise tier.

#### GAP-02: Webhooks / Event Notification System

Zero webhook infrastructure anywhere in the document. Enterprise customers need programmatic notifications for CI/CD integration, alerting pipelines, and third-party tool orchestration.

**Key events that need webhooks:**
- `scan.completed` — scan finished with summary stats
- `gate.failed` — quality gate failed (blocks PR merge)
- `violation.new` — new critical/high violation detected
- `grounding.degraded` — memory grounding score dropped below threshold
- `apikey.expiring` — API key approaching expiration (7 days warning)
- `sync.failed` — sync failed after retries
- `project.created` / `project.deleted`

**What's missing:**
- Webhook registration API: `POST /api/v1/webhooks` (url, events[], secret)
- Webhook management: `GET/PATCH/DELETE /api/v1/webhooks/:id`
- Webhook signature verification (HMAC-SHA256 with shared secret)
- Retry policy: exponential backoff (1s → 2s → 4s → 8s → ...), max 5 retries
- Event catalog with documented payload schemas
- Delivery logs: `GET /api/v1/webhooks/:id/deliveries` (status, response code, latency)
- Dead letter queue for permanently failed deliveries
- Idempotency key (`X-Webhook-Id`) on every delivery
- Test endpoint: `POST /api/v1/webhooks/:id/test` (sends a ping event)

**Cloud-only table needed:**
```sql
CREATE TABLE webhook_endpoints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    url TEXT NOT NULL,
    secret_hash TEXT NOT NULL,
    events TEXT[] NOT NULL,  -- e.g. {'scan.completed', 'gate.failed'}
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE webhook_deliveries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id UUID NOT NULL REFERENCES webhook_endpoints(id),
    event_type TEXT NOT NULL,
    payload JSONB NOT NULL,
    status_code INT,
    response_body TEXT,
    attempt INT NOT NULL DEFAULT 1,
    delivered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    next_retry_at TIMESTAMPTZ
);
```

#### GAP-03: Audit Log API (Searchable, Exportable, SIEM-Ready)

The `audit_log` table exists (Section 2d) but has **zero API surface**. Enterprise security teams cannot query, export, or stream audit events. This blocks SOC 2 CC7.1 (Monitoring & Detection) compliance.

**What's missing:**
- `GET /api/v1/audit` — paginated, filterable audit event query
  - Filters: `?actor=user@email.com`, `?action=delete`, `?resource_type=project`, `?after=2026-01-01T00:00:00Z`, `?before=...`
  - Pagination: cursor-based, `?cursor=X&limit=100`
- `GET /api/v1/audit/export` — bulk export as JSON Lines (for SIEM ingestion)
- SIEM integration formats: syslog (RFC 5424), CEF, JSON Lines
- Immutable audit trail guarantee — cloud audit records are INSERT-only, no UPDATE/DELETE
- Audit event schema documentation (what fields, what actions, what actors)
- Configurable retention per plan (Free: 30 days, Pro: 1 year, Enterprise: unlimited/custom)
- Supabase Realtime subscription for live audit stream (SOC monitoring)

**Audit event schema (cloud):**
```sql
CREATE TABLE cloud_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    actor_id UUID NOT NULL,           -- who did it
    actor_email TEXT NOT NULL,         -- human-readable
    action TEXT NOT NULL,              -- e.g. 'project.delete', 'apikey.create', 'sync.push'
    resource_type TEXT NOT NULL,       -- e.g. 'project', 'apikey', 'webhook'
    resource_id TEXT,                  -- ID of affected resource
    metadata JSONB,                   -- action-specific details
    ip_address INET,                  -- client IP
    user_agent TEXT,                  -- client user agent
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- RLS: tenant isolation
ALTER TABLE cloud_audit_log ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON cloud_audit_log USING (tenant_id = current_setting('app.tenant_id')::UUID);

-- Immutability: no UPDATE/DELETE for non-superusers
CREATE POLICY no_update ON cloud_audit_log FOR UPDATE USING (false);
CREATE POLICY no_delete ON cloud_audit_log FOR DELETE USING (false);
```

#### GAP-04: Team & Organization Management

Only `tenants` and `user_tenant_mappings` exist (Section 3c). Real enterprise orgs need hierarchy, invitations, and seat management.

**What's missing:**

| Feature | Current State | Required |
|---|---|---|
| **Org hierarchy** | Flat: tenant → projects | Org → Teams → Projects (team-scoped access) |
| **Team CRUD** | None | `POST/GET/PATCH/DELETE /api/v1/teams` |
| **User invitation** | None | Email invite → accept → join tenant with role |
| **Seat management** | None | Enforce license seat count per plan |
| **User deactivation** | None | Suspend (not delete) — data preserved, access revoked |
| **Ownership transfer** | None | Transfer project/org ownership to another user |
| **Pending invitations** | None | List, resend, revoke pending invites |
| **Member list** | None | `GET /api/v1/members` — list all tenant members with roles |

**Cloud-only tables needed:**
```sql
CREATE TABLE teams (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    name TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE team_memberships (
    team_id UUID NOT NULL REFERENCES teams(id),
    user_id UUID NOT NULL,
    role TEXT NOT NULL DEFAULT 'member',  -- 'lead', 'member'
    PRIMARY KEY (team_id, user_id)
);

CREATE TABLE team_projects (
    team_id UUID NOT NULL REFERENCES teams(id),
    project_id UUID NOT NULL REFERENCES projects(id),
    PRIMARY KEY (team_id, project_id)
);

CREATE TABLE invitations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    email TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'member',
    invited_by UUID NOT NULL,
    token TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

#### GAP-05: IP Allowlisting

Not mentioned anywhere. Enterprise security teams require restricting API access to specific IP ranges / CIDR blocks. Critical for SOC 2 CC6.1 (logical access controls).

**What's missing:**
- Per-tenant IP allowlist configuration: `POST /api/v1/settings/ip-allowlist`
- IP allowlist enforcement on all API endpoints (Edge Function middleware)
- CIDR notation support (e.g., `10.0.0.0/8`, `192.168.1.0/24`)
- Allowlist bypass for Supabase dashboard (admin-only internal IP)
- Temporary allowlist entries with TTL (for contractor access)

**Cloud-only table:**
```sql
CREATE TABLE ip_allowlist (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    cidr TEXT NOT NULL,         -- e.g. '10.0.0.0/8'
    description TEXT,           -- e.g. 'Corporate VPN'
    expires_at TIMESTAMPTZ,    -- NULL = permanent
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

---

### 11b. P1 — Expected by Enterprise Buyers at Evaluation

These won't block a first call, but will come up during proof-of-concept or security review. Missing any of these makes you look immature vs. SonarCloud/Snyk.

#### GAP-06: API Pagination, Filtering & Sorting

The dashboard read endpoints (Section 6d) return raw data with zero query parameters. Any project with >100 violations will overwhelm the response and the browser.

**What every `GET` list endpoint needs:**
- **Cursor-based pagination:** `?cursor=eyJpZCI6MTAwfQ&limit=50` (base64 cursor, not offset — offset is O(n) on large tables)
- **Filter parameters:** endpoint-specific, e.g. `?severity=critical&file=src/auth.ts&since=2026-01-01`
- **Sort parameters:** `?sort=created_at&order=desc`
- **Response envelope:**
```json
{
  "data": [...],
  "pagination": {
    "cursor": "eyJpZCI6MTUwfQ",
    "has_more": true,
    "total": 1423
  }
}
```
- **HTTP headers:** `X-Total-Count`, `Link: <...>; rel="next"` (RFC 8288)
- **Default limit:** 50, max limit: 200 (prevent accidental full-table dumps)

**Affected endpoints (Section 6d):** `/patterns`, `/violations`, `/gates`, `/health`, `/memories`, `/dna`, `/security`, `/contracts`, `/graph`

#### GAP-07: Rate Limiting (Detailed Design)

Mentioned in one line (P3-05) but has zero design. Enterprise needs predictable, documented limits.

**What's missing:**

| Plan | Sync Requests | Read Requests | Webhooks | Notes |
|---|---|---|---|---|
| **Free** | 10/min, 100/day | 60/min | 0 | Generous for dev/eval |
| **Pro** | 60/min, 5,000/day | 300/min | 5 endpoints | Standard production |
| **Team** | 300/min, 50,000/day | 1,000/min | 25 endpoints | Multi-team |
| **Enterprise** | Custom | Custom | Unlimited | Per-contract |

**Response headers (every response):**
```
X-RateLimit-Limit: 300
X-RateLimit-Remaining: 247
X-RateLimit-Reset: 1707667200
```

**429 response body:**
```json
{
  "error": "rate_limit_exceeded",
  "message": "Rate limit of 300 requests/minute exceeded. Retry after 23 seconds.",
  "retry_after": 23
}
```

**Implementation:** Supabase Edge Functions + per-tenant counter in Redis or Supabase `rate_limit_counters` table with sliding window.

#### GAP-08: API Versioning & Deprecation Policy

Endpoints use `/v1/` but there's no documented policy for what happens when `/v2/` ships.

**What's missing:**
- **Versioning strategy:** URL path versioning (`/api/v1/`, `/api/v2/`) — already implied, just needs documenting
- **Deprecation timeline:** Minimum 12-month sunset period after new version GA
- **Sunset header:** `Sunset: Sat, 01 Feb 2028 00:00:00 GMT` on deprecated endpoints (RFC 8594)
- **Deprecation header:** `Deprecation: true` on deprecated endpoints
- **API changelog:** Versioned, published at `/api/changelog` or in docs
- **Breaking change notification:** Email to all API key owners + webhook event `api.deprecated`
- **SDK version pinning:** SDKs specify which API version they target

#### GAP-09: OpenAPI Specification & SDK

No machine-readable API spec. Enterprise integrations require automated client generation.

**What's missing:**
- **OpenAPI 3.1 spec** for all endpoints — published at `GET /api/v1/openapi.json`
- **Auto-generated TypeScript SDK:** `@drift/cloud-sdk` — generated from OpenAPI spec (e.g., via `openapi-typescript-codegen` or Speakeasy)
- **Postman collection:** auto-generated from OpenAPI, published in Postman workspace
- **Developer documentation site:** Mintlify, Docusaurus, or GitBook — API reference, guides, examples
- **Error code catalog:** standardized error codes with human-readable descriptions and resolution guidance
- **Code examples** in docs for: TypeScript, Python, cURL, Go

**Error code format:**
```json
{
  "error": {
    "code": "SYNC_PAYLOAD_TOO_LARGE",
    "message": "Sync payload exceeds 500KB limit. Split into smaller batches.",
    "doc_url": "https://docs.drift.dev/errors/SYNC_PAYLOAD_TOO_LARGE",
    "request_id": "req_abc123"
  }
}
```

#### GAP-10: Health Check Endpoints & Status Page

No health endpoints, no status page. Enterprise ops teams need to monitor service availability.

**What's missing:**
- `GET /health` — shallow liveness check (is the Edge Function responding?)
```json
{ "status": "ok", "timestamp": "2026-02-11T18:00:00Z" }
```
- `GET /ready` — deep readiness check (DB connected, auth working, read replica responding)
```json
{
  "status": "ok",
  "checks": {
    "database": { "status": "ok", "latency_ms": 12 },
    "auth": { "status": "ok" },
    "read_replica": { "status": "ok", "lag_ms": 45 }
  }
}
```
- **Public status page** (Instatus, Statuspage.io, or self-hosted Cachet)
  - Per-component status: API, Auth, Database, Sync, Dashboard
  - Incident history with RCA (root cause analysis)
  - Scheduled maintenance announcements
  - RSS feed + email subscriber notifications
- **Uptime monitoring:** External pinger (e.g., BetterUptime, Checkly) hitting `/health` every 30s

#### GAP-11: SLA Tiers

No SLA defined anywhere. Enterprise contracts require defined uptime guarantees.

**What's missing:**

| Plan | Uptime SLA | Planned Maintenance Window | Support Response Time | Support Channels |
|---|---|---|---|---|
| **Free** | Best effort | None guaranteed | Community only | GitHub Issues |
| **Pro** | 99.9% (43 min/month downtime) | Sundays 02:00–06:00 UTC | 24h (business days) | Email |
| **Team** | 99.95% (22 min/month) | Sundays 02:00–04:00 UTC | 8h (business days) | Email + Slack Connect |
| **Enterprise** | 99.99% (4 min/month) | Scheduled, 72h notice | 1h (P1), 4h (P2) | Dedicated CSM + Slack + Phone |

**Incident severity definitions:**
- **P1 (Critical):** Service fully unavailable, all tenants affected. Target resolution: 1 hour.
- **P2 (Major):** Significant degradation, sync failing for >10% of tenants. Target: 4 hours.
- **P3 (Minor):** Single tenant affected, workaround available. Target: 24 hours.
- **P4 (Low):** Cosmetic, documentation, minor UX issue. Target: 5 business days.

**SLA credit policy:** If monthly uptime drops below SLA, affected tenants receive service credits (10% of monthly fee per 0.1% below SLA, max 30%).

#### GAP-12: Platform Observability & Alerting

No application-level monitoring for the cloud platform itself. Critical for incident detection.

**What's missing:**
- **Sync metrics:** p50/p95/p99 latency, success/failure rate, payload size distribution
- **API metrics:** request volume by endpoint, error rate (4xx/5xx), latency percentiles
- **Per-tenant metrics:** sync frequency, storage usage, API call volume, last active
- **Edge Function metrics:** cold start frequency, invocation count, timeout rate
- **RLS performance:** `pg_stat_statements` monitoring for slow RLS-filtered queries
- **Alerting rules (PagerDuty/OpsGenie/Slack):**
  - Sync error rate > 5% → P2 alert
  - API p99 latency > 5s → P3 alert
  - Edge Function timeout rate > 1% → P2 alert
  - DB connection pool exhaustion → P1 alert
  - Read replica lag > 5s → P2 alert
- **Distributed tracing:** OpenTelemetry traces across Edge Function → Postgres → Read Replica
- **Dashboard:** Grafana Cloud, Datadog, or Supabase Logs Dashboard

#### GAP-13: Backup & Disaster Recovery (Detailed)

"Supabase point-in-time recovery" is one line. Enterprise contracts require defined RPO/RTO.

**What's missing:**

| Aspect | Current | Required |
|---|---|---|
| **RPO** | Undefined | Free/Pro: 24h, Team: 1h, Enterprise: 15min |
| **RTO** | Undefined | Free/Pro: 8h, Team: 4h, Enterprise: 1h |
| **Backup strategy** | Supabase daily (Pro) | PITR + daily logical dumps to S3 (cross-region) |
| **Cross-region** | Not mentioned | Backup replicated to different region (e.g., US → EU) |
| **Tenant-level restore** | Not possible | `drift cloud restore --project <id> --point-in-time 2026-02-10T12:00:00Z` |
| **DR runbook** | None | Step-by-step recovery procedure, tested quarterly |
| **DR testing** | None | Quarterly DR drill, documented results |
| **Backup verification** | None | Weekly automated restore + integrity check |

**Supabase-specific:**
- Pro plan: daily backups + PITR ($100/mo add-on)
- Team plan: PITR included
- Enterprise: dedicated Postgres with custom backup schedule

#### GAP-14: Idempotency Keys

The sync endpoint (`POST /api/v1/sync`) has no idempotency guarantees. Network retries can cause duplicate row insertions or stale cursor advancement.

**What's missing:**
- `Idempotency-Key` request header support (UUID, client-generated)
- Server-side idempotency key store (24h TTL)
- If same key seen within TTL → return cached response (no DB mutation)
- If no key provided → non-idempotent (current behavior, backward compatible)
- Applies to all mutating endpoints: `POST /sync`, `POST /projects`, `POST /webhooks`, `POST /apikey`

**Cloud-only table:**
```sql
CREATE TABLE idempotency_keys (
    key TEXT PRIMARY KEY,
    tenant_id UUID NOT NULL,
    response_status INT NOT NULL,
    response_body JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT now() + INTERVAL '24 hours'
);

-- Auto-cleanup expired keys
CREATE INDEX idx_idempotency_expires ON idempotency_keys(expires_at);
-- pg_cron job: DELETE FROM idempotency_keys WHERE expires_at < now();
```

---

### 11c. P2 — Differentiators & Growth

These aren't blockers but are expected within 6 months of launch for a competitive enterprise offering.

#### GAP-15: Billing & Subscription Management

`usage_billing` table exists (Section 3c) but has zero payment integration.

**What's missing:**
- **Payment processor integration** — Stripe recommended (Checkout, Billing, Customer Portal)
- **Plan upgrade/downgrade flow** — via API (`POST /api/v1/billing/plan`) + Supabase dashboard
- **Usage metering** — sync count, storage bytes, active projects, API calls (per billing period)
- **Overage handling** — soft limit (warning email at 80%), hard limit (block sync at 100%) or pay-per-use
- **Invoice generation** — PDF invoices via Stripe, accessible at `GET /api/v1/billing/invoices`
- **Trial period** — 14-day free Pro trial → auto-downgrade to Free unless upgraded
- **Annual vs. monthly billing** — 20% discount on annual
- **Enterprise billing** — PO-based / invoice billing (net-30/net-60), no credit card required
- **Usage dashboard** — tenant-facing page showing current usage vs. plan limits

**Cloud-only tables:**
```sql
CREATE TABLE subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL UNIQUE REFERENCES tenants(id),
    stripe_customer_id TEXT,
    stripe_subscription_id TEXT,
    plan TEXT NOT NULL DEFAULT 'free',    -- 'free', 'pro', 'team', 'enterprise'
    billing_cycle TEXT DEFAULT 'monthly', -- 'monthly', 'annual'
    trial_ends_at TIMESTAMPTZ,
    current_period_start TIMESTAMPTZ,
    current_period_end TIMESTAMPTZ,
    seat_limit INT NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'active' -- 'active', 'trialing', 'past_due', 'canceled'
);

CREATE TABLE usage_meters (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    period_start TIMESTAMPTZ NOT NULL,
    period_end TIMESTAMPTZ NOT NULL,
    sync_count INT NOT NULL DEFAULT 0,
    storage_bytes BIGINT NOT NULL DEFAULT 0,
    api_calls INT NOT NULL DEFAULT 0,
    active_projects INT NOT NULL DEFAULT 0,
    webhook_deliveries INT NOT NULL DEFAULT 0
);
```

#### GAP-16: Realtime Dashboard Updates

Marked "future" (Section 6e) but enterprise dashboards without live data feel broken. Supabase Realtime is built-in — this is low-hanging fruit.

**What's missing:**
- **Supabase Realtime channel design:**
  - Channel per project: `project:{project_id}`
  - Events: `scan_complete`, `violation_new`, `gate_result`, `grounding_update`
  - Payload: lightweight summary (not full row — just IDs + key metrics)
- **WebSocket auth:** JWT-based channel authorization via Supabase RLS (built-in)
- **Presence:** who else is viewing this project in the dashboard (optional, nice-to-have)
- **Optimistic UI:** dashboard updates instantly on sync, rolls back if server rejects
- **Fallback:** polling at 30s interval if WebSocket fails

#### GAP-17: CI/CD Platform Integrations

Only `drift cloud push` from CLI (Section 6f). Enterprise CI teams expect first-class integrations.

**What's missing:**
- **GitHub App** — auto-install per org, PR status checks, commit status badges
  - `POST /api/v1/integrations/github/install` (OAuth App install flow)
  - Automatically posts PR comment with drift summary + cloud dashboard link
  - Blocks PR merge if quality gate fails (via GitHub Check Runs API)
- **GitHub Actions marketplace action:** `uses: drift-dev/cloud-sync@v1` with `api-key` input
- **GitLab CI template:** `.gitlab-ci.yml` include template
- **Bitbucket Pipelines pipe:** `bitbucket-pipelines.yml` pipe
- **Badge generation:** shields.io-compatible endpoint
  - `GET /api/v1/projects/:id/badge/health` → SVG badge (e.g., "Health: 82%")
  - `GET /api/v1/projects/:id/badge/violations` → "Violations: 23 critical"
  - `GET /api/v1/projects/:id/badge/gates` → "Gates: passing"

#### GAP-18: Multi-Region & Data Sovereignty Enforcement

Brief mention of region selection (Section 5e) but no enforcement or multi-region architecture.

**What's missing:**
- **Per-tenant region configuration** stored in `tenants` table (`region TEXT NOT NULL DEFAULT 'us-east-1'`)
- **Region-locked data routing** — Edge Function validates tenant region matches Supabase project region
- **Cross-region sync** for global teams — primary region for writes, read replicas in secondary regions
- **Data residency audit report** — `GET /api/v1/compliance/data-residency` showing where data is stored
- **Region migration procedure** — move tenant data between regions (rare but needed for compliance changes)
- **Supported regions (initial):** US East (Virginia), EU West (Frankfurt), APAC (Sydney)

#### GAP-19: Notifications & Alerts (User-Facing)

No user-facing notification system. Users have no way to know about important events without manually checking the dashboard.

**What's missing:**
- **Transactional email** (Resend, Postmark, or Supabase built-in):
  - Welcome email on signup
  - Password reset
  - Invitation accepted/declined
  - Gate failure alerts (configurable per project)
  - Critical/high violation alerts
  - Weekly digest report (project health summary)
  - API key expiration warning (7 days before)
- **Notification preferences API:** `GET/PATCH /api/v1/settings/notifications`
  - Per-user, per-project toggle for each notification type
  - Channel preference: email, in-app, Slack, none
- **In-app notification feed** for dashboard (bell icon → dropdown)
- **Slack/Teams integration:** post alerts to a channel
  - `POST /api/v1/integrations/slack` (OAuth install flow)
  - Channel-level routing (e.g., #drift-alerts → gate failures only)

#### GAP-20: Cloud Data Retention Policies

No cloud-side data retention mentioned. Storage grows unbounded — costs escalate, old data clutters dashboards.

**What's missing:**
- **Configurable retention per plan:**

| Plan | Scan History | Violations | Patterns | Audit Log | Memories |
|---|---|---|---|---|---|
| **Free** | 30 days | 30 days | 90 days | 7 days | 30 days |
| **Pro** | 1 year | 1 year | Unlimited | 1 year | 1 year |
| **Team** | 2 years | 2 years | Unlimited | 2 years | 2 years |
| **Enterprise** | Custom | Custom | Unlimited | Custom | Custom |

- **Automatic cleanup job** — Supabase pg_cron, runs daily, deletes expired rows
- **Tenant notification before expiry** — email 7 days before data reaches retention limit
- **Data export before deletion** — `drift cloud export --before 2025-06-01` to save old data
- **Retention override per project** — enterprise tenants can set custom retention per project

#### GAP-21: Admin Console / Internal Tooling

No internal admin surface for operating the platform.

**What's missing:**
- **Tenant management admin API** (internal-only, not exposed to users):
  - List all tenants with usage stats
  - Suspend/reactivate tenant (e.g., for abuse or non-payment)
  - Delete tenant + all data (GDPR erasure)
  - Impersonate tenant for debugging (with audit trail)
- **Feature flags per tenant** — beta features, plan overrides, custom limits
- **Usage dashboard** — per-tenant storage, sync frequency, API call volume
- **Support tooling** — view tenant audit logs, sync status, error logs
- **Tenant health dashboard** — which tenants are failing syncs? which have stale data?
- **Implementation:** Internal Supabase dashboard or lightweight admin app (Retool, Forest Admin, or custom React admin)

#### GAP-22: Developer Experience — SDK & Docs

No client SDK or developer portal. Third-party integration requires reading raw API docs (which also don't exist).

**What's missing:**
- **TypeScript SDK:** `@drift/cloud-sdk` — auto-generated from OpenAPI spec, published to npm
- **Python SDK:** `drift-cloud` — for data science / reporting integrations
- **Postman / Insomnia collection** — importable API workspace
- **Developer docs site** — Mintlify, Docusaurus, or GitBook
  - API reference (auto-generated from OpenAPI)
  - Getting started guide (signup → link project → push → dashboard)
  - Authentication guide (JWT vs. API key, when to use which)
  - Webhook integration guide (with code examples)
  - CI/CD integration guide (GitHub Actions, GitLab CI)
  - Data privacy & security whitepaper
- **Error code catalog** — every error code with description + resolution steps
- **Changelog** — versioned, with migration guides for breaking changes

---

### 11d. P3 — Nice-to-Have / Future

Lower priority items that add polish and differentiation.

#### GAP-23: Deep Compliance (Beyond SOC 2 Checklist)

| Compliance | Current | What's Needed |
|---|---|---|
| **SOC 2 Type II** | Checklist only (Section 5d) | Continuous evidence collection (Vanta, Drata, or Secureframe), annual audit by CPA firm |
| **ISO 27001** | Mentioned in passing | ISMS documentation, risk assessment, Statement of Applicability, annual audit |
| **HIPAA** | "BAA for Enterprise" (Section 9a) | PHI handling procedures, BAA template, access controls, encryption audit |
| **FedRAMP** | Not mentioned | US government contracts. Requires authorized cloud (AWS GovCloud or Azure Gov), not Supabase |
| **Pen testing** | "Quarterly" (R2) | Formal pen test schedule, published results summary, bug bounty program |
| **Vulnerability disclosure** | None | `security.txt` (RFC 9116), responsible disclosure policy, security@ email |
| **Legal docs** | None | Privacy Policy, Terms of Service, DPA template, Cookie Policy, Acceptable Use Policy |

#### GAP-24: Cross-Tenant Benchmarking (Anonymized)

Enterprise buyers ask "how do we compare?" — anonymized aggregate metrics can drive upgrades and retention.

**What's missing:**
- Anonymized industry benchmarks: "Your code health score is in the 75th percentile across all Drift users"
- Benchmark by: language, framework, team size, industry vertical
- Opt-in only — tenants must explicitly enable benchmark participation
- Only aggregate/anonymized data used — never raw tenant data
- `GET /api/v1/projects/:id/benchmarks` — returns percentile ranks for key metrics

#### GAP-25: Change Management & Feature Announcements

Per [EnterpriseReady](https://www.enterpriseready.io/features/change-management/), enterprise admins need control over rollouts.

**What's missing:**
- **Changelog / release notes** — versioned, published in docs + in-app
- **Advance notice of breaking changes** — 30+ days for API changes, email to admins
- **Feature request tracking** — public roadmap (e.g., Canny, ProductBoard, or GitHub Discussions)
- **Sandbox/staging environment** — tenants can test new features before production rollout
- **Feature flags for tenants** — enterprise admins can enable/disable features per project

#### GAP-26: Infrastructure as Code

No Terraform, Pulumi, or Supabase CLI seed scripts. The Supabase setup is manual and unreproducible.

**What's missing:**
- **Supabase project setup as code** — migrations, RLS policies, Edge Functions, auth config
- **CI pipeline for infrastructure** — GitHub Actions deploys Edge Functions + runs DB migrations
- **Environment parity** — dev / staging / production Supabase projects with identical schemas
- **Seed data** — test tenants, sample projects for dev/staging
- **Rollback procedure** — migration rollback scripts for every DDL change

#### GAP-27: Conflict Resolution (Beyond LWW)

Only Last-Write-Wins described (Section 6b). Enterprise teams with multiple contributors may need more control.

**What's missing:**
- **Configurable strategy per project:** LWW (default), manual review, field-level merge
- **Conflict notification** — alert affected users when a conflict is detected
- **Conflict resolution UI** in dashboard — side-by-side diff, accept/reject per field
- **Conflict audit trail** — `conflict_log` already exists in cortex.db (Section 2d), extend to cloud

---

### 11e. Enterprise Readiness Summary Matrix

| Category | Current Coverage | Gap Severity | Gap IDs |
|---|---|---|---|
| **Auth / SSO** | ✅ Good (Supabase Auth, SAML) | **P0: Missing SCIM** | GAP-01 |
| **Tenant Isolation** | ✅ Strong (RLS, defense-in-depth) | — | — |
| **Encryption** | ✅ Good (AES-256, TLS 1.3) | — | — |
| **Webhooks** | ❌ Missing entirely | **P0** | GAP-02 |
| **Audit Logs** | ⚠️ Table exists, no API | **P0** | GAP-03 |
| **Team Management** | ❌ Flat tenant only | **P0** | GAP-04 |
| **IP Allowlisting** | ❌ Missing entirely | **P0** | GAP-05 |
| **API Pagination** | ❌ No pagination on list endpoints | **P1** | GAP-06 |
| **Rate Limiting** | ⚠️ One-liner, no design | **P1** | GAP-07 |
| **API Versioning** | ⚠️ Uses /v1/, no deprecation policy | **P1** | GAP-08 |
| **API Spec / SDK** | ❌ No OpenAPI, no SDK | **P1** | GAP-09 |
| **Health Checks / Status** | ❌ Missing entirely | **P1** | GAP-10 |
| **SLA Tiers** | ❌ Missing entirely | **P1** | GAP-11 |
| **Observability** | ❌ No platform metrics | **P1** | GAP-12 |
| **Backup / DR** | ⚠️ One-liner PITR mention | **P1** | GAP-13 |
| **Idempotency** | ❌ No idempotency keys | **P1** | GAP-14 |
| **Billing** | ⚠️ Usage table, no Stripe | **P2** | GAP-15 |
| **Realtime** | ⚠️ "Future" | **P2** | GAP-16 |
| **CI/CD Integrations** | ⚠️ CLI-only | **P2** | GAP-17 |
| **Multi-Region** | ⚠️ Region mentioned, not enforced | **P2** | GAP-18 |
| **Notifications** | ❌ Missing entirely | **P2** | GAP-19 |
| **Data Retention** | ❌ Missing entirely | **P2** | GAP-20 |
| **Admin Console** | ❌ Missing entirely | **P2** | GAP-21 |
| **SDK & Docs** | ❌ Missing entirely | **P2** | GAP-22 |
| **Compliance (deep)** | ⚠️ SOC 2 checklist only | **P3** | GAP-23 |
| **Benchmarking** | ❌ Not planned | **P3** | GAP-24 |
| **Change Management** | ❌ Not planned | **P3** | GAP-25 |
| **IaC** | ❌ No Terraform/Pulumi | **P3** | GAP-26 |
| **Conflict Resolution** | ⚠️ LWW only | **P3** | GAP-27 |

**Counts:**
- **P0 (blocks enterprise sales):** 5 gaps
- **P1 (expected at evaluation):** 9 gaps
- **P2 (differentiators):** 8 gaps
- **P3 (nice-to-have):** 5 gaps
- **Total:** 27 gaps identified

---

## Appendix A: Bridge Storage Layer Mapping (Original Audit)

> The detailed bridge-specific storage layer audit (connection ownership, lock patterns, storage operations inventory, internal consumers, proposed trait surface, migration impact matrix) was the original content of this document. It has been preserved in git history and is referenced by Phase 0 of the implementation plan. Key points:

- **7-8 separate `Mutex<Connection>` instances** in production _(revised from 4 — see Phase 0 [AUDIT] connection inventory for full list)_ — includes `DriftRuntime.bridge_db`, `DriftRuntime.drift_db_for_bridge`, `BridgeEventHandler.cortex_db` (misnamed), `BridgeWeightProvider.cortex_db`, `BridgeDecompositionPriorProvider.cortex_db`, plus 3 in standalone `BridgeRuntime`
- **23 `IBridgeStorage` trait methods** proposed (7 writes, 7 reads, 3 formalized ad-hoc, 4 lifecycle, 2 usage)
- **~100 `IDriftStorage` methods** across 6 sub-traits _(revised from ~30 — 149 query functions found across 15 modules)_
- **14 `IDriftReader` trait methods** proposed (12 evidence queries + 2 cross-DB)
- **~30+ files** need signature changes from `&Connection` → trait objects _(revised from ~22 — includes 15 evidence collector files, 5+ specification/tools consumers)_
- **107 NAPI call sites** across 9 binding files need rewiring
- **~20+ test files** need updates _(plus ~10 evidence/grounding test files need IDriftReader test doubles)_
- **~10 `IWorkspaceStorage` trait methods** proposed — discovered in Feb 11 connection audit (P0-15/P0-16/P0-17). `drift-core/src/workspace/` has 12 files with ~30+ direct `Connection::open()` calls bypassing `DatabaseManager`. Includes init, backup, export/import, integrity, GC, status, project, monorepo, destructive ops.
- **~2,500 lines changed, ~1,500 new lines** estimated for the full trait extraction _(revised from ~1,400/~900)_
- **14.5-19.5 days** estimated for Phase 0 _(revised from 12-17 after Feb 11 workspace audit; originally 3-4 days in first audit, 8-10 days in first cloud expansion)_

> **[AUDIT-2] Feb 11 Connection Point Verification:** Full codebase audit of every `Connection::open()`, `Mutex<Connection>`, and `&Connection` parameter across all 3 Rust workspaces (drift, cortex, cortex-drift-bridge). **All connection points in the bridge and drift-napi crates were already accounted for in Phase 0.** One gap found: `drift-core/src/workspace/` module (12 files, ~30+ raw `Connection::open()` calls) was not inventoried. Fixed by adding P0-15, P0-16, P0-17. Cortex crates confirmed already trait-based (`IMemoryStorage` + `ICausalStorage`). No other gaps.

For the full detailed mapping, see git history of this file or the `BRIDGE-CLOUD-READINESS-TRACKER.md` commit prior to the cloud migration expansion.
