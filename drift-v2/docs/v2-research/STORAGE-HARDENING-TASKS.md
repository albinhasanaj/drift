# Storage Layer Hardening Tasks

> Deep audit of all three storage subsystems: **drift-storage** (analysis engine persistence),
> **cortex-storage** (memory system persistence), and **cortex-drift-bridge/storage** (bridge tables).
>
> **Audit date:** 2025-02-09
> **Files audited:** 58 source files, 8 test files, 7 migration modules, 15 cortex migrations
> **Auditor:** Cascade deep-dive

---

## Executive Summary

The storage layer is architecturally sound — connection pooling, WAL mode, batch writing, keyset pagination, and migration infrastructure are all correctly implemented. However, **the layer is severely under-wired**: 9 of 39 migrated tables have zero query functions, all 22 NAPI bindings that should read/write storage are hardcoded stubs returning empty results, the `BatchWriter` is never instantiated from the runtime (only from tests), the `DatabaseManager.with_reader()` path is never used from production code (all reads go through writer), scan results are never persisted to `drift.db`, and the entire `materialized/` module has no callers.

**Bottom line:** The storage schema and low-level plumbing work correctly in isolation (tests pass), but **0% of analysis results flow through storage to NAPI consumers today**. The pipeline is: scan → parse → analyze → (void). Storage sits to the side, fully built but unplumbed.

---

## Findings by Severity

### CRITICAL — Tables With Zero Query Functions (9 tables)

These tables are created by migrations but have **no Rust query module** — no insert, no select, no delete. They are dead schema:

| Table | Migration | Purpose | Impact |
|-------|-----------|---------|--------|
| `scan_history` | v001 | Scan operation log | No scan audit trail |
| `data_access` | v002 | Function→table access patterns | Data flow analysis dead |
| `coupling_cycles` | v005 | Detected SCCs in module graph | Cycle detection output lost |
| `constraint_verifications` | v005 | Constraint check results | Constraint system unverifiable |
| `contract_mismatches` | v005 | BE↔FE contract mismatches | Contract tracking dead |
| `constants` | v005 | Named constants & magic numbers | Constants analysis dead |
| `env_variables` | v005 | Environment variable usage | Env var analysis dead |
| `policy_results` | v006 | Policy evaluation results | Policy engine output lost |
| `degradation_alerts` | v006 | Health degradation alerts | Alerting dead |

**Location:** Migrations at `crates/drift/drift-storage/src/migrations/v001_initial.rs:62-78`, `v002_analysis.rs:19-30`, `v005_structural.rs:23-28,47-55,74-84,86-100,120-134`, `v006_enforcement.rs:100-123`
**Query modules:** `crates/drift/drift-storage/src/queries/` — none of the 11 query files touch these 9 tables.

### CRITICAL — All 22 NAPI Bindings Are Hardcoded Stubs

Every NAPI binding in phases 2-7 returns empty/default results without touching the database:

| NAPI Function | File | Returns |
|---------------|------|---------|
| `drift_analyze()` | `bindings/analysis.rs:82-88` | `Vec::new()` |
| `drift_call_graph()` | `bindings/analysis.rs:93-102` | zeros |
| `drift_boundaries()` | `bindings/analysis.rs:107-114` | `Vec::new()` |
| `drift_confidence()` | `bindings/patterns.rs:12-31` | `[]` |
| `drift_outliers()` | `bindings/patterns.rs:36-49` | `[]` |
| `drift_conventions()` | `bindings/patterns.rs:54-67` | `[]` |
| `drift_patterns()` | `bindings/patterns.rs:72-86` | `[]` |
| `drift_reachability()` | `bindings/graph.rs:23-35` | zeros |
| `drift_taint_analysis()` | `bindings/graph.rs:64-71` | `Vec::new()` |
| `drift_error_handling()` | `bindings/graph.rs:97-102` | `Vec::new()` |
| `drift_impact_analysis()` | `bindings/graph.rs:132-136` | `Vec::new()` |
| `drift_test_topology()` | `bindings/graph.rs:166-183` | zeros |
| `drift_coupling_analysis()` | `bindings/structural.rs:40-46` | `Vec::new()` |
| `drift_constraint_verification()` | `bindings/structural.rs:69-75` | zeros |
| `drift_contract_tracking()` | `bindings/structural.rs:110-116` | `Vec::new()` |
| `drift_constants_analysis()` | `bindings/structural.rs:151-158` | zeros |
| `drift_wrapper_detection()` | `bindings/structural.rs:195-206` | zeros |
| `drift_dna_analysis()` | `bindings/structural.rs:254-266` | zeros |
| `drift_owasp_analysis()` | `bindings/structural.rs:306-318` | zeros |
| `drift_crypto_analysis()` | `bindings/structural.rs:353-362` | zeros |
| `drift_decomposition()` | `bindings/structural.rs:391-398` | zeros |
| `drift_check()` | `bindings/enforcement.rs:76-83` | `overall_passed: true` |
| `drift_audit()` | `bindings/enforcement.rs:87-101` | `health_score: 100.0` |
| `drift_violations()` | `bindings/enforcement.rs:106-107` | `Vec::new()` |
| `drift_gates()` | `bindings/enforcement.rs:112-113` | `Vec::new()` |
| `drift_dismiss_violation()` | `bindings/feedback.rs:24-28` | `success: true` (no-op) |
| `drift_fix_violation()` | `bindings/feedback.rs:33-37` | `success: true` (no-op) |
| `drift_suppress_violation()` | `bindings/feedback.rs:42-49` | `success: true` (no-op) |

**Only `drift_initialize()`, `drift_shutdown()`, `drift_scan()`, `drift_scan_with_progress()`, and `drift_cancel_scan()` are real implementations.** But even `drift_scan()` does NOT persist results to storage — it returns a `ScanSummary` directly, discarding the `ScanDiff` data.

### CRITICAL — Scan Results Never Persisted

The scanner NAPI binding (`bindings/scanner.rs:48-67`) runs the scan and converts the result to a `ScanSummary`, but **never writes file_metadata, parse_cache, or function rows to drift.db**. The `BatchWriter` exists and works (proven by tests), but is never instantiated from the `DriftRuntime` or `ScanTask`.

**Root cause:** `ScanTask.compute()` at line 62-66:
```rust
let diff = scanner.scan(&self.root, &cached, &NoOpHandler)...;
Ok(ScanSummary::from(&diff))  // diff is dropped — no persistence!
```

The `cached` metadata is also `FxHashMap::default()` (line 60), so every scan is a full scan even though incremental infrastructure exists.

### HIGH — `#![allow(dead_code, unused)]` Blanket Suppression

`drift-storage/src/lib.rs:7` has `#![allow(dead_code, unused)]` which silences ALL compiler warnings about unused code across the entire crate. This masks the fact that most query functions, all materialized views, the pagination module, and the `with_immediate_transaction` helper are never called from outside tests. Removing this suppression would immediately surface ~40 unused function warnings.

### HIGH — `DatabaseManager.with_reader()` Never Used in Production

The read pool (4 connections with round-robin selection) is fully implemented at `connection/pool.rs` but `with_reader()` is never called from any NAPI binding or runtime code. The only callers are tests. All `StorageEngine` (cortex) reads also go through the writer connection, defeating the purpose of the read pool.

**Impact:** Under concurrent load, read operations will contend with the writer mutex instead of using the lock-free read pool.

### HIGH — `BatchWriter` Not Integrated Into Runtime

`BatchWriter` is a well-implemented dedicated writer thread with channel-based batching, but:
1. `DriftRuntime` (runtime.rs:28-33) holds a `DatabaseManager` but no `BatchWriter`
2. No NAPI binding creates or uses a `BatchWriter`
3. `BatchWriter::new()` requires a moved `Connection`, conflicting with `DatabaseManager`'s owned `Mutex<Connection>`
4. Only test files instantiate `BatchWriter` (6 call sites, all in tests)

**Design gap:** `BatchWriter` and `DatabaseManager` are parallel write strategies that can't currently coexist. The runtime needs to choose one or compose them.

### HIGH — `with_immediate_transaction` Double-Transaction Bug

`connection/writer.rs:8-35` creates an `unchecked_transaction()` then immediately tries `BEGIN IMMEDIATE` which will fail because a transaction is already active. The `.ok()` on line 26 silently swallows this error, so the transaction runs without IMMEDIATE mode — losing the lock-acquisition guarantee.

```rust
let tx = conn.unchecked_transaction()...;  // starts transaction
conn.execute_batch("BEGIN IMMEDIATE")      // fails: already in transaction
    .ok();                                  // error silently ignored!
let result = f(&tx)?;
tx.commit()...;
```

### HIGH — Cortex Migrations Skip v013

`cortex-storage/src/migrations/mod.rs:31-46` — the MIGRATIONS array jumps from v012 to v014. There is no `v013` module. `LATEST_VERSION` is 15, but only 14 migrations exist. If any database was ever at v013 (impossible since the migration doesn't exist), it would be stuck.

**Risk:** Low (v013 was never shipped), but the version gap is confusing and could cause issues if a v013 migration is added later without adjusting the sequence.

### HIGH — Bridge Retention Duplicated

Retention logic exists in TWO places:
1. `bridge/src/storage/retention.rs:21-51` — standalone module with named constants
2. `bridge/src/storage/tables.rs:218-249` — inline `apply_retention()` function

Both are exported from `mod.rs`. The `tables.rs` version is the one listed in `pub use`, but both compile. A caller using the wrong one gets identical behavior today, but any future change to retention periods could be applied to only one copy.

### HIGH — Bridge Schema Triple-Duplicated

The bridge table DDL is defined in THREE places:
1. `bridge/src/storage/schema.rs:5-59` — `BRIDGE_TABLES_V1` constant
2. `bridge/src/storage/migrations.rs:17-71` — `BRIDGE_SCHEMA_V1` constant  
3. `bridge/src/storage/tables.rs:17-72` — `create_bridge_tables()` inline SQL

All three are identical today, but any schema change must be applied to all three or they'll drift apart. `schema.rs` is imported but never actually used by `tables.rs` or `migrations.rs`.

### MEDIUM — Materialized Views Module Has Zero Callers

`materialized/status.rs`, `materialized/security.rs`, `materialized/trends.rs` implement aggregation queries over enforcement tables, but:
1. No NAPI binding calls them
2. No integration test calls them
3. They query tables (`violations`, `gate_results`, `audit_snapshots`, `health_trends`) that are only populated by the enforcement stubs (which never run)

### MEDIUM — Keyset Pagination Module Has Zero Callers

`pagination/keyset.rs` implements base64-encoded cursor pagination with a custom base64 encoder, but:
1. No NAPI binding uses `PaginationCursor` or `PaginatedResult`
2. The NAPI pattern bindings (`drift_confidence`, `drift_outliers`, `drift_conventions`) accept `after_id` parameters but are stubs — they don't use `PaginationCursor`
3. The only pagination user is `patterns::query_confidence_by_tier()` which has its own inline pagination logic, not using the `keyset` module

### MEDIUM — `WriteStats` Incomplete for New Command Types

`batch/writer.rs:22-31` `WriteStats` tracks counters for 8 operations but `InsertPatternConfidence`, `InsertOutliers`, and `InsertConventions` increments are missing:

```rust
pub struct WriteStats {
    pub file_metadata_rows: usize,
    pub parse_cache_rows: usize,
    pub function_rows: usize,
    pub deleted_files: usize,
    pub call_edge_rows: usize,
    pub detection_rows: usize,
    pub boundary_rows: usize,
    pub flushes: usize,
    // Missing: pattern_confidence_rows, outlier_rows, convention_rows
}
```

In `flush_buffer` (lines 171-179), these three commands execute correctly but don't update any stats counter.

### MEDIUM — `patterns.rs` Query Module Uses `rusqlite::Result` Not `StorageError`

All other query modules return `Result<T, StorageError>`. The `patterns.rs` module at `queries/patterns.rs` returns `rusqlite::Result<T>` directly, breaking the error type contract. Callers must wrap results differently.

### MEDIUM — `advanced.rs` Creates Tables Outside Migration System

`queries/advanced.rs:213-248` `ensure_migration_tables()` uses `CREATE TABLE IF NOT EXISTS` for 3 migration tables (`migration_projects`, `migration_modules`, `migration_corrections`). But these same tables are also created by `migrations/v007_advanced.rs`. The `ensure_migration_tables()` function is redundant and bypasses the migration versioning system.

### MEDIUM — In-Memory Database Read Pool Isolation

`connection/pool.rs:45-57` — in-memory read pool creates separate `open_in_memory()` connections that share NO data with the writer. Each is its own isolated database. Tests that write via `with_writer` and read via `with_reader` will see empty results.

`connection/mod.rs:52` confirms: `ReadPool::open_in_memory(1)` with comment "In-memory: readers can't share the same DB". This means **all in-memory tests must use `with_writer` for reads too**, which is what the code does — but it means the read pool path is completely untested in unit tests.

### MEDIUM — `OptionalExt` Trait Duplicated

The helper trait `OptionalExt<T>` for converting `QueryReturnedNoRows` → `Ok(None)` is defined twice:
1. `queries/graph.rs:376-388`
2. `queries/structural.rs:832-846`

Both are `trait OptionalExt<T>` with identical implementations. Should be extracted to a shared module.

### LOW — Cortex `StorageEngine` Routes ALL Reads Through Writer

Every `IMemoryStorage` method in `cortex-storage/src/engine.rs:66-237` uses `self.pool.writer.with_conn_sync()` for both reads and writes. The `ConnectionPool` has a read pool, but it's never used. This serializes all operations behind a single mutex.

### LOW — Bridge `get_schema_version` Stores Version in `bridge_metrics`

`bridge/src/storage/migrations.rs:78-109` stores the schema version as a `metric_value` REAL in `bridge_metrics` table instead of using SQLite's `PRAGMA user_version`. While this avoids conflicts with drift-core's use of `user_version`, it means:
1. The version is subject to retention cleanup (7-day `bridge_metrics` retention would delete it)
2. The version is a float cast (`version as f64`) which could lose precision for large version numbers
3. Multiple version rows can accumulate (each migration inserts a new row)

**Risk:** The 7-day retention in `apply_retention()` would delete the `schema_version` metric row, causing `get_schema_version()` to fall back to table-existence detection (which returns v1 if any bridge table exists). This would re-run migration v1 on the next startup, which is safe only because of `CREATE TABLE IF NOT EXISTS`.

### LOW — Bridge `configure_readonly_connection` Sets WAL on Read-Only

`bridge/src/storage/pragmas.rs:34-46` sets `PRAGMA journal_mode = WAL` on what's described as a "read-only connection (drift.db)". Setting journal_mode on a read-only connection is a no-op (it requires write access), so this doesn't cause errors, but it's misleading.

---

## Phase Plan

### Phase A: Scan-to-Storage Pipeline Wiring (CRITICAL PATH)

Wire the scan→parse→analyze→persist pipeline so drift.db actually contains data.

| ID | Task | File(s) | Type | Priority |
|----|------|---------|------|----------|
| A-01 | Add `BatchWriter` to `DriftRuntime` (create from separate connection, not DatabaseManager's writer) | `drift-napi/src/runtime.rs` | impl | P0 |
| A-02 | Persist `ScanDiff` to storage in `ScanTask.compute()`: file_metadata, parse_cache, functions via BatchWriter | `drift-napi/src/bindings/scanner.rs:48-67` | impl | P0 |
| A-03 | Load cached file_metadata for incremental scans (replace `FxHashMap::default()`) | `drift-napi/src/bindings/scanner.rs:60` | impl | P0 |
| A-04 | Wire `drift_analyze()` to run analysis pipeline and persist detections, boundaries, call_edges | `drift-napi/src/bindings/analysis.rs:82-88` | impl | P0 |
| A-05 | Fix `with_immediate_transaction` double-transaction bug | `drift-storage/src/connection/writer.rs:8-35` | impl | P1 |
| A-06 | Remove `#![allow(dead_code, unused)]` from drift-storage, fix resulting warnings | `drift-storage/src/lib.rs:7` | impl | P1 |
| A-07 | Route read operations through `with_reader()` in NAPI bindings | all `bindings/*.rs` | impl | P1 |
| A-08 | Test: scan persists file_metadata rows to drift.db | new test | test | P0 |
| A-09 | Test: incremental scan skips unchanged files | new test | test | P0 |
| A-10 | Test: scan + analyze persists detections and boundaries | new test | test | P0 |
| A-11 | Test: `with_reader()` returns data written by `with_writer()` (file-backed) | new test | test | P1 |
| A-12 | Test: `with_immediate_transaction` acquires lock at start | new test | test | P1 |

**Estimated effort:** 3-4 days

### Phase B: NAPI Stub Replacement — Read Path (HIGH)

Replace all 22+ NAPI stubs with real database reads. Depends on Phase A (data must exist in storage).

| ID | Task | File(s) | Type | Priority |
|----|------|---------|------|----------|
| B-01 | Wire `drift_confidence()` to `queries::patterns::query_confidence_by_tier` with keyset pagination | `bindings/patterns.rs:12-31` | impl | P1 |
| B-02 | Wire `drift_outliers()` to `queries::patterns::query_outliers_by_pattern` | `bindings/patterns.rs:36-49` | impl | P1 |
| B-03 | Wire `drift_conventions()` to `queries::patterns::query_conventions_by_category` | `bindings/patterns.rs:54-67` | impl | P1 |
| B-04 | Wire `drift_patterns()` to `queries::patterns::query_all_confidence` | `bindings/patterns.rs:72-86` | impl | P1 |
| B-05 | Wire `drift_violations()` to `queries::enforcement::query_all_violations` | `bindings/enforcement.rs:106-107` | impl | P1 |
| B-06 | Wire `drift_gates()` to `queries::enforcement::query_gate_results` | `bindings/enforcement.rs:112-113` | impl | P1 |
| B-07 | Wire `drift_check()` to run gate evaluation → persist → return results | `bindings/enforcement.rs:76-83` | impl | P1 |
| B-08 | Wire `drift_audit()` to compute health score from audit_snapshots | `bindings/enforcement.rs:87-101` | impl | P1 |
| B-09 | Wire `drift_call_graph()` to `queries::call_edges` + `queries::functions` | `bindings/analysis.rs:93-102` | impl | P1 |
| B-10 | Wire `drift_boundaries()` to `queries::boundaries` | `bindings/analysis.rs:107-114` | impl | P1 |
| B-11 | Wire all 9 structural bindings to corresponding `queries::structural` functions | `bindings/structural.rs` (9 fns) | impl | P1 |
| B-12 | Wire all 5 graph bindings to corresponding `queries::graph` functions | `bindings/graph.rs` (5 fns) | impl | P1 |
| B-13 | Wire `drift_simulate()` to persist results via `queries::advanced::insert_simulation` | `bindings/advanced.rs:11-51` | impl | P2 |
| B-14 | Wire `drift_decisions()` to persist via `queries::advanced::insert_decision` | `bindings/advanced.rs:55-64` | impl | P2 |
| B-15 | Wire 3 feedback functions to persist via `queries::enforcement::insert_feedback` | `bindings/feedback.rs` | impl | P1 |
| B-16 | Test: each wired NAPI binding returns data after scan+analyze | 22+ tests | test | P1 |
| B-17 | Test: keyset pagination cursor encode/decode round-trip | new test | test | P1 |
| B-18 | Test: feedback functions actually modify violation state | new test | test | P1 |

**Estimated effort:** 4-5 days

### Phase C: Missing Query Modules for 9 Orphan Tables (HIGH)

Add CRUD query functions for the 9 tables that have schema but no query module.

| ID | Task | File(s) | Type | Priority |
|----|------|---------|------|----------|
| C-01 | Create `queries/scan_history.rs` — insert, query_recent, update_status | new file | impl | P1 |
| C-02 | Create `queries/data_access.rs` — insert, query_by_function, query_by_table | new file | impl | P1 |
| C-03 | Add `coupling_cycles` queries to `queries/structural.rs` — insert, query_all | `queries/structural.rs` | impl | P2 |
| C-04 | Add `constraint_verifications` queries to `queries/structural.rs` — insert, query_by_constraint | `queries/structural.rs` | impl | P2 |
| C-05 | Add `contract_mismatches` queries to `queries/structural.rs` — insert, query_all, query_by_type | `queries/structural.rs` | impl | P2 |
| C-06 | Create `queries/constants.rs` — insert, query_by_file, query_unused, query_magic_numbers | new file | impl | P2 |
| C-07 | Create `queries/env_variables.rs` — insert, query_by_name, query_missing | new file | impl | P2 |
| C-08 | Add `policy_results` queries to `queries/enforcement.rs` — insert, query_recent | `queries/enforcement.rs` | impl | P2 |
| C-09 | Add `degradation_alerts` queries to `queries/enforcement.rs` — insert, query_recent, query_by_type | `queries/enforcement.rs` | impl | P2 |
| C-10 | Add `InsertScanHistory`, `InsertDataAccess` variants to `BatchCommand` enum | `batch/commands.rs` | impl | P1 |
| C-11 | Handle new `BatchCommand` variants in `flush_buffer` | `batch/writer.rs` | impl | P1 |
| C-12 | Register new query modules in `queries/mod.rs` | `queries/mod.rs` | impl | P1 |
| C-13 | Test: CRUD round-trip for each of the 9 tables | 9 tests | test | P1 |
| C-14 | Test: BatchWriter handles new command types | new test | test | P1 |

**Estimated effort:** 2-3 days

### Phase D: Code Quality & Deduplication (MEDIUM)

Fix error type inconsistencies, remove duplication, and clean up architecture.

| ID | Task | File(s) | Type | Priority |
|----|------|---------|------|----------|
| D-01 | Convert `patterns.rs` from `rusqlite::Result` to `Result<T, StorageError>` | `queries/patterns.rs` (all functions) | impl | P2 |
| D-02 | Remove `ensure_migration_tables()` from `advanced.rs` (tables already in v007 migration) | `queries/advanced.rs:213-248` | impl | P2 |
| D-03 | Extract `OptionalExt` trait to shared `queries/util.rs`, remove duplicates | `queries/graph.rs:376-388`, `queries/structural.rs:832-846` | impl | P2 |
| D-04 | Consolidate bridge schema to single source: use `schema.rs::BRIDGE_TABLES_V1` in both `migrations.rs` and `tables.rs` | `bridge/src/storage/{schema,migrations,tables}.rs` | impl | P2 |
| D-05 | Consolidate bridge retention: remove inline `apply_retention` from `tables.rs`, keep `retention.rs` only | `bridge/src/storage/tables.rs:218-249` | impl | P2 |
| D-06 | Add missing `WriteStats` counters for pattern_confidence, outliers, conventions | `batch/writer.rs:22-31,171-179` | impl | P2 |
| D-07 | Fix bridge `get_schema_version` to use a dedicated table or exclude `schema_version` from retention | `bridge/src/storage/migrations.rs:78-109`, `bridge/src/storage/retention.rs` | impl | P2 |
| D-08 | Wire `PaginationCursor` into pattern NAPI bindings (replace inline pagination) | `bindings/patterns.rs`, `pagination/keyset.rs` | impl | P3 |
| D-09 | Wire `materialized/` views into relevant NAPI bindings | `materialized/*.rs` | impl | P3 |
| D-10 | Test: `patterns.rs` functions return `StorageError` on failure | new test | test | P2 |
| D-11 | Test: bridge schema version survives retention cleanup | new test | test | P2 |
| D-12 | Test: `WriteStats` counters accurate for all command types | new test | test | P2 |

**Estimated effort:** 2-3 days

### Phase E: Cortex Storage & Read Pool Optimization (MEDIUM)

Fix cortex-storage read path and read pool utilization.

| ID | Task | File(s) | Type | Priority |
|----|------|---------|------|----------|
| E-01 | Route `IMemoryStorage` read methods (get, get_bulk, query_*, search_*) through read pool | `cortex-storage/src/engine.rs:66-237` | impl | P2 |
| E-02 | Route `ICausalStorage` read methods (get_edges, has_cycle, counts) through read pool | `cortex-storage/src/engine.rs:240-299` | impl | P2 |
| E-03 | Add cortex migration v013 placeholder or document intentional skip | `cortex-storage/src/migrations/mod.rs` | impl | P3 |
| E-04 | Remove misleading WAL pragma from bridge `configure_readonly_connection` | `bridge/src/storage/pragmas.rs:34-46` | impl | P3 |
| E-05 | Test: concurrent reads don't contend with writer (latency benchmark) | new test | test | P2 |
| E-06 | Test: read pool round-robin distributes across connections | new test | test | P2 |
| E-07 | Test: cortex in-memory tests document reader isolation | new test | test | P3 |

**Estimated effort:** 1-2 days

---

## Dependency Graph

```
Phase A (Scan→Storage Pipeline)     ← CRITICAL PATH, start here
    │
    ├──→ Phase B (NAPI Stub Replacement)  ← depends on A (needs data in DB)
    │        │
    │        └──→ Phase D-08, D-09 (Pagination & Materialized wiring)
    │
    ├──→ Phase C (Missing Query Modules)  ← parallelizable with B
    │
    └──→ Phase D (Code Quality)           ← parallelizable with B/C
    
Phase E (Cortex & Read Pool)              ← independent, parallelizable with all
```

**Critical path:** A(3-4d) → B(4-5d) = **7-9 working days**
**With parallelism:** A(3-4d) → {B + C + D parallel}(4-5d) → E(1-2d) = **8-11 working days**

---

## Summary Statistics

| Metric | Count |
|--------|-------|
| **Tables in drift.db schema** | 39 |
| **Tables with query modules** | 30 |
| **Tables with ZERO query functions** | 9 |
| **NAPI bindings (total)** | 27 |
| **NAPI bindings that are real** | 5 (lifecycle + scanner) |
| **NAPI bindings that are stubs** | 22 |
| **Query modules** | 11 files, ~60 functions |
| **Query functions never called from NAPI** | ~60 (all of them) |
| **Materialized view functions** | 3 (zero callers) |
| **Pagination functions** | 2 types exported (zero callers outside patterns.rs) |
| **Implementation tasks** | 52 |
| **Test tasks** | 38 |
| **Total tasks** | 90 |

---

## Key File Reference

| Component | Path | Size |
|-----------|------|------|
| **drift-storage crate** | `crates/drift/drift-storage/src/` | 18 files |
| **drift-storage migrations** | `crates/drift/drift-storage/src/migrations/` | 7 migrations (v001-v007) |
| **drift-storage queries** | `crates/drift/drift-storage/src/queries/` | 11 modules |
| **drift-storage batch** | `crates/drift/drift-storage/src/batch/` | commands.rs, writer.rs |
| **drift-storage tests** | `crates/drift/drift-storage/tests/` | 8 test files |
| **drift-napi bindings** | `crates/drift/drift-napi/src/bindings/` | 10 modules, 27 NAPI functions |
| **drift-napi runtime** | `crates/drift/drift-napi/src/runtime.rs` | DriftRuntime singleton |
| **cortex-storage engine** | `crates/cortex/cortex-storage/src/engine.rs` | StorageEngine (300 lines) |
| **cortex-storage queries** | `crates/cortex/cortex-storage/src/queries/` | 19 modules |
| **cortex-storage migrations** | `crates/cortex/cortex-storage/src/migrations/` | 14 migrations (v001-v015, skip v013) |
| **bridge storage** | `crates/cortex-drift-bridge/src/storage/` | 6 files |
| **drift-core errors** | `crates/drift/drift-core/src/errors/storage_error.rs` | StorageError enum |
