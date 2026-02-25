# Drift Cloud Readiness — P0 Implementation Plan

> **Source:** `BRIDGE-CLOUD-READINESS-TRACKER.md` — Phase 0 (Storage Engines) + Phase 6 (Enterprise P0 Features, GAP-01 through GAP-05)
> **Scope:** 100% of P0-severity items. All other phases (1-5, 7) excluded per directive.
> **Format:** Matches existing repo conventions (BRIDGE-CORRELATION-HARDENING-TASKS.md, CORTEX-HARDENING-TASKS.md, PRESENTATION-LAYER-HARDENING-TASKS.md, ENFORCEMENT-ENGINE-HARDENING-TASKS.md)
> **Date:** Feb 11, 2026
> **Rule:** No Phase N+1 begins until Phase N quality gate passes.
> **Rule:** All Rust changes must compile with `cargo clippy --workspace -- -D warnings` clean.
> **Rule:** All TS changes must pass `tsc --noEmit` clean.
> **Rule:** Every impl task has a corresponding test task. No untested code.

---

## Executive Summary

The Drift Cloud Readiness Tracker identifies **two categories of P0 items** that block cloud launch and enterprise sales:

1. **Storage Abstraction Layer (Phase 0)** — Drift and Bridge have no storage traits. Without traits, there is no seam to inject a Supabase/Postgres backend. The traits are the swap point: `SqliteDriftStorage` for local, `SupabaseDriftStorage` for cloud. Cortex already has this (`IMemoryStorage` + `ICausalStorage`). Drift and Bridge do not.

2. **Enterprise P0 Features (Phase 6 / GAP-01 through GAP-05)** — Five table-stakes gaps that enterprise procurement will reject the product without: SCIM provisioning, webhooks, audit log API, team/org management, and IP allowlisting.

**Why these are P0:** Without storage traits, the cloud architecture has no foundation — every other phase (infrastructure, sync, API, CLI, hardening) depends on Phase 0. Without the enterprise features, sales teams cannot close enterprise contracts.

**Architecture principle:** Every component is behind a trait boundary. Local SQLite and cloud Postgres are interchangeable implementations. Cloud is 100% opt-in — offline users experience zero changes.

### What's Already Done (Cortex — Reference Architecture)

Cortex already follows the target pattern:
- `cortex-core` defines `IMemoryStorage` (22 methods) + `ICausalStorage` (10 methods)
- `cortex-storage` provides `StorageEngine` implementing both traits
- `ConnectionPool` with `Arc<WriteConnection>` + `Arc<ReadPool>`
- `Arc<T>` blanket impls for trait sharing across NAPI threads
- `Send + Sync` bounds on all traits

**This plan replicates that pattern for Drift and Bridge, then builds the 5 enterprise features on top.**

---

## Progress Summary

| Phase | Description | Impl Tasks | Test Tasks | Status |
|-------|-------------|-----------|-----------|--------|
| A | Drift Storage Trait Design (`drift-core`) | 14 | 12 | Not Started |
| B | Drift Storage Engine + NAPI Rewiring (`drift-storage`, `drift-napi`) | 18 | 16 | Not Started |
| C | Bridge Storage Abstraction + Consumer Rewiring (`cortex-drift-bridge`) | 16 | 14 | Not Started |
| D | SCIM Provisioning (Enterprise GAP-01) | 10 | 8 | Not Started |
| E | Webhook & Event Notification System (Enterprise GAP-02) | 12 | 10 | Not Started |
| F | Audit Log, Team Management & IP Allowlisting (Enterprise GAP-03/04/05) | 18 | 14 | Not Started |
| G | Integration Testing & P0 Parity Verification | 6 | 18 | Not Started |
| **TOTAL** | | **94** | **92** | **186 tasks** |

---

## P0 Item Inventory — Full Cross-Reference

Every P0 item from `BRIDGE-CLOUD-READINESS-TRACKER.md` mapped to this plan:

| Tracker ID | Tracker Description | Plan Phase | Plan IDs |
|---|---|---|---|
| P0-01 | Design drift storage traits in `drift-core` | A | CP0-A-01 through CP0-A-08 |
| P0-02 | Define `IDriftReader` trait | A | CP0-A-09 through CP0-A-11 |
| P0-15 | Define `IWorkspaceStorage` trait | A | CP0-A-12 through CP0-A-14 |
| P0-03 | Build `DriftStorageEngine` | B | CP0-B-01 through CP0-B-06 |
| P0-04 | Implement `IDriftReader` on engine | B | CP0-B-07 |
| P0-05 | Rewire `drift-napi` (107 call sites) | B | CP0-B-08 through CP0-B-13 |
| P0-06 | Update drift-storage tests | B | CP0-B-14 through CP0-B-18 |
| P0-16 | Refactor workspace module | B | CP0-B-10 |
| P0-17 | Update workspace tests | B | CP0-B-18 |
| P0-07 | Define `IBridgeStorage` trait | C | CP0-C-01 through CP0-C-03 |
| P0-08 | Build bridge `ConnectionPool` | C | CP0-C-04 |
| P0-09 | Build `BridgeStorageEngine` | C | CP0-C-05 through CP0-C-07 |
| P0-10 | Rewire bridge consumers (5+ structs) | C | CP0-C-08 through CP0-C-11 |
| P0-11 | Rewire `DriftRuntime` bridge wiring | C | CP0-C-12 |
| P0-12 | Rewire evidence collectors (~15 files) | C | CP0-C-13 through CP0-C-14 |
| P0-13 | Rewire `tools/` directory | C | CP0-C-15 |
| P0-14 | Update bridge test files | C | CP0-C-16 |
| GAP-01 | SCIM Provisioning | D | CP0-D-01 through CP0-D-10 |
| GAP-02 | Webhook System | E | CP0-E-01 through CP0-E-12 |
| GAP-03 | Audit Log API | F | CP0-F-01 through CP0-F-06 |
| GAP-04 | Team & Org Management | F | CP0-F-07 through CP0-F-13 |
| GAP-05 | IP Allowlisting | F | CP0-F-14 through CP0-F-18 |

**Coverage: 17/17 Phase 0 tasks + 5/5 Enterprise P0 GAPs = 100%**

---

## Phase A: Drift Storage Trait Design (`drift-core`)

> **Goal:** Define the trait boundaries that make SQLite↔Postgres swappable. Single source of truth for all drift storage method signatures.
> **Estimated effort:** 3-4 days (1 developer)
> **Tracker refs:** P0-01, P0-02, P0-15
> **Key constraint:** 149 existing query functions across 15 modules in `drift-storage/src/queries/`. A single monolithic trait is unwieldy — use 6 focused sub-traits plus `IDriftReader` (bridge evidence) plus `IWorkspaceStorage` (workspace ops).
> **Architecture pattern:** Follow cortex: `&self` receiver, `Result<T, StorageError>` return, `Send + Sync` bounds, `Arc<T>` blanket impls.

### A1 — Core Sub-Trait Definitions

Each sub-trait maps to 1-3 existing query modules in `drift-storage/src/queries/`. All traits go in a new `drift-core/src/traits/` directory.

| ID | Task | File(s) | Type | Tracker Ref |
|----|------|---------|------|-------------|
| CP0-A-01 | Create `drift-core/src/traits/mod.rs` — module declarations + barrel re-exports for all 8 traits | `drift-core/src/traits/mod.rs` (NEW) | impl | P0-01 |
| CP0-A-02 | Define `IDriftFiles` trait (~5 methods) — `insert_file_metadata()`, `get_file_metadata()`, `list_files()`, `delete_file_metadata()`, `file_count()`. Maps to `queries/files.rs`. Add `Send + Sync` bounds + `Arc<T>` blanket impl. | `drift-core/src/traits/drift_files.rs` (NEW) | impl | P0-01 |
| CP0-A-03 | Define `IDriftAnalysis` trait (~25 methods) — functions CRUD, detections CRUD, patterns (confidence/outliers/conventions), boundaries, call_edges, scan_history. Maps to `queries/analysis.rs`, `queries/patterns.rs`, `queries/graph.rs`, `queries/scan_history.rs`. Add `Send + Sync` bounds + `Arc<T>` blanket impl. | `drift-core/src/traits/drift_analysis.rs` (NEW) | impl | P0-01 |
| CP0-A-04 | Define `IDriftStructural` trait (~37 methods) — coupling_metrics, coupling_cycles, constraints, constraint_verifications, contracts, contract_mismatches, constants, secrets, env_variables, wrappers, dna_genes, dna_mutations, crypto_findings, owasp_findings, decomposition_decisions, data_access. Maps to `queries/structural.rs`, `queries/advanced.rs`. Add `Send + Sync` bounds + `Arc<T>` blanket impl. | `drift-core/src/traits/drift_structural.rs` (NEW) | impl | P0-01 |
| CP0-A-05 | Define `IDriftEnforcement` trait (~21 methods) — violations CRUD, gate_results CRUD, audit_snapshots, health_trends, feedback CRUD, policy_results, degradation_alerts. Maps to `queries/enforcement.rs`, `queries/feedback.rs`. Add `Send + Sync` bounds + `Arc<T>` blanket impl. | `drift-core/src/traits/drift_enforcement.rs` (NEW) | impl | P0-01 |
| CP0-A-06 | Define `IDriftAdvanced` trait (~9 methods) — simulations, decisions, context_cache, migration_projects, migration_modules, migration_corrections. Maps to `queries/advanced.rs`. Add `Send + Sync` bounds + `Arc<T>` blanket impl. | `drift-core/src/traits/drift_advanced.rs` (NEW) | impl | P0-01 |
| CP0-A-07 | Define `IDriftBatchWriter` trait (~5 methods) — `send(command: BatchCommand)`, `flush()`, `flush_sync()`, `stats() -> WriteStats`, `shutdown()`. Abstracts the existing `BatchWriter` behind a trait for cloud implementations (which would batch into HTTP payloads instead of SQLite transactions). Add `Send + Sync` bounds + `Arc<T>` blanket impl. | `drift-core/src/traits/drift_batch.rs` (NEW) | impl | P0-01 |
| CP0-A-08 | Add `From<StorageError> for BridgeError` conversion — unify error types across crate boundaries so `IDriftReader` consumers in bridge code can propagate errors cleanly. Add `From<StorageError> for napi::Error` if not already present. | `drift-core/src/errors.rs` or `cortex-drift-bridge/src/errors/bridge_error.rs` | impl | P0-01 |

### A2 — IDriftReader Trait (Bridge Evidence Interface)

The bridge crate needs read-only access to drift.db for grounding evidence collection. This trait replaces the `ATTACH DATABASE` pattern with a clean abstraction that works for both SQLite (local) and Postgres (cloud).

| ID | Task | File(s) | Type | Tracker Ref |
|----|------|---------|------|-------------|
| CP0-A-09 | Define `IDriftReader` trait (~14 read-only methods) — `pattern_confidence(pattern_id) -> Option<f64>`, `pattern_occurrence_rate(pattern_id) -> Option<f64>`, `false_positive_rate(pattern_id) -> Option<f64>`, `constraint_verified(constraint_id) -> Option<bool>`, `coupling_metric(module) -> Option<f64>`, `dna_health() -> Option<f64>`, `test_coverage(function_id) -> Option<f64>`, `error_handling_gaps(file_prefix) -> Option<u32>`, `decision_evidence(decision_id) -> Option<f64>`, `boundary_data(boundary_id) -> Option<f64>`, `taint_flow_risk(file) -> Option<u32>`, `call_graph_coverage(function_id) -> Option<f64>`, `count_matching_patterns(pattern_ids) -> u32`, `latest_scan_timestamp() -> Option<String>`. These match `query/drift_queries.rs` 1:1. Add `Send + Sync` bounds + `Arc<T>` blanket impl. | `drift-core/src/traits/drift_reader.rs` (NEW) | impl | P0-02 |
| CP0-A-10 | Add `drift-core` dependency to `cortex-drift-bridge/Cargo.toml` — bridge depends on `drift-core` for the `IDriftReader` trait (compile-time only, no runtime dependency on drift-storage) | `cortex-drift-bridge/Cargo.toml` | impl | P0-02 |
| CP0-A-11 | Create `IDriftReaderStub` test helper — in-memory implementation of `IDriftReader` that returns configurable values per method. Used by bridge tests as a test double instead of creating real drift.db connections. | `drift-core/src/traits/test_helpers.rs` (NEW) | impl | P0-02 |

### A3 — IWorkspaceStorage Trait

The workspace module in `drift-core/src/workspace/` has 12 files with ~30+ direct `Connection::open()` calls that bypass `DatabaseManager`. Some operations (backup via SQLite Backup API, `VACUUM INTO`) are inherently SQLite-specific — trait methods return `NotSupported` for cloud backends.

| ID | Task | File(s) | Type | Tracker Ref |
|----|------|---------|------|-------------|
| CP0-A-12 | Define `IWorkspaceStorage` trait (~10 methods) — `initialize(path) -> Result<()>`, `status() -> Result<WorkspaceStatus>`, `project_info() -> Result<ProjectInfo>`, `workspace_context() -> Result<WorkspaceContext>`, `gc() -> Result<GcStats>`, `backup(dest) -> Result<BackupResult>`, `export(dest) -> Result<()>`, `import(source) -> Result<()>`, `integrity_check() -> Result<IntegrityResult>`, `schema_version() -> Result<u32>`. Backup/export return `NotSupported` for non-SQLite backends. Add `Send + Sync` bounds + `Arc<T>` blanket impl. | `drift-core/src/traits/workspace.rs` (NEW) | impl | P0-15 |
| CP0-A-13 | Define supporting types — `WorkspaceStatus`, `ProjectInfo`, `WorkspaceContext`, `GcStats`, `BackupResult`, `IntegrityResult` structs used by `IWorkspaceStorage` return types. Keep lightweight — only the fields needed by consumers. | `drift-core/src/traits/workspace_types.rs` (NEW) | impl | P0-15 |
| CP0-A-14 | Register `pub mod traits;` in `drift-core/src/lib.rs` — export all 8 traits + supporting types from the crate root | `drift-core/src/lib.rs` | impl | P0-15 |

### Phase A Tests

| ID | Test | Type | Ref |
|----|------|------|-----|
| CT0-A-01 | **Trait object safety** — verify all 8 traits are object-safe: `let _: Box<dyn IDriftFiles>` compiles for each trait | unit test in `drift-core` | P0-01 |
| CT0-A-02 | **Arc blanket impls** — verify `Arc<T>` where `T: IDriftFiles` also implements `IDriftFiles` (same for all 8) | unit test | P0-01 |
| CT0-A-03 | **Send + Sync bounds** — verify all traits are `Send + Sync` (required for NAPI thread sharing) — `fn assert_send_sync<T: Send + Sync>() {}` compiles for each trait object | unit test | P0-01 |
| CT0-A-04 | **IDriftReader covers all 10 evidence types** — verify trait has methods for all 10 evidence types used by `grounding/evidence/types.rs`: PatternConfidence, OccurrenceRate, FalsePositiveRate, ConstraintVerified, CouplingMetric, DnaHealth, TestCoverage, ErrorHandlingGaps, DecisionEvidence, BoundaryData | unit test | P0-02 |
| CT0-A-05 | **IDriftReaderStub returns configured values** — set `pattern_confidence("auth_check") = 0.85` → call → verify `Some(0.85)` returned | unit test | P0-02 |
| CT0-A-06 | **IDriftReaderStub defaults to None** — unconfigured method → returns `None` (not panic) | unit test | P0-02 |
| CT0-A-07 | **IWorkspaceStorage backup returns NotSupported for non-SQLite** — create mock non-SQLite impl → call `backup()` → verify `Err(NotSupported)` | unit test | P0-15 |
| CT0-A-08 | **Error type conversion** — `StorageError::NotFound` converts to `BridgeError` cleanly via `From` impl | unit test | P0-01 |
| CT0-A-09 | **Trait method count matches query function count** — verify `IDriftAnalysis` has ≥25 methods, `IDriftStructural` ≥37, `IDriftEnforcement` ≥21, `IDriftAdvanced` ≥9, `IDriftFiles` ≥5, `IDriftBatchWriter` ≥5 — prevents under-extraction | unit test | P0-01 |
| CT0-A-10 | **All 149 query functions covered** — for each public function in `drift-storage/src/queries/*.rs`, verify a corresponding trait method exists across the 6 sub-traits (automated via macro or name-matching test) | integration test | P0-01 |
| CT0-A-11 | **IDriftReader methods match drift_queries.rs** — verify 1:1 correspondence between `IDriftReader` method names and `drift_queries.rs` function names | unit test | P0-02 |
| CT0-A-12 | **IWorkspaceStorage covers all 12 workspace files** — verify every public function across `drift-core/src/workspace/*.rs` has a corresponding trait method | integration test | P0-15 |

### Phase A Quality Gate (QG-A)

- [ ] All 8 trait files created in `drift-core/src/traits/`
- [ ] `cargo check -p drift-core` compiles clean
- [ ] `cargo clippy -p drift-core -- -D warnings` clean
- [ ] All 12 Phase A tests pass
- [ ] `IDriftReader` has exactly 14 methods (1:1 with `drift_queries.rs`)
- [ ] All traits have `Send + Sync` bounds
- [ ] All traits have `Arc<T>` blanket impls
- [ ] `drift-core` has zero new runtime dependencies (traits are zero-cost abstractions)

**Estimated effort:** 3-4 days

---

## Phase B: Drift Storage Engine + NAPI Rewiring (`drift-storage`, `drift-napi`, `drift-core`)

> **Goal:** Build `DriftStorageEngine` implementing all 6 sub-traits + `IDriftReader`, then rewire all 107 NAPI call sites and 12 workspace files to use trait methods instead of raw `&Connection`.
> **Estimated effort:** 5-7 days (1 developer), 3-4 days (2 developers with B1‖B3 parallel)
> **Tracker refs:** P0-03, P0-04, P0-05, P0-06, P0-16, P0-17
> **Depends on:** Phase A (traits must exist before engine can implement them)
> **Key constraint:** 107 NAPI call sites across 9 binding files. 12 workspace files with ~30+ `Connection::open()` calls. All must be rewired without breaking existing behavior.

### B1 — DriftStorageEngine Implementation

| ID | Task | File(s) | Type | Tracker Ref |
|----|------|---------|------|-------------|
| CP0-B-01 | Create `DriftStorageEngine` struct — owns `DatabaseManager` (existing) + `BatchWriter` (existing). Fields: `db: DatabaseManager`, `batch: BatchWriter`, `retention_config: RetentionConfig`. Constructors: `open(path)` and `open_in_memory()` mirroring cortex `StorageEngine`. On `open()`: run migrations, apply retention (like bridge INF-04), initialize materialized views. | `drift-storage/src/engine.rs` (NEW) | impl | P0-03 |
| CP0-B-02 | Implement `IDriftFiles` on `DriftStorageEngine` — route each trait method through `self.db.with_reader(\|conn\| queries::files::xxx(conn, ...))` for reads, `self.db.with_writer(\|conn\| ...)` for writes. Each method delegates to the existing free functions in `queries/files.rs`. | `drift-storage/src/engine.rs` | impl | P0-03 |
| CP0-B-03 | Implement `IDriftAnalysis` on `DriftStorageEngine` — ~25 methods routing through reader/writer to `queries/analysis.rs`, `queries/patterns.rs`, `queries/graph.rs`, `queries/scan_history.rs` | `drift-storage/src/engine.rs` | impl | P0-03 |
| CP0-B-04 | Implement `IDriftStructural` on `DriftStorageEngine` — ~37 methods routing to `queries/structural.rs`, `queries/advanced.rs` | `drift-storage/src/engine.rs` | impl | P0-03 |
| CP0-B-05 | Implement `IDriftEnforcement` on `DriftStorageEngine` — ~21 methods routing to `queries/enforcement.rs`, `queries/feedback.rs` | `drift-storage/src/engine.rs` | impl | P0-03 |
| CP0-B-06 | Implement `IDriftAdvanced` + `IDriftBatchWriter` on `DriftStorageEngine` — advanced routes to `queries/advanced.rs`, batch writer delegates to `self.batch.send()`, `self.batch.flush()`, etc. | `drift-storage/src/engine.rs` | impl | P0-03 |
| CP0-B-07 | Implement `IDriftReader` on `DriftStorageEngine` — 14 read-only methods routing through `self.db.with_reader()`. These are the methods bridge evidence collectors will call. Each delegates to the corrected `drift_queries.rs` functions (already fixed in Bridge Correlation Hardening Phase A). | `drift-storage/src/engine.rs` | impl | P0-04 |

### B2 — NAPI Runtime Rewiring

The `DriftRuntime` struct currently holds raw `DatabaseManager` + `BatchWriter`. After rewiring, it holds `Arc<DriftStorageEngine>` and all NAPI bindings call trait methods.

| ID | Task | File(s) | Type | Tracker Ref |
|----|------|---------|------|-------------|
| CP0-B-08 | Rewire `DriftRuntime` — replace `db: DatabaseManager` + `batch_writer: BatchWriter` with `storage: Arc<DriftStorageEngine>`. Update `DriftRuntime::new()` to construct `DriftStorageEngine::open(path)`. Add `storage()` accessor method returning `&Arc<DriftStorageEngine>`. | `drift-napi/src/runtime.rs` | impl | P0-05 |
| CP0-B-09 | Rewire `analysis.rs` NAPI bindings (48 call sites) — replace all `rt.db.with_writer(\|conn\| ...)` and `rt.db.with_reader(\|conn\| ...)` calls with `rt.storage().method_name(args)`. This is the largest single file — 48 call sites across `drift_analyze()` steps 1-8, `drift_call_graph()`, `drift_boundaries()`. **Must preserve the exact pipeline order** (scan → parse → analyze → patterns → graph → structural → enforcement → degradation). | `drift-napi/src/bindings/analysis.rs` | impl | P0-05 |
| CP0-B-10 | Rewire remaining 8 NAPI binding files (59 call sites total) — `structural.rs` (16), `enforcement.rs` (12), `bridge.rs` (10), `graph.rs` (6), `scanner.rs` (6), `patterns.rs` (4), `feedback.rs` (3), `lifecycle.rs` (2). Each `rt.db.with_reader/with_writer` call → trait method call on `rt.storage()`. **Also rewire workspace module:** refactor 12 files in `drift-core/src/workspace/` from raw `Connection::open()` to `IWorkspaceStorage` trait calls via a `SqliteWorkspaceStorage` implementation. | `drift-napi/src/bindings/*.rs`, `drift-core/src/workspace/*.rs` | impl | P0-05, P0-16 |
| CP0-B-11 | Create `SqliteWorkspaceStorage` — concrete implementation of `IWorkspaceStorage` that wraps the existing workspace logic (backup via SQLite Backup API, `VACUUM INTO` for export, `PRAGMA integrity_check`, etc.). `open(path)` constructor creates/opens the workspace database. | `drift-core/src/workspace/sqlite_storage.rs` (NEW) | impl | P0-16 |
| CP0-B-12 | Expose `DriftStorageEngine` as `Arc<dyn IDriftReader>` for bridge consumption — add `as_drift_reader(&self) -> Arc<dyn IDriftReader>` method on `DriftStorageEngine` (or use the `Arc<T>` blanket impl directly). Wire into `DriftRuntime` so bridge bindings receive `Arc<dyn IDriftReader>` instead of `Option<Mutex<Connection>>`. | `drift-storage/src/engine.rs`, `drift-napi/src/runtime.rs` | impl | P0-04, P0-05 |
| CP0-B-13 | Register `pub mod engine;` in `drift-storage/src/lib.rs` — export `DriftStorageEngine` from the crate. Remove `#![allow(dead_code, unused)]` blanket suppression (finally safe to do so since all query functions are now called through the engine). Fix any resulting warnings. | `drift-storage/src/lib.rs` | impl | P0-03 |

### B3 — Drift Storage + Workspace Tests

| ID | Test | Type | Ref |
|----|------|------|-----|
| CT0-B-01 | **Engine open_in_memory round-trip** — `DriftStorageEngine::open_in_memory()` → insert file_metadata via `IDriftFiles` → read back → verify identical | integration test in `drift-storage/tests/` | P0-03 |
| CT0-B-02 | **Engine read/write routing** — insert via `IDriftAnalysis` (writer) → read via `IDriftAnalysis` (reader) → verify data visible. Confirm reads go through `with_reader()` not `with_writer()` (check pool stats if available). | integration test | P0-03 |
| CT0-B-03 | **BatchWriter integration** — `engine.send(InsertDetections(rows))` → `engine.flush_sync()` → verify rows in DB via `IDriftAnalysis::get_detections()` | integration test | P0-03 |
| CT0-B-04 | **Retention-on-init** — create engine with old data → close → reopen → verify retention cleaned old data (timestamps > retention period) | integration test | P0-03 |
| CT0-B-05 | **Pagination integration** — insert 200 violations → paginate with keyset cursor (limit=50) → verify 4 pages, no duplicates, total=200. This verifies `pagination.rs` is exposed through the engine for cloud sync cursor extraction. | integration test | P0-03 |
| CT0-B-06 | **IDriftReader returns real data** — insert `pattern_confidence` row → call `engine.pattern_confidence("auth_check")` → verify `Some(0.85)`. Test all 14 methods. | integration test | P0-04 |
| CT0-B-07 | **IDriftReader returns None for missing data** — empty engine → all 14 methods return `None` or `0` — no errors, no panics | integration test | P0-04 |
| CT0-B-08 | **NAPI analysis pipeline unchanged** — run `drift_analyze()` with rewired engine on test fixtures → verify output matches pre-rewire output (golden file comparison or structural assertion). This is the regression gate — the rewiring must not change any behavior. | e2e test | P0-05 |
| CT0-B-09 | **NAPI structural bindings wired** — call each structural NAPI binding (`drift_coupling_analysis`, `drift_dna_analysis`, etc.) → verify they return real data from the engine (not empty stubs) | integration test | P0-05 |
| CT0-B-10 | **NAPI enforcement bindings wired** — call `drift_violations()`, `drift_gates()`, `drift_check()`, `drift_audit()` → verify non-stub results | integration test | P0-05 |
| CT0-B-11 | **Workspace: SqliteWorkspaceStorage round-trip** — `SqliteWorkspaceStorage::open(temp_dir)` → `initialize()` → `status()` → verify initialized state | integration test | P0-16 |
| CT0-B-12 | **Workspace: backup + integrity** — initialize workspace → insert data → `backup(dest)` → `integrity_check()` on backup → verify clean | integration test | P0-16 |
| CT0-B-13 | **Workspace: existing tests still pass** — verify all 7 existing workspace test files in `drift-core/tests/` pass after refactor to `IWorkspaceStorage` | regression test | P0-17 |
| CT0-B-14 | **Concurrent NAPI calls safe** — spawn 20 threads calling different storage methods → all complete without deadlock within 5s | stress test | P0-05 |
| CT0-B-15 | **dead_code suppression removed** — `#![allow(dead_code, unused)]` removed from `drift-storage/src/lib.rs` → `cargo clippy` produces zero warnings (all functions now reachable through engine) | compilation test | P0-03 |
| CT0-B-16 | **Engine implements all 7 traits** — compile-time assertion: `fn assert_impls(_: &(impl IDriftFiles + IDriftAnalysis + IDriftStructural + IDriftEnforcement + IDriftAdvanced + IDriftBatchWriter + IDriftReader)) {}` compiles with `DriftStorageEngine` | unit test | P0-03 |

### Phase B Quality Gate (QG-B)

- [ ] `DriftStorageEngine` implements all 7 traits (6 sub-traits + IDriftReader)
- [ ] `SqliteWorkspaceStorage` implements `IWorkspaceStorage`
- [ ] `DriftRuntime` holds `Arc<DriftStorageEngine>` — no raw `DatabaseManager` or `BatchWriter` exposure
- [ ] All 107 NAPI call sites rewired (verified by: removing `pub` from `DatabaseManager.with_reader/with_writer` → no compile errors outside `engine.rs`)
- [ ] All 12 workspace files rewired (verified by: no `Connection::open()` calls in `drift-core/src/workspace/` outside `SqliteWorkspaceStorage`)
- [ ] `#![allow(dead_code, unused)]` removed from `drift-storage/src/lib.rs`
- [ ] `cargo test -p drift-storage` — all tests pass
- [ ] `cargo test -p drift-napi` — compiles clean
- [ ] `cargo clippy -p drift-storage -p drift-napi -p drift-core -- -D warnings` clean
- [ ] All 16 Phase B tests pass
- [ ] Existing drift-storage test suite (182+ tests) — zero regressions
- [ ] Existing workspace test suite (7 files) — zero regressions

**Estimated effort:** 5-7 days

---

## Phase C: Bridge Storage Abstraction + Consumer Rewiring (`cortex-drift-bridge`)

> **Goal:** Build `IBridgeStorage` trait + `BridgeStorageEngine` + `ConnectionPool`, replacing all 7-8 scattered `Mutex<Connection>` instances with a single trait-based engine. Replace the SQLite-specific `ATTACH DATABASE` pattern with `IDriftReader` trait calls (cloud-compatible).
> **Estimated effort:** 4-6 days (1 developer)
> **Tracker refs:** P0-07, P0-08, P0-09, P0-10, P0-11, P0-12, P0-13, P0-14
> **Depends on:** Phase A (bridge needs `IDriftReader` trait), Phase B (bridge needs `Arc<dyn IDriftReader>` from `DriftStorageEngine`)
> **Key constraint:** 7-8 separate `Mutex<Connection>` scattered across `DriftRuntime`, `BridgeEventHandler`, `BridgeWeightProvider`, `BridgeDecompositionPriorProvider`, `BridgeRuntime`. Also ~15 evidence collector files that take raw `&Connection`. All must switch to trait-based access.

### C1 — IBridgeStorage Trait + Engine

| ID | Task | File(s) | Type | Tracker Ref |
|----|------|---------|------|-------------|
| CP0-C-01 | Define `IBridgeStorage` trait (~23 methods) in `cortex-drift-bridge/src/traits.rs` — **7 writes:** `insert_memory()`, `insert_grounding_result()`, `insert_snapshot()`, `insert_event()`, `insert_metric()`, `upsert_weight()`, `upsert_decomposition_prior()`. **7 reads:** `get_memory()`, `query_memories_by_type()`, `get_grounding_history()`, `get_snapshots()`, `get_events()`, `get_metrics()`, `get_schema_version()`. **3 formalized ad-hoc:** `query_all_memories_for_grounding()`, `search_memories_by_tag()`, `get_weight_adjustments()`. **4 lifecycle:** `initialize()`, `migrate()`, `health_check()`, `shutdown()`. **2 usage:** `count_memories()`, `storage_stats()`. Add `Send + Sync` bounds + `Arc<T>` blanket impl. | `cortex-drift-bridge/src/traits.rs` (NEW) | impl | P0-07 |
| CP0-C-02 | Define `IBridgeStorage` supporting types — `BridgeMemoryRow`, `GroundingResultRow`, `GroundingSnapshotRow`, `BridgeEventRow`, `BridgeMetricRow`, `BridgeStorageStats`, `BridgeHealthStatus`. Keep aligned with existing `storage/tables.rs` row types. | `cortex-drift-bridge/src/traits.rs` | impl | P0-07 |
| CP0-C-03 | Add `Arc<T>` blanket impl for `IBridgeStorage` — `impl<T: IBridgeStorage> IBridgeStorage for Arc<T>` delegating all methods. Required for `Arc<BridgeStorageEngine>` sharing across NAPI threads. | `cortex-drift-bridge/src/traits.rs` | impl | P0-07 |
| CP0-C-04 | Build `ConnectionPool` for bridge — modeled after cortex-storage's pool. Fields: `writer: Mutex<Connection>`, `readers: Vec<Connection>` (2-4 read connections), `read_index: AtomicUsize`. Methods: `with_writer<F, T>(&self, f: F) -> Result<T>`, `with_reader<F, T>(&self, f: F) -> Result<T>`. WAL mode enabled on all connections. `open(path)` and `open_in_memory()` constructors. | `cortex-drift-bridge/src/storage/pool.rs` (NEW) | impl | P0-08 |
| CP0-C-05 | Build `BridgeStorageEngine` struct — owns `ConnectionPool`. Implements `IBridgeStorage`. Routes existing `storage/tables.rs` writes through `pool.with_writer()` and `query/` reads through `pool.with_reader()`. On `initialize()`: run schema migrations via `storage::migrate()`, create `bridge_schema_version` table. | `cortex-drift-bridge/src/storage/engine.rs` (NEW) | impl | P0-09 |
| CP0-C-06 | Implement all 23 `IBridgeStorage` methods on `BridgeStorageEngine` — each delegates to existing functions in `storage/tables.rs` (writes) and `query/cortex_queries.rs` + `query/drift_queries.rs` (reads). The existing SQL functions remain as-is; the engine just routes through the pool. | `cortex-drift-bridge/src/storage/engine.rs` | impl | P0-09 |
| CP0-C-07 | Resolve dual-runtime problem — `BridgeRuntime` in `lib.rs` has its own 3 `Mutex<Connection>` fields (`drift_db`, `cortex_db`, `bridge_db`) that are **never used from `DriftRuntime`** (standalone/test only). Decision: deprecate `BridgeRuntime`'s storage role. `BridgeRuntime` becomes a thin wrapper around `BridgeStorageEngine` for standalone use. For NAPI, `DriftRuntime` owns the `BridgeStorageEngine` directly. Add `#[deprecated]` to `BridgeRuntime.drift_db/cortex_db/bridge_db` fields. | `cortex-drift-bridge/src/lib.rs` | impl | P0-09 |

### C2 — Consumer Rewiring

Replace `Option<Mutex<Connection>>` with `Arc<dyn IBridgeStorage>` (for bridge storage) and `Arc<dyn IDriftReader>` (for drift evidence queries) in all consumers.

| ID | Task | File(s) | Type | Tracker Ref |
|----|------|---------|------|-------------|
| CP0-C-08 | Rewire `BridgeEventHandler` — replace `cortex_db: Option<Mutex<Connection>>` (misnamed — it's bridge.db) with `bridge_store: Arc<dyn IBridgeStorage>`. Update `create_memory()`, `on_pattern_discovered()`, and all event handlers to call trait methods. | `cortex-drift-bridge/src/event_mapping/mapper.rs` | impl | P0-10 |
| CP0-C-09 | Rewire `BridgeWeightProvider` — replace `cortex_db: Option<Mutex<Connection>>` with `bridge_store: Arc<dyn IBridgeStorage>`. Update `compute_adaptive_weights()` and `persist_weights()` to call trait methods. | `cortex-drift-bridge/src/specification/weight_provider.rs` | impl | P0-10 |
| CP0-C-10 | Rewire `BridgeDecompositionPriorProvider` — replace `cortex_db: Option<Mutex<Connection>>` with `bridge_store: Arc<dyn IBridgeStorage>`. Update `get_priors()` and `query_priors_with_similarity()`. | `cortex-drift-bridge/src/specification/decomposition_provider.rs` | impl | P0-10 |
| CP0-C-11 | Rewire `specification/events.rs` — 3 functions (`on_spec_corrected`, `on_contract_verified`, `on_decomposition_adjusted`) take raw `bridge_db: Option<&Connection>`. Change to `bridge_store: &dyn IBridgeStorage`. Update `generate_contradiction()` in `grounding/contradiction.rs` similarly. | `cortex-drift-bridge/src/specification/events.rs`, `grounding/contradiction.rs` | impl | P0-10 |
| CP0-C-12 | Rewire `DriftRuntime` bridge wiring — replace `bridge_db: Option<Mutex<Connection>>` with `bridge_store: Option<Arc<BridgeStorageEngine>>`. Replace `drift_db_for_bridge: Option<Mutex<Connection>>` with `drift_reader: Option<Arc<dyn IDriftReader>>` (provided by Phase B's `DriftStorageEngine`). Update `lock_bridge_db()` helper → `bridge_storage()` returning `&Arc<dyn IBridgeStorage>`. NAPI bridge bindings call `rt.bridge_storage().method()` instead of `rt.lock_bridge_db()`. | `drift-napi/src/runtime.rs`, `drift-napi/src/bindings/bridge.rs` | impl | P0-11 |

### C3 — Evidence Collector + Cross-DB Rewiring

The grounding evidence system has ~15 files that take raw `&Connection` to drift.db. Replace with `Arc<dyn IDriftReader>` trait calls.

| ID | Task | File(s) | Type | Tracker Ref |
|----|------|---------|------|-------------|
| CP0-C-13 | Rewire evidence collectors (~15 files) — `grounding/evidence/collector.rs` (12 collector functions), `grounding/evidence/composite.rs`, `grounding/loop_runner.rs`. All currently receive `&Connection` (drift.db) for evidence queries. Replace with `&dyn IDriftReader`. Each `collect_one()` call becomes a trait method call (e.g., `reader.pattern_confidence(id)` instead of `drift_queries::pattern_confidence(conn, id)`). | `cortex-drift-bridge/src/grounding/evidence/collector.rs`, `composite.rs`, `loop_runner.rs` | impl | P0-12 |
| CP0-C-14 | Replace `query/cross_db.rs` ATTACH pattern — the `with_drift_attached()` RAII guard and `count_matching_patterns()` (which uses `ATTACH DATABASE drift.db AS drift`) must be replaced with `IDriftReader::count_matching_patterns()` trait call. This is critical for cloud compatibility — Postgres doesn't have `ATTACH DATABASE`. Remove `query/attach.rs` RAII guard (no longer needed). | `cortex-drift-bridge/src/query/cross_db.rs`, `query/attach.rs` | impl | P0-12 |
| CP0-C-15 | Rewire `tools/` directory consumers — `tools/drift_health.rs` (`handle_drift_health()`) and `tools/drift_grounding_check.rs` (`handle_drift_grounding_check()`) take `Option<&Mutex<Connection>>`. Rewire to receive `&dyn IBridgeStorage` and `&dyn IDriftReader`. | `cortex-drift-bridge/src/tools/drift_health.rs`, `tools/drift_grounding_check.rs` | impl | P0-13 |
| CP0-C-16 | Update ~20+ bridge test files — each test file creates `Connection::open_in_memory()` manually. Switch to `BridgeStorageEngine::open_in_memory()`. Evidence/grounding test files (~10) need `IDriftReaderStub` (from Phase A) instead of mock drift.db connections. | `cortex-drift-bridge/tests/*.rs` | impl | P0-14 |

### Phase C Tests

| ID | Test | Type | Ref |
|----|------|------|-----|
| CT0-C-01 | **BridgeStorageEngine open_in_memory round-trip** — `open_in_memory()` → `insert_memory()` → `get_memory()` → verify identical | integration test | P0-09 |
| CT0-C-02 | **ConnectionPool read/write separation** — write via pool → read via pool → verify data visible through reader connections (not just writer) | integration test | P0-08 |
| CT0-C-03 | **ConnectionPool WAL mode active** — `open()` → verify `PRAGMA journal_mode` returns `wal` on all connections | integration test | P0-08 |
| CT0-C-04 | **IBridgeStorage covers all existing operations** — for each public function in `storage/tables.rs` and `query/cortex_queries.rs`, verify a corresponding trait method exists | compilation test | P0-07 |
| CT0-C-05 | **Engine health_check reports connected** — `open_in_memory()` → `health_check()` → verify status is `Connected` | unit test | P0-09 |
| CT0-C-06 | **BridgeEventHandler uses trait** — fire `on_pattern_discovered` → verify memory inserted via `IBridgeStorage::insert_memory()` (not raw SQL) | integration test | P0-10 |
| CT0-C-07 | **Evidence collector uses IDriftReader** — provide `IDriftReaderStub` with `pattern_confidence("auth") = 0.9` → collect evidence → verify `PatternConfidence` evidence item returned with value 0.9 | integration test | P0-12 |
| CT0-C-08 | **Cross-DB ATTACH pattern eliminated** — `grep -r "ATTACH DATABASE" cortex-drift-bridge/src/` returns zero matches (no ATTACH anywhere in production code) | static analysis | P0-12 |
| CT0-C-09 | **Grounding loop uses trait-based evidence** — create `BridgeStorageEngine` + `IDriftReaderStub` with sample data → run grounding loop → verify evidence collected, verdict is not `InsufficientData` | integration test | P0-12 |
| CT0-C-10 | **DriftRuntime bridge wiring works** — `DriftRuntime::new()` → verify `bridge_storage()` returns valid engine, `drift_reader()` returns valid reader | integration test | P0-11 |
| CT0-C-11 | **NAPI bridge bindings use engine** — call `driftBridgeStatus()` through NAPI → verify it queries `BridgeStorageEngine` (not raw `Mutex<Connection>`) | integration test | P0-11 |
| CT0-C-12 | **Dual-runtime deprecated** — `BridgeRuntime.drift_db`, `.cortex_db`, `.bridge_db` have `#[deprecated]` attribute | compilation check | P0-09 |
| CT0-C-13 | **Existing bridge test suite passes** — all 795+ existing bridge tests pass with `BridgeStorageEngine` backing (zero regressions) | regression test | P0-14 |
| CT0-C-14 | **Concurrent bridge operations safe** — spawn 10 threads: 5 writing memories + 5 reading grounding results → all complete without deadlock | stress test | P0-09 |

### Phase C Quality Gate (QG-C)

- [ ] `BridgeStorageEngine` implements `IBridgeStorage` (23 methods)
- [ ] All 7-8 `Mutex<Connection>` instances replaced (verified by: `grep -r "Mutex<Connection>" cortex-drift-bridge/src/` returns only `ConnectionPool` internals)
- [ ] `ATTACH DATABASE` pattern fully eliminated (zero matches in production code)
- [ ] `DriftRuntime.bridge_db` and `drift_db_for_bridge` replaced with trait-based fields
- [ ] `BridgeRuntime` storage fields deprecated
- [ ] `cargo test -p cortex-drift-bridge` — all 795+ tests pass
- [ ] `cargo clippy -p cortex-drift-bridge -p drift-napi -- -D warnings` clean
- [ ] All 14 Phase C tests pass
- [ ] Bridge evidence collectors use `IDriftReader` (no raw `&Connection` to drift.db)

**Estimated effort:** 4-6 days

---

## Phase D: SCIM Provisioning (Enterprise GAP-01)

> **Goal:** Implement SCIM 2.0 endpoints (RFC 7644) for automated user provisioning/deprovisioning from enterprise IdPs (Okta, Azure AD, OneLogin). Without SCIM, enterprise procurement rejects the product — terminated employees retain Drift access until manually revoked.
> **Estimated effort:** 2-3 days (1 developer)
> **Tracker refs:** GAP-01, P6-01 through P6-05
> **Depends on:** Phase 1 (Cloud Infrastructure — Supabase project must exist) — **can start in parallel with Phases A-C if Supabase project is provisioned early**
> **Technology:** Supabase Edge Functions (Deno/Hono) + Supabase Auth (GoTrue). Evaluate WorkOS as unified SSO+SCIM provider for Enterprise tier (decision gate in CP0-D-01).

### D1 — SCIM Infrastructure

| ID | Task | File(s) | Type | Tracker Ref |
|----|------|---------|------|-------------|
| CP0-D-01 | **Decision gate: WorkOS vs. hand-rolled SCIM** — evaluate WorkOS ($$$) vs. custom Edge Functions. WorkOS provides unified SSO+SCIM as a service. If cost-effective for Enterprise tier, use WorkOS and keep Supabase Auth for Free/Pro. Document decision in ADR (Architecture Decision Record). Output: chosen approach + cost estimate. | `docs/adr/ADR-001-scim-provider.md` (NEW) | impl | GAP-01 |
| CP0-D-02 | Create SCIM bearer token infrastructure — `scim_tokens` table in Supabase (tenant_id, token_hash SHA-256, created_at, revoked_at). Separate from user JWTs. Edge Function middleware validates SCIM bearer token and extracts `tenant_id`. One SCIM token per tenant, admin-only creation via `POST /api/v1/settings/scim`. | `supabase/migrations/xxx_scim_tokens.sql` (NEW), Edge Function middleware | impl | GAP-01 |
| CP0-D-03 | Implement `POST /scim/v2/Users` (create user) — receives IdP user attributes (userName, name, emails, active). Creates Supabase Auth user via Admin API. Inserts `user_tenant_mappings` row with default role. Returns SCIM User resource (RFC 7643 §4.1). Validates required fields, returns 400 with SCIM error schema on invalid input. | `supabase/functions/scim-users/index.ts` (NEW) | impl | GAP-01 |
| CP0-D-04 | Implement `GET /scim/v2/Users` (list users) + `GET /scim/v2/Users/:id` (get user) — paginated list with `startIndex` + `count` (SCIM pagination, not cursor). Filter support: `filter=userName eq "user@example.com"`. Returns SCIM ListResponse. | `supabase/functions/scim-users/index.ts` | impl | GAP-01 |
| CP0-D-05 | Implement `PATCH /scim/v2/Users/:id` (update user) — supports SCIM PatchOp (RFC 7644 §3.5.2): `replace` operations on `active`, `name`, `emails`. When `active: false` → deactivate user (see CP0-D-07). | `supabase/functions/scim-users/index.ts` | impl | GAP-01 |
| CP0-D-06 | Implement `DELETE /scim/v2/Users/:id` (delete user) — soft-delete: sets `active: false` in Supabase Auth, revokes all API keys, logs audit event. Data preserved, access revoked. Hard-delete only via GDPR `DELETE /api/v1/account`. | `supabase/functions/scim-users/index.ts` | impl | GAP-01 |
| CP0-D-07 | Implement SCIM deprovisioning logic — when IdP sends `active: false` (PATCH) or DELETE: (1) disable Supabase Auth user via Admin API, (2) revoke all `api_keys` for user, (3) end all active sessions, (4) insert `cloud_audit_log` event with action `user.deprovisioned`, (5) emit `user.deprovisioned` webhook (Phase E). | `supabase/functions/scim-users/index.ts` | impl | GAP-01 |

### D2 — SCIM Groups

| ID | Task | File(s) | Type | Tracker Ref |
|----|------|---------|------|-------------|
| CP0-D-08 | Implement `POST/GET/PATCH/DELETE /scim/v2/Groups` — maps IdP groups to Drift teams (Phase F). Group membership → team membership via `team_memberships` table. `PATCH` supports `add`/`remove` members operations. | `supabase/functions/scim-groups/index.ts` (NEW) | impl | GAP-01 |
| CP0-D-09 | Implement group-to-role mapping — configurable per-tenant mapping: IdP group name → Drift role (`owner`, `admin`, `member`, `viewer`). Stored in `scim_group_mappings` table. Default: all groups map to `member`. | `supabase/migrations/xxx_scim_group_mappings.sql` (NEW), Edge Function | impl | GAP-01 |
| CP0-D-10 | SCIM conformance validation — run Okta SCIM test harness + Azure AD SCIM validator against endpoints. Fix any non-conformance. Document supported SCIM features vs. optional features. | test harness | impl | GAP-01 |

### Phase D Tests

| ID | Test | Type | Ref |
|----|------|------|-----|
| CT0-D-01 | **SCIM create user → Supabase Auth user exists** — `POST /scim/v2/Users` with valid attributes → verify user in Supabase Auth + `user_tenant_mappings` row | integration test | GAP-01 |
| CT0-D-02 | **SCIM deactivate user → access revoked** — create user → `PATCH active: false` → verify Auth disabled, API keys revoked, sessions ended, audit log entry | integration test | GAP-01 |
| CT0-D-03 | **SCIM list users with filter** — create 5 users → `GET /scim/v2/Users?filter=userName eq "user3@example.com"` → verify single result | integration test | GAP-01 |
| CT0-D-04 | **SCIM pagination** — create 25 users → `GET /scim/v2/Users?startIndex=1&count=10` → verify `totalResults=25`, `itemsPerPage=10`, `startIndex=1` | integration test | GAP-01 |
| CT0-D-05 | **SCIM group creates team** — `POST /scim/v2/Groups` → verify `teams` row created with matching name | integration test | GAP-01 |
| CT0-D-06 | **SCIM group membership syncs** — add user to group via `PATCH /scim/v2/Groups/:id` → verify `team_memberships` row | integration test | GAP-01 |
| CT0-D-07 | **SCIM bearer token auth** — request without token → 401. Request with invalid token → 401. Request with valid token → 200. | security test | GAP-01 |
| CT0-D-08 | **SCIM tenant isolation** — tenant A's SCIM token cannot access tenant B's users (even if user IDs guessed) | security test | GAP-01 |

### Phase D Quality Gate (QG-D)

- [ ] SCIM `/Users` CRUD works (create, get, list, update, delete)
- [ ] SCIM `/Groups` CRUD works
- [ ] Deprovisioning revokes all access within 60s of IdP signal
- [ ] SCIM bearer token auth enforced on all endpoints
- [ ] Tenant isolation verified — cross-tenant SCIM access blocked
- [ ] Okta SCIM test harness passes (or Azure AD SCIM validator)
- [ ] All 8 Phase D tests pass
- [ ] Audit log entries created for all provisioning/deprovisioning events

**Estimated effort:** 2-3 days

---

## Phase E: Webhook & Event Notification System (Enterprise GAP-02)

> **Goal:** Build a complete webhook infrastructure for programmatic CI/CD integration, alerting pipelines, and third-party tool orchestration. Enterprise customers need event-driven notifications, not polling.
> **Estimated effort:** 2-3 days (1 developer)
> **Tracker refs:** GAP-02, P6-06 through P6-10
> **Depends on:** Phase 1 (Cloud Infrastructure — Supabase tables must exist)
> **Technology:** Supabase Edge Functions + Supabase Queues (or pg_cron + outbox table) for async delivery. HMAC-SHA256 signature verification.

### E1 — Webhook Infrastructure

| ID | Task | File(s) | Type | Tracker Ref |
|----|------|---------|------|-------------|
| CP0-E-01 | Create `webhook_endpoints` + `webhook_deliveries` tables — DDL from GAP-02 spec. Add RLS policies (tenant isolation). Add indexes on `tenant_id`, `endpoint_id`, `next_retry_at`. Add `webhook_event_types` reference table with all supported event types. | `supabase/migrations/xxx_webhooks.sql` (NEW) | impl | GAP-02 |
| CP0-E-02 | Implement webhook registration API — `POST /api/v1/webhooks` (url, events[], description). Validate URL (HTTPS only, no localhost/private IPs). Generate shared secret (32 bytes, crypto-random). Store `secret_hash` (SHA-256). Return webhook ID + raw secret (shown once). `GET /api/v1/webhooks` (list for tenant). `PATCH /api/v1/webhooks/:id` (update URL, events, active). `DELETE /api/v1/webhooks/:id`. | `supabase/functions/webhooks/index.ts` (NEW) | impl | GAP-02 |
| CP0-E-03 | Implement webhook signature generation — `X-Drift-Signature: sha256=HMAC(secret, timestamp.payload)`. Include `X-Drift-Timestamp` (Unix epoch) and `X-Drift-Webhook-Id` (UUID, idempotency key) headers. Follow Stripe's signature verification pattern. | `supabase/functions/webhooks/signature.ts` (NEW) | impl | GAP-02 |
| CP0-E-04 | Implement webhook dispatch engine — async function triggered after database events. For each matching webhook endpoint: serialize payload, sign with HMAC-SHA256, POST to registered URL. Record delivery attempt in `webhook_deliveries`. Timeout: 10s per delivery. Circuit breaker: disable endpoint after 50 consecutive failures. | `supabase/functions/webhook-dispatch/index.ts` (NEW) | impl | GAP-02 |
| CP0-E-05 | Implement retry with exponential backoff — on HTTP 5xx or timeout: schedule retry at `1s → 2s → 4s → 8s → 16s` intervals (max 5 retries). Use `next_retry_at` column in `webhook_deliveries`. Retries processed by pg_cron job or Supabase Queue consumer. After 5 failures: mark delivery as `failed` (dead letter). | `supabase/functions/webhook-dispatch/retry.ts` (NEW) | impl | GAP-02 |

### E2 — Event Wiring

| ID | Task | File(s) | Type | Tracker Ref |
|----|------|---------|------|-------------|
| CP0-E-06 | Define event catalog — 7 core events with documented payload schemas: `scan.completed` (scan summary), `gate.failed` (gate name, score, threshold), `violation.new` (severity, file, rule), `grounding.degraded` (memory_id, old_score, new_score), `apikey.expiring` (key_name, expires_at), `sync.failed` (error, retry_count), `project.created` / `project.deleted`. Each event has a JSON Schema definition. | `supabase/functions/webhooks/event_schemas.ts` (NEW) | impl | GAP-02 |
| CP0-E-07 | Wire `POST /api/v1/sync` → `scan.completed` event — after sync succeeds, check if any webhook endpoints subscribe to `scan.completed`. If yes, dispatch asynchronously (never block sync on webhook delivery). | `supabase/functions/sync/index.ts` (modify) | impl | GAP-02 |
| CP0-E-08 | Wire gate results → `gate.failed` event — after gate results upserted during sync, check for failing gates. Fire `gate.failed` for each. | `supabase/functions/sync/index.ts` (modify) | impl | GAP-02 |
| CP0-E-09 | Wire violation insert → `violation.new` event — after new critical/high violations upserted, fire `violation.new`. Only for new violations (not existing ones re-synced). | `supabase/functions/sync/index.ts` (modify) | impl | GAP-02 |
| CP0-E-10 | Implement webhook delivery logs API — `GET /api/v1/webhooks/:id/deliveries` (paginated, cursor-based). Fields: event_type, status_code, response_body (truncated), attempt, delivered_at, latency_ms. | `supabase/functions/webhooks/index.ts` | impl | GAP-02 |
| CP0-E-11 | Implement test endpoint — `POST /api/v1/webhooks/:id/test` sends a `ping` event with test payload. Verifies endpoint is reachable and signature verification works. Returns delivery result immediately (synchronous for test only). | `supabase/functions/webhooks/index.ts` | impl | GAP-02 |
| CP0-E-12 | Implement webhook secret rotation — `POST /api/v1/webhooks/:id/rotate-secret`. Generates new secret, stores as `secret_hash_new`. During 24h rotation window, both old and new secrets are valid for signature verification. After 24h, old secret deleted. | `supabase/functions/webhooks/index.ts` | impl | GAP-02 |

### Phase E Tests

| ID | Test | Type | Ref |
|----|------|------|-----|
| CT0-E-01 | **Webhook registration round-trip** — `POST /api/v1/webhooks` → `GET /api/v1/webhooks` → verify endpoint in list with correct URL and events | integration test | GAP-02 |
| CT0-E-02 | **Webhook signature verification** — register webhook → trigger event → capture delivery → verify `X-Drift-Signature` matches HMAC of payload with secret | integration test | GAP-02 |
| CT0-E-03 | **Webhook retry on 500** — register webhook pointing to mock server returning 500 → trigger event → verify 5 retry attempts with exponential backoff timing | integration test | GAP-02 |
| CT0-E-04 | **Webhook dead letter after max retries** — 5 consecutive 500s → verify delivery status is `failed`, no more retries scheduled | integration test | GAP-02 |
| CT0-E-05 | **scan.completed fires after sync** — register webhook for `scan.completed` → `POST /api/v1/sync` → verify webhook received with scan summary payload | e2e test | GAP-02 |
| CT0-E-06 | **gate.failed fires on failing gate** — sync with failing gate result → verify `gate.failed` webhook with gate name and score | e2e test | GAP-02 |
| CT0-E-07 | **Webhook URL validation** — attempt to register `http://` (not HTTPS) → 400. Attempt `https://localhost` → 400. Attempt private IP → 400. | security test | GAP-02 |
| CT0-E-08 | **Webhook tenant isolation** — tenant A's webhook cannot be read/modified by tenant B | security test | GAP-02 |
| CT0-E-09 | **Webhook test endpoint** — `POST /api/v1/webhooks/:id/test` → verify mock server receives `ping` event with valid signature | integration test | GAP-02 |
| CT0-E-10 | **Secret rotation dual-validity** — rotate secret → verify OLD secret still valid for 24h → verify NEW secret also valid → after 24h, old invalid | integration test | GAP-02 |

### Phase E Quality Gate (QG-E)

- [ ] Webhook CRUD API works (register, list, update, delete)
- [ ] HMAC-SHA256 signature on every delivery
- [ ] Retry with exponential backoff (5 attempts)
- [ ] Dead letter queue for permanently failed deliveries
- [ ] `scan.completed`, `gate.failed`, `violation.new` events wired
- [ ] Webhook delivery logs queryable via API
- [ ] Test endpoint works (`POST /api/v1/webhooks/:id/test`)
- [ ] Secret rotation with 24h dual-validity window
- [ ] URL validation blocks HTTP, localhost, and private IPs
- [ ] All 10 Phase E tests pass

**Estimated effort:** 2-3 days

---

## Phase F: Audit Log API, Team Management & IP Allowlisting (Enterprise GAP-03/04/05)

> **Goal:** Implement the remaining 3 enterprise P0 gaps: searchable/exportable audit log API (SOC 2 CC7.1), team & org hierarchy with invitations, and IP allowlisting for API access control (SOC 2 CC6.1).
> **Estimated effort:** 3-4 days (1 developer), 2 days (2 developers with F1‖F2 parallel)
> **Tracker refs:** GAP-03 (P6-15 through P6-17), GAP-04 (P6-11 through P6-14), GAP-05 (P6-18)
> **Depends on:** Phase 1 (Cloud Infrastructure — Supabase tables must exist)
> **Technology:** Supabase Edge Functions (Deno/Hono), Postgres RLS, `inet` type for CIDR matching.

### F1 — Audit Log API (GAP-03)

| ID | Task | File(s) | Type | Tracker Ref |
|----|------|---------|------|-------------|
| CP0-F-01 | Create `cloud_audit_log` table with immutability policies — DDL from GAP-03 spec. RLS policy: `tenant_id = current_setting('app.tenant_id')::UUID`. Immutability: `CREATE POLICY no_update ... FOR UPDATE USING (false)`, `CREATE POLICY no_delete ... FOR DELETE USING (false)`. Indexes on `(tenant_id, created_at)`, `(tenant_id, actor_id)`, `(tenant_id, action)`. Partition by month for large-scale tenants (via pg_partman or native Postgres partitioning). | `supabase/migrations/xxx_cloud_audit_log.sql` (NEW) | impl | GAP-03 |
| CP0-F-02 | Wire audit events into all mutating API endpoints — create reusable `logAuditEvent(tenant_id, actor_id, actor_email, action, resource_type, resource_id, metadata, ip, user_agent)` function. Call from every `POST/PATCH/DELETE` handler. Actions follow `resource.verb` convention (e.g., `project.delete`, `apikey.create`, `sync.push`, `webhook.register`, `user.deprovisioned`). Extract IP from `X-Forwarded-For` header, user agent from `User-Agent`. | `supabase/functions/shared/audit.ts` (NEW), all Edge Function handlers | impl | GAP-03 |
| CP0-F-03 | Implement audit query API — `GET /api/v1/audit` with cursor-based pagination + filters: `?actor=user@email.com`, `?action=delete`, `?resource_type=project`, `?after=2026-01-01T00:00:00Z`, `?before=...`, `?cursor=X`, `?limit=100` (max 200). Response envelope: `{ data, pagination: { cursor, has_more, total } }`. | `supabase/functions/audit/index.ts` (NEW) | impl | GAP-03 |
| CP0-F-04 | Implement audit export API — `GET /api/v1/audit/export` returns JSON Lines format (one JSON object per line) for SIEM ingestion. Supports same filters as query API. Streams response (not buffered) for large exports. `Content-Type: application/x-ndjson`. | `supabase/functions/audit/index.ts` | impl | GAP-03 |
| CP0-F-05 | Implement configurable audit retention per plan — Free: 30 days, Pro: 1 year, Team: 2 years, Enterprise: custom. pg_cron job runs daily: `DELETE FROM cloud_audit_log WHERE created_at < now() - plan_retention_interval AND tenant_id IN (SELECT id FROM tenants WHERE plan = ...)`. Tenant notification email 7 days before data reaches retention limit. | `supabase/migrations/xxx_audit_retention.sql` (NEW), pg_cron config | impl | GAP-03 |
| CP0-F-06 | Implement Supabase Realtime subscription for live audit stream — enterprise tenants can subscribe to `audit:{tenant_id}` Realtime channel. Each audit event INSERT triggers Postgres notification → Supabase Realtime broadcasts to subscribers. Enables live SOC monitoring dashboards. | `supabase/functions/audit/realtime.ts` (NEW) | impl | GAP-03 |

### F2 — Team & Organization Management (GAP-04)

| ID | Task | File(s) | Type | Tracker Ref |
|----|------|---------|------|-------------|
| CP0-F-07 | Create `teams`, `team_memberships`, `team_projects`, `invitations` tables — DDL from GAP-04 spec. RLS policies (tenant isolation). Indexes on FKs. `invitations.token` is UNIQUE + indexed for fast lookup. `invitations.expires_at` default 7 days. | `supabase/migrations/xxx_teams.sql` (NEW) | impl | GAP-04 |
| CP0-F-08 | Implement team CRUD API — `POST /api/v1/teams` (org admins only), `GET /api/v1/teams` (list teams for tenant), `PATCH /api/v1/teams/:id` (update name/description), `DELETE /api/v1/teams/:id` (cascade deletes memberships + project assignments). | `supabase/functions/teams/index.ts` (NEW) | impl | GAP-04 |
| CP0-F-09 | Implement team membership management — `POST /api/v1/teams/:id/members` (add member by user_id or email), `DELETE /api/v1/teams/:id/members/:user_id` (remove member), `PATCH /api/v1/teams/:id/members/:user_id` (change role: `lead` or `member`). `GET /api/v1/teams/:id/members` (list with roles). | `supabase/functions/teams/index.ts` | impl | GAP-04 |
| CP0-F-10 | Implement team-project assignment — `POST /api/v1/teams/:id/projects` (assign project to team), `DELETE /api/v1/teams/:id/projects/:project_id` (unassign). Team members can only access projects assigned to their teams. RLS policy on all project-scoped tables: `project_id IN (SELECT project_id FROM team_projects WHERE team_id IN (SELECT team_id FROM team_memberships WHERE user_id = auth.uid()))`. | `supabase/functions/teams/index.ts`, RLS policy updates | impl | GAP-04 |
| CP0-F-11 | Implement invitation flow — `POST /api/v1/invitations` (email, role, team_id?). Sends invitation email via Resend/Postmark with unique token link. `POST /api/v1/invitations/:token/accept` — creates user (if new) or adds to tenant (if existing). `GET /api/v1/invitations` — list pending invitations. `DELETE /api/v1/invitations/:id` — revoke. Resend capability: `POST /api/v1/invitations/:id/resend`. | `supabase/functions/invitations/index.ts` (NEW) | impl | GAP-04 |
| CP0-F-12 | Implement seat management — `GET /api/v1/members` (paginated member list with roles, last_active). Enforce `seat_limit` from `subscriptions` table: return 402 Payment Required if invite would exceed limit. `GET /api/v1/members/count` → `{ active, pending_invites, seat_limit, remaining }`. | `supabase/functions/members/index.ts` (NEW) | impl | GAP-04 |
| CP0-F-13 | Implement ownership transfer — `POST /api/v1/settings/transfer-ownership` (new_owner_id). Requires current owner auth. Transfers org ownership atomically: update `tenants.owner_id`, update old owner role to `admin`, update new owner role to `owner`. Audit log entry for both old and new owner. | `supabase/functions/settings/index.ts` (NEW) | impl | GAP-04 |

### F3 — IP Allowlisting (GAP-05)

| ID | Task | File(s) | Type | Tracker Ref |
|----|------|---------|------|-------------|
| CP0-F-14 | Create `ip_allowlist` table — DDL from GAP-05 spec. RLS policy. `cidr` column uses Postgres `INET` or `CIDR` type for native CIDR matching. `expires_at` allows temporary entries (contractor access). | `supabase/migrations/xxx_ip_allowlist.sql` (NEW) | impl | GAP-05 |
| CP0-F-15 | Implement IP allowlist CRUD API — `POST /api/v1/settings/ip-allowlist` (cidr, description, expires_at?). `GET /api/v1/settings/ip-allowlist` (list entries). `DELETE /api/v1/settings/ip-allowlist/:id` (remove entry). Validate CIDR format. | `supabase/functions/settings/ip-allowlist.ts` (NEW) | impl | GAP-05 |
| CP0-F-16 | Implement IP allowlist enforcement middleware — Edge Function middleware runs before every API handler. Extracts client IP from `X-Forwarded-For`. If tenant has allowlist entries: `SELECT 1 FROM ip_allowlist WHERE tenant_id = $1 AND $2::inet <<= cidr::inet AND (expires_at IS NULL OR expires_at > now())`. If no match → 403 Forbidden with descriptive error. If allowlist is empty → all IPs allowed (default open). | `supabase/functions/shared/ip-allowlist-middleware.ts` (NEW) | impl | GAP-05 |
| CP0-F-17 | Implement Supabase dashboard bypass — internal Supabase IPs are always allowed regardless of tenant allowlist (admin-only access via dashboard is never blocked). Add `is_internal` flag or separate bypass list. | `supabase/functions/shared/ip-allowlist-middleware.ts` | impl | GAP-05 |
| CP0-F-18 | Implement CLI escape hatch — `drift cloud ip-allowlist reset` command (requires owner auth + email confirmation) for lockout recovery. Clears all allowlist entries. Audit log entry with action `ip_allowlist.emergency_reset`. | `packages/drift-cli/src/commands/cloud.ts` (modify) | impl | GAP-05 |

### Phase F Tests

| ID | Test | Type | Ref |
|----|------|------|-----|
| CT0-F-01 | **Audit log immutability** — INSERT succeeds → UPDATE same row → 403 (RLS blocks). DELETE same row → 403 (RLS blocks). | security test | GAP-03 |
| CT0-F-02 | **Audit log query with filters** — insert 100 events with varying actors/actions → query `?actor=admin@co.com&action=project.delete` → verify only matching events returned | integration test | GAP-03 |
| CT0-F-03 | **Audit log export JSON Lines** — insert 50 events → `GET /api/v1/audit/export` → verify response is valid NDJSON, 50 lines, each parseable as JSON | integration test | GAP-03 |
| CT0-F-04 | **Audit log tenant isolation** — tenant A's audit events invisible to tenant B (even with direct DB query) | security test | GAP-03 |
| CT0-F-05 | **Team CRUD round-trip** — create team → add 3 members → assign 2 projects → verify team members can access assigned projects | integration test | GAP-04 |
| CT0-F-06 | **Team-scoped project access** — user NOT in team → attempt access to team's project → 403 | security test | GAP-04 |
| CT0-F-07 | **Invitation flow complete** — invite user by email → verify email sent → accept invitation with token → verify user added to tenant with correct role | e2e test | GAP-04 |
| CT0-F-08 | **Invitation expiry** — create invitation → wait > 7 days (mock time) → attempt accept → 410 Gone | integration test | GAP-04 |
| CT0-F-09 | **Seat limit enforcement** — tenant with seat_limit=5, 4 active members → invite 1 → success (5/5). Invite another → 402 | integration test | GAP-04 |
| CT0-F-10 | **IP allowlist blocks non-matching IP** — add `10.0.0.0/8` to allowlist → request from `192.168.1.1` → 403 | security test | GAP-05 |
| CT0-F-11 | **IP allowlist allows matching CIDR** — add `192.168.0.0/16` → request from `192.168.1.100` → allowed | integration test | GAP-05 |
| CT0-F-12 | **IP allowlist empty = all allowed** — no entries → request from any IP → allowed | integration test | GAP-05 |
| CT0-F-13 | **IP allowlist temporary entry expires** — add entry with `expires_at = now() + 1h` → allowed now → mock time +2h → blocked | integration test | GAP-05 |
| CT0-F-14 | **Ownership transfer atomic** — transfer ownership → verify new owner is `owner`, old owner is `admin`, audit log has entries for both | integration test | GAP-04 |

### Phase F Quality Gate (QG-F)

- [ ] `cloud_audit_log` table immutable (no UPDATE/DELETE for non-superusers)
- [ ] Audit query API with cursor pagination + 5 filter types
- [ ] Audit export in JSON Lines format (SIEM-ready)
- [ ] Team CRUD with membership + project assignment
- [ ] Invitation flow end-to-end (invite → email → accept → member)
- [ ] Seat limit enforcement returns 402 when exceeded
- [ ] IP allowlist blocks non-matching IPs, allows matching CIDRs
- [ ] IP allowlist empty = default open (no lockout on fresh setup)
- [ ] Temporary IP entries expire correctly
- [ ] CLI escape hatch for IP allowlist lockout recovery
- [ ] Tenant isolation verified on all new tables
- [ ] All 14 Phase F tests pass

**Estimated effort:** 3-4 days

---

## Phase G: Integration Testing & P0 Parity Verification

> **Goal:** End-to-end verification that the storage abstraction layer works across all three databases, that cloud-swappable trait boundaries are complete, and that all enterprise P0 features are production-ready. This is the final gate before Phase 1 (Cloud Infrastructure) begins.
> **Estimated effort:** 2-3 days (1 developer)
> **Tracker refs:** All P0 items (cross-cutting verification)
> **Depends on:** Phases A-F all complete

### G1 — Cross-Subsystem Integration

| ID | Task | File(s) | Type | Tracker Ref |
|----|------|---------|------|-------------|
| CP0-G-01 | **Full pipeline integration test** — Initialize `DriftStorageEngine` + `BridgeStorageEngine` + cortex `StorageEngine`. Run `drift_scan()` → verify results persisted to drift.db via engine. Run `bridge_ground_all()` → verify evidence read from drift.db via `IDriftReader`, grounding results written to bridge.db via `IBridgeStorage`. Run cortex `create_memory()` → verify cortex.db updated. All three DBs through trait-based engines. | `drift-napi/tests/integration/full_pipeline_test.rs` (NEW) | impl | All |
| CP0-G-02 | **Cloud-swap simulation test** — Create `MockDriftStorage` (in-memory HashMap) implementing all 7 drift traits. Plug into `DriftRuntime` instead of `DriftStorageEngine`. Run `drift_analyze()` → verify it works identically to SQLite-backed engine (same output structure, same pipeline). This proves the trait boundary is sufficient for a Postgres backend. | `drift-napi/tests/integration/cloud_swap_test.rs` (NEW) | impl | P0-01 |
| CP0-G-03 | **Bridge cloud-swap simulation** — Create `MockBridgeStorage` implementing `IBridgeStorage`. Plug into `DriftRuntime`. Run `driftBridgeGroundAll()` → verify grounding works with mock storage. Create `MockDriftReader` implementing `IDriftReader`. Verify evidence collection works with mock reader. | `cortex-drift-bridge/tests/integration/cloud_swap_test.rs` (NEW) | impl | P0-07 |
| CP0-G-04 | **Trait completeness audit** — automated test that verifies every `pub fn` in `drift-storage/src/queries/*.rs` has a corresponding trait method, every `pub fn` in `cortex-drift-bridge/src/storage/tables.rs` has a corresponding `IBridgeStorage` method, and every `pub fn` in `drift-core/src/workspace/*.rs` has a corresponding `IWorkspaceStorage` method. Prevents trait drift. | `drift-core/tests/trait_completeness_test.rs` (NEW) | impl | P0-01, P0-07, P0-15 |
| CP0-G-05 | **Connection leak test** — open all 3 engines → run 1000 operations each → close all → verify all SQLite connections closed (no file locks remaining). Verify temp files cleaned up. | `drift-napi/tests/integration/connection_leak_test.rs` (NEW) | impl | P0-03, P0-09 |
| CP0-G-06 | **Performance regression gate** — benchmark key operations before and after trait extraction. Trait dispatch overhead must be <1% (function pointer indirection is ~1ns per call). Benchmark: 10,000 `get_file_metadata()` calls, 1,000 `insert_detection()` calls, 100 `pattern_confidence()` calls. | `drift-storage/benches/engine_benchmark.rs` (NEW) | impl | P0-03 |

### Phase G Tests

| ID | Test | Type | Ref |
|----|------|------|-----|
| CT0-G-01 | **Full pipeline: scan → store → ground → evidence → verdict** — end-to-end with real test fixtures, all through trait-based engines | e2e test | All |
| CT0-G-02 | **Mock storage: drift traits are sufficient for cloud** — `MockDriftStorage` produces identical analysis output to `DriftStorageEngine` | integration test | P0-01 |
| CT0-G-03 | **Mock storage: bridge traits are sufficient for cloud** — `MockBridgeStorage` + `MockDriftReader` produces identical grounding output | integration test | P0-07 |
| CT0-G-04 | **Zero raw Connection usage in production code** — `grep -r "&Connection" drift-napi/src/ cortex-drift-bridge/src/` returns only trait impl internals and test code. No NAPI binding, no consumer, no tool takes raw `&Connection`. | static analysis | All |
| CT0-G-05 | **Zero ATTACH DATABASE in production code** — `grep -r "ATTACH DATABASE" crates/` returns zero matches in non-test code | static analysis | P0-12 |
| CT0-G-06 | **Zero Mutex\<Connection\> outside engines** — `grep -r "Mutex<Connection>" crates/` returns only `ConnectionPool` internals in `drift-storage` and `cortex-drift-bridge` | static analysis | P0-10 |
| CT0-G-07 | **All 3 engines implement Send + Sync** — compile-time assertion for `DriftStorageEngine`, `BridgeStorageEngine`, cortex `StorageEngine` | unit test | All |
| CT0-G-08 | **All 3 engines work behind Arc** — `Arc<DriftStorageEngine>`, `Arc<BridgeStorageEngine>`, `Arc<StorageEngine>` all implement their respective traits | unit test | All |
| CT0-G-09 | **Connection leak: zero open handles after shutdown** — 1000 ops → shutdown → no file locks | stress test | P0-03 |
| CT0-G-10 | **Performance: trait dispatch overhead < 1%** — direct function call vs. trait method call benchmark | benchmark | P0-03 |
| CT0-G-11 | **SCIM + webhook + audit integration** — SCIM deprovisions user → webhook `user.deprovisioned` fires → audit log entry created. Full cross-feature test. | e2e test | GAP-01, GAP-02, GAP-03 |
| CT0-G-12 | **Team + IP allowlist integration** — create team → assign project → team member from allowed IP → success. Same member from blocked IP → 403. | e2e test | GAP-04, GAP-05 |
| CT0-G-13 | **Full enterprise flow** — create tenant → invite member → member accepts → create team → assign project → configure webhook → scan → webhook fires → audit log records all events | e2e test | All enterprise GAPs |
| CT0-G-14 | **Regression: existing Rust test suites pass** — `cargo test --workspace` in `crates/drift/` (all drift crates), `crates/cortex/` (all cortex crates), `crates/cortex-drift-bridge/`. Zero regressions. | regression test | All |
| CT0-G-15 | **Regression: existing TS test suites pass** — `npm test` across drift-cli, drift-mcp, drift-ci, drift-napi-contracts. Zero regressions. | regression test | All |
| CT0-G-16 | **Clippy clean across all workspaces** — `cargo clippy --all-targets -D warnings` for drift, cortex, cortex-drift-bridge workspaces | compilation test | All |
| CT0-G-17 | **TypeScript clean** — `tsc --noEmit` for all TS packages | compilation test | All |
| CT0-G-18 | **Storage trait surface area audit** — verify final trait method counts: `IDriftFiles` ≥5, `IDriftAnalysis` ≥25, `IDriftStructural` ≥37, `IDriftEnforcement` ≥21, `IDriftAdvanced` ≥9, `IDriftBatchWriter` ≥5, `IDriftReader` =14, `IWorkspaceStorage` ≥10, `IBridgeStorage` ≥23 = **total ≥149 drift + 23 bridge = ≥172 trait methods** | audit test | All |

### Phase G Quality Gate (QG-G) — Final P0 Gate

- [ ] Full pipeline works end-to-end through trait-based engines (scan → store → ground → evidence → verdict)
- [ ] Mock storage implementations prove cloud-swappability
- [ ] Zero raw `&Connection` in NAPI bindings or bridge consumers
- [ ] Zero `ATTACH DATABASE` in production code
- [ ] Zero `Mutex<Connection>` outside engine internals
- [ ] All 3 engines are `Send + Sync + Arc`-compatible
- [ ] Trait dispatch overhead < 1% (performance regression gate)
- [ ] SCIM + webhook + audit cross-feature integration works
- [ ] Team + IP allowlist cross-feature integration works
- [ ] `cargo test --workspace` passes across all 3 Rust workspaces
- [ ] `npm test` passes across all TS packages
- [ ] `cargo clippy --all-targets -D warnings` clean
- [ ] `tsc --noEmit` clean
- [ ] ≥172 total trait methods covering all storage operations
- [ ] All 18 Phase G tests pass

**Estimated effort:** 2-3 days

---

## Dependency Graph

```
Phase A (Drift Storage Traits)
  │
  ├──► Phase B (Drift Engine + NAPI Rewiring)
  │         │
  │         └──► Phase C (Bridge Storage + Consumer Rewiring) ───┐
  │                                                               │
  │   Phase D (SCIM Provisioning) ─────────────────────────────┐ │
  │     ║ can start in parallel with A/B/C                     │ │
  │     ║ if Supabase project provisioned                      │ │
  │                                                             │ │
  │   Phase E (Webhook System) ────────────────────────────────┤ │
  │     ║ can start in parallel with A/B/C                     │ │
  │     ║ if Supabase project provisioned                      │ │
  │                                                             │ │
  │   Phase F (Audit + Teams + IP Allowlist) ──────────────────┤ │
  │     ║ can start in parallel with A/B/C                     │ │
  │     ║ if Supabase project provisioned                      │ │
  │                                                             ▼ ▼
  └──────────────────────────────────────────► Phase G (Integration Testing)
```

**Key dependency rules:**
- **A → B:** Traits must exist before engine can implement them
- **A + B → C:** Bridge needs `IDriftReader` trait (A) and `Arc<dyn IDriftReader>` from engine (B)
- **D, E, F are independent** of A/B/C — they only need Supabase project provisioned
- **D ↔ E ↔ F have soft dependencies** (SCIM deprovisioning emits webhooks, all actions write audit log) but can be built in any order with stubs
- **G depends on ALL** — integration testing requires every phase complete

### Critical Path Analysis

**Sequential critical path (1 developer):**
```
A (3-4d) → B (5-7d) → C (4-6d) → G (2-3d) = 14-20 days (storage)
D (2-3d) + E (2-3d) + F (3-4d) = 7-10 days (enterprise, sequential)
Total serial: 21-30 working days
```

**Optimized path (2 developers):**
```
Developer 1: A → B → C → G (storage critical path)
Developer 2: D → E → F → joins G (enterprise features)

Developer 1: 14-20 days
Developer 2: 7-10 days (finishes before Dev 1, assists with G)
Total: 16-22 working days (bounded by storage critical path)
```

**Optimized path (3 developers):**
```
Developer 1: A → B (drift engine + NAPI rewiring)
Developer 2: waits for A2/A3 (~Day 2) → C (bridge engine + rewiring)
Developer 3: D ‖ E ‖ F (enterprise features, parallel start Day 1)
All three: → G (integration testing)

Total: 12-17 working days
```

---

## Summary Statistics

| Metric | Value |
|--------|-------|
| **Total implementation tasks** | 94 |
| **Total test tasks** | 92 |
| **Grand total tasks** | 186 |
| **P0 tracker items covered** | 17/17 Phase 0 + 5/5 Enterprise GAPs = **22/22 (100%)** |
| **Phases** | 7 (A through G) |
| **Quality gates** | 7 (QG-A through QG-G) |
| **Estimated effort (1 dev, serial)** | 21-30 working days |
| **Estimated effort (2 devs, parallel)** | 16-22 working days |
| **Estimated effort (3 devs, optimal)** | 12-17 working days |
| **Rust trait methods (new)** | ≥172 (149 drift + 23 bridge) |
| **Files created (new)** | ~25-30 |
| **Files modified** | ~60-70 |
| **Estimated lines changed** | ~2,500 |
| **Estimated new lines** | ~1,500 |
| **Cloud-only Postgres tables (new)** | 8 (audit_log, teams, team_memberships, team_projects, invitations, webhook_endpoints, webhook_deliveries, ip_allowlist) |
| **Supabase migrations (new)** | 5-6 |
| **Supabase Edge Functions (new)** | 8-10 |

---

## Key File Reference

### Rust — Storage Traits (Phase A)

| File | Contents |
|------|----------|
| `drift-core/src/traits/mod.rs` | Module declarations + barrel re-exports |
| `drift-core/src/traits/drift_files.rs` | `IDriftFiles` trait (~5 methods) |
| `drift-core/src/traits/drift_analysis.rs` | `IDriftAnalysis` trait (~25 methods) |
| `drift-core/src/traits/drift_structural.rs` | `IDriftStructural` trait (~37 methods) |
| `drift-core/src/traits/drift_enforcement.rs` | `IDriftEnforcement` trait (~21 methods) |
| `drift-core/src/traits/drift_advanced.rs` | `IDriftAdvanced` trait (~9 methods) |
| `drift-core/src/traits/drift_batch.rs` | `IDriftBatchWriter` trait (~5 methods) |
| `drift-core/src/traits/drift_reader.rs` | `IDriftReader` trait (14 methods) |
| `drift-core/src/traits/workspace.rs` | `IWorkspaceStorage` trait (~10 methods) |
| `drift-core/src/traits/test_helpers.rs` | `IDriftReaderStub` test double |

### Rust — Storage Engines (Phases B, C)

| File | Contents |
|------|----------|
| `drift-storage/src/engine.rs` | `DriftStorageEngine` — implements all 7 drift traits |
| `drift-core/src/workspace/sqlite_storage.rs` | `SqliteWorkspaceStorage` — implements `IWorkspaceStorage` |
| `cortex-drift-bridge/src/traits.rs` | `IBridgeStorage` trait (23 methods) |
| `cortex-drift-bridge/src/storage/pool.rs` | Bridge `ConnectionPool` |
| `cortex-drift-bridge/src/storage/engine.rs` | `BridgeStorageEngine` — implements `IBridgeStorage` |

### Rust — Rewiring Targets (Phases B, C)

| File | Change |
|------|--------|
| `drift-napi/src/runtime.rs` | `DatabaseManager` → `Arc<DriftStorageEngine>` |
| `drift-napi/src/bindings/analysis.rs` | 48 call sites rewired |
| `drift-napi/src/bindings/structural.rs` | 16 call sites rewired |
| `drift-napi/src/bindings/enforcement.rs` | 12 call sites rewired |
| `drift-napi/src/bindings/bridge.rs` | 10 call sites rewired |
| `drift-napi/src/bindings/graph.rs` | 6 call sites rewired |
| `drift-napi/src/bindings/scanner.rs` | 6 call sites rewired |
| `drift-napi/src/bindings/patterns.rs` | 4 call sites rewired |
| `drift-napi/src/bindings/feedback.rs` | 3 call sites rewired |
| `drift-napi/src/bindings/lifecycle.rs` | 2 call sites rewired |
| `drift-core/src/workspace/*.rs` | 12 files, ~30+ `Connection::open()` → `IWorkspaceStorage` |
| `cortex-drift-bridge/src/event_mapping/mapper.rs` | `Mutex<Connection>` → `Arc<dyn IBridgeStorage>` |
| `cortex-drift-bridge/src/specification/*.rs` | 3 files, raw `&Connection` → trait |
| `cortex-drift-bridge/src/grounding/evidence/*.rs` | ~15 files, `&Connection` → `&dyn IDriftReader` |
| `cortex-drift-bridge/src/tools/*.rs` | 2 files, `Mutex<Connection>` → trait |

### Cloud — Enterprise P0 (Phases D, E, F)

| File | Contents |
|------|----------|
| `supabase/functions/scim-users/index.ts` | SCIM 2.0 `/Users` CRUD |
| `supabase/functions/scim-groups/index.ts` | SCIM 2.0 `/Groups` CRUD |
| `supabase/functions/webhooks/index.ts` | Webhook registration + management API |
| `supabase/functions/webhook-dispatch/index.ts` | Async dispatch engine + retry |
| `supabase/functions/audit/index.ts` | Audit query + export API |
| `supabase/functions/teams/index.ts` | Team CRUD + membership + projects |
| `supabase/functions/invitations/index.ts` | Invitation flow |
| `supabase/functions/members/index.ts` | Seat management |
| `supabase/functions/settings/ip-allowlist.ts` | IP allowlist CRUD |
| `supabase/functions/shared/audit.ts` | Reusable `logAuditEvent()` helper |
| `supabase/functions/shared/ip-allowlist-middleware.ts` | IP enforcement middleware |

---

## Verification Commands

```bash
# Phase A — Trait compilation
cargo check -p drift-core
cargo clippy -p drift-core -- -D warnings
cargo test -p drift-core

# Phase B — Engine + NAPI
cargo test -p drift-storage
cargo clippy -p drift-storage -p drift-napi -p drift-core -- -D warnings
# Verify no raw Connection in NAPI bindings:
grep -rn "&Connection" crates/drift/drift-napi/src/bindings/ | grep -v "// trait impl"

# Phase C — Bridge
cargo test -p cortex-drift-bridge
cargo clippy -p cortex-drift-bridge -- -D warnings
# Verify ATTACH eliminated:
grep -rn "ATTACH DATABASE" crates/cortex-drift-bridge/src/
# Verify Mutex<Connection> eliminated from consumers:
grep -rn "Mutex<Connection>" crates/cortex-drift-bridge/src/ | grep -v "pool.rs"

# Phase D-F — Enterprise (requires Supabase project)
supabase db reset
supabase functions serve
# Run integration tests against local Supabase

# Phase G — Full regression
cargo test --workspace --manifest-path crates/drift/Cargo.toml
cargo test --workspace --manifest-path crates/cortex/Cargo.toml
cargo test -p cortex-drift-bridge
cargo clippy --all-targets -D warnings --manifest-path crates/drift/Cargo.toml
cargo clippy --all-targets -D warnings --manifest-path crates/cortex/Cargo.toml
cargo clippy --all-targets -D warnings --manifest-path crates/cortex-drift-bridge/Cargo.toml
cd drift && npx tsc --noEmit && npx vitest run
```

---

## Appendix: Architecture Before & After

### Before (Current State)

```
NAPI Binding ──► raw &Connection / Mutex<Connection> ──► SQL queries (free fns)
Bridge Consumer ──► Mutex<Connection> (bridge.db) ──► SQL queries (free fns)
Bridge Evidence ──► ATTACH DATABASE drift.db ──► Cross-DB SQL join
Workspace ──► Connection::open() (bypasses DatabaseManager) ──► SQL
```

**Problems:** No seam for cloud backends. SQLite-specific patterns (`ATTACH DATABASE`, `Connection::open()`, `VACUUM INTO`) baked into business logic. 7-8 scattered `Mutex<Connection>` instances with no central ownership.

### After (Phase 0 Complete)

```
NAPI Binding ──► Arc<DriftStorageEngine> ──► IDriftFiles / IDriftAnalysis / ...
                                              │
                                              ├── SQLite impl (local): queries/*.rs via DatabaseManager
                                              └── [Future] Postgres impl: REST/gRPC to Supabase

Bridge Consumer ──► Arc<dyn IBridgeStorage> ──► BridgeStorageEngine
                                                 │
                                                 ├── SQLite impl (local): storage/tables.rs via ConnectionPool
                                                 └── [Future] Postgres impl: REST to Supabase

Bridge Evidence ──► Arc<dyn IDriftReader> ──► DriftStorageEngine (read-only)
                                               │
                                               ├── SQLite impl (local): drift_queries.rs via read pool
                                               └── [Future] Postgres impl: REST to Supabase

Workspace ──► Box<dyn IWorkspaceStorage> ──► SqliteWorkspaceStorage
                                              │
                                              ├── SQLite impl: Backup API, VACUUM INTO, integrity_check
                                              └── Cloud impl: returns NotSupported (backup N/A for cloud)
```

**The trait boundaries are the cloud migration seam.** Everything above the trait line stays identical. Only the implementations below change. Cloud is 100% opt-in — offline users experience zero changes.
