# Agent Prompt: Cloud P0 Phase B — Drift Storage Engine + NAPI Rewiring

## Your Mission

You are building the `DriftStorageEngine` — a unified storage engine that implements all 7 drift storage traits defined in Phase A — and then rewiring every NAPI binding and workspace file to use trait methods instead of raw `&Connection` calls. This is the single largest phase of the Cloud P0 plan: **~103 NAPI call sites across 10 binding files + 15 `Connection::open()` calls across 5 workspace files**.

Phase A (already complete) defined the traits in `drift-core/src/traits/storage/`. **You are not designing traits. You are implementing them on a concrete engine and rewiring all consumers.**

When this phase is done, no code outside `drift-storage/src/engine.rs` will touch a raw `&Connection`. The trait boundary becomes the cloud migration seam — swap the engine implementation, and everything above it works unchanged.

**Speed does not matter. Correctness does. The rewiring must not change any observable behavior. Every test must verify that the rewired path produces identical results to the original.**

---

## Documents You MUST Read Before Writing Any Code

Read these in order. Do not skip any.

1. **`docs/v2-research/CLOUD-P0-IMPLEMENTATION-PLAN.md`** — Phase B section (lines ~162-233). Your work order: 13 implementation tasks (CP0-B-01 through CP0-B-13) + 16 test tasks (CT0-B-01 through CT0-B-16) + Quality Gate (QG-B).

2. **`crates/drift/drift-core/src/traits/storage/`** — The 8 trait files + barrel module created in Phase A. These are your target interfaces. Study every method signature and row type.

3. **`crates/drift/drift-napi/src/runtime.rs`** — The singleton runtime. Currently holds `pub db: DatabaseManager` and `pub batch_writer: BatchWriter`. You will replace these with `storage: Arc<DriftStorageEngine>`.

4. **`crates/drift/drift-storage/src/connection/mod.rs`** — `DatabaseManager` with `with_reader()` / `with_writer()`. Your engine wraps this. Understand the read/write routing.

5. **`crates/drift/drift-napi/src/bindings/analysis.rs`** — The largest binding file (~50 call sites). Study the `rt.db.with_reader(|conn| queries::xxx(conn, ...))` pattern you'll be replacing.

6. **`crates/drift/drift-storage/src/queries/`** — 17 query modules (files, functions, parse_cache, detections, patterns, scan_history, boundaries, call_edges, graph, structural, enforcement, advanced, constants, env_variables, data_access, util, mod). These are the free functions your engine delegates to.

After reading all six, you should be able to answer:
- How many `rt.db.with_reader/with_writer` + `rt.batch_writer` call sites exist across all binding files? (Answer: ~48 in `with_reader`/`with_writer` + ~55 `batch_writer.send`/`flush`/`flush_sync`/`checkpoint` = ~103 total across 8 active files)
- What is the read/write routing pattern in `DatabaseManager`? (Answer: `Mutex<Connection>` for writes, `ReadPool` for reads)
- Why can't `drift-core` depend on `drift-storage`? (Answer: circular dependency — `drift-storage` depends on `drift-core`)
- Where are the row types defined? (Answer: in `drift-core/src/traits/storage/*.rs`, duplicated from `drift-storage/src/queries/*.rs`)
- How does the Cortex engine solve the same problem? (Answer: `cortex-storage/src/engine.rs` implements `IMemoryStorage` + `ICausalStorage` traits from `cortex-core`)
- Which query module is the largest and maps to which trait? (Answer: `structural.rs` at 38.7 KB maps to `IDriftStructural` with 71 methods)

If you cannot answer all 6, re-read the documents.

---

## Phase Execution Order

Execute sub-phases in this exact order. Do not skip ahead.

### Sub-Phase B1: DriftStorageEngine Implementation (CP0-B-01 through CP0-B-07)

**Goal:** Create `drift-storage/src/engine.rs` that wraps `DatabaseManager` + `BatchWriter` and implements all 7 traits.

**File you will create:**
- `drift-storage/src/engine.rs` (NEW)

**File you will modify:**
- `drift-storage/src/lib.rs` — Add `pub mod engine;` and `pub use engine::DriftStorageEngine;`

**Architecture:**

```rust
use std::sync::Arc;
use drift_core::errors::StorageError;
use drift_core::traits::storage::*;
use crate::connection::DatabaseManager;
use crate::batch::{BatchWriter, commands::BatchCommand};

pub struct DriftStorageEngine {
    db: DatabaseManager,
    batch: BatchWriter,
}

impl DriftStorageEngine {
    pub fn open(path: &std::path::Path) -> Result<Self, StorageError> {
        let db = DatabaseManager::open(path)?;
        let batch_conn = db.open_batch_connection()?;
        let batch = BatchWriter::new(batch_conn);
        Ok(Self { db, batch })
    }

    pub fn open_in_memory() -> Result<Self, StorageError> {
        let db = DatabaseManager::open_in_memory()?;
        let batch_conn = db.open_batch_connection()?;
        let batch = BatchWriter::new(batch_conn);
        Ok(Self { db, batch })
    }

    /// Concrete batch send — NAPI bindings call this with typed BatchCommand.
    pub fn send_batch(&self, command: BatchCommand) -> Result<(), StorageError> { ... }

    /// WAL checkpoint delegation — lifecycle.rs needs this.
    pub fn checkpoint(&self) -> Result<(), StorageError> {
        self.db.checkpoint()
    }

    /// Database path (None for in-memory).
    pub fn path(&self) -> Option<&std::path::Path> {
        self.db.path()
    }

    /// Expose for bridge consumption (Phase C / B4 cleanup)
    pub fn as_drift_reader(self: &Arc<Self>) -> Arc<dyn IDriftReader> {
        Arc::clone(self) as Arc<dyn IDriftReader>
    }
}
```

**Implementation pattern for each trait method:**

```rust
// READ methods → route through self.db.with_reader()
impl IDriftFiles for DriftStorageEngine {
    fn load_all_file_metadata(&self) -> Result<Vec<FileMetadataRow>, StorageError> {
        self.db.with_reader(|conn| {
            // Call existing free function, convert row types
            let rows = crate::queries::files::load_all_file_metadata(conn)?;
            Ok(rows.into_iter().map(|r| FileMetadataRow {
                path: r.path,
                language: r.language,
                // ... field mapping ...
            }).collect())
        })
    }

    // WRITE methods → route through self.db.with_writer()
    fn update_function_count(&self, path: &str, count: i64) -> Result<(), StorageError> {
        self.db.with_writer(|conn| {
            crate::queries::files::update_function_count(conn, path, count)
        })
    }
}
```

**Critical detail — Row type conversion:**
The trait files in `drift-core` define their own row types (e.g., `drift_core::traits::storage::drift_files::FileMetadataRow`). The query functions in `drift-storage` return their own row types (e.g., `drift_storage::queries::files::FileMetadataRow`). These are structurally identical but are different Rust types. You have two options:

1. **Convert between them** (safe, explicit) — map field-by-field in each trait method
2. **Replace drift-storage's row types with drift-core's** (cleaner, less code) — change `drift-storage/src/queries/*.rs` to import and return the `drift-core` types directly

**Option 2 is preferred** because it eliminates duplication and is what Cortex does (cortex-storage uses `BaseMemory` from cortex-core directly). However, if this causes too many cascading changes, use Option 1 with `From` impls.

**Trait implementation order (verified method counts from actual Phase A code):**
1. `IDriftFiles` (9 methods) — file_metadata CRUD + parse_cache CRUD. Maps to `queries/files.rs` + `queries/parse_cache.rs`.
2. `IDriftAnalysis` (39 methods) — functions, detections, patterns, boundaries, call_edges, scan_history. Maps to `queries/functions.rs`, `queries/detections.rs`, `queries/patterns.rs`, `queries/boundaries.rs`, `queries/call_edges.rs`, `queries/scan_history.rs`.
3. `IDriftStructural` (71 methods) — coupling, constraints, contracts, secrets, wrappers, DNA, crypto, OWASP, decomposition, constants, env_variables, data_access, reachability, taint, errors, impact, test_coverage, test_quality. Maps to `queries/structural.rs`, `queries/constants.rs`, `queries/env_variables.rs`, `queries/data_access.rs`, `queries/graph.rs`.
4. `IDriftEnforcement` (21 methods) — violations, gates, audit, health, feedback, policy, degradation. Maps to `queries/enforcement.rs`.
5. `IDriftAdvanced` (9 methods) — simulations, decisions, context_cache, migrations. Maps to `queries/advanced.rs`.
6. `IDriftBatchWriter` (5 methods: `send_raw`, `flush`, `flush_sync`, `stats`, `shutdown`) — delegates to `self.batch`. **IMPORTANT:** The trait uses type-erased `send_raw(&str, &[u8])` to avoid drift-storage dependency in drift-core. Your engine MUST also provide a concrete `send_batch(command: BatchCommand)` method (NOT on the trait) for NAPI bindings to call directly. See "Batch Writer Bridging" below.
7. `IDriftReader` (14 methods) — read-only subset for bridge evidence. Maps to `queries/drift_queries.rs` pattern (already corrected in Bridge Correlation Hardening Phase A).

**Total: 168 trait methods + 1 concrete helper (`send_batch`) = 169 methods to implement.**

**Batch Writer Bridging — `send_batch()` vs `send_raw()`:**

The `IDriftBatchWriter` trait in drift-core uses `send_raw(&str, &[u8])` because drift-core cannot depend on drift-storage's `BatchCommand` enum. But NAPI bindings currently call `rt.batch_writer.send(BatchCommand::InsertDetections(rows))` with concrete typed commands. You need BOTH:

```rust
impl DriftStorageEngine {
    /// Concrete method for NAPI bindings — accepts typed BatchCommand directly.
    /// This is NOT on the trait — it's an inherent method on DriftStorageEngine only.
    pub fn send_batch(&self, command: BatchCommand) -> Result<(), StorageError> {
        self.batch.send(command).map_err(|e| StorageError::SqliteError {
            message: e.to_string(),
        })
    }
}

impl IDriftBatchWriter for DriftStorageEngine {
    /// Trait method for cloud implementations — type-erased.
    fn send_raw(&self, command_name: &str, payload: &[u8]) -> Result<(), StorageError> {
        // Deserialize payload back to BatchCommand using command_name as discriminant
        let command = BatchCommand::deserialize(command_name, payload)?;
        self.send_batch(command)
    }
    fn flush(&self) -> Result<(), StorageError> { self.batch.flush().map_err(/*...*/) }
    fn flush_sync(&self) -> Result<WriteStats, StorageError> { /* delegate + convert */ }
    fn stats(&self) -> WriteStats { /* delegate + convert */ }
    fn shutdown(self: Box<Self>) -> Result<WriteStats, StorageError> { self.flush_sync() }
}
```

NAPI bindings call `rt.storage().send_batch(BatchCommand::InsertDetections(rows))` — the concrete method.
Cloud implementations call `send_raw("InsertDetections", &serialized_bytes)` — the trait method.
Both paths converge at the same `BatchWriter::send()` call.

**Gate:** `cargo check -p drift-storage` compiles clean. `cargo clippy -p drift-storage -- -D warnings` clean.

---

### Sub-Phase B2: NAPI Runtime Rewiring (CP0-B-08 through CP0-B-10)

**Goal:** Replace `DriftRuntime.db` + `DriftRuntime.batch_writer` with `Arc<DriftStorageEngine>`. Rewire all ~103 NAPI call sites.

**Files you will modify (verified call site counts via `grep -c 'rt\.db\.|rt\.batch_writer\.' <file>`):**
- `drift-napi/src/runtime.rs` — The runtime struct (owns `db` + `batch_writer` → owns `storage: Arc<DriftStorageEngine>`)
- `drift-napi/src/bindings/analysis.rs` — **~50 call sites** (2 `with_reader` + 1 `with_writer` + ~30 `batch_writer.send` + 4 `flush`/`flush_sync` + ~13 scattered)
- `drift-napi/src/bindings/structural.rs` — **18 call sites** (all `rt.db.with_reader`)
- `drift-napi/src/bindings/enforcement.rs` — **13 call sites** (all `rt.db.with_reader`)
- `drift-napi/src/bindings/graph.rs` — **7 call sites** (all `rt.db.with_reader`)
- `drift-napi/src/bindings/scanner.rs` — **5 call sites** (2 `with_reader` + 1 `with_writer` + 2 `batch_writer`)
- `drift-napi/src/bindings/patterns.rs` — **4 call sites** (all `rt.db.with_reader`)
- `drift-napi/src/bindings/feedback.rs` — **3 call sites** (all `rt.db.with_writer`)
- `drift-napi/src/bindings/lifecycle.rs` — **3 call sites** (1 `checkpoint` + 2 `with_writer`)

**Files you do NOT modify in B2 (verified: zero `rt.db`/`rt.batch_writer` calls):**
- `drift-napi/src/bindings/bridge.rs` — Uses `rt.lock_bridge_db()`, `rt.lock_drift_db_for_bridge()`, `rt.causal_engine`, `rt.bridge_config` only. **Phase C scope.**
- `drift-napi/src/bindings/advanced.rs` — No storage calls (uses different pattern or is stubs).

**Runtime struct transformation:**

```rust
// BEFORE:
pub struct DriftRuntime {
    pub db: DatabaseManager,
    pub batch_writer: BatchWriter,
    pub config: DriftConfig,
    pub dispatcher: EventDispatcher,
    pub project_root: Option<PathBuf>,
    pub bridge_db: Option<Mutex<rusqlite::Connection>>,
    // ...
}

// AFTER:
pub struct DriftRuntime {
    storage: Arc<DriftStorageEngine>,
    pub config: DriftConfig,
    pub dispatcher: EventDispatcher,
    pub project_root: Option<PathBuf>,
    pub bridge_db: Option<Mutex<rusqlite::Connection>>,
    // ...
}

impl DriftRuntime {
    /// Access the storage engine.
    pub fn storage(&self) -> &Arc<DriftStorageEngine> {
        &self.storage
    }
}
```

**Rewiring pattern for NAPI bindings:**

```rust
// BEFORE (analysis.rs line 101-103):
let files = rt.db.with_reader(|conn| {
    drift_storage::queries::files::load_all_file_metadata(conn)
}).map_err(storage_err)?;

// AFTER:
let files = rt.storage().load_all_file_metadata()
    .map_err(storage_err)?;
```

```rust
// BEFORE (batch writer):
rt.batch_writer.send(BatchCommand::InsertDetections(rows));

// AFTER:
rt.storage().send_batch(BatchCommand::InsertDetections(rows));
```

**Critical constraints:**
1. **Do NOT change the NAPI function signatures.** The TypeScript interface must not change. Only the internal routing changes.
2. **Preserve pipeline order in `drift_analyze()`.** Steps 1-8 must execute in the same sequence.
3. **Bridge fields stay for now.** `bridge_db`, `drift_db_for_bridge`, `causal_engine` — these are Phase C's concern. Leave them as-is.
4. **The `dispatcher` field stays.** `EventDispatcher` is unrelated to storage.
5. **Work file-by-file.** Rewire `analysis.rs` first (largest), verify it compiles, then move to the next file.

**Gate:** `cargo check -p drift-napi` compiles clean. No changes to any `#[napi]` function signatures.

---

### Sub-Phase B3: Workspace Rewiring (CP0-B-10 partial, CP0-B-11)

**Goal:** Create `SqliteWorkspaceStorage` implementing `IWorkspaceStorage`, refactor workspace files that use `Connection::open()`.

**File you will create:**
- `drift-core/src/workspace/sqlite_storage.rs` (NEW)

**Files with `Connection::open()` calls (verified via `grep -c 'Connection::open' <file>`):**
- `drift-core/src/workspace/backup.rs` — **6 calls** (Backup API, open source + destination)
- `drift-core/src/workspace/export.rs` — **3 calls** (VACUUM INTO pattern)
- `drift-core/src/workspace/init.rs` — **3 calls** (create/open workspace DB)
- `drift-core/src/workspace/migration.rs` — **2 calls** (open for migration)
- `drift-core/src/workspace/integrity.rs` — **1 call** (`open_with_flags` read-only)

**Files that take `&Connection` parameters (no `Connection::open()` but still need trait rewiring):**
- `drift-core/src/workspace/context.rs` — Takes `&Connection`, needs `&dyn IWorkspaceStorage`
- `drift-core/src/workspace/project.rs` — Takes `&Connection`
- `drift-core/src/workspace/status.rs` — Takes `&Connection`
- `drift-core/src/workspace/gc.rs` — Takes `&Connection`
- `drift-core/src/workspace/destructive.rs` — Takes `&Connection`
- `drift-core/src/workspace/monorepo.rs` — Takes `&Connection`

**Files you do NOT need to rewire (no Connection usage):**
- `drift-core/src/workspace/mod.rs` — Module declarations only (add `pub mod sqlite_storage;`)
- `drift-core/src/workspace/errors.rs` — Error types only
- `drift-core/src/workspace/ci.rs` — CI helper, no DB access
- `drift-core/src/workspace/detect.rs` — Workspace detection, filesystem only
- `drift-core/src/workspace/lock.rs` — File locking, no DB access

**Total: 16 files in workspace dir. 5 files with `Connection::open()` (15 calls). 6 files with `&Connection` params. 5 files clean.**

**Key difference from NAPI rewiring:** Workspace files use `Connection::open()` directly (not `DatabaseManager`). They also use SQLite-specific APIs like `Backup`, `VACUUM INTO`, and `PRAGMA integrity_check`. The `SqliteWorkspaceStorage` impl encapsulates these raw SQLite APIs internally. A future cloud impl would return `StorageError::NotSupported` for backup/vacuum operations.

**Gate:** `cargo test -p drift-core` — all existing workspace tests pass. No `Connection::open()` calls in `drift-core/src/workspace/` outside `sqlite_storage.rs`.

---

### Sub-Phase B4: Cleanup (CP0-B-12, CP0-B-13)

**Goal:** Expose `IDriftReader` for bridge, remove dead_code suppression.

**Files you will modify:**
- `drift-storage/src/engine.rs` — Add `as_drift_reader()` method
- `drift-napi/src/runtime.rs` — Wire `drift_db_for_bridge` to use `storage.as_drift_reader()` instead of a separate `Mutex<Connection>`
- `drift-storage/src/lib.rs` — Verify `#![allow(dead_code, unused)]` is gone (already removed per PH4-04 comment, but verify no warnings)

**Gate:** `cargo clippy -p drift-storage -p drift-napi -p drift-core -- -D warnings` — zero warnings.

---

## Tests You Will Write

After all implementation is complete, write these 16 tests.

### Engine Integration Tests (in `drift-storage/tests/engine_integration_test.rs`, NEW)

| ID | Test | What It Proves |
|----|------|----------------|
| CT0-B-01 | `open_in_memory()` → `IDriftFiles::load_all_file_metadata()` returns empty → insert file via writer → read back → fields identical | Engine round-trip works |
| CT0-B-02 | Insert via `IDriftAnalysis` (writer) → read via `IDriftAnalysis` (reader) → data visible | Read/write routing correct |
| CT0-B-03 | `send_batch(InsertDetections(rows))` → `flush_sync()` → `get_detections_by_file()` returns rows | BatchWriter integration |
| CT0-B-04 | Create engine with old timestamps → close → reopen → verify retention cleaned old data | Retention-on-init works |
| CT0-B-05 | Insert 200 violations → paginate with keyset cursor (limit=50) → 4 pages, no duplicates | Pagination exposed through engine |
| CT0-B-06 | Insert `pattern_confidence` row → `engine.pattern_confidence("auth_check")` → returns `Some(0.85)` | IDriftReader returns real data |
| CT0-B-07 | Empty engine → all 14 IDriftReader methods → `None` or `0`, no errors | IDriftReader empty-state safe |

### NAPI Regression Tests (in `drift-napi/tests/engine_rewiring_test.rs`, NEW)

| ID | Test | What It Proves |
|----|------|----------------|
| CT0-B-08 | Run `drift_analyze()` on test fixtures → output structure matches expected | Rewiring didn't break pipeline |
| CT0-B-09 | Call each structural binding → returns non-empty data | Structural bindings wired |
| CT0-B-10 | Call enforcement bindings → returns non-empty data | Enforcement bindings wired |

### Workspace Tests (in `drift-core/tests/workspace_engine_test.rs`, NEW)

| ID | Test | What It Proves |
|----|------|----------------|
| CT0-B-11 | `SqliteWorkspaceStorage::open(temp_dir)` → `initialize()` → `status()` → initialized | Workspace trait impl works |
| CT0-B-12 | Initialize → insert data → `backup(dest)` → `integrity_check()` on backup → clean | Backup through trait |
| CT0-B-13 | All 7 existing workspace test files pass | Zero regressions |

### Stress + Compilation Tests

| ID | Test | What It Proves |
|----|------|----------------|
| CT0-B-14 | Spawn 20 threads calling different storage methods → all complete within 5s | Concurrency safe |
| CT0-B-15 | `cargo clippy -p drift-storage -- -D warnings` produces zero warnings | dead_code suppression gone |
| CT0-B-16 | `fn assert_all(_: &(impl IDriftFiles + IDriftAnalysis + IDriftStructural + IDriftEnforcement + IDriftAdvanced + IDriftBatchWriter + IDriftReader)) {}` compiles with `DriftStorageEngine` | Engine implements all 7 traits |

### Testing Philosophy

- **CT0-B-01 through B-07** test the engine in isolation — no NAPI involved
- **CT0-B-08 through B-10** test the NAPI layer after rewiring — these are REGRESSION tests, not feature tests. The expected output must be identical to pre-rewire behavior.
- **CT0-B-14** catches deadlocks from incorrect `Mutex` usage. Use `Arc<Barrier>` for synchronized start, `std::thread::spawn` with timeout.
- **CT0-B-16** is a compile-time assertion — if it compiles, it passes.

---

## Testing Standards

Every test you write must meet ALL of these criteria.

### What Makes a Good Test
- **Targets a specific failure mode** — not "does it work?" but "does it fail correctly when the engine is empty?"
- **Has a clear assertion** — not `assert!(result.is_ok())` but `assert_eq!(rows.len(), 200)` or `assert_eq!(page_count, 4)`
- **Tests the trait boundary** — call via `&dyn IDriftFiles`, not `&DriftStorageEngine`, to verify dynamic dispatch works
- **Includes negative cases** — empty DB, missing data, concurrent access

### What Makes a Bad Test (do NOT write these)
- Tests that only verify `is_ok()` without checking the actual returned value
- Tests that mock so much they test the mock, not the engine
- Tests that are flaky due to timing (use deterministic assertions, not `sleep`)
- Tests that duplicate existing drift-storage tests — your tests verify the ENGINE LAYER, not the SQL

### Specific Test Patterns Required
- **Round-trip fidelity:** Write via engine → read via engine → every field matches. This catches field-mapping bugs in row type conversion.
- **Read/write routing:** Verify reads go through `with_reader()` not `with_writer()`. If `DatabaseManager` exposes pool stats, assert reader pool was used.
- **Retention-on-init:** Insert data with old timestamps → close engine → reopen → verify old data was cleaned by retention. This catches initialization ordering bugs.
- **Concurrency safety:** Use `std::thread::spawn` with `Arc<Barrier>` for synchronized start. 20 threads, 5-second timeout. Any deadlock or panic = fail.
- **Compile-time trait assertion:** `fn assert_impls(_: &(impl IDriftFiles + IDriftAnalysis + ...)) {}` — if the engine doesn't implement a trait, this won't compile. Zero runtime cost.
- **Golden-file regression:** For CT0-B-08, capture `drift_analyze()` output structure before rewiring (or use a structural assertion). After rewiring, the output must be identical.

---

## Architecture Constraints

These are non-negotiable. Violating any will break the system.

1. **`DriftStorageEngine` owns `DatabaseManager` and `BatchWriter`.** It is the single owner. No one else creates these. After rewiring, `DatabaseManager::with_reader()` and `with_writer()` should only be called from inside `engine.rs`.

2. **Reads go through `with_reader()`, writes through `with_writer()`.** This is the existing WAL-mode concurrency model. Do not bypass it.

3. **`Arc<DriftStorageEngine>` is the sharing mechanism.** The `Arc<T>` blanket impls on all traits (from Phase A) mean `Arc<DriftStorageEngine>` automatically implements all traits. Use `Arc::clone()` for sharing, never `&DriftStorageEngine` across thread boundaries.

4. **In-memory mode must work.** `DriftStorageEngine::open_in_memory()` must work for testing. In-memory SQLite has isolation limitations (reads can't see writes through separate connections). The existing `DatabaseManager::open_in_memory()` handles this — don't break it.

5. **Do NOT change `#[napi]` function signatures.** The TypeScript contract must not change. Only the internal routing changes.

6. **Do NOT touch bridge fields yet.** `bridge_db`, `drift_db_for_bridge`, `bridge_config`, `causal_engine`, `bridge_initialized`, `bridge_deduplicator` — these are Phase C's scope. Leave them exactly as-is in `DriftRuntime`.

7. **Row type strategy must be consistent.** If you choose to replace drift-storage's row types with drift-core's (Option 2), do it for ALL query modules. Don't mix approaches.

8. **Preserve the `BatchWriter` channel pattern.** `BatchWriter` uses `crossbeam-channel` for async batch writes. The engine's `send_batch()` method should delegate to `self.batch.send()`. Don't replace the channel with synchronous writes.

---

## Forbidden Actions

These will break the system or create debt that blocks future phases:

1. **Do NOT change any `#[napi]` function signature.** Not the name, not the parameters, not the return type. The TypeScript contract is frozen.
2. **Do NOT bypass `with_reader()`/`with_writer()`.** Every storage call must go through these. Direct `conn.execute()` in bindings = bug.
3. **Do NOT touch bridge fields.** `bridge_db`, `drift_db_for_bridge`, `bridge_config`, `causal_engine`, `bridge_initialized`, `bridge_deduplicator` — Phase C scope. Any change here blocks Phase C.
4. **Do NOT mix row type conversion strategies.** Pick Option 1 (From impls) or Option 2 (shared types) for ALL query modules. Do not use Option 1 for files.rs and Option 2 for functions.rs.
5. **Do NOT delete any existing tests.** You may update assertions if the API surface changes (e.g., different import paths), but never weaken or remove a test.
6. **Do NOT add `#[allow(dead_code)]` to engine.rs.** If a method triggers dead_code, the engine is incomplete — implement the missing trait method.
7. **Do NOT replace the BatchWriter channel with synchronous writes.** The `crossbeam-channel` pattern exists for performance. Preserve it.
8. **Do NOT create a second `DatabaseManager`.** The engine owns the only one. If you need a connection for bridge, that's Phase C.

---

## Effort Estimate

| Sub-Phase | Tasks | Estimated Effort | Key Risk |
|-----------|-------|-----------------|----------|
| B1: Engine Implementation | CP0-B-01 to B-07 | 3-4 days | Row type conversion strategy (Option 1 vs 2) cascades |
| B2: NAPI Rewiring | CP0-B-08 to B-10 | 2-3 days | analysis.rs is ~83 KB with ~50 call sites — careful mechanical work |
| B3: Workspace Rewiring | CP0-B-10 partial, B-11 | 1-2 days | SQLite-specific APIs (Backup, VACUUM INTO) need careful abstraction |
| B4: Cleanup + Tests | CP0-B-12, B-13 + CT0-B-01 to B-16 | 1-2 days | Concurrency test (CT0-B-14) may expose hidden deadlocks |
| **Total** | **13 impl + 16 test** | **7-11 days** | |

**With 2 engineers (B1 || B3):** 5-8 days.

**Dependencies:**
- Phase A (complete) → Phase B (this phase)
- Phase B → Phase C (bridge rewiring to `DriftStorageEngine`)
- Phase B → Phase D (cloud storage backend implementation)

---

## Subsystems That Are Clean (do NOT modify internals)

- **`drift-analysis/`** — All analysis algorithms (parsers, detectors, pattern intelligence, enforcement gates). You call into these from NAPI bindings but do not change their internals.
- **`drift-storage/src/queries/*.rs`** — The SQL query functions are correct. You route through them, not rewrite them. (Exception: you may change their row type imports if using Option 2.)
- **`drift-storage/src/migrations/`** — Schema migrations are complete and correct.
- **`drift-storage/src/connection/`** — `DatabaseManager`, `ReadPool`, pragmas. You wrap these, not rewrite them.
- **`drift-storage/src/batch/`** — BatchWriter + commands. You delegate to these.
- **`drift-storage/src/pagination/`** — Keyset pagination. Expose through engine but don't change.
- **Bridge crate (`cortex-drift-bridge/`)** — Phase C. Don't touch.

---

## How to Verify Your Work

After each sub-phase, run:

```bash
# Sub-Phase B1 — Engine compiles
cargo check -p drift-storage
cargo clippy -p drift-storage -- -D warnings

# Sub-Phase B2 — NAPI compiles
cargo check -p drift-napi
cargo clippy -p drift-napi -- -D warnings

# Sub-Phase B3 — Workspace compiles + existing tests pass
cargo test -p drift-core
cargo clippy -p drift-core -- -D warnings

# Sub-Phase B4 — Everything clean
cargo clippy -p drift-storage -p drift-napi -p drift-core -- -D warnings

# All tests (after writing tests)
cargo test -p drift-storage
cargo test -p drift-core
cargo test -p drift-napi

# Full workspace regression
cargo test --workspace --manifest-path crates/drift/Cargo.toml
cargo clippy --all-targets -D warnings --manifest-path crates/drift/Cargo.toml
```

If any test fails, fix it before moving to the next sub-phase. Do not accumulate broken tests.

---

## Verification Grep Commands

After all rewiring, these greps confirm completeness:

```bash
# Zero raw with_reader/with_writer outside engine.rs:
grep -rn "\.with_reader\|\.with_writer" crates/drift/drift-napi/src/
# Expected: 0 matches (all with_reader/with_writer calls now inside engine.rs only)

# Zero batch_writer usage outside engine.rs:
grep -rn "batch_writer" crates/drift/drift-napi/src/
# Expected: 0 matches in bindings/ (only engine.rs owns the BatchWriter)

# Zero Connection::open() in workspace (outside sqlite_storage.rs):
grep -rn "Connection::open" crates/drift/drift-core/src/workspace/ | grep -v sqlite_storage
# Expected: 0 matches (all 15 calls now encapsulated in sqlite_storage.rs)

# Zero DatabaseManager in NAPI bindings:
grep -rn "DatabaseManager" crates/drift/drift-napi/src/bindings/
# Expected: 0 matches

# Zero raw DatabaseManager usage in runtime (should only reference DriftStorageEngine):
grep -rn "DatabaseManager" crates/drift/drift-napi/src/runtime.rs
# Expected: 0 matches (DatabaseManager is owned by DriftStorageEngine, not runtime)

# Engine implements all traits (this is CT0-B-16):
grep -rn "impl IDrift" crates/drift/drift-storage/src/engine.rs
# Expected: 7 matches (IDriftFiles, IDriftAnalysis, IDriftStructural, IDriftEnforcement, IDriftAdvanced, IDriftBatchWriter, IDriftReader)

# Workspace storage implements trait:
grep -rn "impl IWorkspaceStorage" crates/drift/drift-core/src/workspace/sqlite_storage.rs
# Expected: 1 match

# bridge.rs and advanced.rs UNTOUCHED:
git diff --name-only | grep -E "bridge\.rs|advanced\.rs"
# Expected: 0 matches (these files should not appear in the diff)
```

---

## Critical Questions You Must Be Able to Answer After Each Sub-Phase

### After B1:
- Does `DriftStorageEngine::open_in_memory()` → `load_all_file_metadata()` compile and return `Ok(vec![])`?
- How many `impl` blocks does `engine.rs` have? (Answer: 7 trait impls + 1 inherent impl)
- Are reads routed through `with_reader()` and writes through `with_writer()`?

### After B2:
- Does `drift_analyze()` still work? (Compile check is sufficient — behavior test is CT0-B-08)
- Is `DriftRuntime.db` gone? Is `DriftRuntime.batch_writer` gone?
- Does `rt.storage()` return `&Arc<DriftStorageEngine>`?

### After B3:
- Are there zero `Connection::open()` calls in `drift-core/src/workspace/` outside `sqlite_storage.rs`?
- Do all 7 existing workspace test files pass?

### After B4:
- Does `as_drift_reader()` return `Arc<dyn IDriftReader>`?
- Does `cargo clippy --all-targets -D warnings` pass for all 3 crates?
- Are there zero `#![allow(dead_code)]` in `drift-storage/src/lib.rs`?

---

## Quality Gate (QG-B) — All Must Pass Before Phase B is Complete

- [ ] `DriftStorageEngine` implements all 7 traits (6 sub-traits + IDriftReader) — verified by CT0-B-16 compile-time assertion
- [ ] `DriftStorageEngine` has concrete `send_batch(BatchCommand)` method for NAPI callers
- [ ] `SqliteWorkspaceStorage` implements `IWorkspaceStorage`
- [ ] `DriftRuntime` holds `Arc<DriftStorageEngine>` — no raw `DatabaseManager` or `BatchWriter` exposure
- [ ] All ~103 NAPI call sites rewired (verified by: `grep -rn "\.with_reader\|\.with_writer" crates/drift/drift-napi/src/` returns 0 matches)
- [ ] All 15 workspace `Connection::open()` calls encapsulated (verified by: `grep -rn "Connection::open" crates/drift/drift-core/src/workspace/ | grep -v sqlite_storage` returns 0 matches)
- [ ] `cargo test -p drift-storage` — all tests pass (182+ existing + 7 new engine tests)
- [ ] `cargo test -p drift-core` — all tests pass (existing workspace tests + 3 new)
- [ ] `cargo test -p drift-napi` — compiles clean
- [ ] `cargo clippy -p drift-storage -p drift-napi -p drift-core -- -D warnings` clean
- [ ] All 16 Phase B tests pass
- [ ] Existing drift-storage test suite (182+ tests) — zero regressions
- [ ] Existing workspace test suite — zero regressions
- [ ] `bridge.rs` and `advanced.rs` are UNTOUCHED (Phase C scope)

---

## Appendix: Phase A Trait File Reference (Verified)

These are the actual trait files created in Phase A. Method counts are verified from source.

| Trait | File | Methods | Key Subsystems |
|-------|------|---------|----------------|
| `IDriftFiles` | `drift-core/src/traits/storage/drift_files.rs` | 9 | file_metadata CRUD, parse_cache CRUD |
| `IDriftAnalysis` | `drift-core/src/traits/storage/drift_analysis.rs` | 39 | functions (5), detections (10), patterns (8), boundaries (6), call_edges (6), scan_history (4) |
| `IDriftStructural` | `drift-core/src/traits/storage/drift_structural.rs` | 71 | coupling (6), constraints (5), contracts (6), secrets (3), wrappers (3), dna (6), crypto (3), owasp (3), decomposition (2), constants (7), env_variables (7), data_access (6), reachability (3), taint (3), errors (2), impact (2), test_coverage (2), test_quality (2) |
| `IDriftEnforcement` | `drift-core/src/traits/storage/drift_enforcement.rs` | 21 | violations (3), gates (2), audit (2), health (2), feedback (7), policy (2), degradation (3) |
| `IDriftAdvanced` | `drift-core/src/traits/storage/drift_advanced.rs` | 9 | simulations (2), decisions (1), context_cache (1), migrations (5) |
| `IDriftBatchWriter` | `drift-core/src/traits/storage/drift_batch.rs` | 5 | send_raw, flush, flush_sync, stats, shutdown |
| `IDriftReader` | `drift-core/src/traits/storage/drift_reader.rs` | 14 | pattern_confidence, occurrence_rate, false_positive_rate, constraint_verified, coupling_metric, dna_health, test_coverage, error_handling_gaps, decision_evidence, boundary_data, taint_flow_risk, call_graph_coverage, count_matching_patterns, latest_scan_timestamp |
| `IWorkspaceStorage` | `drift-core/src/traits/storage/workspace.rs` | 10 | initialize, status, project_info, workspace_context, gc, backup, export, import, integrity_check, schema_version |
| **TOTAL** | **10 files** | **178** | |

**Supporting files:**
- `drift-core/src/traits/storage/workspace_types.rs` — `WorkspaceStatus`, `ProjectInfo`, `WorkspaceContext`, `GcStats`, `BackupResult`, `IntegrityResult`
- `drift-core/src/traits/storage/test_helpers.rs` — `IDriftReaderStub` in-memory test double

---

## Appendix: Query Module → Trait Mapping

| Query Module | File Size | Maps To Trait | Notes |
|---|---|---|---|
| `files.rs` | 4.7 KB | `IDriftFiles` | file_metadata CRUD |
| `parse_cache.rs` | 2.6 KB | `IDriftFiles` | parse cache CRUD |
| `functions.rs` | 4.7 KB | `IDriftAnalysis` | function CRUD + counts |
| `detections.rs` | 10.6 KB | `IDriftAnalysis` | detection CRUD + queries |
| `patterns.rs` | 8.8 KB | `IDriftAnalysis` | confidence, outliers, conventions |
| `boundaries.rs` | 5.5 KB | `IDriftAnalysis` | boundary CRUD |
| `call_edges.rs` | 4.3 KB | `IDriftAnalysis` | call edge CRUD |
| `scan_history.rs` | 3.6 KB | `IDriftAnalysis` | scan lifecycle |
| `structural.rs` | 38.7 KB | `IDriftStructural` | coupling, constraints, contracts, secrets, wrappers, DNA, crypto, OWASP, decomposition |
| `constants.rs` | 4.6 KB | `IDriftStructural` | constants CRUD |
| `env_variables.rs` | 5.1 KB | `IDriftStructural` | env variable CRUD |
| `data_access.rs` | 4.0 KB | `IDriftStructural` | data access CRUD |
| `graph.rs` | 13.1 KB | `IDriftStructural` | reachability, taint, errors, impact, test_coverage, test_quality |
| `enforcement.rs` | 23.8 KB | `IDriftEnforcement` | violations, gates, audit, health, feedback, policy, degradation |
| `advanced.rs` | 6.8 KB | `IDriftAdvanced` | simulations, decisions, context_cache, migrations |
| `util.rs` | 0.5 KB | (internal) | Helper utilities |
| `mod.rs` | 0.3 KB | (barrel) | Re-exports |

---

## Appendix: DriftRuntime Fields — What Changes vs. What Stays

| Field | Current Type | After Phase B | Notes |
|---|---|---|---|
| `db` | `DatabaseManager` | **REMOVED** — owned by `DriftStorageEngine` | |
| `batch_writer` | `BatchWriter` | **REMOVED** — owned by `DriftStorageEngine` | |
| `storage` | *(new)* | `Arc<DriftStorageEngine>` | Replaces `db` + `batch_writer` |
| `config` | `DriftConfig` | **UNCHANGED** | |
| `dispatcher` | `EventDispatcher` | **UNCHANGED** | |
| `project_root` | `Option<PathBuf>` | **UNCHANGED** | |
| `bridge_db` | `Option<Mutex<Connection>>` | **UNCHANGED** — Phase C | |
| `bridge_config` | `BridgeConfig` | **UNCHANGED** — Phase C | |
| `causal_engine` | `Option<CausalEngine>` | **UNCHANGED** — Phase C | |
| `bridge_initialized` | `bool` | **UNCHANGED** — Phase C | |
| `drift_db_for_bridge` | `Option<Mutex<Connection>>` | **Wire to `storage.as_drift_reader()`** — B4 cleanup | Replace raw Connection with trait |
| `bridge_deduplicator` | `Mutex<EventDeduplicator>` | **UNCHANGED** — Phase C | |
