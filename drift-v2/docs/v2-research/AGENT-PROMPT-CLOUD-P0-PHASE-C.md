# Agent Prompt: Cloud P0 Phase C — Bridge Storage Abstraction + Consumer Rewiring

## Your Mission

You are building the `IBridgeStorage` trait, `BridgeStorageEngine`, and `ConnectionPool` for the `cortex-drift-bridge` crate, then rewiring every consumer to use trait-based access instead of raw `Mutex<Connection>` and `&Connection`. You are also eliminating the SQLite-specific `ATTACH DATABASE` pattern, replacing it with `IDriftReader` trait calls from Phase B.

**This phase has three distinct rewiring targets:**
1. **Bridge storage consumers** (7 files) — currently hold `Option<Mutex<Connection>>` for bridge.db writes/reads. Switch to `Arc<dyn IBridgeStorage>`.
2. **Evidence collectors** (~15 files) — currently take raw `&Connection` for drift.db queries. Switch to `&dyn IDriftReader` (from Phase A/B).
3. **DriftRuntime bridge wiring** (2 files) — `bridge_db`, `drift_db_for_bridge` replaced with trait-based fields.

When this phase is done:
- **Zero `Mutex<Connection>` in bridge consumer structs** — only inside `ConnectionPool` internals
- **Zero `ATTACH DATABASE` in production code** — cross-DB queries go through `IDriftReader`
- **Zero raw `&Connection` in evidence collectors** — all go through `&dyn IDriftReader`
- The bridge becomes cloud-compatible: swap the `BridgeStorageEngine` impl with a Supabase-backed impl, and everything above it works unchanged.

**Speed does not matter. Correctness does. Every existing test (700+) must pass after rewiring.**

---

## Documents You MUST Read Before Writing Any Code

Read these in order. Do not skip any.

1. **`docs/v2-research/CLOUD-P0-IMPLEMENTATION-PLAN.md`** — Phase C section (lines ~235-309). Your work order: 16 implementation tasks (CP0-C-01 through CP0-C-16) + 14 test tasks (CT0-C-01 through CT0-C-14) + Quality Gate (QG-C).

2. **`crates/cortex-drift-bridge/src/lib.rs`** — `BridgeRuntime` struct with 3 `Mutex<Connection>` fields (`drift_db`, `cortex_db`, `bridge_db`). This is the standalone bridge runtime — used in tests and standalone mode, NOT from `DriftRuntime`.

3. **`crates/drift/drift-napi/src/runtime.rs`** — `DriftRuntime` struct with bridge fields: `bridge_db: Option<Mutex<Connection>>`, `drift_db_for_bridge: Option<Mutex<Connection>>`, `bridge_config`, `causal_engine`, `bridge_initialized`, `bridge_deduplicator`. Helper methods: `lock_bridge_db()`, `lock_drift_db_for_bridge()`.

4. **`crates/drift/drift-napi/src/bindings/bridge.rs`** — 21 `#[napi]` bridge functions. Uses `rt.lock_bridge_db()` and `rt.lock_drift_db_for_bridge()` to get `MutexGuard<Connection>` for each call.

5. **`crates/cortex-drift-bridge/src/grounding/evidence/collector.rs`** — 12 evidence collector functions, each takes `&Connection` (drift.db). The central `collect_one()` dispatches by `EvidenceType`.

6. **`crates/cortex-drift-bridge/src/query/cross_db.rs`** — The `ATTACH DATABASE` pattern via `with_drift_attached()`. Uses `query/attach.rs` RAII guard. **This entire pattern must be eliminated.**

7. **`crates/cortex-drift-bridge/src/napi/functions.rs`** — 20 NAPI-ready functions. Several take `Option<&rusqlite::Connection>` for drift_db and bridge_db. These signatures change to take trait references.

After reading all seven, you should be able to answer:
- How many `Mutex<Connection>` instances exist across both runtimes? (Answer: 3 in `BridgeRuntime` + 2 in `DriftRuntime` + 1 in `BridgeEventHandler` + 1 each in `BridgeWeightProvider` and `BridgeDecompositionPriorProvider` = **8 total**)
- Which files take raw `&Connection` for drift.db evidence queries? (Answer: `collector.rs` (12 functions), `composite.rs` (2 functions), `loop_runner.rs` (passes through))
- What does the `ATTACH DATABASE` pattern do? (Answer: `cross_db.rs:with_drift_attached()` attaches drift.db to a bridge.db connection so cross-DB SQL queries work. Postgres has no equivalent.)
- Where is `IDriftReader` defined? (Answer: `drift-core/src/traits/storage/drift_reader.rs`, from Phase A)
- Why can't the bridge just import `DriftStorageEngine` directly? (Answer: circular dependency — `drift-napi` depends on `cortex-drift-bridge`, and `DriftStorageEngine` is in `drift-storage` which drift-napi also depends on. The bridge receives `Arc<dyn IDriftReader>` via dependency injection, never importing the concrete type.)

If you cannot answer all 5, re-read the documents.

---

## Phase Execution Order

Execute sub-phases in this exact order. Do not skip ahead.

### Sub-Phase C1: IBridgeStorage Trait + ConnectionPool + BridgeStorageEngine (CP0-C-01 through CP0-C-07)

**Goal:** Define `IBridgeStorage` trait, build `ConnectionPool`, build `BridgeStorageEngine` that implements the trait.

**Files you will create:**
- `cortex-drift-bridge/src/traits.rs` (NEW) — trait + row types + `Arc<T>` blanket impl
- `cortex-drift-bridge/src/storage/pool.rs` (NEW) — `ConnectionPool`
- `cortex-drift-bridge/src/storage/engine.rs` (NEW) — `BridgeStorageEngine`

**Files you will modify:**
- `cortex-drift-bridge/src/lib.rs` — Add `pub mod traits;` export
- `cortex-drift-bridge/src/storage/mod.rs` — Add `pub mod pool;` and `pub mod engine;` exports

#### IBridgeStorage Trait Design (CP0-C-01, CP0-C-02, CP0-C-03)

```rust
// cortex-drift-bridge/src/traits.rs
use std::sync::Arc;
use crate::errors::BridgeResult;

// ── Row types (aligned with storage/tables.rs + query/*.rs) ──
pub struct BridgeMemoryRow {
    pub id: String,
    pub memory_type: String,
    pub content: String,
    pub summary: String,
    pub confidence: f64,
    pub importance: String,
    pub tags: String,       // JSON array
    pub linked_patterns: String, // JSON array
    pub created_at: String,
}

pub struct GroundingResultRow { /* ... fields from tables.rs store_grounding_result */ }
pub struct GroundingSnapshotRow { /* ... fields from tables.rs store_grounding_snapshot */ }
pub struct BridgeEventRow { /* ... fields from tables.rs log_event */ }
pub struct BridgeMetricRow { /* ... fields from tables.rs record_metric */ }
pub struct BridgeStorageStats { pub memory_count: u64, pub event_count: u64, /* ... */ }
pub struct BridgeHealthStatus { pub connected: bool, pub wal_mode: bool }

pub trait IBridgeStorage: Send + Sync {
    // ── 7 Writes ──
    fn insert_memory(&self, memory: &cortex_core::memory::BaseMemory) -> BridgeResult<()>;
    fn insert_grounding_result(&self, result: &crate::grounding::GroundingResult, memory_id: &str) -> BridgeResult<()>;
    fn insert_snapshot(&self, snapshot: &crate::grounding::GroundingSnapshot) -> BridgeResult<()>;
    fn insert_event(&self, event_type: &str, memory_type: Option<&str>, memory_id: Option<&str>, confidence: Option<f64>) -> BridgeResult<()>;
    fn insert_metric(&self, key: &str, value: f64) -> BridgeResult<()>;
    fn upsert_weight(&self, section: &str, weight: f64) -> BridgeResult<()>;
    fn upsert_decomposition_prior(&self, module_id: &str, data_json: &str) -> BridgeResult<()>;

    // ── 7 Reads ──
    fn get_memory(&self, id: &str) -> BridgeResult<Option<BridgeMemoryRow>>;
    fn query_memories_by_type(&self, memory_type: &str, limit: usize) -> BridgeResult<Vec<BridgeMemoryRow>>;
    fn get_grounding_history(&self, memory_id: &str, limit: usize) -> BridgeResult<Vec<(f64, String, String)>>;
    fn get_snapshots(&self, limit: usize) -> BridgeResult<Vec<GroundingSnapshotRow>>;
    fn get_events(&self, limit: usize) -> BridgeResult<Vec<BridgeEventRow>>;
    fn get_metrics(&self, key: &str) -> BridgeResult<Vec<BridgeMetricRow>>;
    fn get_schema_version(&self) -> BridgeResult<u32>;

    // ── 3 Formalized ad-hoc queries ──
    fn query_all_memories_for_grounding(&self) -> BridgeResult<Vec<BridgeMemoryRow>>;
    fn search_memories_by_tag(&self, tag: &str, limit: usize) -> BridgeResult<Vec<BridgeMemoryRow>>;
    fn get_weight_adjustments(&self) -> BridgeResult<Vec<(String, f64)>>;

    // ── 4 Lifecycle ──
    fn initialize(&self) -> BridgeResult<()>;
    fn migrate(&self) -> BridgeResult<()>;
    fn health_check(&self) -> BridgeResult<BridgeHealthStatus>;
    fn shutdown(&self) -> BridgeResult<()>;

    // ── 2 Usage ──
    fn count_memories(&self) -> BridgeResult<u64>;
    fn storage_stats(&self) -> BridgeResult<BridgeStorageStats>;
}

// Arc<T> blanket impl — required for Arc<BridgeStorageEngine> sharing
impl<T: IBridgeStorage> IBridgeStorage for Arc<T> {
    fn insert_memory(&self, memory: &cortex_core::memory::BaseMemory) -> BridgeResult<()> {
        (**self).insert_memory(memory)
    }
    // ... delegate all 23 methods ...
}
```

**Critical detail:** The `BridgeMemoryRow` struct is intentionally NOT `BaseMemory`. The bridge stores a simplified view (JSON strings for content/tags/patterns). The trait methods accept `BaseMemory` for writes (serializing internally) and return `BridgeMemoryRow` for reads.

#### ConnectionPool (CP0-C-04)

```rust
// cortex-drift-bridge/src/storage/pool.rs
use std::sync::{atomic::{AtomicUsize, Ordering}, Mutex};
use rusqlite::Connection;
use crate::errors::BridgeResult;

pub struct ConnectionPool {
    writer: Mutex<Connection>,
    readers: Vec<Mutex<Connection>>,
    read_index: AtomicUsize,
}

impl ConnectionPool {
    pub fn open(path: &std::path::Path, read_pool_size: usize) -> BridgeResult<Self> { ... }
    pub fn open_in_memory() -> BridgeResult<Self> { ... }

    pub fn with_writer<F, T>(&self, f: F) -> BridgeResult<T>
    where F: FnOnce(&Connection) -> BridgeResult<T> { ... }

    pub fn with_reader<F, T>(&self, f: F) -> BridgeResult<T>
    where F: FnOnce(&Connection) -> BridgeResult<T> { ... }
}
```

**Key decisions:**
- **`read_pool_size` default: 2** — bridge workload is lighter than drift. 2 readers + 1 writer.
- **WAL mode enabled on all connections** — via `storage::configure_connection()` / `storage::configure_readonly_connection()`.
- **Round-robin reader selection** — `read_index.fetch_add(1, Ordering::Relaxed) % readers.len()`
- **In-memory mode:** Single connection for both read and write (SQLite in-memory DBs are not shared across connections). `readers` vector contains references to the same logical DB via `file::memdb1?mode=memory&cache=shared` URI or a single-connection approach. Model after drift-storage's `DatabaseManager::open_in_memory()`.

#### BridgeStorageEngine (CP0-C-05, CP0-C-06)

```rust
// cortex-drift-bridge/src/storage/engine.rs
use std::sync::Arc;
use crate::errors::BridgeResult;
use crate::traits::{IBridgeStorage, BridgeMemoryRow, /* ... */};
use super::pool::ConnectionPool;

pub struct BridgeStorageEngine {
    pool: ConnectionPool,
}

impl BridgeStorageEngine {
    pub fn open(path: &std::path::Path) -> BridgeResult<Self> { ... }
    pub fn open_in_memory() -> BridgeResult<Self> { ... }
}

impl IBridgeStorage for BridgeStorageEngine {
    fn insert_memory(&self, memory: &cortex_core::memory::BaseMemory) -> BridgeResult<()> {
        self.pool.with_writer(|conn| {
            crate::storage::tables::store_memory(conn, memory)
        })
    }

    fn get_memory(&self, id: &str) -> BridgeResult<Option<BridgeMemoryRow>> {
        self.pool.with_reader(|conn| {
            crate::query::cortex_queries::get_memory_by_id(conn, id)
                .map(|opt| opt.map(|r| BridgeMemoryRow { /* field map */ }))
        })
    }

    // ... route each method through pool.with_writer() or pool.with_reader() ...
}
```

**Implementation pattern:** Each trait method delegates to existing free functions in `storage/tables.rs` (writes) or `query/cortex_queries.rs` + `query/drift_queries.rs` (reads). The existing SQL functions remain unchanged — the engine just routes them through the pool.

#### BridgeRuntime Deprecation (CP0-C-07)

Add `#[deprecated]` to the 3 `Mutex<Connection>` fields on `BridgeRuntime` in `lib.rs`. The standalone `BridgeRuntime` should wrap `BridgeStorageEngine` for test/standalone use:

```rust
pub struct BridgeRuntime {
    #[deprecated(note = "Use BridgeStorageEngine instead")]
    drift_db: Option<Mutex<rusqlite::Connection>>,
    #[deprecated(note = "Use BridgeStorageEngine instead")]
    cortex_db: Option<Mutex<rusqlite::Connection>>,
    #[deprecated(note = "Use BridgeStorageEngine instead")]
    bridge_db: Option<Mutex<rusqlite::Connection>>,
    // ... non-deprecated fields stay ...
}
```

**Note:** Full `BridgeRuntime` replacement is optional for Phase C. The priority is rewiring `DriftRuntime` and all NAPI consumers. `BridgeRuntime` is used in standalone/test mode and can be fully replaced in a follow-up.

**Gate:** `cargo check -p cortex-drift-bridge` compiles clean. `cargo clippy -p cortex-drift-bridge -- -D warnings` clean.

---

### Sub-Phase C2: Consumer Rewiring (CP0-C-08 through CP0-C-12)

**Goal:** Replace `Option<Mutex<Connection>>` with `Arc<dyn IBridgeStorage>` (for bridge storage) and `Arc<dyn IDriftReader>` (for drift evidence queries) in all consumer structs.

#### File-by-file rewiring:

**1. `event_mapping/mapper.rs` — BridgeEventHandler (CP0-C-08)**

```rust
// BEFORE:
pub struct BridgeEventHandler {
    cortex_db: Option<Mutex<rusqlite::Connection>>,  // misnamed — it's bridge.db
    // ...
}
impl BridgeEventHandler {
    pub fn new(cortex_db: Option<Mutex<rusqlite::Connection>>, ...) -> Self { ... }
}

// AFTER:
pub struct BridgeEventHandler {
    bridge_store: Option<Arc<dyn IBridgeStorage>>,
    // ...
}
impl BridgeEventHandler {
    pub fn new(bridge_store: Option<Arc<dyn IBridgeStorage>>, ...) -> Self { ... }
}
```

All internal calls change from:
```rust
let conn = db_mutex.lock()...;
crate::storage::tables::store_memory(&conn, &memory)?;
crate::storage::tables::log_event(&conn, ...)?;
```
To:
```rust
store.insert_memory(&memory)?;
store.insert_event(...)?;
```

**2. `specification/weight_provider.rs` — BridgeWeightProvider (CP0-C-09)**

```rust
// BEFORE:
pub struct BridgeWeightProvider {
    cortex_db: Option<Mutex<rusqlite::Connection>>,
    cache: Mutex<HashMap<String, AdaptiveWeightTable>>,
}

// AFTER:
pub struct BridgeWeightProvider {
    bridge_store: Option<Arc<dyn IBridgeStorage>>,
    cache: Mutex<HashMap<String, AdaptiveWeightTable>>,
}
```

**3. `specification/decomposition_provider.rs` — BridgeDecompositionPriorProvider (CP0-C-10)**

```rust
// BEFORE:
pub struct BridgeDecompositionPriorProvider {
    cortex_db: Option<Mutex<rusqlite::Connection>>,
}

// AFTER:
pub struct BridgeDecompositionPriorProvider {
    bridge_store: Option<Arc<dyn IBridgeStorage>>,
}
```

**4. `specification/events.rs` — 3 event functions (CP0-C-11)**

```rust
// BEFORE:
pub fn on_spec_corrected(
    correction: &SpecCorrection,
    causal_engine: &CausalEngine,
    bridge_db: Option<&rusqlite::Connection>,
) -> BridgeResult<String> { ... }

// AFTER:
pub fn on_spec_corrected(
    correction: &SpecCorrection,
    causal_engine: &CausalEngine,
    bridge_store: Option<&dyn IBridgeStorage>,
) -> BridgeResult<String> { ... }
```

Same pattern for `on_contract_verified()` and `on_decomposition_adjusted()`.

Also update `grounding/contradiction.rs` — `generate_contradiction()` takes bridge_db similarly.

**5. `drift-napi/src/runtime.rs` + `drift-napi/src/bindings/bridge.rs` — DriftRuntime (CP0-C-12)**

```rust
// BEFORE (runtime.rs):
pub struct DriftRuntime {
    pub bridge_db: Option<Mutex<rusqlite::Connection>>,
    pub drift_db_for_bridge: Option<Mutex<rusqlite::Connection>>,
    // ...
}
impl DriftRuntime {
    pub fn lock_bridge_db(&self) -> Option<MutexGuard<'_, Connection>> { ... }
    pub fn lock_drift_db_for_bridge(&self) -> Option<MutexGuard<'_, Connection>> { ... }
}

// AFTER (runtime.rs):
pub struct DriftRuntime {
    pub bridge_store: Option<Arc<BridgeStorageEngine>>,
    pub drift_reader: Option<Arc<dyn IDriftReader>>,
    // ...
}
impl DriftRuntime {
    pub fn bridge_storage(&self) -> Option<&Arc<BridgeStorageEngine>> {
        self.bridge_store.as_ref()
    }
    pub fn drift_reader(&self) -> Option<&Arc<dyn IDriftReader>> {
        self.drift_reader.as_ref()
    }
}
```

**DriftRuntime initialization changes:**
- Instead of `Connection::open(bridge_db_path)` → `BridgeStorageEngine::open(&bridge_db_path)`
- Instead of `Connection::open_with_flags(drift_path, READ_ONLY)` → use `storage.as_drift_reader()` from Phase B's `DriftStorageEngine` (the `drift_reader` is provided by Phase B)
- `BridgeEventHandler::new()` now receives `Some(Arc::clone(&bridge_store))` instead of `Some(Mutex::new(conn))`
- `open_bridge_for_handler()` is eliminated — the `BridgeStorageEngine` is thread-safe, no separate connection needed

**NAPI binding rewiring pattern (bridge.rs):**

```rust
// BEFORE:
pub fn drift_bridge_ground_all() -> napi::Result<serde_json::Value> {
    let rt = get_bridge_runtime()?;
    let bridge_guard = rt.lock_bridge_db();
    let memories = if let Some(ref db) = bridge_guard {
        query_all_memories_for_grounding(db).map_err(bridge_err)?
    } else { vec![] };
    let drift_guard = rt.lock_drift_db_for_bridge();
    cortex_drift_bridge::napi::functions::bridge_ground_all(
        &memories, &rt.bridge_config.grounding,
        drift_guard.as_deref(), bridge_guard.as_deref(),
    ).map_err(bridge_err)
}

// AFTER:
pub fn drift_bridge_ground_all() -> napi::Result<serde_json::Value> {
    let rt = get_bridge_runtime()?;
    let store = rt.bridge_storage().ok_or_else(|| bridge_unavailable())?;
    let memories = store.query_all_memories_for_grounding().map_err(bridge_err)?;
    cortex_drift_bridge::napi::functions::bridge_ground_all(
        &memories, &rt.bridge_config.grounding,
        rt.drift_reader().map(|r| r.as_ref()),
        store.as_ref(),
    ).map_err(bridge_err)
}
```

**Critical constraints for C2:**
1. **Do NOT change `#[napi]` function signatures.** TypeScript contract unchanged.
2. **Do NOT change `cortex_drift_bridge::napi::functions` signatures yet** — those change in C3 when evidence collectors are rewired.
3. **The `query_all_memories_for_grounding()` in bridge.rs moves to `IBridgeStorage`** — the inline SQL query (lines 398-463 of bridge.rs) becomes a trait method implemented on `BridgeStorageEngine`.
4. **`bridge_initialized` bool stays** — it indicates whether the bridge is usable. Now it's `bridge_store.is_some()`.
5. **`causal_engine` field stays** — it's not a storage concern. The `CausalEngine` is a graph algorithm, not a database.
6. **`bridge_deduplicator` field stays** — it's in-memory event dedup, not storage.

**Gate:** `cargo check -p drift-napi -p cortex-drift-bridge` compiles clean.

---

### Sub-Phase C3: Evidence Collector + Cross-DB Rewiring (CP0-C-13 through CP0-C-16)

**Goal:** Replace raw `&Connection` in evidence collectors with `&dyn IDriftReader`. Eliminate `ATTACH DATABASE` pattern entirely.

**Files you will modify:**

**1. Evidence collector rewiring (CP0-C-13):**

- `grounding/evidence/collector.rs` — 12 collector functions + `collect_one()` dispatcher

```rust
// BEFORE:
pub fn collect_one(
    evidence_type: EvidenceType,
    ctx: &EvidenceContext,
    drift_conn: &Connection,
) -> BridgeResult<Option<GroundingEvidence>> { ... }

fn collect_pattern_confidence(ctx: &EvidenceContext, conn: &Connection) -> ... {
    drift_queries::pattern_confidence(conn, pattern_id)?
}

// AFTER:
pub fn collect_one(
    evidence_type: EvidenceType,
    ctx: &EvidenceContext,
    drift_reader: &dyn IDriftReader,
) -> BridgeResult<Option<GroundingEvidence>> { ... }

fn collect_pattern_confidence(ctx: &EvidenceContext, reader: &dyn IDriftReader) -> ... {
    reader.pattern_confidence(pattern_id)?
}
```

- `grounding/evidence/composite.rs` — `collect_all()` and `collect_selected()`

```rust
// BEFORE:
pub fn collect_all(ctx: &EvidenceContext, drift_conn: &Connection) -> Vec<GroundingEvidence>
pub fn collect_selected(types: &[EvidenceType], ctx: &EvidenceContext, drift_conn: &Connection) -> Vec<GroundingEvidence>

// AFTER:
pub fn collect_all(ctx: &EvidenceContext, drift_reader: &dyn IDriftReader) -> Vec<GroundingEvidence>
pub fn collect_selected(types: &[EvidenceType], ctx: &EvidenceContext, drift_reader: &dyn IDriftReader) -> Vec<GroundingEvidence>
```

- `grounding/loop_runner.rs` — `run()` and `ground_single()`

```rust
// BEFORE:
pub fn run(&self, memories: &[MemoryForGrounding], _drift_db: Option<&rusqlite::Connection>, bridge_db: Option<&rusqlite::Connection>, ...) -> ...
pub fn ground_single(&self, memory: &MemoryForGrounding, drift_db: Option<&rusqlite::Connection>, bridge_db: Option<&rusqlite::Connection>) -> ...

// AFTER:
pub fn run(&self, memories: &[MemoryForGrounding], drift_reader: Option<&dyn IDriftReader>, bridge_store: Option<&dyn IBridgeStorage>, ...) -> ...
pub fn ground_single(&self, memory: &MemoryForGrounding, drift_reader: Option<&dyn IDriftReader>, bridge_store: Option<&dyn IBridgeStorage>) -> ...
```

**2. Cross-DB ATTACH elimination (CP0-C-14):**

- `query/cross_db.rs` — `with_drift_attached()` is **deleted** (or emptied and deprecated). `count_matching_patterns()` and `latest_scan_timestamp()` move to `IDriftReader` calls.

```rust
// BEFORE (cross_db.rs):
pub fn count_matching_patterns(conn: &Connection, pattern_ids: &[String]) -> BridgeResult<u64> {
    // Uses "drift.pattern_confidence" (ATTACHED database prefix)
    ...
}

// AFTER: This function is no longer needed. Callers use:
//   reader.count_matching_patterns(pattern_ids)?
// The IDriftReader implementation in DriftStorageEngine queries its own DB directly.
```

- `query/attach.rs` — `AttachGuard` is **no longer used by production code**. Keep for backward compatibility but add `#[deprecated]` annotation.

**3. `napi/functions.rs` signature changes (CP0-C-13 cascading):**

The 20 bridge NAPI functions need updated signatures where they currently accept `Option<&rusqlite::Connection>`:

```rust
// BEFORE:
pub fn bridge_ground_memory(
    memory: &MemoryForGrounding,
    config: &GroundingConfig,
    drift_db: Option<&rusqlite::Connection>,
    bridge_db: Option<&rusqlite::Connection>,
) -> BridgeResult<serde_json::Value>

// AFTER:
pub fn bridge_ground_memory(
    memory: &MemoryForGrounding,
    config: &GroundingConfig,
    drift_reader: Option<&dyn IDriftReader>,
    bridge_store: Option<&dyn IBridgeStorage>,
) -> BridgeResult<serde_json::Value>
```

Functions affected: `bridge_ground_memory`, `bridge_ground_all`, `bridge_grounding_history`, `bridge_spec_correction`, `bridge_contract_verified`, `bridge_decomposition_adjusted`, `bridge_health`.

Functions NOT affected (no DB access): `bridge_status`, `bridge_translate_link`, `bridge_translate_constraint_link`, `bridge_event_mappings`, `bridge_groundability`, `bridge_license_check`, `bridge_intents`, `bridge_adaptive_weights`, `bridge_explain_spec`, `bridge_counterfactual`, `bridge_intervention`, `bridge_unified_narrative`, `bridge_prune_causal`.

**4. `tools/drift_health.rs` rewiring (CP0-C-15):**

```rust
// BEFORE:
pub fn handle_drift_health(
    cortex_db: Option<&std::sync::Mutex<rusqlite::Connection>>,
    drift_db: Option<&std::sync::Mutex<rusqlite::Connection>>,
    causal_engine: Option<&cortex_causal::CausalEngine>,
) -> BridgeResult<serde_json::Value>

// AFTER:
pub fn handle_drift_health(
    bridge_store: Option<&dyn IBridgeStorage>,
    drift_reader: Option<&dyn IDriftReader>,
    causal_engine: Option<&cortex_causal::CausalEngine>,
) -> BridgeResult<serde_json::Value>
```

Also update `health/checks.rs` — `check_cortex_db()` and `check_drift_db()` take `Option<&Mutex<Connection>>`. Change to take the trait references and call `health_check()` on each.

**5. Test file updates (CP0-C-16):**

~20+ test files in `cortex-drift-bridge/tests/` create `Connection::open_in_memory()` manually. Switch to `BridgeStorageEngine::open_in_memory()`. Evidence/grounding tests (~10 files) that pass raw `&Connection` for drift.db need an `IDriftReaderStub` — a simple struct that implements `IDriftReader` with configurable return values (from Phase A's `drift-core` traits, or create one in the bridge test utils).

**Gate:** `cargo check -p cortex-drift-bridge -p drift-napi` compiles clean. `grep -r "ATTACH DATABASE" cortex-drift-bridge/src/` returns zero matches (only in tests or deprecated code).

---

## Tests You Will Write

After all implementation is complete, write these 14 tests.

### Engine + Pool Tests (in `cortex-drift-bridge/tests/bridge_engine_test.rs`, NEW)

| ID | Test | What It Proves |
|----|------|----------------|
| CT0-C-01 | `open_in_memory()` → `insert_memory(BaseMemory)` → `get_memory(id)` → fields match | Engine round-trip works |
| CT0-C-02 | Write via `pool.with_writer()` → read via `pool.with_reader()` → data visible | Read/write separation works, WAL propagates |
| CT0-C-03 | `ConnectionPool::open()` → check `PRAGMA journal_mode` on writer and reader → both return `wal` | WAL mode active on all connections |
| CT0-C-04 | For each public function in `storage/tables.rs` and `query/cortex_queries.rs`, verify a method exists on `IBridgeStorage` (compile-time assertion via trait bound test) | Trait covers all operations |
| CT0-C-05 | `open_in_memory()` → `health_check()` → connected=true, wal_mode=true | Health check works |

### Consumer Rewiring Tests (in `cortex-drift-bridge/tests/bridge_rewiring_test.rs`, NEW)

| ID | Test | What It Proves |
|----|------|----------------|
| CT0-C-06 | Create `BridgeEventHandler` with `Arc<BridgeStorageEngine>` → fire `on_pattern_discovered()` → query `count_memories()` → count > 0 | EventHandler uses trait correctly |
| CT0-C-07 | Create `IDriftReaderStub` with `pattern_confidence("auth") = 0.9` → `collect_one(PatternConfidence, ctx, &stub)` → returns evidence with value 0.9 | Evidence collector uses IDriftReader |
| CT0-C-08 | `grep -r "ATTACH DATABASE" cortex-drift-bridge/src/` → 0 matches in non-deprecated, non-test code | ATTACH pattern eliminated |
| CT0-C-09 | Create `BridgeStorageEngine` + `IDriftReaderStub` with sample data → run grounding loop → evidence collected, verdict != InsufficientData | Full grounding loop through traits |
| CT0-C-10 | Verify `DriftRuntime` struct has `bridge_store: Option<Arc<BridgeStorageEngine>>` and `drift_reader: Option<Arc<dyn IDriftReader>>` (compile-time) | Runtime uses trait-based fields |
| CT0-C-11 | Call `bridge_status()` NAPI function → returns valid JSON with `available: true` | NAPI bindings use engine |
| CT0-C-12 | Verify `BridgeRuntime.drift_db`, `.cortex_db`, `.bridge_db` have `#[deprecated]` (compiler warning test) | Dual-runtime deprecated |

### Regression + Stress Tests

| ID | Test | What It Proves |
|----|------|----------------|
| CT0-C-13 | Run entire existing bridge test suite (700+ tests) → all pass | Zero regressions |
| CT0-C-14 | Spawn 10 threads: 5 calling `insert_memory()` + 5 calling `get_memory()` → all complete within 5s | Concurrent access safe |

### Testing Philosophy

- **CT0-C-07 is the most important test.** It proves the evidence→drift.db query path works through the trait abstraction. If this test passes, cloud compatibility is achievable (swap the IDriftReader impl).
- **CT0-C-08 is a static analysis test.** Run `grep` and assert on the output. This prevents anyone from re-introducing `ATTACH DATABASE`.
- **CT0-C-13 is non-negotiable.** If any of the 700+ existing tests fail, the rewiring has a bug. Fix it before proceeding.
- **IDriftReaderStub** for testing: Create a simple struct that implements `IDriftReader` with configurable return values. Store them in a `HashMap<String, Option<f64>>` or similar. This is test infrastructure — don't overthink it.

---

## Architecture Constraints

These are non-negotiable. Violating any will break the system.

1. **`BridgeStorageEngine` owns `ConnectionPool`.** It is the single owner for bridge.db connections. After rewiring, no code outside `storage/engine.rs` and `storage/pool.rs` should call `Connection::open()` for bridge.db.

2. **Evidence collectors receive `&dyn IDriftReader`, NOT `&Connection`.** The bridge crate never imports `drift-storage`. It receives drift data through the `IDriftReader` trait (defined in `drift-core`). This is the cloud abstraction boundary.

3. **`Arc<dyn IBridgeStorage>` is the sharing mechanism for bridge storage.** Use `Arc::clone()` for sharing across structs. The `Arc<T>` blanket impl makes this automatic.

4. **In-memory mode must work.** `BridgeStorageEngine::open_in_memory()` is critical for testing. 700+ tests depend on in-memory SQLite.

5. **Do NOT change `#[napi]` function signatures.** The TypeScript contract must not change. Only the internal routing changes.

6. **Do NOT remove `BridgeRuntime` entirely.** Deprecate its storage fields, but the struct is used in standalone mode and some tests. A full replacement is a separate task.

7. **`CausalEngine` is NOT storage.** It stays as `Option<CausalEngine>` on `DriftRuntime`. Don't try to wrap it in a trait in this phase.

8. **Preserve the bridge deduplicator.** `EventDeduplicator` is in-memory and unrelated to storage. Leave it on `DriftRuntime` as-is.

9. **Bridge never writes to drift.db.** The `IDriftReader` trait is read-only by design (D6 compliance). The bridge reads drift data for evidence collection but never modifies it.

---

## Subsystems That Are Clean (do NOT modify internals)

- **`drift-core/src/traits/storage/`** — Phase A output. These traits are your inputs, not your outputs.
- **`drift-storage/src/engine.rs`** — Phase B output. You consume `as_drift_reader()` from this, don't modify it.
- **`drift-analysis/`** — All analysis algorithms. Untouched.
- **`cortex-drift-bridge/src/causal/`** — Causal graph algorithms. They don't touch storage directly.
- **`cortex-drift-bridge/src/config/`** — Configuration. Untouched.
- **`cortex-drift-bridge/src/license/`** — License gating. Untouched (except `usage_tracking.rs` if it takes `&Connection` — check and rewire if needed).
- **`cortex-drift-bridge/src/link_translation/`** — Pure functions. Untouched.
- **`cortex-drift-bridge/src/intents/`** — Pure data. Untouched.

---

## How to Verify Your Work

After each sub-phase, run:

```bash
# Sub-Phase C1 — Engine + pool + trait compile
cargo check -p cortex-drift-bridge
cargo clippy -p cortex-drift-bridge -- -D warnings

# Sub-Phase C2 — Consumer rewiring compiles
cargo check -p cortex-drift-bridge -p drift-napi
cargo clippy -p cortex-drift-bridge -p drift-napi -- -D warnings

# Sub-Phase C3 — Evidence + ATTACH eliminated + everything compiles
cargo check -p cortex-drift-bridge -p drift-napi
cargo clippy -p cortex-drift-bridge -p drift-napi -- -D warnings

# Full test suite (after writing tests)
cargo test -p cortex-drift-bridge
cargo test -p drift-napi

# Full workspace regression
cargo test --workspace --manifest-path crates/drift/Cargo.toml
cargo clippy --all-targets -D warnings --manifest-path crates/drift/Cargo.toml
```

---

## Verification Grep Commands

After all rewiring, these greps confirm completeness:

```bash
# Zero Mutex<Connection> in bridge consumer structs (only in pool.rs internals):
grep -rn "Mutex<.*Connection>" crates/cortex-drift-bridge/src/ | grep -v pool.rs | grep -v lib.rs
# Expected: 0 matches (lib.rs still has deprecated fields)

# Zero ATTACH DATABASE in production code:
grep -rn "ATTACH DATABASE" crates/cortex-drift-bridge/src/ | grep -v "deprecated" | grep -v "test"
# Expected: 0 matches

# Zero raw &Connection in evidence collectors:
grep -rn "&Connection" crates/cortex-drift-bridge/src/grounding/evidence/
# Expected: 0 matches

# Zero raw &Connection in napi/functions.rs:
grep -rn "rusqlite::Connection" crates/cortex-drift-bridge/src/napi/functions.rs
# Expected: 0 matches

# Zero lock_bridge_db / lock_drift_db_for_bridge in drift-napi:
grep -rn "lock_bridge_db\|lock_drift_db_for_bridge" crates/drift/drift-napi/src/
# Expected: 0 matches

# Engine implements IBridgeStorage:
grep -rn "impl IBridgeStorage" crates/cortex-drift-bridge/src/storage/engine.rs
# Expected: 1 match
```

---

## Critical Questions You Must Be Able to Answer After Each Sub-Phase

### After C1:
- Does `BridgeStorageEngine::open_in_memory()` → `insert_memory()` → `get_memory()` round-trip work?
- How many methods does `IBridgeStorage` have? (Answer: 23 — 7 writes + 7 reads + 3 ad-hoc + 4 lifecycle + 2 usage)
- Is WAL mode active on all pool connections?
- Does `ConnectionPool::with_reader()` round-robin across readers?

### After C2:
- Is `BridgeEventHandler.cortex_db` replaced with `bridge_store: Option<Arc<dyn IBridgeStorage>>`?
- Is `DriftRuntime.bridge_db` replaced with `bridge_store: Option<Arc<BridgeStorageEngine>>`?
- Is `DriftRuntime.drift_db_for_bridge` replaced with `drift_reader: Option<Arc<dyn IDriftReader>>`?
- Are `lock_bridge_db()` and `lock_drift_db_for_bridge()` removed from `DriftRuntime`?

### After C3:
- Does `collect_one()` take `&dyn IDriftReader` instead of `&Connection`?
- Does `with_drift_attached()` still exist? (Answer: deprecated or removed, never called from production code)
- Does `grep -r "ATTACH DATABASE" src/` return 0 matches?
- Do all 700+ existing bridge tests pass?

---

## Quality Gate (QG-C) — All Must Pass Before Phase C is Complete

- [ ] `BridgeStorageEngine` implements `IBridgeStorage` (23 methods)
- [ ] All 8 `Mutex<Connection>` instances replaced with trait-based access (verified by grep)
- [ ] `ATTACH DATABASE` pattern fully eliminated from production code (verified by grep)
- [ ] `DriftRuntime.bridge_db` and `drift_db_for_bridge` replaced with `bridge_store` and `drift_reader`
- [ ] `BridgeRuntime` storage fields deprecated (`#[deprecated]`)
- [ ] Evidence collectors use `&dyn IDriftReader` — zero `&Connection` in `grounding/evidence/`
- [ ] NAPI bridge functions (`napi/functions.rs`) take trait references instead of `&Connection`
- [ ] `cargo test -p cortex-drift-bridge` — all 700+ tests pass (zero regressions)
- [ ] `cargo test -p drift-napi` — compiles clean
- [ ] `cargo clippy -p cortex-drift-bridge -p drift-napi -- -D warnings` — zero warnings
- [ ] All 14 Phase C tests pass
- [ ] Tools (`drift_health.rs`, `drift_grounding_check.rs`) use trait references
