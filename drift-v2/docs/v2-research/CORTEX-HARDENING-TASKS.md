# Cortex Memory System Hardening Tasks

> Deep audit of all 23 Cortex sub-crates, 1 bridge crate, 1 TypeScript package, and the NAPI runtime.
>
> **Audit date:** 2026-02-09
> **Files audited:** ~400+ source files across `crates/cortex/*`, `crates/cortex-drift-bridge/`, `packages/cortex/`
> **Source findings:** `CORTEX-DEEP-AUDIT-FINDINGS.md` — 45 findings across 14 sections (A–N)
> **Auditor:** Cascade deep-dive (3 passes)

---

## Executive Summary

The Cortex memory system is architecturally ambitious — 23 Rust sub-crates implementing temporal event sourcing, HDBSCAN consolidation, CRDT-based multi-agent convergence, 5-factor decay, hybrid FTS5+vector retrieval, and a 3-tier embedding cache. The individual algorithms are well-implemented and mathematically correct.

However, **the system has a systemic wiring failure: engines compute results but never persist them.** Learning generates UUIDs but never creates BaseMemory objects. Consolidation runs a 6-phase pipeline but discards its output. The causal graph lives in-memory and is never hydrated from storage. The L2 "SQLite" embedding cache is actually a HashMap. Decay is never scheduled. The observability engine exists in the runtime but the health NAPI binding ignores it. Multi-agent creates fresh connections per call, making in-memory mode stateless.

**Bottom line:** The algorithms work. The storage works. The wiring between them is missing. This spec fixes that wiring, then hardens the edges where silent failures hide.

**Severity:** P0=4, P1=14, P2=22, P3=5 → **45 findings total**

---

## Findings by Severity

### P0 — CRITICAL: Production-Breaking (4 findings)

#### P0-1. Learning Engine Never Persists Memories (Audit D2)
**File:** `cortex-learning/src/engine.rs:72-101`
```rust
DedupAction::Add => {
    // ...calibrate confidence...
    Some(uuid::Uuid::new_v4().to_string())  // UUID generated, no BaseMemory created
}
```
The `learn()` method generates a UUID and returns it in `LearningResult.memory_created`, but **never constructs a `BaseMemory` object and never calls any storage method**. The caller (NAPI `cortex_learning_analyze_correction`) receives the UUID and returns it to TypeScript, which believes a memory was created. It was not.

**Impact:** Every correction, every piece of user feedback, every learned principle is silently discarded. The entire learning pipeline is a no-op.

**Root cause chain:** `LearningEngine` has no reference to `IMemoryStorage`. It holds `existing_memories: Vec<BaseMemory>` which is never populated from NAPI (line 29), so dedup always sees an empty list → every correction is treated as new → UUID generated → dropped.

#### P0-2. Consolidation Pipeline Never Persists Results (Audit I3)
**File:** `cortex-consolidation/src/pipeline/mod.rs:55-142`
```rust
// Phase 4: Abstraction → builds new BaseMemory
let new_memory = phase4_abstraction::build_semantic_memory(&abstraction)?;
// Phase 5: Integration → decides Create or Update
let action = phase5_integration::determine_action(new_memory, ...);
match action {
    IntegrationAction::Create(mem) => { created.push(mem.id.clone()); }
    IntegrationAction::Update { existing_id, .. } => { created.push(existing_id); }
}
// Phase 6: Pruning → plans archival
let pruning = phase6_pruning::plan_pruning(&cluster_refs, &new_id);
archived.extend(pruning.archived_ids);
// ← Pipeline ends here. No storage.insert(), no storage.update(), no storage.archive()
```
The 6-phase pipeline (Selection → Clustering → Recall Gate → Abstraction → Integration → Pruning) runs correctly, builds new `BaseMemory` objects, plans archival of source episodes — then **returns IDs without persisting anything**. The `ConsolidationEngine` (engine.rs:102-106) calls `pipeline::run_pipeline()` and records metrics, but the created memories and archival decisions are never written to storage.

**Impact:** Consolidation appears to succeed (metrics are recorded, dashboard shows runs), but zero semantic memories are created and zero episodic memories are archived.

#### P0-3. Multi-Agent Creates Fresh Connections Per Call (Audit B4)
**File:** `cortex-napi/src/bindings/multiagent.rs:19-54`
```rust
fn get_engine() -> napi::Result<cortex_multiagent::MultiAgentEngine> {
    let rt = runtime::get()?;
    let (writer, readers) = open_multiagent_connections(&rt)?;  // NEW connections every call
    Ok(cortex_multiagent::MultiAgentEngine::new(
        std::sync::Arc::new(writer),
        std::sync::Arc::new(readers),
        config,
    ))
}
```
Every multi-agent NAPI call (`register_agent`, `share_memory`, `get_trust`, etc.) creates a brand-new `WriteConnection` + `ReadPool`. For file-backed databases, this means connection churn. For **in-memory databases**, each call gets an isolated empty database — `register_agent` writes to DB₁, `get_agent` reads from DB₂ → always returns `None`.

**Impact:** Multi-agent is completely broken in in-memory mode. In file-backed mode, it works but with severe connection churn (12 NAPI functions × connections per call).

#### P0-4. Cloud Conflict Resolution Is a No-Op (Audit A1)
**File:** `cortex-cloud/src/sync/mod.rs` — `ConflictResolver` is constructed but its `resolve()` method returns `ConflictOutcome::AcceptRemote` for all conflicts without examining content. The `sync()` method in `engine.rs:136-138` passes `&mut self.conflicts` to `SyncManager.sync()`, but the resolver's merge logic is never invoked — it always accepts remote.

**Impact:** In multi-device scenarios, local changes are silently overwritten by remote changes. No actual merge or conflict detection occurs.

---

### P1 — HIGH: Silent Data Loss / Incorrect Behavior (14 findings)

| ID | Finding | File | Line(s) | Impact |
|----|---------|------|---------|--------|
| P1-1 | `_was_useful` feedback parameter discarded | `cortex-napi/src/bindings/generation.rs` | 55-71 | User feedback never reaches learning engine |
| P1-2 | Multi-agent sync counts always zero | `cortex-napi/src/bindings/multiagent.rs` | 392-396 | `applied_count: 0, buffered_count: 0` hardcoded after real sync |
| P1-3 | Decay engine never scheduled | `cortex-napi/src/runtime.rs` | 89 | `DecayEngine::new()` created, never called. Confidence never decays. |
| P1-4 | Causal graph never hydrated from storage | `cortex-causal/src/engine.rs` | 86 | `CausalEngine::new()` starts empty. Edges persisted but never loaded. |
| P1-5 | Cloud engine initialized with empty API key | `cortex-napi/src/runtime.rs` | 120 | `AuthMethod::ApiKey(String::new())` → all auth fails |
| P1-6 | Quota usage never updated → sync permanently throttled | `cortex-cloud/src/quota` | — | `secs_since_last_sync` never updated after first sync |
| P1-7 | Duplicate StorageEngine for prediction | `cortex-napi/src/runtime.rs` | 102-106 | Second `StorageEngine::open()` → separate connection pool, in-memory = isolated DB |
| P1-8 | Temporal engine opens raw connections bypassing pool | `cortex-napi/src/runtime.rs` | 129-147 | Third set of connections, not shared with main storage |
| P1-9 | `EmbeddingEngine` trait impl bypasses provider chain | `cortex-embeddings/src/engine.rs` | 140-155 | `IEmbeddingProvider` impl creates fresh TF-IDF fallback, ignoring configured providers |
| P1-10 | Consolidation metrics are hardcoded | `cortex-consolidation/src/pipeline/mod.rs` | 411-417 | `precision=0.8, lift=1.5, stability=0.9` → auto-tuning tunes on fake data |
| P1-11 | `drift_cortex_reembed` tool is fake | `packages/cortex/src/tools/system/drift_cortex_reembed.ts` | 15-30 | Searches for each summary, doesn't trigger re-embedding |
| P1-12 | `drift_cortex_validate` tool doesn't validate | `packages/cortex/src/tools/system/drift_cortex_validate.ts` | 10-35 | Lists candidates, never runs 4-dimension validation engine |
| P1-13 | L2 "SQLite" embedding cache is actually a HashMap | `cortex-embeddings/src/cache/l2_sqlite.rs` | 12-17 | 3-tier cache is effectively 1-tier. Embeddings lost on restart. |
| P1-14 | `rebuild_from_storage` is a no-op stub | `cortex-causal/src/graph/sync.rs` | 11-31 | `_graph` parameter never written to. `ICausalStorage` lacks `list_all_nodes()`. |

---

### P2 — MEDIUM: Degraded Functionality (22 findings)

| ID | Finding | File | Impact |
|----|---------|------|--------|
| P2-1 | Health snapshot has 7/12 fields hardcoded to zero | `cortex-napi/src/bindings/health.rs:32-45` | `archived_memories`, `db_size_bytes`, `embedding_cache_hit_rate`, `stale_count`, `contradiction_count`, `consolidation_count`, `memories_needing_validation` all zero |
| P2-2 | Duplicate `EmbeddingEngine` for consolidation | `cortex-napi/src/runtime.rs:98-99` | Second engine, separate from main, separate degradation chain |
| P2-3 | `cortex_shutdown` is a no-op | `cortex-napi/src/bindings/lifecycle.rs` | No flush, no cleanup, no WAL checkpoint |
| P2-4 | Migration v013 skipped | `cortex-storage/src/migrations/mod.rs:31-46` | Version gap v012→v014 |
| P2-5 | Temporal events use `Utc::now()` not DB time | `cortex-storage/src/temporal_events.rs` | Clock skew between app and DB |
| P2-6 | All reads go through writer mutex | `cortex-storage/src/engine.rs:66-237` | Read pool exists but unused, serializes all ops |
| P2-7 | Bridge serialization errors silently swallowed | `cortex-drift-bridge/src/napi/functions.rs` | `unwrap_or(json!({"error": "..."}))` |
| P2-8 | Token count uses `len()/4` not TokenCounter | `cortex-consolidation/src/pipeline/mod.rs:429-432` | Inaccurate token estimation |
| P2-9 | Only Episodic memories eligible for consolidation | `cortex-consolidation/src/pipeline/phase1_selection.rs:55` | Insights, Semantic, Procedural excluded |
| P2-10 | GC relies on non-decaying confidence | `packages/cortex/src/tools/system/drift_cortex_gc.ts:20` | Since decay never runs (P1-3), GC threshold never triggers |
| P2-11 | Link/unlink tools have read-modify-write race | `packages/cortex/src/tools/memory/drift_memory_link.ts` | Concurrent link ops can overwrite each other |
| P2-12 | Privacy `in_comment` always false | `cortex-privacy/src/engine.rs:135` | No AST-level comment detection |
| P2-13 | Privacy `apply_replacements` assumes descending sort | `cortex-privacy/src/engine.rs:122-136` | No assertion or sort; ascending input corrupts offsets |
| P2-14 | Vector search is brute-force O(n) full table scan | `cortex-storage/src/queries/vector_search.rs:21-48` | Loads ALL embeddings into memory. sqlite-vec never loaded. |
| P2-15 | `update_memory` doesn't regenerate embeddings | `cortex-storage/src/queries/memory_crud.rs:131-279` | Stale similarity scores after content changes |
| P2-16 | `bulk_insert` is not batched | `cortex-storage/src/queries/memory_crud.rs:296-303` | Loop of individual inserts, no transaction |
| P2-17 | ObservabilityEngine bypassed by health NAPI | `cortex-napi/src/bindings/health.rs:32-45` | Engine exists in runtime but health builds ad-hoc snapshot |
| P2-18 | All 5 metrics collectors in-memory only | `cortex-observability/src/metrics/mod.rs` | No persistence, lost on restart |
| P2-19 | Hardcoded 1-week drift window | `cortex-temporal/src/engine.rs:139` | `Duration::hours(168)` not configurable |
| P2-20 | Prediction cache key `__no_file__` collision | `cortex-prediction/src/engine.rs:42` | Multiple no-file predictions share one cache entry |
| P2-21 | Prediction confidence `unwrap_or(0.0)` | `cortex-prediction/src/engine.rs:118` | No-prediction case silently returns 0.0 confidence |
| P2-22 | `retract_memory` opens raw `rusqlite::Connection` | `cortex-napi/src/bindings/multiagent.rs:262-267` | Bypasses pool, in-memory = isolated DB |

---

### P3 — LOW: Code Quality (5 findings)

| ID | Finding | File | Impact |
|----|---------|------|--------|
| P3-1 | Read pool round-robin `AtomicUsize` wraps silently | `cortex-storage/src/pool/read_pool.rs:45` | Cosmetic; modulo handles it |
| P3-2 | NAPI bridge uses `unknown` return types | `packages/cortex/src/bridge/index.ts` | No runtime validation |
| P3-3 | `#[allow(dead_code)]` on test helpers | `cortex-retrieval/tests/property/` | Acceptable for test code |
| P3-4 | Tool count comment says 43, array has 40 | `packages/cortex/src/tools/index.ts:523-524` | Stale comment |
| P3-5 | `load_node_edges` creates "unknown" node types | `cortex-causal/src/graph/sync.rs:112-113` | Degrades causal narrative quality |

---

## Phase Plan

### Phase A: Persistence Gap — Learning & Consolidation (CRITICAL PATH)

Fix the two P0 bugs where engines compute results but never persist them. This is the single highest-impact change — it makes the learning and consolidation pipelines actually functional.

| ID | Task | File(s) | Type | Audit Ref |
|----|------|---------|------|-----------|
| A-01 | Add `storage: Arc<dyn IMemoryStorage>` to `LearningEngine`, pass from runtime | `cortex-learning/src/engine.rs:18-23`, `cortex-napi/src/runtime.rs:95` | impl | P0-1 |
| A-02 | In `LearningEngine::learn()`, construct `BaseMemory` from extracted principle, category mapping, and calibrated confidence, then call `storage.insert()` | `cortex-learning/src/engine.rs:72-101` | impl | P0-1 |
| A-03 | Populate `existing_memories` from storage on engine init (or query on each `learn()` call for dedup) | `cortex-learning/src/engine.rs:29` | impl | P0-1 |
| A-04 | Add `storage: Arc<dyn IMemoryStorage>` to `ConsolidationEngine`, pass from runtime | `cortex-consolidation/src/engine.rs:20-33`, `cortex-napi/src/runtime.rs:99` | impl | P0-2 |
| A-05 | After `pipeline::run_pipeline()`, persist created memories via `storage.insert()` and archive source episodes via `storage.update()` | `cortex-consolidation/src/engine.rs:102-132` | impl | P0-2 |
| A-06 | Replace hardcoded consolidation metrics with real measurements from pipeline phases | `cortex-consolidation/src/pipeline/mod.rs:411-417` | impl | P1-10 |
| A-07 | Replace `summary.len() / 4` token estimation with `TokenCounter::count()` | `cortex-consolidation/src/pipeline/mod.rs:429-432` | impl | P2-8 |
| A-08 | Wire `_was_useful` parameter to learning engine feedback | `cortex-napi/src/bindings/generation.rs:55-71` | impl | P1-1 |
| A-09 | **Test: learning creates a real memory in storage** — insert correction → verify `storage.get(id)` returns a BaseMemory with correct type, summary, confidence, content_hash | new test in `cortex-learning/tests/` | test | P0-1 |
| A-10 | **Test: learning dedup works against storage** — insert correction → insert same correction → verify second returns `DedupAction::Noop` or `Update`, not a new UUID | new test | test | P0-1 |
| A-11 | **Test: learning handles storage failure gracefully** — mock `IMemoryStorage` that returns `Err` on insert → verify `learn()` propagates error, doesn't panic | new test | test | P0-1 |
| A-12 | **Test: consolidation persists created semantic memories** — run pipeline with 5 episodic memories → verify new Semantic memory exists in storage with correct `source_episodes`, `knowledge`, `content_hash` | new test in `cortex-consolidation/tests/` | test | P0-2 |
| A-13 | **Test: consolidation archives source episodes** — after consolidation, verify source episodic memories have `archived=true` and `superseded_by` set to the new semantic memory ID | new test | test | P0-2 |
| A-14 | **Test: consolidation with storage failure rolls back cleanly** — mock storage that fails on 3rd insert → verify no partial state (either all created or none) | new test | test | P0-2 |
| A-15 | **Test: consolidation metrics are real** — run pipeline → verify `precision` is computed from actual recall gate scores, not hardcoded 0.8 | new test | test | P1-10 |
| A-16 | **Test: token estimation matches TokenCounter** — compare `len()/4` vs `TokenCounter::count()` on 100 real memory summaries → assert max 10% deviation (regression gate) | new test | test | P2-8 |
| A-17 | **Test: concurrent consolidation rejected** — start consolidation in background → attempt second → verify `MergeFailed` error, first completes normally | new test | test | — |
| A-18 | **Test: feedback signal reaches learning** — call `track_outcome(ids, was_useful=false)` → verify learning engine receives negative feedback and adjusts confidence | new test | test | P1-1 |

**Estimated effort:** 4-5 days

---

### Phase B: Connection Lifecycle & Runtime Consolidation

Eliminate the 3 separate connection pools and fix multi-agent's per-call connection creation. This is the second-highest impact change — it makes in-memory mode work correctly and eliminates connection churn.

| ID | Task | File(s) | Type | Audit Ref |
|----|------|---------|------|-----------|
| B-01 | Remove duplicate `StorageEngine` for prediction — pass `&rt.storage` reference instead | `cortex-napi/src/runtime.rs:101-106` | impl | P1-7 |
| B-02 | Remove duplicate `WriteConnection`+`ReadPool` for temporal — share from `rt.storage.pool()` | `cortex-napi/src/runtime.rs:128-147` | impl | P1-8 |
| B-03 | Remove duplicate `EmbeddingEngine` for consolidation — pass `&rt.embeddings` reference | `cortex-napi/src/runtime.rs:98-99` | impl | P2-2 |
| B-04 | Move multi-agent engine creation to runtime init — store as `multiagent: Option<Mutex<MultiAgentEngine>>` in `CortexRuntime`, sharing storage connections | `cortex-napi/src/bindings/multiagent.rs:19-54`, `cortex-napi/src/runtime.rs` | impl | P0-3 |
| B-05 | Fix `retract_memory` to use shared connections instead of raw `rusqlite::Connection::open()` | `cortex-napi/src/bindings/multiagent.rs:259-271` | impl | P2-22 |
| B-06 | Replace `tokio::runtime::Runtime::new()` per temporal NAPI call with `Handle::try_current()` (already done in multiagent, apply to temporal) | `cortex-napi/src/bindings/temporal.rs` | impl | — |
| B-07 | Fix multi-agent sync result to return real counts from `SyncManager` | `cortex-napi/src/bindings/multiagent.rs:392-396` | impl | P1-2 |
| B-08 | **Test: in-memory mode — multi-agent register then get returns the agent** — `register_agent("test")` → `get_agent("test")` → assert not null, correct name | new integration test | test | P0-3 |
| B-09 | **Test: in-memory mode — prediction reads memories from main storage** — insert memory via main storage → call prediction → verify it finds the memory | new integration test | test | P1-7 |
| B-10 | **Test: in-memory mode — temporal reads events from main storage** — emit event via main storage → query via temporal → verify event found | new integration test | test | P1-8 |
| B-11 | **Test: file-backed mode — only 1 WriteConnection exists** — init runtime with file path → assert `Arc::strong_count` on writer is 1 (shared, not duplicated) | new test | test | P1-7 |
| B-12 | **Test: multi-agent connection reuse** — call `register_agent` 100 times → assert no connection leak (check SQLite connection count or pool stats) | new test | test | P0-3 |
| B-13 | **Test: multi-agent sync returns real counts** — register 2 agents, create memories in agent A's namespace, sync A→B → verify `applied_count > 0` | new test | test | P1-2 |
| B-14 | **Test: concurrent multi-agent calls don't deadlock** — spawn 10 threads each calling different multi-agent functions → all complete within 5s | new test | test | P0-3 |
| B-15 | **Test: retract_memory actually tombstones in shared DB** — share memory → retract → get_memory → verify archived or tombstoned | new test | test | P2-22 |

**Estimated effort:** 3-4 days

---

### Phase C: Engine Wiring — Decay, Causal, Cloud, Observability

Wire engines that exist but are never called, never hydrated, or never scheduled.

| ID | Task | File(s) | Type | Audit Ref |
|----|------|---------|------|-----------|
| C-01 | Add `list_all_node_ids()` method to `ICausalStorage` trait | `cortex-core/src/traits.rs` (or wherever `ICausalStorage` is defined) | impl | P1-14 |
| C-02 | Implement `list_all_node_ids()` in `cortex-storage` `ICausalStorage` impl | `cortex-storage/src/engine.rs` (causal impl block) | impl | P1-14 |
| C-03 | Implement real `rebuild_from_storage` — iterate all node IDs, load edges, populate graph | `cortex-causal/src/graph/sync.rs:11-31` | impl | P1-14 |
| C-04 | Call `rebuild_from_storage` during `CausalEngine::new()` or add `hydrate(&storage)` method called from runtime init | `cortex-causal/src/engine.rs`, `cortex-napi/src/runtime.rs:86` | impl | P1-4 |
| C-05 | Store node metadata (type, label) in `causal_edges` table or add `causal_nodes` table | `cortex-storage/src/migrations/` (new v016) | impl | P3-5 |
| C-06 | Fix `load_node_edges` to use stored node metadata instead of `"unknown"` | `cortex-causal/src/graph/sync.rs:112-113` | impl | P3-5 |
| C-07 | Add decay scheduling — either a background task in runtime or an explicit `cortex_decay_run` NAPI binding that the TS layer calls periodically | `cortex-napi/src/runtime.rs`, new `bindings/decay.rs` | impl | P1-3 |
| C-08 | Wire decay results to storage — update memory confidence and emit `Decayed` temporal event | new code in decay NAPI binding | impl | P1-3 |
| C-09 | Fix cloud `AuthMethod::ApiKey(String::new())` — read API key from config or environment variable | `cortex-napi/src/runtime.rs:120` | impl | P1-5 |
| C-10 | Fix quota `secs_since_last_sync` — update timestamp after successful sync | `cortex-cloud/src/quota` | impl | P1-6 |
| C-11 | Wire `ObservabilityEngine.health_report()` to use real data — query archived count, stale count, contradiction count, embedding cache stats from storage and engines | `cortex-napi/src/bindings/health.rs:32-45` | impl | P2-1, P2-17 |
| C-12 | Route `IMemoryStorage` read methods through read pool instead of writer mutex | `cortex-storage/src/engine.rs:66-237` | impl | P2-6 |
| C-13 | Implement `cortex_shutdown` — flush WAL, checkpoint, drain pending events | `cortex-napi/src/bindings/lifecycle.rs` | impl | P2-3 |
| C-14 | **Test: causal graph survives restart** — insert edges → drop engine → create new engine with same DB → verify edges present | new test | test | P1-4, P1-14 |
| C-15 | **Test: causal rebuild loads ALL edges** — insert 100 edges across 50 nodes → rebuild → verify graph has all 100 edges and 50+ nodes with correct types | new test | test | P1-14 |
| C-16 | **Test: causal rebuild with empty storage is safe** — rebuild from empty DB → verify empty graph, no errors | new test | test | P1-14 |
| C-17 | **Test: decay actually reduces confidence** — create memory with `last_accessed` 90 days ago → run decay → verify confidence decreased | new test | test | P1-3 |
| C-18 | **Test: decay triggers archival** — create memory with confidence 0.16, `last_accessed` 180 days ago → run decay → verify confidence < 0.15 → verify archival decision is `Archive` | new test | test | P1-3 |
| C-19 | **Test: decay emits temporal event** — run decay on a memory → verify `Decayed` event in temporal event store with correct old/new confidence | new test | test | P1-3 |
| C-20 | **Test: decay batch processes 1000 memories under 1s** — performance regression gate | new test | test | P1-3 |
| C-21 | **Test: cloud rejects empty API key at init** — `CloudEngine::new(ApiKey(""))` → verify error or warning, not silent failure | new test | test | P1-5 |
| C-22 | **Test: quota allows sync after successful sync** — sync once → verify `check_sync_frequency()` returns true for next sync (not permanently throttled) | new test | test | P1-6 |
| C-23 | **Test: health snapshot has real values** — insert 10 memories (3 archived) → get health → verify `total_memories=10`, `archived_memories=3`, `average_confidence` matches | new test | test | P2-1 |
| C-24 | **Test: read pool distributes reads** — file-backed DB, insert data, call 100 reads → verify reads distributed across pool connections (not all through writer) | new test | test | P2-6 |
| C-25 | **Test: shutdown checkpoints WAL** — write data → shutdown → verify WAL file is empty or DB file contains all data | new test | test | P2-3 |
| C-26 | **Test: cloud conflict resolution merges correctly** — create local change + remote change for same memory → sync → verify merge result (not blind accept-remote) | new test | test | P0-4 |

**Estimated effort:** 5-6 days

---

### Phase D: Embedding Pipeline & Vector Search

Fix the embedding cache, vector search performance, and stale embedding problem.

| ID | Task | File(s) | Type | Audit Ref |
|----|------|---------|------|-----------|
| D-01 | Wire L2 cache to real SQLite connection from `cortex-storage` pool | `cortex-embeddings/src/cache/l2_sqlite.rs:12-17` | impl | P1-13 |
| D-02 | Fix `EmbeddingEngine` `IEmbeddingProvider` trait impl to use the configured provider chain + cache, not a fresh TF-IDF fallback | `cortex-embeddings/src/engine.rs:140-155` | impl | P1-9 |
| D-03 | Add embedding regeneration to `update_memory` — when `content_hash` changes, delete old embedding link and trigger re-embed | `cortex-storage/src/queries/memory_crud.rs:131-279` | impl | P2-15 |
| D-04 | Wrap `bulk_insert` in a single transaction with prepared statement reuse | `cortex-storage/src/queries/memory_crud.rs:296-303` | impl | P2-16 |
| D-05 | Load sqlite-vec extension at `StorageEngine::open()` time, or document that brute-force is intentional for small datasets | `cortex-storage/src/engine.rs` | impl | P2-14 |
| D-06 | If sqlite-vec not available, add early-exit optimization: skip embeddings with dimension mismatch, use SIMD-friendly cosine if available | `cortex-storage/src/queries/vector_search.rs:40-48` | impl | P2-14 |
| D-07 | **Test: L2 cache persists across engine restarts** — embed text → drop engine → create new engine with same DB → lookup → verify cache hit | new test | test | P1-13 |
| D-08 | **Test: L2 cache miss promotes to L1** — cold start → embed text (L2 miss, provider called) → embed same text again → verify L1 hit (provider NOT called second time) | new test | test | P1-13 |
| D-09 | **Test: embedding provider chain degrades correctly** — configure ONNX (unavailable) → fallback → TF-IDF → verify TF-IDF used, degradation event logged | new test | test | P1-9 |
| D-10 | **Test: consolidation uses real embeddings not TF-IDF** — configure a mock provider → run consolidation → verify mock provider was called (not TF-IDF fallback) | new test | test | P1-9 |
| D-11 | **Test: update_memory regenerates embedding** — insert memory → embed → update summary → verify new embedding differs from old | new test | test | P2-15 |
| D-12 | **Test: stale embedding detection** — update memory content_hash without re-embedding → vector search → verify result has lower relevance than freshly embedded memory with same content | new test | test | P2-15 |
| D-13 | **Test: bulk_insert 1000 memories under 2s** — performance regression gate, verify single transaction (check SQLite journal) | new test | test | P2-16 |
| D-14 | **Test: bulk_insert atomicity** — insert 100 memories where #50 has invalid data → verify 0 memories inserted (all-or-nothing) | new test | test | P2-16 |
| D-15 | **Test: vector search with 10K embeddings under 500ms** — performance regression gate for brute-force path | new test | test | P2-14 |
| D-16 | **Test: vector search returns correct top-K** — insert 100 memories with known embeddings → search with known query → verify top-5 are the expected 5 most similar | new test | test | P2-14 |

**Estimated effort:** 3-4 days

---

### Phase E: TypeScript Tools & NAPI Correctness

Fix the TS tools that claim to do things they don't, and harden the NAPI boundary.

| ID | Task | File(s) | Type | Audit Ref |
|----|------|---------|------|-----------|
| E-01 | Rewrite `drift_cortex_reembed` to actually re-embed: for each memory, call `embeddings.embed()` with the summary, then `vector_search::store_embedding()` to update the stored embedding | `packages/cortex/src/tools/system/drift_cortex_reembed.ts` | impl | P1-11 |
| E-02 | Rewrite `drift_cortex_validate` to actually run the 4-dimension validation engine on candidates, return validation results with scores | `packages/cortex/src/tools/system/drift_cortex_validate.ts` | impl | P1-12 |
| E-03 | Fix `drift_cortex_gc` to work with decay — call decay engine first, then archive memories below threshold | `packages/cortex/src/tools/system/drift_cortex_gc.ts` | impl | P2-10 |
| E-04 | Fix link/unlink race condition — use `memoryUpdateLinks()` atomic operation instead of read-modify-write pattern, or add optimistic concurrency (version check) | `packages/cortex/src/tools/memory/drift_memory_link.ts`, `drift_memory_unlink.ts` | impl | P2-11 |
| E-05 | Fix tool count comment (43 → actual count) | `packages/cortex/src/tools/index.ts:523` | impl | P3-4 |
| E-06 | Fix privacy `apply_replacements` — sort matches descending by start position before applying, or assert sorted | `cortex-privacy/src/engine.rs:122-136` | impl | P2-13 |
| E-07 | Add `in_comment` detection — at minimum, check if match offset falls within `//`, `/* */`, `#`, or `--` comment syntax | `cortex-privacy/src/engine.rs:135` | impl | P2-12 |
| E-08 | Fix bridge serialization error handling — replace `unwrap_or(json!({"error": "..."}))` with proper `CortexError` propagation | `cortex-drift-bridge/src/napi/functions.rs` | impl | P2-7 |
| E-09 | **Test: reembed actually changes stored embeddings** — insert memory → embed → modify embedding provider to return different vectors → reembed → verify stored embedding changed | new test | test | P1-11 |
| E-10 | **Test: reembed handles provider failure gracefully** — configure failing provider → reembed → verify partial success reported, no crash | new test | test | P1-11 |
| E-11 | **Test: validate returns real validation scores** — insert memory with low confidence → validate → verify result contains validation dimensions (temporal, semantic, structural, confidence) with non-zero scores | new test | test | P1-12 |
| E-12 | **Test: validate on empty DB returns empty results** — no memories → validate → verify empty array, no error | new test | test | P1-12 |
| E-13 | **Test: GC archives decayed memories** — insert memory with old `last_accessed` → run decay → run GC → verify memory archived | new test | test | P2-10 |
| E-14 | **Test: GC doesn't archive fresh memories** — insert memory with recent `last_accessed` and high confidence → run GC → verify NOT archived | new test | test | P2-10 |
| E-15 | **Test: concurrent link operations don't lose data** — spawn 10 concurrent `link` calls on same memory with different patterns → verify all 10 patterns present after completion | new test | test | P2-11 |
| E-16 | **Test: concurrent unlink + link don't corrupt** — link 5 patterns → concurrently unlink pattern A and link pattern F → verify final state is consistent (4 or 5 patterns, never 3) | new test | test | P2-11 |
| E-17 | **Test: privacy replacements don't corrupt text** — text with 5 PII matches → apply_replacements → verify all 5 replaced, no offset corruption, output length correct | new test | test | P2-13 |
| E-18 | **Test: privacy with ascending-order matches** — feed matches in ascending order (natural regex scan order) → verify replacements still correct (tests the sort fix) | new test | test | P2-13 |
| E-19 | **Test: privacy in_comment reduces score** — PII inside `// comment` → verify lower context score than same PII in code | new test | test | P2-12 |
| E-20 | **Test: bridge serialization failure returns CortexError** — feed unserializable data → verify proper error type, not swallowed JSON | new test | test | P2-7 |

**Estimated effort:** 3-4 days

---

### Phase F: Observability, Metrics & Diagnostics

Wire the observability engine, persist metrics, and add migration gap fix.

| ID | Task | File(s) | Type | Audit Ref |
|----|------|---------|------|-----------|
| F-01 | Wire `MetricsCollector` to record real metrics from retrieval, consolidation, storage, embedding, and session operations | `cortex-observability/src/metrics/*.rs`, callers in each engine | impl | P2-18 |
| F-02 | Add metrics persistence — write periodic snapshots to `observability_metrics` table (created by v012 migration) | `cortex-observability/src/metrics/mod.rs`, `cortex-storage/src/queries/` | impl | P2-18 |
| F-03 | Wire `QueryLog` to persist to `query_log` table (created by v012 migration) | `cortex-observability/src/query_log.rs`, `cortex-storage/src/queries/` | impl | P2-18 |
| F-04 | Add v013 migration placeholder or renumber v014/v015 to close the gap | `cortex-storage/src/migrations/mod.rs:31-46` | impl | P2-4 |
| F-05 | Fix temporal event timestamps — use `strftime('%Y-%m-%dT%H:%M:%fZ', 'now')` in SQL instead of `Utc::now()` in Rust | `cortex-storage/src/temporal_events.rs` | impl | P2-5 |
| F-06 | Make drift detection window configurable via `CortexConfig.temporal` | `cortex-temporal/src/engine.rs:139` | impl | P2-19 |
| F-07 | Fix prediction cache key collision — use `"__no_active_file__"` or hash of query context instead of `"__no_file__"` | `cortex-prediction/src/engine.rs:42` | impl | P2-20 |
| F-08 | **Test: metrics survive restart** — record 100 retrieval metrics → restart → verify metrics loaded from DB | new test | test | P2-18 |
| F-09 | **Test: query log persists and rotates** — log 60K queries → verify only 50K retained (ring buffer) → restart → verify persisted entries loaded | new test | test | P2-18 |
| F-10 | **Test: migration v013 gap handled** — run migrations on fresh DB → verify `LATEST_VERSION` matches actual migration count | new test | test | P2-4 |
| F-11 | **Test: temporal events use DB time** — insert event → query event → verify timestamp is within 1s of DB `strftime('now')`, not Rust `Utc::now()` (test with clock skew simulation) | new test | test | P2-5 |
| F-12 | **Test: drift window respects config** — set window to 24h → verify only 24h of data used for drift metrics, not hardcoded 168h | new test | test | P2-19 |
| F-13 | **Test: prediction cache doesn't collide** — predict with file=None, query="A" → predict with file=None, query="B" → verify different results (not cached collision) | new test | test | P2-20 |
| F-14 | **Test: prediction with no candidates returns explicit empty** — empty DB → predict → verify `confidence=0.0` and `memory_ids=[]`, not an error | new test | test | P2-21 |

**Estimated effort:** 2-3 days

---

## Dependency Graph

```
Phase A (Persistence Gap)              ← CRITICAL PATH, start here
    │
    ├──→ Phase B (Connection Lifecycle) ← depends on A (shared storage refs)
    │        │
    │        └──→ Phase C (Engine Wiring) ← depends on B (shared connections for causal hydration)
    │                 │
    │                 └──→ Phase F (Observability) ← depends on C (engines wired to record metrics)
    │
    ├──→ Phase D (Embedding Pipeline)   ← parallelizable with B after A
    │
    └──→ Phase E (TS Tools & NAPI)      ← parallelizable with B/D after A
```

**Critical path:** A(4-5d) → B(3-4d) → C(5-6d) → F(2-3d) = **14-18 working days**

**With parallelism:**
```
Week 1:  A (persistence gap)
Week 2:  B (connections) + D (embeddings, parallel)
Week 3:  C (engine wiring) + E (TS tools, parallel)
Week 4:  F (observability) + integration testing
```
**With parallelism: 16-22 working days** (2 engineers: 10-12 days)

---

## Summary Statistics

| Metric | Count |
|--------|-------|
| **Cortex sub-crates audited** | 23 |
| **Source files audited** | ~400+ |
| **Total audit findings** | 45 |
| **P0 (production-breaking)** | 4 |
| **P1 (silent data loss)** | 14 |
| **P2 (degraded functionality)** | 22 |
| **P3 (code quality)** | 5 |
| **Implementation tasks** | 62 |
| **Test tasks** | 82 |
| **Total tasks** | 144 |
| **Subsystems found clean** | 10 (compression, CRDT, reclassification, tokens, retrieval, storage engine, embeddings degradation, causal inference, temporal event store, session) |

---

## Key File Reference

| Component | Path | Key Lines |
|-----------|------|-----------|
| **NAPI Runtime (singleton)** | `crates/cortex/cortex-napi/src/runtime.rs` | 36-51 (struct), 64-166 (init) |
| **NAPI Health bindings** | `crates/cortex/cortex-napi/src/bindings/health.rs` | 14-50 (hardcoded snapshot) |
| **NAPI Multi-agent bindings** | `crates/cortex/cortex-napi/src/bindings/multiagent.rs` | 19-54 (per-call connections) |
| **NAPI Generation bindings** | `crates/cortex/cortex-napi/src/bindings/generation.rs` | 55-71 (`_was_useful` discarded) |
| **NAPI Consolidation bindings** | `crates/cortex/cortex-napi/src/bindings/consolidation.rs` | 12-41 (no persistence) |
| **NAPI Temporal bindings** | `crates/cortex/cortex-napi/src/bindings/temporal.rs` | 80-240 (Runtime::new per call) |
| **Learning engine** | `crates/cortex/cortex-learning/src/engine.rs` | 72-101 (UUID but no BaseMemory) |
| **Consolidation engine** | `crates/cortex/cortex-consolidation/src/engine.rs` | 84-133 (no storage call) |
| **Consolidation pipeline** | `crates/cortex/cortex-consolidation/src/pipeline/mod.rs` | 55-142 (6 phases, no persist) |
| **Causal engine** | `crates/cortex/cortex-causal/src/engine.rs` | 86 (never hydrated) |
| **Causal graph sync** | `crates/cortex/cortex-causal/src/graph/sync.rs` | 11-31 (rebuild no-op) |
| **Decay engine** | `crates/cortex/cortex-decay/src/engine.rs` | 11-92 (never called) |
| **Cloud engine** | `crates/cortex/cortex-cloud/src/engine.rs` | 84-178 (sync, conflict) |
| **Embedding engine** | `crates/cortex/cortex-embeddings/src/engine.rs` | 140-155 (trait bypass) |
| **L2 cache** | `crates/cortex/cortex-embeddings/src/cache/l2_sqlite.rs` | 12-17 (HashMap not SQLite) |
| **Storage engine** | `crates/cortex/cortex-storage/src/engine.rs` | 66-237 (reads through writer) |
| **Vector search** | `crates/cortex/cortex-storage/src/queries/vector_search.rs` | 21-48 (brute-force scan) |
| **Memory CRUD** | `crates/cortex/cortex-storage/src/queries/memory_crud.rs` | 131-279 (update), 296-303 (bulk) |
| **Privacy engine** | `crates/cortex/cortex-privacy/src/engine.rs` | 122-136 (sort assumption) |
| **Observability engine** | `crates/cortex/cortex-observability/src/engine.rs` | — (exists, bypassed) |
| **Observability metrics** | `crates/cortex/cortex-observability/src/metrics/mod.rs` | — (in-memory only) |
| **Query log** | `crates/cortex/cortex-observability/src/query_log.rs` | 50-51 (50K cap, no persist) |
| **TS Tools index** | `packages/cortex/src/tools/index.ts` | 523-524 (count mismatch) |
| **TS Reembed tool** | `packages/cortex/src/tools/system/drift_cortex_reembed.ts` | 15-30 (fake) |
| **TS Validate tool** | `packages/cortex/src/tools/system/drift_cortex_validate.ts` | 10-35 (doesn't validate) |
| **TS GC tool** | `packages/cortex/src/tools/system/drift_cortex_gc.ts` | 20 (non-decaying confidence) |
| **TS Link tool** | `packages/cortex/src/tools/memory/drift_memory_link.ts` | — (read-modify-write race) |
| **TS Bridge client** | `packages/cortex/src/bridge/client.ts` | 60-90 (sync wrapped as async) |
| **Migrations** | `crates/cortex/cortex-storage/src/migrations/mod.rs` | 31-46 (v013 gap) |
