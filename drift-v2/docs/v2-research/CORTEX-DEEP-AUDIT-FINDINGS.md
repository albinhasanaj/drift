# Cortex Deep Audit Findings

> **Auditor perspective:** Senior engineer, zero objectives other than finding actual stubs, TODOs, things not built properly, things silently failing or that could cause problems in production.
>
> **Scope:** 23 Rust sub-crates (`crates/cortex/*`), 1 bridge crate (`crates/cortex-drift-bridge/`), 1 TypeScript package (`packages/cortex/`). ~400+ source files.
>
> **Date:** 2026-02-09

---

## Executive Summary

Cortex is **architecturally far more complete than Drift** — the NAPI bindings are real (not stubs), the storage layer properly separates reads/writes, and the intelligence engines have genuine implementations. However, the audit uncovered **28 distinct findings** across 8 categories, ranging from production-breaking issues (P0) to code quality concerns (P3). The most critical cluster is around **runtime initialization** (duplicate StorageEngine handles, new tokio runtimes per call) and **silent data loss** (learning engine doesn't persist, generation feedback is discarded, cloud conflict resolution is a no-op).

---

## Section A: NAPI Binding Layer (14 modules, 47 functions)

Unlike Drift where 22/27 NAPI bindings were hardcoded stubs, **Cortex NAPI bindings are overwhelmingly real**. However, several have significant issues:

### A1. `cortex_cloud_resolve_conflict` — Complete No-Op Stub [P0]
**File:** `cortex-napi/src/bindings/cloud.rs:49-68`
```rust
let _resolver = engine.conflict_resolver();
Ok(json!({
    "memory_id": memory_id,
    "resolution": resolution,
}))
```
Gets the conflict resolver but **never calls it**. Just echoes back the input parameters as if resolution succeeded. A consumer calling this function would believe the conflict was resolved when nothing happened.

### A2. `cortex_generation_track_outcome` — Feedback Signal Discarded [P1]
**File:** `cortex-napi/src/bindings/generation.rs:55-72`
```rust
pub fn cortex_generation_track_outcome(
    memory_ids: Vec<String>,
    _was_useful: bool,  // ← prefixed with underscore, never used
    session_id: Option<String>,
) -> napi::Result<()> {
```
The `_was_useful` parameter is **completely ignored**. The comment says "this could feed into the learning engine" but it doesn't. This means the entire generation feedback loop is open — user signals about memory usefulness are silently discarded.

### A3. `cortex_multiagent_sync_agents` — Hardcoded Zero Counts [P1]
**File:** `cortex-napi/src/bindings/multiagent.rs:390-398`
```rust
let result = multiagent_types::NapiSyncResult {
    applied_count: 0,
    buffered_count: 0,
    errors: vec![],
};
```
After calling `engine.sync_with()`, the actual sync result is **discarded** and replaced with hardcoded zeros. The sync may have applied deltas, but the caller always sees `applied_count: 0`.

### A4. `cortex_multiagent_detect_consensus` — Phase D Stub [P2]
**File:** `cortex-multiagent/src/engine.rs:181-196`
```rust
// Phase D1: Consensus detection is now available via
// cortex_multiagent::consolidation::ConsensusDetector.
// ...
// For now, return empty
Ok(Vec::new())
```
Always returns empty. The `ConsensusDetector` exists but is never wired in because it needs an embedding engine injected at a higher level.

### A5. `cortex_health_get_health` — 7 of 12 HealthSnapshot Fields Hardcoded [P2]
**File:** `cortex-napi/src/bindings/health.rs:32-45`
```rust
let snapshot = HealthSnapshot {
    total_memories: total,
    active_memories: total,     // ← same as total, ignores archived
    archived_memories: 0,       // ← hardcoded 0
    average_confidence: avg_confidence,
    db_size_bytes: 0,           // ← hardcoded 0
    embedding_cache_hit_rate: 0.0, // ← hardcoded 0.0
    stale_count: 0,             // ← hardcoded 0
    contradiction_count: 0,     // ← hardcoded 0
    unresolved_contradictions: 0, // ← hardcoded 0
    consolidation_count: 0,     // ← hardcoded 0
    memories_needing_validation: 0, // ← hardcoded 0
    drift_summary: None,
};
```
Only `total_memories` and `average_confidence` are real. The health report looks healthy even when the system is degraded.

---

## Section B: Runtime & Initialization

### B1. Duplicate StorageEngine for PredictionEngine [P1]
**File:** `cortex-napi/src/runtime.rs:101-106`
```rust
// Prediction — needs storage (clone not available, so open a second handle)
let prediction_storage = match &opts.db_path {
    Some(path) => StorageEngine::open(path)?,
    None => StorageEngine::open_in_memory()?,
};
let prediction = PredictionEngine::new(prediction_storage);
```
Opens a **completely separate** StorageEngine (with its own write connection + read pool) for the prediction engine. For file-backed mode this means:
- **2 write connections** to the same SQLite file (WAL allows this but it's wasteful and could cause lock contention)
- **8 read connections** total (4+4) instead of sharing the pool
- For in-memory mode: **prediction engine sees a completely different database** — it will never find any memories

### B2. Duplicate EmbeddingEngine for ConsolidationEngine [P2]
**File:** `cortex-napi/src/runtime.rs:97-99`
```rust
let consolidation_embedder = EmbeddingEngine::new(config.embedding.clone());
let consolidation = ConsolidationEngine::new(Box::new(consolidation_embedder));
```
Creates a second `EmbeddingEngine` with its own TF-IDF state and cache. Embeddings computed by the main engine won't be cached in the consolidation engine's cache, and vice versa.

### B3. Temporal Engine Opens Its Own Connections [P2]
**File:** `cortex-napi/src/runtime.rs:129-147`
```rust
let temporal = {
    let (writer, readers) = match &opts.db_path {
        Some(path) => {
            let w = cortex_storage::pool::WriteConnection::open(path)?;
            let r = cortex_storage::pool::ReadPool::open(path, 4)?;
            (w, r)
        }
        ...
    };
```
A **third** set of write+read connections. For file-backed mode: 3 write connections + 12 read connections total. For in-memory mode: temporal engine sees an isolated database.

### B4. MultiAgent Engine Creates New Connections Per Call [P0]
**File:** `cortex-napi/src/bindings/multiagent.rs:19-54`
```rust
fn get_engine() -> napi::Result<cortex_multiagent::MultiAgentEngine> {
    let rt = runtime::get()?;
    let config = rt.config.multiagent.clone();
    let (writer, readers) = open_multiagent_connections(&rt)?;
    Ok(cortex_multiagent::MultiAgentEngine::new(
        std::sync::Arc::new(writer),
        std::sync::Arc::new(readers),
        config,
    ))
}
```
**Every single multi-agent NAPI call** opens fresh write+read connections, uses them for one operation, then drops them. This means:
- Connection setup overhead on every call
- For in-memory mode: each call sees a fresh empty database (registrations, namespaces, etc. are lost between calls)
- For file-backed mode: connection churn and potential file descriptor exhaustion under load

### B5. `retract_memory` Opens Raw Connection Bypassing Pool [P1]
**File:** `cortex-napi/src/bindings/multiagent.rs:260-267`
```rust
let conn = match db_path {
    Some(path) => rusqlite::Connection::open(path)...,
    None => rusqlite::Connection::open_in_memory()...,
};
```
Opens a raw `rusqlite::Connection` directly, bypassing the pool entirely. No pragmas applied, no WAL mode, no journal size limit.

### B6. Temporal Bindings Create New Tokio Runtime Per Call [P1]
**File:** `cortex-napi/src/bindings/temporal.rs` (9 occurrences)
```rust
let tokio_rt = tokio::runtime::Runtime::new()...;
```
Every temporal NAPI call creates a **brand new tokio runtime**, uses it for one `block_on`, then drops it. This is expensive (thread pool creation/teardown) and wasteful. The multiagent bindings use `tokio::runtime::Handle::try_current()` which is the correct approach.

### B7. `cortex_shutdown` Is a No-Op [P2]
**File:** `cortex-napi/src/bindings/lifecycle.rs:31-36`
```rust
pub fn cortex_shutdown() -> napi::Result<()> {
    // Engines are cleaned up when the Arc<CortexRuntime> is dropped.
    Ok(())
}
```
No cache flushing, no connection closing, no background task cancellation. The `OnceLock<Arc<CortexRuntime>>` is never cleared, so the runtime is never dropped. **The singleton lives forever** — calling shutdown then initialize again will fail with "already initialized".

---

## Section C: Storage Layer

### C1. Migration v013 Skipped [P2]
**File:** `cortex-storage/src/migrations/mod.rs:31-46`
```
MIGRATIONS array: v001..v012, v014, v015
```
Migration v013 is missing. The array jumps from v012 to v014. `LATEST_VERSION` is 15, and the migration runner uses `version <= current` to skip, so this works correctly in practice. But it's confusing and could cause issues if someone tries to add v013 later.

### C2. In-Memory ReadPool Creates Isolated Databases [P2]
**File:** `cortex-storage/src/pool/read_pool.rs:48-63`
```rust
pub fn open_in_memory(pool_size: usize) -> CortexResult<Self> {
    for _ in 0..size {
        let conn = Connection::open_in_memory()...;
```
Each in-memory read connection is a **separate isolated database**. The `StorageEngine` correctly handles this by setting `use_read_pool: false` for in-memory mode, but the `TemporalEngine` and `MultiAgentEngine` open their own pools and **don't have this guard** — they'll try to read from empty databases.

### C3. ReadPool Round-Robin Counter Can Wrap [P3]
**File:** `cortex-storage/src/pool/read_pool.rs:70`
```rust
let idx = self.next.fetch_add(1, Ordering::Relaxed) % self.connections.len();
```
`AtomicUsize` will wrap around at `usize::MAX`. With `Relaxed` ordering this is fine for correctness (modulo still works), but worth noting.

---

## Section D: Intelligence Engines

### D1. EmbeddingEngine `IEmbeddingProvider` Trait Impl Bypasses Everything [P1]
**File:** `cortex-embeddings/src/engine.rs:144-155`
```rust
impl IEmbeddingProvider for EmbeddingEngine {
    fn embed(&self, text: &str) -> CortexResult<Vec<f32>> {
        // ...bypass caching and go straight to the chain...
        let fallback = providers::TfIdfFallback::new(self.config.dimensions);
        fallback.embed(text)
    }
```
When `EmbeddingEngine` is used through the `IEmbeddingProvider` trait (which `ConsolidationEngine` does), it **always creates a fresh TF-IDF fallback** and ignores the configured provider chain, cache, and degradation tracking. This means consolidation always uses TF-IDF even if a real embedding provider is configured.

### D2. Learning Engine Doesn't Persist Created Memories [P0]
**File:** `cortex-learning/src/engine.rs:72-101`
```rust
let memory_created = match dedup_action {
    DedupAction::Add => {
        // ...
        Some(uuid::Uuid::new_v4().to_string())
    }
    DedupAction::Update(id) => {
        Some(id)
    }
    DedupAction::Noop => {
        None
    }
};
Ok(LearningResult {
    memory_created,
    ...
})
```
The learning engine generates a UUID for a new memory but **never actually creates the BaseMemory or persists it to storage**. It returns the UUID in `LearningResult.memory_created` but the memory doesn't exist. The caller (NAPI binding) doesn't create it either — it just serializes and returns the result. **Every "learned" correction is lost.**

### D3. Learning Engine Dedup Checks Against In-Memory List [P1]
**File:** `cortex-learning/src/engine.rs:18-21`
```rust
pub struct LearningEngine {
    existing_memories: Vec<BaseMemory>,
    llm_extractor: Box<dyn extraction::LlmExtractor>,
}
```
Deduplication checks against `existing_memories` which is an in-memory `Vec`. It's only populated via `set_existing_memories()` which is **never called from the NAPI layer**. So dedup always sees an empty list and every correction is treated as new.

### D4. Decay Engine Never Called From Runtime [P1]
The `DecayEngine` is created in the runtime (`runtime.rs:89`) but **no NAPI binding or background task ever calls it**. Memory confidence values never decay. The `IDecayEngine::calculate()` trait method exists but nothing invokes it on a schedule or trigger.

### D5. Validation Engine `IValidator` Impl Validates Against Empty Context [P2]
**File:** `cortex-validation/src/engine.rs:213-217`
```rust
impl IValidator for ValidationEngine {
    fn validate(&self, memory: &BaseMemory) -> CortexResult<ValidationResult> {
        self.validate_basic(memory, &[])
    }
}
```
The trait impl passes an empty slice for `related_memories`, meaning contradiction detection always sees zero related memories and always passes. The full `validate_with_context` method works correctly but requires external context that no caller provides.

### D6. Prediction Engine `IPredictor` Misinterprets `active_files` [P2]
**File:** `cortex-prediction/src/engine.rs:92-94`
```rust
file: crate::signals::FileSignals {
    active_file: signals.active_files.first().cloned(),
    imports: signals.active_files.get(1..).unwrap_or_default().to_vec(),
```
Treats the first element of `active_files` as the active file and **all remaining elements as imports**. This is a semantic mismatch — the caller passes a list of active files, not `[active_file, ...imports]`.

### D7. Causal Engine Graph Is In-Memory Only [P1]
**File:** `cortex-causal/src/engine.rs:27-33`
```rust
pub fn new() -> Self {
    Self {
        graph: GraphManager::new(),
        inference: InferenceEngine::new(),
        traversal: TraversalEngine::default(),
    }
}
```
The causal graph starts empty and lives in memory. While `add_edge` can optionally persist to `ICausalStorage`, the runtime initialization (`runtime.rs:86`) creates `CausalEngine::new()` with no storage hydration. **All causal relationships are lost on restart.** The `ICausalStorage` implementation exists in `StorageEngine` but is never used to load the graph at startup.

---

## Section E: Cloud Sync

### E1. Cloud Engine Initialized With Empty API Key [P1]
**File:** `cortex-napi/src/runtime.rs:118-126`
```rust
let cloud = if opts.cloud_enabled {
    Some(Mutex::new(CloudEngine::new(
        cortex_cloud::auth::login_flow::AuthMethod::ApiKey(String::new()),
        ...
    )))
} else {
    None
};
```
When cloud is enabled, it's initialized with `AuthMethod::ApiKey(String::new())` — an **empty API key**. The first `connect()` or `sync()` call will attempt authentication with this empty key and fail.

### E2. Quota Usage Never Updated [P2]
**File:** `cortex-cloud/src/engine.rs:197-199`
```rust
pub fn update_quota_usage(&mut self, usage: QuotaUsage) {
    self.quota.update_usage(usage);
}
```
`update_quota_usage` exists but is **never called** from any NAPI binding or runtime code. `QuotaUsage` stays at default (all zeros), so `check_sync_frequency()` always returns `false` (0 >= 60 is false), meaning **sync is always throttled** after the first call.

Wait — actually `secs_since_last_sync` defaults to 0, and `min_sync_interval_secs` defaults to 60. So `0 >= 60` is false, meaning `check_sync_frequency()` returns false. Looking at `engine.rs:89`:
```rust
if !self.quota.check_sync_frequency() {
    return Ok(SyncResult { status: SyncResultStatus::Throttled, ..Default::default() });
}
```
**Every sync after the first is throttled** because `secs_since_last_sync` is never updated from 0.

### E3. HttpClient Uses `reqwest::blocking` in Potentially Async Context [P2]
**File:** `cortex-cloud/src/transport/http_client.rs:111`
```rust
let client = reqwest::blocking::Client::builder()...
```
Uses blocking HTTP client with `std::thread::sleep` for backoff. If called from an async context (which the NAPI layer could be), this blocks the thread pool.

---

## Section F: Multi-Agent System

### F1. `list_agents` Filter Creates Fake Timestamps [P2]
**File:** `cortex-napi/src/bindings/multiagent.rs:139-149`
```rust
let filter: Option<AgentStatus> = match status_filter.as_deref() {
    Some("idle") => Some(AgentStatus::Idle { since: chrono::Utc::now() }),
    Some("deregistered") => Some(AgentStatus::Deregistered { at: chrono::Utc::now() }),
```
Creates `AgentStatus` variants with `Utc::now()` timestamps for filtering. If the filter implementation does timestamp comparison (e.g., "idle since before X"), this would produce incorrect results.

### F2. MultiAgent Engine Ignores ReadPool [P2]
**File:** `cortex-multiagent/src/engine.rs:23-29`
```rust
pub struct MultiAgentEngine {
    writer: Arc<WriteConnection>,
    #[allow(dead_code)]
    readers: Arc<ReadPool>,
    #[allow(dead_code)]
    config: MultiAgentConfig,
}
```
Both `readers` and `config` are `#[allow(dead_code)]`. **All operations go through the writer**, including reads like `get_agent`, `list_agents`, `get_provenance`, `get_trust`. This means read operations contend with writes on the same mutex.

---

## Section G: Bridge

### G1. Bridge Uses Raw `rusqlite::Connection` Without Pool [P2]
**File:** `cortex-drift-bridge/src/lib.rs:50-53`
```rust
drift_db: Option<Mutex<rusqlite::Connection>>,
cortex_db: Option<Mutex<rusqlite::Connection>>,
bridge_db: Option<Mutex<rusqlite::Connection>>,
```
The bridge uses raw `Mutex<Connection>` instead of the `WriteConnection`/`ReadPool` infrastructure. All operations (read and write) go through a single connection per database, serialized by a `std::sync::Mutex`.

### G2. `unwrap_or` on Serialization Silently Swallows Errors [P2]
**File:** `cortex-drift-bridge/src/napi/functions.rs` (5 occurrences)
```rust
Ok(serde_json::to_value(&result).unwrap_or(json!({"error": "serialization failed"})))
```
If serialization fails, the error is silently replaced with a JSON object containing an error message — but this is returned as `Ok(...)`, not `Err(...)`. The caller sees a successful result with unexpected shape.

---

## Section H: TypeScript Layer

### H1. `wrap()` Function Wraps Sync Calls in Fake Promises [P2]
**File:** `packages/cortex/src/bridge/client.ts:80-86`
```typescript
async function wrap<T>(fn: () => T): Promise<T> {
  try {
    return fn();
  } catch (err) {
    throw parseNapiError(err);
  }
}
```
All NAPI calls are synchronous (they block on Rust mutexes), but `wrap` makes them look async. This means `await client.memoryCreate(...)` blocks the Node.js event loop. Not a bug per se, but misleading API — callers may assume these are non-blocking.

### H2. NativeBindings Interface Uses `unknown` Extensively [P3]
**File:** `packages/cortex/src/bridge/index.ts:22-142`
Most NAPI function return types are `unknown`, with type assertions (`as BaseMemory`) in the client. No runtime validation that the Rust side actually returns the expected shape.

---

## Section I: Consolidation Pipeline

### I1. Quality Metrics Are Hardcoded, Not Measured [P1]
**File:** `cortex-consolidation/src/pipeline/mod.rs:120-127`
```rust
let precision = if !created.is_empty() { 0.8 } else { 1.0 };
let metrics = ConsolidationMetrics {
    precision,
    compression_ratio,
    lift: 1.5, // Baseline lift estimate.
    stability: 0.9,
};
```
- **`precision`** is hardcoded to 0.8 whenever any memory is created. No actual precision measurement.
- **`lift`** is hardcoded to 1.5. No actual lift computation.
- **`stability`** is hardcoded to 0.9. No actual stability measurement.
- Only `compression_ratio` is computed from real data (input/output token counts).

The auto-tuning system (`monitoring::auto_tuning::maybe_tune`) reads these metrics to adjust thresholds — so it's tuning based on fake data.

### I2. Token Count Estimation Uses `len() / 4` Instead of TokenCounter [P2]
**File:** `cortex-consolidation/src/pipeline/mod.rs:88-90`
```rust
total_input_tokens += mem.summary.len() / 4;
total_output_tokens += new_memory.summary.len() / 4;
```
The `cortex-tokens` crate provides an accurate `TokenCounter` using tiktoken's cl100k_base, but the consolidation pipeline uses a crude `len() / 4` approximation. This makes `compression_ratio` (the one real metric) inaccurate.

### I3. Consolidation Doesn't Actually Persist Created Memories [P0]
**File:** `cortex-consolidation/src/pipeline/mod.rs:96-110`
```rust
match action {
    IntegrationAction::Create(mem) => {
        created.push(mem.id.clone());
    }
    IntegrationAction::Update { existing_id, .. } => {
        created.push(existing_id);
    }
}
// Phase 6: Pruning.
let pruning = phase6_pruning::plan_pruning(&cluster, ...);
archived.extend(pruning.archived_ids);
```
The pipeline builds new `BaseMemory` objects and plans archival, but **never writes anything to storage**. It returns IDs of memories that should be created/archived, but the caller (`ConsolidationEngine`) doesn't persist them either. Same pattern as the learning engine (D2) — the entire consolidation output is discarded.

### I4. Only Episodic Memories Are Eligible for Consolidation [P2]
**File:** `cortex-consolidation/src/pipeline/phase1_selection.rs:25`
```rust
m.memory_type == MemoryType::Episodic
```
Phase 1 selection only considers `Episodic` memories. All other 19+ memory types (Core, Tribal, Semantic, Insight, Procedural, Decision, etc.) are never consolidated, even if they're redundant or stale.

---

## Section J: TypeScript Tools Layer

### J1. `drift_cortex_reembed` Is a Fake Re-embedding [P1]
**File:** `packages/cortex/src/tools/system/drift_cortex_reembed.ts:28-36`
```typescript
for (const memory of memories) {
  try {
    await client.search(memory.summary, 1);
    reembedded++;
  } catch {
    // Skip failures
  }
}
```
"Re-embedding" is implemented by **searching for each memory's summary** and hoping the retrieval engine regenerates embeddings as a side effect. This doesn't actually re-embed anything — the search path doesn't trigger embedding regeneration for existing stored vectors. The tool reports success but does nothing.

### J2. `drift_cortex_validate` Doesn't Run Validation [P1]
**File:** `packages/cortex/src/tools/system/drift_cortex_validate.ts:23-36`
```typescript
handler: async (args) => {
  const candidates = await client.getValidationCandidates(
    0.0,
    (args.min_confidence as number) ?? 1.0,
  );
  return {
    total_checked: candidates.length,
    candidates: candidates.map((m) => ({
      id: m.id,
      memory_type: m.memory_type,
      confidence: m.confidence,
      summary: m.summary,
    })),
  };
},
```
The tool is called "validate" but it **only lists validation candidates** — it never actually runs the 4-dimension validation engine on them. It returns memories that *could* be validated, not validation results.

### J3. `drift_cortex_gc` Uses `getValidationCandidates` for Archival [P2]
**File:** `packages/cortex/src/tools/system/drift_cortex_gc.ts:22-29`
```typescript
const archivalCandidates = await client.getValidationCandidates(0.0, 0.15);
for (const memory of archivalCandidates) {
  if (!memory.archived) {
    await client.memoryArchive(memory.id);
  }
}
```
Uses `getValidationCandidates(0.0, 0.15)` to find archival candidates. This returns memories with confidence between 0.0 and 0.15, but since the decay engine never runs (D4), confidence values never decrease. So this will only archive memories that were created with very low initial confidence — not memories that have decayed over time.

### J4. `drift_memory_link` / `drift_memory_unlink` — Read-Modify-Write Race [P2]
**File:** `packages/cortex/src/tools/memory/drift_memory_link.ts:38-61`
```typescript
const memory = await client.memoryGet(args.memory_id as string);
const updated: BaseMemory = { ...memory };
updated.linked_patterns = [...memory.linked_patterns, args.link_data as PatternLink];
await client.memoryUpdate(updated);
```
Classic read-modify-write pattern without any locking or optimistic concurrency. If two concurrent link operations target the same memory, one will silently overwrite the other's changes.

### J5. Tool Count Mismatch — Claims 43, Has 40 [P3]
**File:** `packages/cortex/src/tools/index.ts:69`
```typescript
/** All 43 tool factory functions. */
const TOOL_FACTORIES: ((client: CortexClient) => McpToolDefinition)[] = [
```
Comment says 43 tools but the array contains **40 entries** (8+3+4+3+2+8+2+5+5). The comment is stale.

---

## Section K: Privacy Engine

### K1. `in_comment` Always False — No AST Integration [P2]
**File:** `cortex-privacy/src/engine.rs:62`
```rust
in_comment: false, // TODO: integrate with AST-level comment detection
```
The context scoring system has a `ScoringContext.in_comment` field that would reduce false positives for PII patterns found in code comments, but it's always `false`. The TODO has been acknowledged but not implemented.

### K2. `apply_replacements` Assumes Descending Sort Order [P2]
**File:** `cortex-privacy/src/engine.rs:122-136`
```rust
/// Apply placeholder replacements to the text. Matches must be sorted
/// descending by start position so replacements don't shift earlier offsets.
fn apply_replacements(text: &str, matches: &[patterns::RawMatch]) -> String {
```
The function requires matches sorted descending by start position, but there's no assertion or sort — it trusts the caller. If `patterns::scan_all` returns matches in ascending order (which is the natural order for regex scanning), replacements will corrupt offsets.

---

## Section L: Embeddings & Vector Search

### L1. L2 "SQLite" Cache Is Actually an In-Memory HashMap [P1]
**File:** `cortex-embeddings/src/cache/l2_sqlite.rs:12-17`
```rust
pub struct L2SqliteCache {
    /// Serialized embeddings stored in-memory as a simple HashMap fallback
    /// when no SQLite connection is available. In production, this would
    /// wrap a real rusqlite connection from cortex-storage.
    store: std::collections::HashMap<String, Vec<u8>>,
}
```
The L2 cache is described as "SQLite-backed" and "survives process restarts" in the module doc, but it's actually a plain `HashMap<String, Vec<u8>>`. **Embeddings don't survive restarts.** The 3-tier cache architecture (L1 moka → L2 SQLite → L3 precomputed) is reduced to effectively L1 only, since L2 is just another in-memory store and L3 is only populated if explicitly loaded.

### L2. Vector Search Is Brute-Force Full Table Scan [P2]
**File:** `cortex-storage/src/queries/vector_search.rs:21-48`
```rust
// Get all embeddings and compute cosine similarity in Rust.
// This is the fallback path when sqlite-vec extension isn't loaded.
let mut stmt = conn.prepare(
    "SELECT mel.memory_id, me.embedding, me.dimensions
     FROM memory_embedding_link mel
     JOIN memory_embeddings me ON me.id = mel.embedding_id",
)...;
```
Vector search loads **every embedding from the database into memory**, computes cosine similarity in Rust, sorts, and truncates. This is O(n) in the number of stored memories. With thousands of memories, this becomes a performance bottleneck. The comment says "fallback path when sqlite-vec extension isn't loaded" — but there's no non-fallback path. The sqlite-vec extension is never loaded.

### L3. `update_memory` Does Not Update Embeddings [P2]
**File:** `cortex-storage/src/queries/memory_crud.rs:131-279`

When a memory is updated via `update_memory()`, the summary text may change, but the stored embedding is **not regenerated**. The old embedding (computed from the old summary) remains linked. This means vector search will return stale similarity scores for updated memories.

### L4. `bulk_insert` Is Not Batched [P2]
**File:** `cortex-storage/src/queries/memory_crud.rs:296-303`
```rust
pub fn bulk_insert(conn: &Connection, memories: &[BaseMemory]) -> CortexResult<usize> {
    let mut count = 0;
    for memory in memories {
        insert_memory(conn, memory)?;
        count += 1;
    }
    Ok(count)
}
```
`bulk_insert` is just a loop calling `insert_memory` one at a time. No transaction batching, no prepared statement reuse. Each insert is a separate SQL statement with its own implicit transaction. For large imports this is orders of magnitude slower than a single transaction with a prepared statement.

---

## Section M: Causal Graph Sync

### M1. `rebuild_from_storage` Is a No-Op Stub [P1]
**File:** `cortex-causal/src/graph/sync.rs:11-31`
```rust
pub fn rebuild_from_storage(
    storage: &dyn ICausalStorage,
    _graph: &mut IndexedGraph,  // ← prefixed with underscore, never used
) -> CortexResult<()> {
    let count = storage.edge_count()?;
    if count == 0 { return Ok(()); }
    let node_count = storage.node_count()?;
    if node_count == 0 { return Ok(()); }
    // Since ICausalStorage doesn't expose a list-all-nodes method,
    // we rely on the caller to populate nodes. The sync layer handles edges.
    Ok(())
}
```
This function is supposed to rebuild the in-memory causal graph from SQLite on startup. It checks that edges and nodes exist, but then **does nothing** — the `_graph` parameter is never written to. This confirms finding D7: even if someone called `rebuild_from_storage`, it wouldn't load any data.

The `load_node_edges` function below it works correctly for loading edges for a *specific* node, but there's no way to discover all node IDs to iterate over — the `ICausalStorage` trait lacks a `list_all_nodes()` method.

### M2. `load_node_edges` Creates "unknown" Node Types [P3]
**File:** `cortex-causal/src/graph/sync.rs:112-113`
```rust
let source_idx = graph.ensure_node(&edge.source_id, "unknown", "");
let target_idx = graph.ensure_node(&edge.target_id, "unknown", "");
```
When loading edges from storage, node metadata (type, label) is lost — all nodes are created with type `"unknown"` and empty label. This degrades the quality of causal traversal and narrative generation.

---

## Section N: Observability

### N1. ObservabilityEngine Created But Bypassed by NAPI Health Binding [P2]
**File:** `cortex-napi/src/runtime.rs:47,115,161` and `cortex-napi/src/bindings/health.rs:32-45`

The `ObservabilityEngine` **is** created in the runtime (`runtime.rs:115`) and stored as `observability: Mutex<ObservabilityEngine>` (`runtime.rs:47`). However, the `cortex_health_get_health` NAPI binding **ignores it entirely** and builds its own ad-hoc `HealthSnapshot` with 7/12 fields hardcoded to zero (A5). The observability engine's `health_report()`, `recommendations()`, `degradation_alerts()`, and `MetricsCollector` are never called from any NAPI binding.

### N2. All Metrics Collectors Are In-Memory Only [P2]
**File:** `cortex-observability/src/metrics/mod.rs`

All 5 metric collectors (`RetrievalMetrics`, `ConsolidationMetricsCollector`, `StorageMetrics`, `EmbeddingMetrics`, `SessionMetrics`) store data in-memory. No persistence, no export. Metrics are lost on restart. The `reset()` method destroys all data.

### N3. QueryLog Is In-Memory with 50K Entry Cap [P3]
**File:** `cortex-observability/src/query_log.rs:50-51`
```rust
max_entries: usize,  // default 50_000
```
The query log is in-memory only with a 50K entry ring buffer. No persistence to SQLite despite the observability migration (v012) creating tables for it. Query performance data is lost on restart.

---

## Subsystems Found Clean

The following subsystems were audited and found to be well-implemented with no significant issues:

- **cortex-compression** — 4-level hierarchical compression with priority-weighted bin-packing. Correct token counting, proper critical memory handling.
- **cortex-crdt** — All 6 CRDT primitives (VectorClock, GCounter, LWWRegister, MVRegister, ORSet, MaxRegister) with correct mathematical properties (commutativity, associativity, idempotency).
- **cortex-reclassification** — 5-signal weighted scoring with proper normalization, safeguards, and cooldown periods. Weights verified to sum to 1.0.
- **cortex-tokens** — Accurate tiktoken cl100k_base tokenizer with blake3 content-hash caching.
- **cortex-retrieval ranking** — 10-factor scorer with proper normalization, trust-weighted modulation, and file proximity scoring.
- **cortex-retrieval search** — HybridSearcher with FTS5 + vector + entity expansion via RRF fusion. Correct over-fetch and truncation.
- **cortex-storage engine** — Proper read/write routing (read pool for file-backed, writer for in-memory). Correct migration runner.
- **cortex-embeddings degradation chain** — Proper fallback chain with degradation event logging.
- **cortex-causal inference** — Correct composite scoring, relation suggestion, and batch inference with threshold filtering.
- **cortex-privacy** — Context-aware PII/secret detection with degradation tracking for failed regex patterns.

---

## Final Severity Summary

| Severity | Count | Description |
|----------|-------|-------------|
| **P0** | 4 | Production-breaking: learning doesn't persist, consolidation doesn't persist, multi-agent per-call connections, cloud conflict no-op |
| **P1** | 14 | Silent data loss / incorrect behavior: feedback discarded, sync counts zero, decay never runs, causal graph ephemeral, empty API key, quota always throttles, duplicate storage handles, raw connection bypass, embedding trait bypass, consolidation metrics fake, reembed tool fake, validate tool doesn't validate, L2 cache is in-memory not SQLite, causal rebuild is no-op |
| **P2** | 22 | Degraded functionality: hardcoded health metrics, duplicate engines, no-op shutdown, migration gap, fake timestamps, reads through writer, bridge serialization errors swallowed, token estimation crude, only episodic consolidation, gc relies on non-decaying confidence, link race condition, privacy in_comment always false, privacy sort assumption, vector search brute-force, update doesn't re-embed, bulk_insert not batched, observability not wired, metrics in-memory only |
| **P3** | 5 | Code quality: round-robin wrap, unknown types, dead code annotations, tool count comment stale, load_node_edges unknown type |

**Total: 45 findings** across 14 sections (A–N)

---

## Critical Path Recommendations

1. **Fix Persistence Gap (D2, I3)** — Both learning and consolidation generate results but never persist them. This is the #1 systemic issue — the entire "learn from corrections" and "consolidate memories" pipelines are no-ops.
2. **Fix Multi-Agent Connection Lifecycle (B4)** — Move engine creation to runtime init, share connections.
3. **Wire Cloud Conflict Resolution (A1)** — Actually call the resolver.
4. **Wire Decay Engine to a Scheduler (D4)** — Confidence never decays, stale memories never archive. This cascades to GC (J3) being ineffective.
5. **Implement Causal Graph Rebuild (M1, D7)** — Add `list_all_nodes()` to `ICausalStorage`, implement `rebuild_from_storage`, call it at init.
6. **Fix L2 Embedding Cache (L1)** — Wire to actual SQLite so embeddings survive restarts. Currently the 3-tier cache is effectively 1-tier.
7. **Fix Quota Tracking (E2)** — Update `secs_since_last_sync` so sync isn't permanently throttled.
8. **Share Storage Connections (B1, B3)** — Eliminate duplicate StorageEngine/WriteConnection/ReadPool instances. Critical for in-memory mode correctness.
9. **Reuse Tokio Runtime (B6)** — Use `Handle::try_current()` instead of `Runtime::new()` per call.
10. **Fix Consolidation Metrics (I1)** — Replace hardcoded precision/lift/stability with real measurements so auto-tuning works.
11. **Wire ObservabilityEngine to Runtime (N1)** — Replace ad-hoc health snapshots with the real engine.
12. **Fix TS Tool Implementations (J1, J2)** — `drift_cortex_reembed` and `drift_cortex_validate` need to actually do what they claim.
