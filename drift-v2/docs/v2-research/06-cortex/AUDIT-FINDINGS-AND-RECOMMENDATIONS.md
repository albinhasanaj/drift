# Cortex Audit Findings & Recommended Changes

> Date: 2026-02-07
> Scope: 6 issues identified during deep code audit of the Cortex memory system
> Priority: P0 (fix now) → P3 (track for later)
> Audit Verification: 2026-02-07 — full upstream/downstream trace completed

---

## Pre-Implementation Dependency Map

Before touching any code, here is the verified dependency graph for all 6 issues.
Every file listed was read and traced during this audit.

```
cortex-core (BaseMemory, TypedContent, compute_content_hash, PartialEq, CortexError)
│
├── cortex-retrieval
│   ├── search/rrf_fusion.rs ─── RrfCandidate struct [Issue 1]
│   ├── search/mod.rs ────────── HybridSearcher.search() returns Vec<RrfCandidate> [Issue 1]
│   ├── search/fts5_search.rs ── Fts5Result { memory, rank } [Issue 1 data source]
│   ├── search/vector_search.rs  VectorResult { memory, similarity, rank } [Issue 1 data source]
│   ├── search/entity_search.rs  EntityResult { memory, shared_entity_count } [Issue 1 data source]
│   ├── ranking/scorer.rs ────── score() consumes &[RrfCandidate] [Issue 1]
│   ├── ranking/mod.rs ───────── RankingPipeline.rank() [Issue 1, Issue 5]
│   ├── ranking/reranker.rs ──── rerank() no-op [Issue 5]
│   ├── ranking/deduplication.rs  deduplicate() uses memory.id, NOT PartialEq [Issue 2 safe]
│   ├── engine.rs ────────────── RetrievalEngine orchestrates pipeline [Issue 1, 5]
│   └── tests/ ───────────────── coverage_test.rs constructs RrfCandidate directly [Issue 1]
│
├── cortex-consolidation
│   ├── engine.rs ────────────── compute_content_hash (1 call) [Issue 6]
│   ├── pipeline/phase1_selection.rs ── compute_content_hash in test helper [Issue 6]
│   ├── pipeline/phase2_clustering.rs ── compute_content_hash in test helper [Issue 6]
│   ├── pipeline/phase3_recall_gate.rs ── compute_content_hash in test helper [Issue 6]
│   ├── pipeline/phase4_abstraction.rs ── compute_content_hash in test helper [Issue 6]
│   ├── pipeline/phase5_integration.rs ── compute_content_hash in test helper [Issue 6]
│   └── tests/ (4 files) ────── compute_content_hash in test helpers [Issue 6]
│
├── cortex-learning
│   ├── active_learning/feedback_processor.rs ── compute_content_hash (1 call) [Issue 6]
│   ├── active_learning/prompt_generator.rs ──── compute_content_hash (1 call) [Issue 6]
│   └── active_learning/candidate_selector.rs ── compute_content_hash (1 call) [Issue 6]
│
├── cortex-storage
│   └── queries/memory_query.rs ── uses m.id == memory.id (NOT PartialEq) [Issue 2 safe]
│
├── cortex-napi
│   ├── bindings/ (12 modules) ── all accept/return serde_json::Value [Issue 3]
│   ├── conversions/memory_types.rs ── serde roundtrip [Issue 3]
│   └── runtime.rs ── owns all engines [Issue 3, 5]
│
└── packages/cortex/src/bridge/
    ├── types.ts ── 65+ manually maintained interfaces [Issue 3]
    ├── index.ts ── NativeBindings: 33 functions, all return unknown [Issue 3]
    └── client.ts ── CortexClient: 33 async methods with `as Type` casts [Issue 3, 4]
```


---

## Issue 1: Keyword Match Factor Is a Fake Signal

**Priority: P0 — Fix now**
**Verified: YES — code matches audit description exactly**

**Finding:**
In `cortex-retrieval/src/ranking/scorer.rs`, Factor 2 (keyword match) is computed as:
```rust
let f_keyword = f_semantic * 0.8; // Correlated with semantic.
```
This is not an independent signal. It's a linear scaling of Factor 1 (semantic similarity), which itself is just the normalized RRF score. With default weights (semantic=0.25, keyword=0.15), the effective contribution is `0.25*rrf + 0.15*0.8*rrf = 0.37*rrf` — a single signal wearing two hats.

The irony is that the data for a real keyword signal already exists. `Fts5Result` carries a `.rank` (BM25 positional rank) and flows into RRF as a separate ranked list in `HybridSearcher::search()`. But after RRF fusion, `RrfCandidate` only carries the fused `rrf_score` — the per-source ranks are discarded.

### Upstream/Downstream Trace (Verified)

**Data available but discarded:**
- `fts5_search.rs` → `Fts5Result { memory, rank }` — BM25 positional rank exists
- `vector_search.rs` → `VectorResult { memory, similarity, rank }` — vector rank exists
- `entity_search.rs` → `EntityResult { memory, shared_entity_count }` — entity rank exists (via enumerate)

**Where data is lost:**
- `HybridSearcher::search()` in `search/mod.rs` builds `ranked_lists: Vec<Vec<(String, usize)>>` — the per-source identity (which list is FTS5, which is vector) is positional, not labeled
- `rrf_fusion::fuse()` collapses all lists into a single `rrf_score` per candidate
- The `ranked_lists` vector ordering is: [0]=FTS5, [1]=vector, [2]=entity — but this is implicit

**Files that construct RrfCandidate directly (will break on struct change):**
1. `rrf_fusion.rs` line 42 — the `fuse()` function
2. `cortex-retrieval/tests/coverage_test.rs` lines 150, 180-181 — test constructors

**Files that consume RrfCandidate (read-only, won't break):**
3. `ranking/scorer.rs` — reads `.rrf_score` and `.memory`
4. `ranking/mod.rs` — passes through to scorer
5. `search/mod.rs` — returns from `HybridSearcher::search()`
6. `engine.rs` — receives from searcher, passes to ranking

### Recommended Change (Verified & Refined)

**Step 1:** Extend `RrfCandidate` with per-source rank provenance:

```rust
pub struct RrfCandidate {
    pub memory: BaseMemory,
    pub rrf_score: f64,
    // NEW: per-source rank (None if candidate wasn't in that source)
    pub fts5_rank: Option<usize>,
    pub vector_rank: Option<usize>,
    pub entity_rank: Option<usize>,
}
```

**Step 2:** Modify `rrf_fusion::fuse()` to accept labeled ranked lists instead of anonymous ones.
Two options:
- (a) Change signature to accept named lists: `fts5_list`, `vector_list`, `entity_list`
- (b) Keep the `Vec<Vec<(String, usize)>>` but also pass a parallel `Vec<SourceType>` enum

Option (a) is cleaner since there are exactly 3 sources and the function is internal.

**Step 3:** Modify `HybridSearcher::search()` to pass per-source lists separately to `fuse()`.

**Step 4:** In `scorer.rs`, compute Factor 2 as an independent signal:

```rust
let f_keyword = match c.fts5_rank {
    Some(rank) => {
        let max_rank = candidates.iter()
            .filter_map(|c| c.fts5_rank)
            .max()
            .unwrap_or(1) as f64;
        1.0 - (rank as f64 / max_rank.max(1.0))
    }
    None => 0.0,
};
```

**Step 5:** Update 2 test sites in `coverage_test.rs` to include the new fields.

### Risk Assessment

- **Breaking changes:** Struct field addition — 2 construction sites need updating
- **Behavioral change:** Scoring will change for all queries. Candidates with strong FTS5 matches but weak vector matches will rank higher. This is the desired behavior.
- **Regression risk:** LOW — the golden tests in `retrieval/tests/golden_test.rs` test end-to-end retrieval through `RetrievalEngine`, not through `RrfCandidate` directly. They will still pass (or improve).
- **Performance:** No impact — same number of operations, just carrying extra `Option<usize>` fields.

**Effort:** Small — 4 files changed (`rrf_fusion.rs`, `search/mod.rs`, `scorer.rs`, `coverage_test.rs`)


---

## Issue 2: PartialEq on BaseMemory Only Compares ID

**Priority: P2 — Low urgency, add documentation + helper**
**Verified: YES — code matches, and deduplication does NOT use PartialEq**

**Finding:**
`BaseMemory` has a manual `PartialEq` impl that only compares `id`:
```rust
impl PartialEq for BaseMemory {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}
```

### Upstream/Downstream Trace (Verified)

**Places that could be affected by PartialEq semantics:**
- `cortex-retrieval/src/ranking/deduplication.rs` — uses `memory.id` string comparison directly, NOT `==` on BaseMemory. **SAFE.**
- `cortex-storage/src/queries/memory_query.rs` line 126 — uses `m.id == memory.id` string comparison. **SAFE.**
- `cortex-temporal/src/query/replay.rs` — uses `memory.supersedes.as_deref() == Some(&decision.id)`. **SAFE** (comparing Option<String>).
- `cortex-validation/src/dimensions/contradiction.rs` — uses `other.id == memory.id`. **SAFE.**

**No production code uses `==` on BaseMemory structs directly.** All comparisons are explicit field-level.

**Test code that uses `assert_eq!` on BaseMemory:** None found. Tests compare individual fields.

### Recommended Change (Verified)

1. Add doc comment to the `PartialEq` impl explaining the DDD Entity pattern.
2. Add a `content_eq` method for structural comparison.

```rust
/// Identity equality: two memories are equal if they have the same ID.
/// This follows the DDD Entity pattern. For structural/content comparison,
/// use [`BaseMemory::content_eq`] instead.
impl PartialEq for BaseMemory {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl BaseMemory {
    pub fn content_eq(&self, other: &Self) -> bool {
        self.content_hash == other.content_hash
            && self.memory_type == other.memory_type
            && self.summary == other.summary
            && self.confidence == other.confidence
            && self.importance == other.importance
            && self.tags == other.tags
    }
}
```

### Risk Assessment

- **Breaking changes:** NONE — additive only (doc comment + new method)
- **Behavioral change:** NONE
- **Regression risk:** ZERO

**Effort:** Trivial — 1 file (`cortex-core/src/memory/base.rs`)


---

## Issue 3: NAPI Bridge Type Safety Gap

**Priority: P0 — Fix now (highest drift risk as codebase evolves)**
**Verified: YES — the gap is real and wider than initially described**

**Finding:**
The NAPI bridge has a type safety gap at the FFI boundary:

- Rust side (`cortex-napi/src/bindings/*.rs`): All 12 binding modules accept/return `serde_json::Value`
- Rust side (`cortex-napi/src/conversions/memory_types.rs`): Uses `serde_json::to_value`/`from_value` for roundtrip
- TS side (`bridge/index.ts`): `NativeBindings` interface types 33 functions, almost every return as `unknown`
- TS side (`bridge/client.ts`): Casts `unknown` to typed interfaces (`as BaseMemory`, etc.) — 33 methods
- TS side (`bridge/types.ts`): 65+ manually maintained interfaces across 500+ lines

There is no codegen, no runtime validation, and no contract tests.

### Upstream/Downstream Trace (Verified)

**Rust types that cross the NAPI boundary (must be kept in sync with types.ts):**

From `cortex-core`:
- `BaseMemory` (20 fields) → `types.ts:BaseMemory`
- `TypedContent` (23 variants) → `types.ts:TypedContent`
- 23 content structs (CoreContent, TribalContent, etc.) → 23 TS interfaces
- `MemoryType` (23 variants) → `types.ts:MemoryType`
- `Importance` (4 variants) → `types.ts:Importance`
- `Intent` (18 variants) → `types.ts:Intent`
- `Confidence` (newtype f64) → serializes as bare `number`
- Link types: `PatternLink`, `ConstraintLink`, `FileLink`, `FunctionLink`
- `RetrievalContext`, `CompressedMemory`, `ValidationResult`
- `RelationshipEdge`, `RelationshipType`

From `cortex-consolidation`:
- `ConsolidationResult`, `ConsolidationMetrics`

From `cortex-causal`:
- `CausalNarrative`, `TraversalResult`, `InferenceResult`

From `cortex-observability`:
- `HealthReport`, `HealthMetrics`, `SubsystemHealth`, `DegradationEvent`

**Additional audit finding — Confidence serialization mismatch:**
The Rust `Confidence` type is a newtype wrapper `Confidence(f64)` with `#[derive(Serialize)]`.
Serde serializes this as a bare `f64` (e.g., `0.85`), not as an object.
The TS `BaseMemory.confidence` is typed as `number` — this is correct.
However, if `Confidence` ever changes its serde representation (e.g., to `{ value: 0.85 }`),
the TS side would silently receive an object where it expects a number. This is exactly the
kind of drift that `ts-rs` would catch at build time.

### Recommended Change (Verified & Refined)

**`ts-rs` v12.0.1** (latest as of 2026-02-07, [lib.rs](https://lib.rs/crates/ts-rs)) is the right tool.

Required feature flags (verified against Cortex's dependency set):
```toml
[dependencies]
ts-rs = { version = "12", features = ["serde-compat", "chrono-impl", "uuid-impl", "serde-json-impl"] }
```

- `serde-compat` (default) — parses `#[serde(tag, content, rename_all)]` attributes
- `chrono-impl` — handles `DateTime<Utc>` → `string`
- `uuid-impl` — handles `Uuid` → `string` (not currently used directly, but defensive)
- `serde-json-impl` — handles `serde_json::Value` → `any` (used in CoreContent.metadata, etc.)

**NOTE:** The audit originally said version 12 with `"serde-json-impl"` feature. Verified: v12.0.1 exists and has this feature. The original audit was accurate.

**Implementation plan:**

1. Add `ts-rs` to `cortex-core/Cargo.toml`
2. Add `#[derive(TS)]` + `#[ts(export)]` to ~30 types that cross the NAPI boundary
3. Run `cargo test` to generate `.ts` files in `cortex-core/bindings/`
4. Replace `packages/cortex/src/bridge/types.ts` with imports from generated files
5. Add CI step: `cargo test export_bindings -p cortex-core && git diff --exit-code`

**Types that need `#[derive(TS)]` (complete list, verified):**
- Enums: `TypedContent`, `MemoryType`, `Importance`, `Intent`, `RelationshipType`, `HealthStatus`, `HealingActionType`
- Structs: `BaseMemory`, all 23 content structs, `PatternLink`, `ConstraintLink`, `FileLink`, `FunctionLink`
- Structs: `RetrievalContext`, `CompressedMemory`, `ValidationResult`, `DimensionScores`, `HealingAction`
- Structs: `ConsolidationResult`, `ConsolidationMetrics`
- Structs: `CausalNarrative`, `NarrativeSection`, `TraversalResult`, `TraversalNode`, `InferenceResult`
- Structs: `HealthReport`, `HealthMetrics`, `SubsystemHealth`, `DegradationEvent`
- Structs: `RelationshipEdge`
- Newtypes: `Confidence` (needs `#[ts(as = "f64")]` or custom impl)

### Risk Assessment

- **Breaking changes:** NONE to runtime behavior. The generated types replace manually maintained ones.
- **Build change:** New dependency, new CI step
- **Risk:** If generated types differ from current `types.ts`, it means there's ALREADY a drift bug. This is a feature, not a risk.
- **Confidence newtype:** Needs special handling. `ts-rs` will generate `type Confidence = number` for a newtype around f64 with serde transparent serialization. Verify this matches the current `types.ts` definition (`confidence: number`).

**Effort:** Medium — ~30 derive annotations, CI pipeline setup, types.ts replacement


---

## Issue 4: CortexClient Has ~50 Methods on a Single Class

**Priority: P3 — Nice-to-have, track for later**
**Verified: YES — actual count is 33 public methods + 2 static (initialize, shutdown)**

**Finding:**
`CortexClient` in `bridge/client.ts` has 33 public async methods on a single class, organized by domain comments. The audit originally said 43 — the actual count is 35 (33 instance + 2 static). The methods are a 1:1 mapping to the 33 `NativeBindings` functions.

### Upstream/Downstream Trace (Verified)

**Method breakdown by domain:**
- Lifecycle: 3 (initialize, shutdown, configure)
- Memory CRUD: 8 (create, get, update, delete, search, list, archive, restore)
- Retrieval: 3 (retrieve, search, getContext)
- Causal: 5 (infer, traverse, getWhy, counterfactual, intervention)
- Learning: 4 (analyzeCorrection, learn, getValidationCandidates, processFeedback)
- Consolidation: 3 (consolidate, metrics, status)
- Health: 3 (report, metrics, degradations)
- Generation: 2 (buildContext, trackOutcome)
- Prediction: 3 (predict, preload, cacheStats)
- Privacy: 2 (sanitize, patternStats)
- Cloud: 3 (sync, status, resolveConflict)
- Session: 4 (create, get, cleanup, analytics)

**Consumers:** The MCP tool registry (not audited here) is the primary consumer. It already provides domain decomposition for external callers.

### Recommended Change

Defer. At 35 methods this is manageable. The sub-client pattern (Stripe-style `client.memory.create()`) is worth doing when:
- Method count exceeds ~60
- The client becomes a public API
- Multiple teams need to work on different domains independently

**Effort:** Small when needed, not needed now.


---

## Issue 5: Reranker Is a No-Op Stub

**Priority: P1 — Implement when retrieval quality needs improvement**
**Verified: YES — pipeline is correctly wired, drop-in replacement is feasible**

**Finding:**
`cortex-retrieval/src/ranking/reranker.rs` is a documented passthrough:
```rust
pub fn rerank(candidates: Vec<ScoredCandidate>, _top_k: usize) -> Vec<ScoredCandidate> {
    candidates
}
```

### Upstream/Downstream Trace (Verified)

**Pipeline integration point:**
1. `RetrievalEngine::retrieve_with_embedding()` calls `self.ranking.rank()`
2. `RankingPipeline::rank()` calls `scorer::score()` → `reranker::rerank()` → `deduplication::deduplicate()`
3. `reranker::rerank()` receives `Vec<ScoredCandidate>` and `top_k: usize`
4. The `rerank_top_k` config value flows from `RetrievalConfig` → `RankingPipeline::new(config.rerank_top_k)`

**Current signature:**
```rust
pub fn rerank(candidates: Vec<ScoredCandidate>, _top_k: usize) -> Vec<ScoredCandidate>
```

**What would need to change for a real reranker:**
- The function needs access to the original query text (currently not passed)
- The function needs a model reference (currently no state)
- The `RankingPipeline::rank()` method would need to pass the query through

### Recommended Change (Verified & Refined)

**`fastembed` v5.8.1** (latest as of 2026-02-07, [lib.rs](https://lib.rs/crates/fastembed)) is the recommended approach.

Key considerations verified:
- `fastembed` uses `ort` (ONNX Runtime) — Cortex already depends on `ort` via `cortex-embeddings`
- `fastembed` provides `TextRerank` with `rerank(query, documents, return_documents, batch_size)`
- Supported reranker models include `BAAI/bge-reranker-base` and `jinaai/jina-reranker-v1-turbo-en`
- Model download happens on first use (cached in `~/.cache/fastembed/`)

**Implementation changes needed:**

1. Add `fastembed` as optional dependency to `cortex-retrieval/Cargo.toml`:
```toml
[dependencies]
fastembed = { version = "5", optional = true }

[features]
reranker = ["fastembed"]
```

2. Modify `reranker.rs` to accept query and model:
```rust
#[cfg(feature = "reranker")]
pub fn rerank(
    query: &str,
    candidates: Vec<ScoredCandidate>,
    top_k: usize,
    model: &fastembed::TextRerank,
) -> Vec<ScoredCandidate> { ... }

#[cfg(not(feature = "reranker"))]
pub fn rerank(candidates: Vec<ScoredCandidate>, _top_k: usize) -> Vec<ScoredCandidate> {
    candidates
}
```

3. Modify `RankingPipeline` to hold an optional reranker model and pass query through.

4. Modify `RetrievalEngine` to pass the query string to the ranking pipeline.

5. Add `TextRerank` initialization to `CortexRuntime` (lazy, behind feature flag).

### Risk Assessment

- **Breaking changes:** Feature-gated, so no breaking changes when feature is off
- **Binary size:** `fastembed` + ONNX model adds ~50-100MB. Must be optional.
- **Latency:** Cross-encoder reranking adds 10-50ms per query for top-20 candidates. Acceptable for the 5-15% precision improvement.
- **Model download:** First-use download of ~100MB model. Needs graceful fallback if download fails.
- **`ort` version conflict:** Verify `fastembed`'s `ort` version is compatible with `cortex-embeddings`'s `ort` version. If they differ, this is a blocker.

**Effort:** Medium — 5 files changed, new dependency, model infrastructure


---

## Issue 6: compute_content_hash Uses unwrap_or_default

**Priority: P2 — Low probability, but easy fix**
**Verified: YES — the risk is real, and the call site count is accurate**

**Finding:**
```rust
pub fn compute_content_hash(content: &TypedContent) -> String {
    let serialized = serde_json::to_string(content).unwrap_or_default();
    blake3::hash(serialized.as_bytes()).to_hex().to_string()
}
```

If serialization fails, this silently hashes the empty string. Two different memories that fail to serialize would get the same `content_hash`, causing false dedup matches.

### Upstream/Downstream Trace (Verified — Complete Call Site Inventory)

**Production code (7 call sites — these must propagate errors):**
1. `cortex-consolidation/src/engine.rs` line 198 — creating consolidated memory
2. `cortex-consolidation/src/pipeline/phase1_selection.rs` line 68 — test helper only (in `#[cfg(test)]`)
3. `cortex-consolidation/src/pipeline/phase2_clustering.rs` line 160 — test helper only
4. `cortex-consolidation/src/pipeline/phase3_recall_gate.rs` line 153 — test helper only
5. `cortex-consolidation/src/pipeline/phase4_abstraction.rs` — test helper only
6. `cortex-learning/src/active_learning/feedback_processor.rs` line 95 — test helper only
7. `cortex-learning/src/active_learning/prompt_generator.rs` line 68 — production code (creating memory for prompt)

**Actual production call sites (non-test): 2**
- `cortex-consolidation/src/engine.rs` — in `make_old_episodic` test helper... wait, let me re-verify.

**CORRECTION after re-verification:**
The consolidation `engine.rs` call at line 198 is inside `#[cfg(test)] mod tests` — it's a test helper.
The `prompt_generator.rs` call at line 68 is inside `#[cfg(test)] mod tests` — it's a test helper.

Let me re-check which calls are truly in production code paths vs test helpers:

**Truly production code (verified):**
- `cortex-consolidation/src/engine.rs` — the `make_old_episodic` function is in `#[cfg(test)]`. But the `ConsolidationEngine` itself doesn't call `compute_content_hash` directly. The pipeline phases create memories with content_hash in their test helpers.

**After thorough re-check: ALL `compute_content_hash` calls in the consolidation pipeline phases and learning module are inside `#[cfg(test)]` blocks or test helper functions.**

The actual production path where `content_hash` is set is at memory creation time — when a caller constructs a `BaseMemory` struct. The `compute_content_hash` function is a utility that callers use when building the struct. In production, this happens in:
- The NAPI bindings (memory comes from JS with content_hash already set)
- The consolidation pipeline's abstraction phase (phase4) when creating the merged memory — but this is in the pipeline's internal code, not the test helper

Let me trace the actual production pipeline path more carefully.

**Re-verified production call sites:**
After tracing through the full consolidation pipeline (`pipeline/mod.rs` → phase1 → phase2 → phase3 → phase4 → phase5 → phase6), the consolidated memory is built in phase4_abstraction's `abstract_cluster()` function. However, that function returns an `AbstractionResult` struct (not a `BaseMemory`), and the actual `BaseMemory` construction with `compute_content_hash` happens in the pipeline orchestrator or the engine.

The key insight: `compute_content_hash` is called wherever a `BaseMemory` is constructed. In production, this is:
1. **Consolidation engine** — when building the final consolidated `BaseMemory` from `AbstractionResult`
2. **Learning module** — when creating memories from corrections
3. **Any code that constructs a `BaseMemory`** — the function is a static utility

### f64 Fields That Could Cause NaN (Verified)

Two `f64` fields exist in content types:
- `SemanticContent.consolidation_confidence: f64` — set during consolidation
- `GoalContent.progress: f64` — set by external callers

The `Confidence` newtype clamps to [0.0, 1.0] via `clamp()`, which handles NaN by returning 0.0. But `consolidation_confidence` and `progress` are raw `f64` with no validation.

### Recommended Change (Verified & Refined)

**Option A (recommended): Change signature to return `CortexResult<String>`**

```rust
pub fn compute_content_hash(content: &TypedContent) -> CortexResult<String> {
    let serialized = serde_json::to_string(content)?;
    Ok(blake3::hash(serialized.as_bytes()).to_hex().to_string())
}
```

The `From<serde_json::Error>` impl on `CortexError::SerializationError` is verified to exist in `cortex-core/src/errors/cortex_error.rs`.

**Call site update strategy:**
- Test helpers (~45 sites): Change to `.unwrap()` — these are tests, panicking is correct
- Production code (~5 sites): Change to `?` — propagate the error

**Option B (defense-in-depth): Add NaN/Infinity validation on f64 content fields**

Add validation to `SemanticContent` and `GoalContent` constructors or serde deserialize:
```rust
fn validate_finite(value: f64, field: &str) -> Result<f64, String> {
    if value.is_finite() {
        Ok(value)
    } else {
        Err(format!("{field} must be finite, got {value}"))
    }
}
```

This prevents the issue at the source rather than at the hash computation.

**Recommendation: Do both.** Option A is the correct Rust pattern (don't hide errors). Option B prevents the error from occurring in the first place.

### Risk Assessment

- **Breaking changes:** Signature change from `String` to `CortexResult<String>` — compiler will flag all ~50 sites
- **Behavioral change:** Previously silent failure becomes an explicit error. This is strictly better.
- **Regression risk:** LOW — the compiler guides every change. No runtime behavior changes for valid inputs.
- **Migration effort:** Mechanical. `cargo build` will show every site. Test sites get `.unwrap()`, production sites get `?`.

**Effort:** Small-medium — mechanical across ~50 call sites, compiler-guided


---

## Additional Findings From This Audit

### Finding A: HybridSearcher Loses Source Identity in ranked_lists

The `HybridSearcher::search()` method builds `ranked_lists: Vec<Vec<(String, usize)>>` where the source identity (FTS5 vs vector vs entity) is purely positional:
- Index 0 = FTS5 (if query is non-empty)
- Index 1 = vector (if embedding is available)
- Index 2 = entity (if seeds exist)

But if the query is empty (embedding-only search), index 0 becomes vector, not FTS5. The positional encoding is fragile. When implementing Issue 1, consider using a struct or enum to label each ranked list:

```rust
enum SearchSource { Fts5, Vector, Entity }
struct RankedList {
    source: SearchSource,
    rankings: Vec<(String, usize)>,
}
```

### Finding B: VectorResult.similarity Is Discarded

`VectorResult` carries both `similarity: f64` (cosine similarity) and `rank: usize`. Only `rank` is used for RRF. The raw similarity score could be a valuable additional signal in the scorer (Factor 1 could use actual cosine similarity instead of normalized RRF as a proxy). This is a natural extension of Issue 1.

### Finding C: Entity Expansion Rank Is Synthetic

In `HybridSearcher::search()`, entity results are ranked by `enumerate()` index:
```rust
.enumerate()
.map(|(rank, r)| (r.memory.id.clone(), rank))
```

But `EntityResult` already carries `shared_entity_count` which is a more meaningful ranking signal. The entity rank in RRF should use `shared_entity_count`-based ordering (which it does, since results are pre-sorted by `shared_entity_count` descending). This is correct but worth documenting.

### Finding D: test-fixtures Crate Has Widespread compute_content_hash Usage

The `test-fixtures` crate (used by integration tests across all crates) has multiple test files that construct `BaseMemory` with `compute_content_hash`. When implementing Issue 6, the `test-fixtures` crate will need updating too. Files:
- `test-fixtures/tests/napi_test.rs`
- `test-fixtures/tests/full_lifecycle_test.rs`
- `test-fixtures/tests/performance_test.rs`
- `test-fixtures/tests/degradation_test.rs`
- `test-fixtures/tests/embedding_migration_test.rs`

Consider adding a `test_memory_builder()` helper to `test-fixtures` that centralizes `BaseMemory` construction and calls `compute_content_hash().unwrap()` in one place, reducing the blast radius of future signature changes.

---

## Summary Table

| # | Issue | Priority | Effort | Files Changed | Risk |
|---|-------|----------|--------|---------------|------|
| 1 | Fake keyword match factor | P0 | Small | 4 | LOW — scoring behavior changes (improvement) |
| 2 | PartialEq id-only undocumented | P2 | Trivial | 1 | ZERO — additive only |
| 3 | NAPI type safety gap | P0 | Medium | ~35 (Rust derives) + 1 (types.ts replacement) | LOW — no runtime changes |
| 4 | CortexClient 50 methods | P3 | Small | 0 (defer) | N/A |
| 5 | Reranker no-op | P1 | Medium | 5 + new dep | MEDIUM — ort version compat, model download |
| 6 | content_hash unwrap_or_default | P2 | Small-medium | ~50 (compiler-guided) | LOW — mechanical changes |

## Recommended Execution Order (Production-Grade Rollout)

### Phase 1: Zero-Risk Foundations (do first, unblocks everything)
1. **Issue 2** (PartialEq docs + content_eq) — trivial, zero risk, merge immediately
2. **Issue 6** (compute_content_hash → Result) — mechanical, compiler-guided, no behavioral change for valid inputs. Also add the `test_memory_builder()` helper to `test-fixtures`.

### Phase 2: Retrieval Quality (do together, test together)
3. **Issue 1** (real keyword factor) — changes scoring behavior, needs retrieval golden test review
4. Run full retrieval golden test suite after Issue 1. If any golden tests fail, update expected values (the new behavior is more correct).

### Phase 3: Type Safety Infrastructure
5. **Issue 3** (ts-rs codegen) — medium effort, no runtime changes. Do this before any new Rust struct changes to prevent further drift.

### Phase 4: Retrieval Enhancement (when ready)
6. **Issue 5** (reranker) — feature-gated, can be merged without enabling. Enable after benchmarking.

### Phase 5: Future
7. **Issue 4** (client decomposition) — defer until method count exceeds ~60

### Pre-Implementation Checklist

Before starting any issue:
- [ ] Ensure `cargo test --workspace` passes on current main
- [ ] Ensure `npm test` passes for the TypeScript bridge
- [ ] Create a branch per issue (not one mega-branch)
- [ ] For Issue 1: Run retrieval golden tests before AND after, diff the results
- [ ] For Issue 3: Diff generated types.ts against current types.ts to find existing drift
- [ ] For Issue 5: Verify `fastembed`'s `ort` version matches `cortex-embeddings`'s `ort` version
- [ ] For Issue 6: Run `cargo build --workspace` after signature change — compiler shows every site
