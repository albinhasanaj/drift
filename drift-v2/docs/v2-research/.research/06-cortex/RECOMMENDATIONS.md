# 06 Cortex Memory System — Recommendations

> Concrete improvement recommendations for Drift v2's Cortex memory system, derived from the v1 recap and targeted external research (R1-R15).

---

## CX1: Hybrid Search — FTS5 + sqlite-vec with Reciprocal Rank Fusion

**Priority**: P0
**Evidence**: R2 (Simon Willison, Microsoft Azure), R8 (sqlite-vec best practices)

Replace vector-only retrieval with hybrid search combining FTS5 full-text search and sqlite-vec vector similarity, fused via Reciprocal Rank Fusion (RRF).

**Why**: Vector search misses exact keyword matches (function names, pattern IDs, specific terms like "bcrypt"). Full-text search misses semantic meaning. RRF combines both without score normalization: `score = Σ 1/(60 + rank_i)`.

**Implementation**:
- Add FTS5 virtual table on memory content + summary + tags
- Run both FTS5 and vector queries in parallel
- Fuse results with RRF (k=60)
- Pre-filter by type/importance before both searches to reduce candidate set

---

## CX2: Code-Specific Embedding Model

**Priority**: P0
**Evidence**: R3 (Modal benchmarks, CodeXEmbed paper, Jina Code, Qodo Embed)

Replace general-purpose 384-dim Transformers.js embeddings with a code-specific model.

**Recommended models**:
- Local: Jina Code Embeddings v2 (137M params, Apache 2.0, 8192 context) or CodeRankEmbed (137M, MIT, 8192 context)
- API: VoyageCode3 (32K context, 2048 dims, 300+ languages)
- Matryoshka support: Store 1024-dim, use 384-dim for fast search, full dims for re-ranking

**Rust migration**: Use `ort` crate (ONNX Runtime) for 3-5x speedup over Transformers.js (R4).

---

## CX3: Embedding Enrichment

**Priority**: P1
**Evidence**: R14 (RAG optimization), R8 (sqlite-vec best practices)

Prepend structured metadata to memory content before embedding generation:
```
[tribal|critical|security] Never call the payment API without idempotency keys.
Files: src/payments/api.ts, src/checkout/service.ts
Patterns: payment-api-pattern, idempotency-pattern
```

This gives the embedding model more signal about memory context, improving similarity search for related queries. One-time cost at embedding time.

---

## CX4: Two-Phase Memory Pipeline (Mem0-Inspired)

**Priority**: P1
**Evidence**: R1 (Mem0 paper — 26% improvement over OpenAI memory, 91% lower p95 latency)

Add explicit deduplication/update phase before memory storage:
1. **Extraction phase**: Identify salient facts from interaction
2. **Update phase**: Compare each candidate against existing memories via vector similarity → LLM determines ADD, UPDATE, DELETE, or NOOP

This prevents memory bloat and ensures consistency. Currently Cortex creates memories directly without checking for near-duplicates.

---

## CX5: Graph-Based Memory Layer

**Priority**: P2
**Evidence**: R1 (Mem0g graph variant), R11 (CausalKG paper)

Add optional entity-relationship graph where nodes are entities (with types, embeddings, metadata) and edges are typed relationships as triplets (source, relation, destination). Enables multi-hop reasoning that flat memory stores cannot support.

**Implementation**: Use `petgraph::StableGraph` in Rust (R5) synced with SQLite causal_edges table. StableGraph handles frequent add/remove of edges. Built-in Tarjan's SCC detects circular causal chains.

---

## CX6: Retrieval Re-Ranking Stage

**Priority**: P1
**Evidence**: R10 (RAG production best practices)

Add a two-stage retrieval pipeline:
1. **Fast retrieval**: Hybrid search (CX1) returns top-K candidates (K=50)
2. **Precise re-ranking**: Cross-encoder or lightweight LLM scores each candidate against the query

This significantly improves precision. The re-ranker can be a small model (e.g., cross-encoder from sentence-transformers) running locally via `ort`.

---

## CX7: Accurate Token Counting

**Priority**: P0
**Evidence**: R12 (tiktoken, tiktoken-rs)

Replace string-length approximation with actual tokenizer-based counting. Use `tiktoken-rs` in Rust, `tiktoken` or `js-tiktoken` in TypeScript. Cache token counts per memory (they don't change unless content changes).

**Impact**: Prevents budget overflows (truncation) and underutilization (wasted context window).

---

## CX8: Evidence-Based Memory Promotion

**Priority**: P1
**Evidence**: R15 (Governed Memory Fabric), R7 (neuroscience-inspired consolidation), R18 (EDM — metric-guided selective consolidation), R19 (recall-gated consolidation)

Replace time-only consolidation triggers with evidence-based promotion thresholds:
- Memory promoted to semantic only if confirmed by ≥2 episodes, validated by user feedback, or supported by pattern data
- Add retrieval-difficulty triggers: if a memory that should be relevant keeps scoring low, it needs reinforcement or embedding refresh
- Per-memory adaptive decay rates based on access patterns (not just type-based half-lives)
- **Recall-gated quality gate**: Before consolidating a cluster, run test queries (cluster key phrases) against the embedding index. Only consolidate if episodes rank highly — this prevents consolidating poorly-encoded memories (R19)

---

## CX9: Expanded Privacy Patterns

**Priority**: P0
**Evidence**: R9 (Elastic PII detection, layered approach)

Expand from 10 patterns to 50+:
- All provider-specific secrets from Rust core (Azure keys, GCP service accounts, npm/PyPI tokens, Slack tokens, GitHub tokens)
- Connection strings (PostgreSQL, MySQL, MongoDB, Redis URLs with embedded passwords)
- Base64-encoded secrets
- Hardcoded IPs in configuration
- Consider NER for unstructured PII in tribal/meeting/conversation memories

---

## CX10: Memory System Observability

**Priority**: P1
**Evidence**: R13 (Salesforce system-level AI, enterprise RAG maintenance)

Extend `getHealth()` to enterprise-grade observability:
- Retrieval effectiveness: was the retrieved memory actually used by the AI?
- Token efficiency: how much of the budget was useful vs wasted?
- Memory quality trends over time: is the system getting smarter or degrading?
- Audit trail for all memory mutations (create, update, archive, confidence changes)
- Query timing, cache hit rates, embedding latency

---

## CX11: Causal Graph Improvements

**Priority**: P2
**Evidence**: R11 (CausalKG paper), R5 (petgraph)

- Enforce DAG constraint — detect and handle cycles
- Add counterfactual queries: "What would have happened if we hadn't adopted this pattern?"
- Add intervention queries: "If we change this convention, what memories become invalid?"
- Version causal edges for evolution tracking
- Consider LLM-assisted causal discovery to augment heuristic strategies

---

## CX12: Concurrent Caching with Moka

**Priority**: P1
**Evidence**: R6 (moka crate — TinyLFU + LRU, thread-safe)

Replace L1 in-memory Map with `moka::sync::Cache`:
- TinyLFU provides better hit ratio than simple LRU
- Per-entry TTL enables adaptive expiration (prediction cache: short TTL, embedding cache: long TTL)
- Size-aware eviction prevents memory bloat from large embeddings
- Thread-safe without external locking

---

## CX13: Query Expansion for Improved Recall

**Priority**: P2
**Evidence**: R10 (RAG production best practices)

Generate 2-3 query variants before searching:
- Original query
- Rephrased with synonyms/related terms
- Hypothetical Document Embedding (HyDE): generate a hypothetical answer and embed that

This bridges the gap between query style and memory content style, improving recall for memories that use different terminology than the query.

---

---

## CX14: Algorithmic Consolidation Engine (No LLM Required)

**Priority**: P0
**Evidence**: R16 (TextRank + TF-IDF extractive summarization), R17 (HDBSCAN clustering), R19 (recall-gated consolidation)

Replace LLM-dependent consolidation abstraction with a fully algorithmic pipeline that works offline, is deterministic, auditable, and fast. LLM-enhanced consolidation becomes an optional quality upgrade, not a requirement.

**Pipeline: Cluster → Rank → Merge → Distill → Gate**

**Step 1 — Cluster (HDBSCAN)**:
Group episodic memories using HDBSCAN on a composite similarity signal:
- Embedding cosine similarity (primary signal, weighted 0.5)
- Shared linked files count (weighted 0.2)
- Shared linked patterns count (weighted 0.15)
- Shared linked functions count (weighted 0.1)
- Shared tags count (weighted 0.05)

HDBSCAN is ideal because: (1) no predefined cluster count needed, (2) identifies noise points (episodes too unique to consolidate), (3) handles varying cluster densities. Minimum cluster size = 2 (aligns with evidence-based promotion threshold from CX8).

Use `hdbscan` Rust crate (pure Rust, accepts `Vec<Vec<f32>>`).

**Step 2 — Rank within cluster (Anchor Selection)**:
Select the anchor memory — the episode with the highest composite score:
```
anchor_score = confidence × importance_weight × log2(accessCount + 1)
```
Where importance_weight: critical=4.0, high=2.0, normal=1.0, low=0.5.

The anchor provides the structural template for the consolidated semantic memory.

**Step 3 — Merge unique details (Embedding-Based Deduplication)**:
For each non-anchor episode in the cluster:
1. Split content into sentences.
2. Compute embedding for each sentence (already available or cheap to generate via `ort`).
3. Compare each sentence against the anchor's sentences using cosine similarity.
4. Sentences with similarity < 0.85 to all anchor sentences are "novel" — pull them in.
5. Sentences with similarity ≥ 0.85 are near-duplicates — drop them.

This gives the anchor's core content enriched with unique details from supporting episodes, without redundancy.

**Step 4 — Distill summary (TextRank + TF-IDF)**:
Generate the consolidated memory's summary using a hybrid approach:
1. Build a TextRank graph across all sentences in the cluster (nodes = sentences, edges = embedding cosine similarity). Run PageRank iteration to identify the most central sentences.
2. Use TF-IDF across the cluster to identify distinctive key phrases (terms that are frequent in this cluster but rare across all memories).
3. Take the top-1 TextRank sentence as the summary base. Append the top-3 TF-IDF key phrases if they're not already present.
4. Truncate to ~20 tokens (summary target length).

**Step 5 — Metadata union**:
- Tags: union of all tags across the cluster
- Linked files: union with citation preservation (keep the most recent content_hash per file)
- Linked patterns: union
- Linked functions: union
- Confidence: `weighted_avg(cluster_confidences) × cluster_size_boost` where cluster_size_boost = `min(1.3, 1.0 + (cluster_size - 2) × 0.05)` — more episodes confirming = higher confidence
- Importance: max importance from the cluster

**Step 6 — Recall gate (Quality check)**:
Before finalizing, run a recall test (R19):
1. Extract the top-3 TF-IDF key phrases from the cluster.
2. Run them as queries against the embedding index.
3. If the cluster's episodes rank in the top-10 results for at least 2/3 queries, the cluster is well-encoded → proceed with consolidation.
4. If not, the episodes may be poorly encoded → refresh embeddings first, then re-test. If still failing, defer consolidation and flag for review.

**Optional LLM enhancement**:
When an LLM is available (API key configured or cloud-connected), offer an optional polish step:
- Take the algorithmically consolidated memory and ask the LLM to rephrase it into more natural language.
- The LLM does NOT do the consolidation logic — it only polishes the output.
- Track whether LLM-polished memories have higher retrieval rates than unpolished ones to validate the value.

**Why this is better than LLM-first**:
- Deterministic: same inputs always produce the same output. Testable, reproducible, debuggable.
- Fast: runs in microseconds in Rust. No API latency, no token cost.
- Auditable: every sentence in the output traces to a source episode with a similarity score.
- Offline-first: works everywhere, no external dependencies.
- The LLM becomes an optional quality enhancer, not a critical dependency.

---

## CX15: Consolidation Quality Monitoring

**Priority**: P0
**Evidence**: R18 (EDM — metric-guided selective consolidation, 2× memory precision with 50% fewer retained experiences)

Track consolidation quality over time and use metrics to auto-tune thresholds. This is the monitoring and weighting layer that makes algorithmic consolidation self-improving.

**Core Metrics**:

1. **Memory Precision** (most important): After consolidation, track whether the consolidated memory gets retrieved and used within 30 days.
   - `precision = consolidated_memories_accessed / total_consolidated_memories`
   - Target: ≥ 0.7 (70% of consolidated memories should be accessed at least once)
   - If below target: cluster similarity threshold may be too loose (consolidating unrelated episodes)

2. **Compression Ratio**: Total tokens in source episodes → tokens in consolidated memory.
   - `ratio = source_tokens / consolidated_tokens`
   - Target: 3:1 to 5:1
   - Below 3:1: not enough consolidation (too much content preserved)
   - Above 5:1: potential information loss (too aggressive)

3. **Retrieval Lift**: Does the consolidated memory get retrieved more often than the individual episodes it replaced?
   - `lift = consolidated_access_rate / avg_episode_access_rate`
   - Target: ≥ 1.5 (consolidated memory should be 50% more discoverable)
   - Below 1.0: consolidation hurt discoverability — investigate

4. **Contradiction Rate**: How often does a consolidated memory get contradicted within 30 days of creation?
   - `contradiction_rate = contradicted_consolidations / total_consolidations`
   - Target: ≤ 0.05 (5% or less)
   - Above target: merge logic may be combining conflicting episodes

5. **Stability Score**: How much does a consolidated memory's confidence change in the first 30 days?
   - `stability = 1.0 - abs(confidence_at_30d - confidence_at_creation)`
   - Target: ≥ 0.85
   - Below target: the consolidated memory is being frequently challenged

**Auto-Tuning Feedback Loop**:
- Store metrics per consolidation event in a `consolidation_metrics` table.
- Every 100 consolidation events (or weekly, whichever comes first), compute aggregate metrics.
- If Memory Precision drops below 0.7: increase minimum cluster size by 1 and tighten similarity threshold by 0.05.
- If Compression Ratio exceeds 5:1: lower the sentence novelty threshold (include more content).
- If Contradiction Rate exceeds 0.05: add a pre-consolidation contradiction check — scan cluster episodes for internal contradictions before merging.
- Log all threshold adjustments to the audit trail for transparency.

**Dashboard exposure**: Surface these metrics through the health/observability system (CX10) so users can see consolidation quality trends.

---

## CX16: Updated Embedding Provider Hierarchy

**Priority**: P0
**Evidence**: R20 (Codestral Embed — new SOTA), R3 (code embedding comparison), R4 (ort crate)

Update the embedding provider hierarchy to reflect the current state of the art (as of February 2026):

**API providers (cloud-connected mode)**:
1. Codestral Embed (Mistral) — new SOTA on SWE-Bench and Text2Code. Matryoshka support (truncate to 256-dim with INT8 and still beat competitors). Best quality-to-cost ratio.
2. VoyageCode3 — 32K context, 2048 dims, 300+ languages. Strong fallback.
3. OpenAI text-embedding-3-large — general purpose, widely available.

**Local providers (offline OSS mode)**:
1. Jina Code Embeddings v2 (137M params, Apache 2.0, 8192 context) via `ort` (ONNX Runtime). Default for offline use.
2. CodeRankEmbed (137M, MIT, 8192 context) via `ort`. Alternative if Jina unavailable.

**Fallback (air-gapped, no ONNX)**:
1. all-MiniLM-L6-v2 via Transformers.js (current v1 behavior). For environments that can't run ONNX.

**Matryoshka strategy**: Store embeddings at full model dimensions (1024 for Jina, 2048 for Voyage/Codestral). Use truncated dimensions (384 or 256) for fast candidate search. Use full dimensions for re-ranking (CX6). This gives the speed of small embeddings with the precision of large ones.

---

---

## CX17: Testing Strategy

**Priority**: P0
**Evidence**: R21 (proptest — property-based testing in Rust)

Define a multi-layer testing strategy that proves Cortex works correctly without relying on subjective evaluation.

**Layer 1 — Property-Based Tests (proptest)**:
Every subsystem has invariants that must hold for all inputs:

| Subsystem | Properties |
|---|---|
| Consolidation | Idempotent (same cluster → same output). Deterministic (no randomness). Monotonic confidence (more supporting episodes → higher confidence). No orphaned links (every linked file/pattern in output exists in at least one input episode). Output token count < sum of input token counts. |
| Decay | Monotonically decreasing over time without access. Bounded: 0.0 ≤ confidence ≤ 1.0. Importance anchor never increases confidence beyond base × 2.0. Access boost capped at 1.5×. |
| Compression | Level ordering: tokens(L0) < tokens(L1) < tokens(L2) < tokens(L3). Level 3 is lossless (all content preserved). Level 0 contains only ID. compressToFit never exceeds budget. |
| Retrieval | Higher-importance memories rank above lower-importance at equal similarity. Session deduplication never returns already-sent memories. Token budget never exceeded. |
| Causal graph | DAG enforcement: no cycles after any insertion. Traversal depth ≤ maxDepth. Traversal nodes ≤ maxNodes. Bidirectional traversal = union of forward + backward. |
| Hybrid search | RRF scores are monotonically decreasing. FTS5 results + vector results ⊆ RRF results. Empty query returns empty results. |
| Privacy | Sanitized output never contains raw PII/secrets. Sanitization is idempotent (sanitizing twice = sanitizing once). |
| Token counting | count(a + b) ≤ count(a) + count(b) + 1. count("") = 0. Cached count = uncached count. |

**Layer 2 — Golden Dataset Tests**:
Curated test fixtures with known expected outputs:
- 10 consolidation scenarios: clusters of 2-5 episodic memories with expected semantic memory output (anchor selection, novel sentence extraction, summary generation).
- 10 retrieval scenarios: queries with known relevant memories, expected ranking order.
- 5 contradiction scenarios: pairs of conflicting memories with expected confidence propagation.
- 5 causal inference scenarios: memory pairs with expected causal relationship type and strength.

Golden datasets live in `crates/cortex/test-fixtures/` and are version-controlled. Updated when algorithms change.

**Layer 3 — Performance Benchmarks (criterion)**:
Track latency and throughput at various scales using the `criterion` crate:

| Benchmark | Targets |
|---|---|
| Retrieval latency (100 memories) | < 5ms p95 |
| Retrieval latency (10K memories) | < 50ms p95 |
| Consolidation (cluster of 5) | < 10ms |
| Embedding generation (single, local ONNX) | < 100ms |
| Embedding generation (batch of 10, local ONNX) | < 500ms |
| Hybrid search (FTS5 + vec + RRF, 10K memories) | < 30ms p95 |
| Decay calculation (1K memories) | < 1ms |
| Causal traversal (depth 5, 1K edges) | < 5ms |

Benchmarks run in CI. Regressions > 20% fail the build.

**Layer 4 — Integration Tests**:
End-to-end flows through the full system:
- Create 50 episodic memories → trigger consolidation → verify semantic memories created → query and verify retrieval → trigger decay → verify confidence changes → trigger validation → verify healing.
- Concurrent access: 10 parallel read queries + 1 write (consolidation) → verify no data corruption.
- Embedding model swap: create memories with model A → switch to model B → verify re-embedding pipeline → verify retrieval still works during transition.

---

## CX18: Graceful Degradation Matrix

**Priority**: P0
**Evidence**: R23 (fallback chain pattern, Rust error handling)

Define fallback behavior for every component that can fail. The system should never crash or lose data — it degrades gracefully and tells the user what's happening.

**Degradation Matrix**:

| Component | Failure Mode | Fallback | User Impact |
|---|---|---|---|
| ONNX embedding model | Model file missing or corrupt | Try fallback model → use cached embeddings → use TF-IDF sparse vectors → return error | Retrieval quality degrades but still works. New memories created without embeddings are flagged for re-embedding. |
| SQLite database | File corruption detected | Attempt WAL recovery → rebuild from most recent backup → start fresh with warning | If recovery succeeds: no data loss. If fresh start: memories lost, audit log explains what happened. |
| sqlite-vec extension | Extension fails to load | Disable vector search → use FTS5-only retrieval → degrade to metadata-only filtering | Retrieval loses semantic similarity but keyword search still works. |
| FTS5 index | Index corruption | Rebuild FTS5 index from memory content (non-blocking background task) | Brief period of keyword-search-only degradation during rebuild. |
| Causal graph (petgraph) | In-memory graph inconsistent with SQLite | Rebuild graph from `causal_edges` table | Causal traversal temporarily unavailable during rebuild (~seconds). |
| Embedding dimension mismatch | Model change (384→1024 or vice versa) | Detect dimension difference on startup → trigger background re-embedding pipeline → use FTS5-only search for un-migrated memories → complete when all re-embedded | Retrieval works throughout via FTS5. Quality improves as re-embedding progresses. |
| HDBSCAN clustering | Fails on edge case input | Fall back to simple metadata-based grouping (shared files + patterns) | Consolidation quality slightly lower but still functional. |
| Token counter (tiktoken) | Model file missing | Fall back to character-length approximation (length/4) | Budget management less accurate but functional. |
| Privacy sanitizer | Regex compilation failure | Skip the failing pattern, log warning, continue with remaining patterns | One pattern type unsanitized. Audit log records the gap. |
| Prediction cache (moka) | Memory pressure | Evict prediction cache first (it's regenerable) → reduce L1 embedding cache size | Prediction preloading disabled. Retrieval still works, just not pre-warmed. |

**Implementation pattern**: Every fallback is a variant of Rust's `Result` chain:
```rust
async fn get_embedding(&self, text: &str) -> Result<Vec<f32>, CortexError> {
    self.onnx_provider.embed(text).await
        .or_else(|_| self.fallback_provider.embed(text).await)
        .or_else(|_| self.cache.get_cached(text))
        .or_else(|_| Ok(self.tfidf_fallback(text)))
        .map_err(|e| {
            self.health.record_degradation("embedding", &e);
            e
        })
}
```

Every degradation event is logged to the audit trail with: component, failure mode, fallback used, timestamp, and recovery status.

---

## CX19: Versioned Embedding Migration Pipeline

**Priority**: P0
**Evidence**: R24 (storage growth model), R3/R20 (embedding model changes)

Handle embedding model changes (dimension changes, model upgrades) without downtime or data loss.

**Problem**: When switching from 384-dim general-purpose to 1024-dim code-specific embeddings, every existing memory's embedding becomes incompatible. Memories with old embeddings can't be compared against queries embedded with the new model.

**Solution — Background Re-Embedding Pipeline**:

1. **Detection**: On startup, compare the configured embedding model's dimensions and name against a `embedding_model_info` table. If they differ, a migration is needed.

2. **Metadata tracking**:
```sql
CREATE TABLE embedding_model_info (
  id INTEGER PRIMARY KEY,
  model_name TEXT NOT NULL,
  dimensions INTEGER NOT NULL,
  activated_at TEXT NOT NULL,
  migration_status TEXT DEFAULT 'pending'  -- pending|in_progress|complete
);

ALTER TABLE memory_embedding_link ADD COLUMN model_version INTEGER DEFAULT 1;
```

3. **Transition period**: During migration, memories have mixed embedding versions. The retrieval engine handles this:
   - For queries: embed with the NEW model.
   - For candidate scoring: if memory has new embedding → use cosine similarity. If memory has old embedding → fall back to FTS5 score only (skip vector similarity for that candidate).
   - This means un-migrated memories are still retrievable via keyword search, just not via semantic similarity.

4. **Background worker**: A low-priority background task re-embeds memories in batches:
   - Batch size: 50 memories per cycle
   - Throttle: 100ms pause between batches (don't starve foreground operations)
   - Priority: high-importance and frequently-accessed memories first
   - Progress tracked in `embedding_model_info.migration_status`
   - Resumable: if interrupted, picks up where it left off via `model_version` column

5. **Completion**: When all memories are re-embedded, update `migration_status = 'complete'`. Remove the FTS5-only fallback path for old embeddings. Optionally VACUUM to reclaim space from old embedding rows.

6. **Matryoshka optimization**: If the new model supports Matryoshka (Jina Code, Codestral Embed), store full-dimension embeddings but create a truncated copy at 384-dim for fast search. The sqlite-vec virtual table uses the truncated version. Re-ranking (CX6) uses the full version.

---

## CX20: Concurrency Model

**Priority**: P0
**Evidence**: R22 (SQLite read-write connection pooling, WAL mode)

Define the ownership and synchronization model for all shared state in Cortex.

**SQLite Access Pattern — Read-Write Pool**:
```
┌─────────────────────────────────────────┐
│           ConnectionPool                 │
│                                          │
│  Write Connection (1, exclusive)         │
│  ├── Behind tokio::sync::Mutex           │
│  ├── Used by: consolidation, decay,      │
│  │   validation, learning, memory CRUD   │
│  └── Serialized writes, no contention    │
│                                          │
│  Read Connections (N, concurrent)        │
│  ├── Pool of 4-8 connections             │
│  ├── Used by: retrieval, search, MCP     │
│  │   queries, prediction, health checks  │
│  └── Fully concurrent, never blocked     │
│       by writer                          │
└─────────────────────────────────────────┘
```

**SQLite Pragmas** (set on every connection):
```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA mmap_size = 268435456;    -- 256MB memory-mapped I/O
PRAGMA cache_size = -64000;       -- 64MB page cache
PRAGMA busy_timeout = 5000;       -- 5s retry on lock
PRAGMA foreign_keys = ON;
PRAGMA auto_vacuum = INCREMENTAL; -- Reclaim space incrementally
```

**In-Memory State Synchronization**:

| State | Type | Access Pattern |
|---|---|---|
| Causal graph (petgraph) | `Arc<RwLock<StableGraph>>` | Many concurrent readers (traversal, narrative). Exclusive writer (inference, pruning). RwLock allows concurrent reads. |
| Embedding cache L1 (moka) | `moka::sync::Cache` | Thread-safe internally. No external locking needed. |
| Prediction cache (moka) | `moka::sync::Cache` | Thread-safe internally. No external locking needed. |
| Session contexts | `Arc<DashMap<SessionId, SessionContext>>` | Concurrent per-session access. DashMap provides fine-grained locking per key. |
| Consolidation state | `Arc<AtomicBool>` (is_running flag) | Only one consolidation cycle at a time. Check-and-set before starting. |
| Health metrics | `Arc<RwLock<HealthMetrics>>` | Frequent reads (health checks), infrequent writes (metric updates). |

**Background Task Scheduling**:
```
┌──────────────────────────────────────┐
│         Cortex Runtime               │
│                                      │
│  Foreground (responds to queries):   │
│  ├── Retrieval (read pool)           │
│  ├── Search (read pool)              │
│  ├── MCP tool handlers (read pool)   │
│  └── Memory CRUD (write connection)  │
│                                      │
│  Background (periodic tasks):        │
│  ├── Consolidation (every 6h or      │
│  │   triggered by pressure)          │
│  ├── Decay processing (every 1h)     │
│  ├── Validation (every 4h)           │
│  ├── Prediction preloading           │
│  │   (on file change)                │
│  ├── Re-embedding migration          │
│  │   (when model changes)            │
│  └── Compaction (weekly)             │
│                                      │
│  All background tasks use the write  │
│  connection via Mutex — they queue   │
│  behind each other, never starve     │
│  foreground reads.                   │
└──────────────────────────────────────┘
```

**Key principle**: Reads never wait for writes. Writes are serialized but fast (individual SQLite transactions). Background tasks yield between batches to prevent write-starvation of foreground CRUD operations.

---

## CX21: Data Budget and Storage Compaction

**Priority**: P1
**Evidence**: R24 (storage growth model — 7.5KB per memory, ~800MB-1GB at 5 years heavy use)

Define storage growth expectations and compaction strategy to keep cortex.db manageable.

**Storage Budget Per Memory**:
| Component | Size | Notes |
|---|---|---|
| Content (JSON) | ~2KB | Typed struct, not raw text |
| Embedding (1024-dim f32) | 4KB | Full dimension storage |
| Embedding (384-dim f32, truncated) | 1.5KB | For fast search |
| Metadata + indexes | ~1KB | Tags, links, timestamps |
| FTS5 index contribution | ~0.5KB | ~30% of text content |
| Audit log (per memory lifetime) | ~2.5KB | ~5 events × 0.5KB |
| **Total per memory** | **~11.5KB** | Conservative estimate |

**Growth Projections**:
| Usage Level | Memories/Day | 1 Year | 3 Years | 5 Years |
|---|---|---|---|---|
| Light (solo dev) | 5 | 14MB | 42MB | 70MB |
| Normal (active dev) | 15 | 42MB | 126MB | 210MB |
| Heavy (team/enterprise) | 50 | 140MB | 420MB | 700MB |
| Extreme (CI + multiple devs) | 100 | 280MB | 840MB | 1.4GB |

**Compaction Strategy**:

1. **Archived memory cleanup** (monthly): Memories archived for > 90 days with confidence < 0.1 and zero access in the last 90 days → permanently delete content and embedding. Keep a tombstone record (ID, type, archived_at, deletion_reason) for audit trail. Reclaim ~90% of the memory's storage.

2. **Audit log rotation** (monthly): Audit entries older than 1 year → compress into monthly summary records (count of operations by type, not individual entries). Keeps the audit trail useful for trends without unbounded growth.

3. **Embedding deduplication**: If two memories have identical content hashes, share the embedding row. Saves ~4KB per duplicate.

4. **Incremental VACUUM** (weekly): `PRAGMA incremental_vacuum(1000)` — reclaim up to 1000 pages per run. Non-blocking, runs during low-activity periods.

5. **Full VACUUM** (quarterly, optional): Only if fragmentation exceeds 30% (detected via `PRAGMA page_count` vs `PRAGMA freelist_count`). Requires temporary disk space equal to database size. Run during off-hours.

6. **Storage health reporting**: Include in `getHealth()`:
   - Database file size
   - Active memory count vs archived count
   - Embedding storage size
   - FTS5 index size
   - Fragmentation percentage
   - Projected growth rate (based on last 30 days)
   - Estimated time until 500MB / 1GB thresholds

---

## CX22: Memory Importance Auto-Reclassification

**Priority**: P1
**Evidence**: RECAP limitation #11 (importance is static at creation time)

Automatically adjust memory importance based on observed usage patterns. A memory created as "normal" that gets accessed 50 times in a month is clearly more important than its label suggests.

**Reclassification Signals**:

| Signal | Weight | Logic |
|---|---|---|
| Access frequency (30-day) | 0.35 | > 20 accesses/month → candidate for upgrade. < 1 access/month for 3 months → candidate for downgrade. |
| Retrieval rank (30-day avg) | 0.25 | Consistently in top-5 results → important. Consistently outside top-20 → less important. |
| Linked entity count | 0.15 | Linked to ≥ 3 active patterns/constraints → structurally important. Zero links → isolated. |
| Contradiction involvement | 0.10 | Frequently cited in contradiction resolution (as the "winner") → authoritative. |
| User feedback | 0.15 | Explicitly confirmed by user → boost. Explicitly rejected → downgrade. |

**Reclassification Rules**:
```
composite_score = Σ(signal × weight)

If current = low AND composite_score > 0.7 for 2 consecutive months → upgrade to normal
If current = normal AND composite_score > 0.85 for 2 consecutive months → upgrade to high
If current = high AND composite_score > 0.95 for 3 consecutive months → upgrade to critical
If current = critical AND composite_score < 0.5 for 3 consecutive months → downgrade to high
If current = high AND composite_score < 0.3 for 3 consecutive months → downgrade to normal
If current = normal AND composite_score < 0.15 for 3 consecutive months → downgrade to low
```

**Safeguards**:
- Never auto-downgrade a memory that was manually set to critical by a user. Respect explicit user intent.
- Reclassification changes are logged to the audit trail with the composite score and contributing signals.
- Maximum one reclassification per memory per month (prevent oscillation).
- Reclassification runs as a background task (monthly), not on every access.

---

## CX23: Cortex CLI Surface

**Priority**: P1 (to be extracted into CLI research when that category is finalized)
**Evidence**: Cortex subsystem capabilities, MCP tool surface

Define the developer-facing CLI commands for Cortex. These will be integrated into the main `drift` CLI as subcommands.

**Core Commands**:
```
drift cortex status              # Health dashboard: memory count, confidence avg,
                                 # storage size, consolidation status, embedding model
drift cortex search <query>      # Hybrid search with RRF, returns ranked memories
drift cortex why <file|pattern>  # Trigger the "why" system — causal narrative
drift cortex explain <memory-id> # Show full memory with causal chain, linked entities
drift cortex add <type>          # Interactive memory creation (guided prompts)
drift cortex learn               # Trigger learning from recent corrections
drift cortex consolidate         # Manual consolidation trigger
drift cortex validate            # Run validation across all memories
drift cortex export              # Export memories as JSON (for backup/migration)
drift cortex import <file>       # Import memories from JSON
drift cortex gc                  # Run compaction (archived cleanup + vacuum)
drift cortex metrics             # Consolidation quality metrics (CX15)
drift cortex reembed             # Trigger re-embedding pipeline manually
```

**Flags**:
```
--format json|table|minimal      # Output format (default: table)
--type <memory-type>             # Filter by memory type
--importance <low|normal|high|critical>  # Filter by importance
--limit <n>                      # Limit results
--since <date>                   # Filter by date
--verbose                        # Include full content, not just summaries
```

**Note**: This section defines the CLI surface for Cortex. Full implementation details, argument parsing, output formatting, and integration with the broader `drift` CLI will be planned in the CLI research category (10-cli). This section serves as the contract between Cortex and the CLI layer.

---

## Summary Table

| # | Recommendation | Priority | Evidence |
|---|---------------|----------|----------|
| CX1 | Hybrid search (FTS5 + sqlite-vec + RRF) | P0 | R2, R8 |
| CX2 | Code-specific embedding model | P0 | R3, R4, R20 |
| CX3 | Embedding enrichment with metadata | P1 | R14, R8 |
| CX4 | Two-phase memory pipeline (Mem0-inspired) | P1 | R1 |
| CX5 | Graph-based memory layer | P2 | R1, R11 |
| CX6 | Retrieval re-ranking stage | P1 | R10 |
| CX7 | Accurate token counting (tiktoken) | P0 | R12 |
| CX8 | Evidence-based memory promotion | P1 | R15, R7, R18, R19 |
| CX9 | Expanded privacy patterns (50+) | P0 | R9 |
| CX10 | Memory system observability | P1 | R13 |
| CX11 | Causal graph improvements | P2 | R11, R5 |
| CX12 | Concurrent caching with moka | P1 | R6 |
| CX13 | Query expansion for improved recall | P2 | R10 |
| CX14 | Algorithmic consolidation engine (no LLM) | P0 | R16, R17, R19 |
| CX15 | Consolidation quality monitoring | P0 | R18 |
| CX16 | Updated embedding provider hierarchy | P0 | R3, R4, R20 |
| CX17 | Testing strategy (property + golden + perf) | P0 | R21 |
| CX18 | Graceful degradation matrix | P0 | R23 |
| CX19 | Versioned embedding migration pipeline | P0 | R24 |
| CX20 | Concurrency model (RW pool + state sync) | P0 | R22 |
| CX21 | Data budget and storage compaction | P1 | R24 |
| CX22 | Memory importance auto-reclassification | P1 | RECAP #11 |
| CX23 | Cortex CLI surface (contract for 10-cli) | P1 | Cortex capabilities |

## Phase 0: Foundational Architecture Decisions

### FA1: Hybrid Database Schema (FTS5 + sqlite-vec + RRF)

**Priority**: P0 (Build First)
**Effort**: Medium
**Impact**: Determines retrieval quality for all memory operations — the single most impactful architectural decision

**What to Build**:
A cortex.db schema that combines three search modalities in a single SQLite database: structured queries (standard tables + indexes), full-text search (FTS5 virtual table), and vector similarity search (sqlite-vec virtual table). Results are fused via Reciprocal Rank Fusion (RRF).

**Why hybrid**: Vector-only search misses exact keyword matches (e.g., searching for "bcrypt" might return memories about "password hashing" but miss the one that literally says "use bcrypt"). FTS5 catches these. RRF combines both without requiring score normalization: `score = Σ 1/(60 + rank_i)`.

**Schema additions**:
```sql
-- FTS5 virtual table for keyword search
CREATE VIRTUAL TABLE memory_fts USING fts5(
    summary,
    content,
    tags,
    content=memories,
    content_rowid=rowid
);

-- Triggers to keep FTS5 in sync with memories table
CREATE TRIGGER memory_fts_insert AFTER INSERT ON memories BEGIN
    INSERT INTO memory_fts(rowid, summary, content, tags)
    VALUES (NEW.rowid, NEW.summary, NEW.content, NEW.tags);
END;

CREATE TRIGGER memory_fts_delete AFTER DELETE ON memories BEGIN
    INSERT INTO memory_fts(memory_fts, rowid, summary, content, tags)
    VALUES ('delete', OLD.rowid, OLD.summary, OLD.content, OLD.tags);
END;

CREATE TRIGGER memory_fts_update AFTER UPDATE ON memories BEGIN
    INSERT INTO memory_fts(memory_fts, rowid, summary, content, tags)
    VALUES ('delete', OLD.rowid, OLD.summary, OLD.content, OLD.tags);
    INSERT INTO memory_fts(rowid, summary, content, tags)
    VALUES (NEW.rowid, NEW.summary, NEW.content, NEW.tags);
END;
```

**RRF fusion query pattern**:
```sql
-- Combine FTS5 and vector results with RRF
WITH fts_results AS (
    SELECT rowid, rank() OVER () as fts_rank
    FROM memory_fts WHERE memory_fts MATCH ?
    ORDER BY rank LIMIT 50
),
vec_results AS (
    SELECT memory_id, row_number() OVER () as vec_rank
    FROM memory_embeddings
    WHERE embedding MATCH ? AND k = 50
),
combined AS (
    SELECT COALESCE(f.rowid, v.memory_id) as memory_id,
           1.0 / (60 + COALESCE(f.fts_rank, 999)) +
           1.0 / (60 + COALESCE(v.vec_rank, 999)) as rrf_score
    FROM fts_results f
    FULL OUTER JOIN vec_results v ON f.rowid = v.memory_id
)
SELECT m.*, c.rrf_score
FROM combined c
JOIN memories m ON m.rowid = c.memory_id
ORDER BY c.rrf_score DESC
LIMIT ?;
```

**Evidence**:
- Hybrid search with RRF: https://simonwillison.net/2024/Oct/4/hybrid-full-text-search-and-vector-search-with-sqlite/
- Azure hybrid search: https://learn.microsoft.com/en-us/azure/search/hybrid-search-overview
- sqlite-vec: https://github.com/asg017/sqlite-vec

---

### FA2: Code-Specific Embedding Model

**Priority**: P0 (Build First)
**Effort**: Medium
**Impact**: Determines retrieval quality for all memory operations

**What to Build**:
Replace the general-purpose 384-dim Transformers.js model with a code-specific embedding model. Support multiple dimensions via Matryoshka representation.

**Provider hierarchy**:
1. **Local (default)**: Jina Code Embeddings v2 (137M params, Apache 2.0, 8192 context) via ONNX Runtime. Store 1024-dim embeddings. Use 384-dim truncation for fast search, full 1024-dim for re-ranking.
2. **API (optional)**: VoyageCode3 (32K context, 2048 dims, 300+ languages). For teams that want maximum quality.
3. **Fallback**: all-MiniLM-L6-v2 via Transformers.js (current behavior, for air-gapped environments without ONNX).

**Embedding enrichment**: Before embedding, prepend structured metadata:
```
[{type}|{importance}|{category}] {summary}
Files: {linkedFiles}
Patterns: {linkedPatterns}
```
This gives the embedding model more signal for discriminative representations.

**Evidence**:
- Code embedding comparison: https://modal.com/blog/6-best-code-embedding-models-compared
- Jina Code: https://jina.ai/models/jina-code-embeddings-1.5b/
- Embedding enrichment: https://hyperion-consulting.io/en/insights/rag-optimization-production-2026-best-practices

---

### FA3: Structured Error Handling and Audit Trail

**Priority**: P0 (Build First)
**Effort**: Low
**Impact**: Every subsystem uses this — impossible to retrofit

**What to Build**:
Every memory mutation (create, update, archive, confidence change, link, unlink) is logged to an append-only audit table. Every error uses structured error types.

```sql
CREATE TABLE memory_audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  memory_id TEXT NOT NULL,
  operation TEXT NOT NULL,  -- create|update|archive|restore|link|unlink|decay|validate|consolidate
  details TEXT,             -- JSON: what changed
  actor TEXT,               -- system|user|consolidation|decay|validation|learning
  timestamp TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_audit_memory ON memory_audit_log(memory_id);
CREATE INDEX idx_audit_timestamp ON memory_audit_log(timestamp);
```

For Rust:
```rust
#[derive(thiserror::Error, Debug)]
pub enum CortexError {
    #[error("memory not found: {id}")]
    MemoryNotFound { id: String },
    #[error("invalid memory type: {type_name}")]
    InvalidType { type_name: String },
    #[error("embedding failed: {0}")]
    EmbeddingError(#[from] EmbeddingError),
    #[error("storage error: {0}")]
    StorageError(#[from] rusqlite::Error),
    #[error("causal cycle detected: {path}")]
    CausalCycle { path: String },
    #[error("token budget exceeded: needed {needed}, available {available}")]
    TokenBudgetExceeded { needed: usize, available: usize },
}
```

**Evidence**:
- Governed memory fabric: https://www.csharp.com/article/the-gdel-autonomous-memory-fabric-db-layer-the-database-substrate-that-makes-c/
- thiserror: https://docs.rs/thiserror

---

## Phase 1: Storage & Embedding Core

Build the foundational data layer that everything else depends on.

### R1: Memory Storage with Bitemporal Tracking

**Priority**: P0
**Effort**: High

**What to Build**:
SQLite storage implementing the full `IMemoryStorage` interface from v1, with these v2 enhancements:

1. All 23 memory types with typed content (serde serialization, not JSON blobs)
2. Bitemporal tracking: transaction_time (when recorded) + valid_time (when true)
3. Relationship system with 13 relationship types and strength scoring
4. Link tables: memory_patterns, memory_constraints, memory_files (with citations), memory_functions
5. FTS5 index for keyword search (FA1)
6. Vector table for semantic search (FA1)
7. Audit log for all mutations (FA3)
8. WAL mode, NORMAL synchronous, 256MB mmap

**Key difference from v1**: Content stored as typed Rust structs (via serde), not JSON blobs. This enables compile-time validation and faster deserialization.

**Dependencies**: `rusqlite` (bundled SQLite), `serde` + `serde_json`, `chrono`, `uuid`

---

### R2: Embedding Engine with ONNX Runtime

**Priority**: P0
**Effort**: High

**What to Build**:
Multi-provider embedding system with code-specific models and 3-tier caching.

**Architecture**:
```rust
#[async_trait]
pub trait EmbeddingProvider: Send + Sync {
    fn name(&self) -> &str;
    fn dimensions(&self) -> usize;
    async fn embed(&self, text: &str) -> Result<Vec<f32>>;
    async fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>>;
    fn is_available(&self) -> bool;
}
```

**Providers**:
1. `OnnxProvider` — Loads ONNX models via `ort` crate. Default: Jina Code v2 (1024-dim). Supports quantized models (INT8) for faster inference.
2. `OpenAIProvider` — API-based, for teams wanting maximum quality.
3. `OllamaProvider` — Local Ollama instance.
4. `FallbackProvider` — Simple TF-IDF based embeddings for air-gapped environments with no ML runtime.

**3-Tier Cache**:
- L1: `moka::sync::Cache` with size-aware eviction (embedding vectors are large)
- L2: SQLite table with content-hash keys
- L3: Memory-mapped precomputed embeddings for frequently-accessed content

**Embedding enrichment** (FA2): Prepend metadata before embedding.

**Matryoshka support**: Store full-dimension embeddings. Truncate to lower dimensions for fast search. Use full dimensions for re-ranking.

**Evidence**:
- ort crate: https://ort.pyke.io/
- Rust ONNX benchmarks: https://markaicode.com/rust-onnx-ml-models-2025/
- moka cache: https://docs.rs/moka/latest/moka/

---

### R3: Accurate Token Counting

**Priority**: P0
**Effort**: Low

**What to Build**:
Replace string-length approximation with actual tokenizer-based counting.

Use `tiktoken-rs` for cl100k_base (GPT-4/Claude compatible) tokenization. Cache token counts per memory (they don't change unless content changes).

```rust
use tiktoken_rs::cl100k_base;

pub struct TokenCounter {
    bpe: tiktoken_rs::CoreBPE,
    cache: moka::sync::Cache<String, usize>,  // content_hash -> token_count
}

impl TokenCounter {
    pub fn count(&self, text: &str) -> usize {
        let hash = blake3::hash(text.as_bytes()).to_hex().to_string();
        self.cache.get_with(hash, || self.bpe.encode_ordinary(text).len())
    }
}
```

**Key difference from v1**: v1 used `text.length / 4` approximation. v2 uses exact tokenization with caching.

**Evidence**:
- tiktoken-rs: https://docs.rs/tiktoken-rs/

---

## Phase 2: Retrieval & Search

### R4: Hybrid Retrieval Engine with Re-Ranking

**Priority**: P0
**Effort**: High

**What to Build**:
A two-stage retrieval pipeline: fast candidate gathering → precise re-ranking.

**Stage 1 — Candidate Gathering** (fast, broad):
1. Pre-filter by memory type based on intent weighting (same as v1)
2. Pre-filter by importance (skip low-importance for tight budgets)
3. Run hybrid search (FA1): FTS5 + sqlite-vec with RRF fusion
4. Gather additional candidates by linked entities (patterns, files, functions)
5. Deduplicate candidates

**Stage 2 — Re-Ranking** (precise, narrow):
1. Score each candidate with multi-factor relevance scorer:
   - Semantic similarity (from vector search, already computed)
   - Keyword match score (from FTS5, already computed)
   - File proximity (same file/directory as active context)
   - Pattern alignment (linked to relevant patterns)
   - Recency (last accessed, last validated)
   - Confidence level
   - Importance level
   - Intent-type match (boosted types for current intent)
2. Apply session deduplication (skip already-sent memories)
3. Compress to fit token budget using hierarchical compression
4. Return with metadata (scores, compression levels, token counts)

**Query expansion**: For the focus string, generate 2-3 variants:
- Original: "authentication middleware"
- Variant 1: "auth middleware guard interceptor"
- Variant 2: "login session token verification"
Run all variants through hybrid search, merge results.

**Evidence**:
- RAG re-ranking: https://hyperion-consulting.io/en/insights/rag-optimization-production-2026-best-practices
- Hybrid search: https://learn.microsoft.com/en-us/azure/search/hybrid-search-overview

---

### R5: 4-Level Hierarchical Compression with Accurate Budgeting

**Priority**: P0
**Effort**: Medium

**What to Build**:
Same 4-level compression as v1, but with accurate token counting (R3) and smarter packing.

**Levels**: Level 0 (IDs, ~5 tokens), Level 1 (one-liners, ~50 tokens), Level 2 (with examples, ~200 tokens), Level 3 (full context, ~500+ tokens).

**Packing algorithm**: Replace greedy approach with a priority-weighted bin-packing:
1. Sort memories by `importance × relevance_score` (descending)
2. For each memory, try Level 3 → 2 → 1 → 0 until it fits remaining budget
3. Critical memories always get at least Level 1
4. Track actual token counts (R3), not estimates

**Key difference from v1**: Accurate token counting prevents budget overflows. Priority-weighted packing ensures the most important memories get the most detail.

---

### R6: Intent-Aware Retrieval with Expanded Intent Taxonomy

**Priority**: P1
**Effort**: Medium

**What to Build**:
Expand the intent taxonomy and make intent weighting configurable.

**V2 Intent Taxonomy** (18 intents):
- Domain-agnostic: create, investigate, decide, recall, learn, summarize, compare
- Code-specific: add_feature, fix_bug, refactor, security_audit, understand_code, add_test, review_code, deploy, migrate
- Universal: spawn_agent, execute_workflow, track_progress

**Intent → Type Boost Matrix** (configurable via TOML):
```toml
[intents.fix_bug]
tribal = 1.5
incident = 1.8
code_smell = 1.5
episodic = 1.3
feedback = 1.2

[intents.security_audit]
tribal = 1.8
incident = 1.5
constraint_override = 1.3
pattern_rationale = 1.2
```

**Key difference from v1**: Configurable weights, expanded taxonomy, and the boost matrix is data-driven (can be tuned based on retrieval effectiveness metrics).

---

## Phase 3: Knowledge Management

### R7: Algorithmic Consolidation with Evidence-Based Promotion

**Priority**: P0 (upgraded from P1 — core differentiator, no LLM dependency)
**Effort**: High

**What to Build**:
A fully algorithmic 6-phase consolidation pipeline that works offline with zero LLM dependency. LLM polish is an optional enhancement, not a requirement. This is the primary consolidation path for both OSS and cloud versions.

**Phase 1 — Candidate Selection**: Select episodic memories eligible for consolidation (age > 7 days, status = pending, confidence > 0.3). Filter out memories already consolidated or archived.

**Phase 2 — Clustering (HDBSCAN)**: Cluster candidates using HDBSCAN on composite similarity vectors (CX14). Minimum cluster size = 2. Memories flagged as noise are deferred — they need more supporting episodes.

**Phase 3 — Recall Gate**: For each cluster, run a recall test (CX14 Step 6). Extract top-3 TF-IDF key phrases, query the embedding index. If episodes don't rank well, refresh embeddings and re-test. If still failing, defer and flag for review.

**Phase 4 — Algorithmic Abstraction**: For clusters that pass the recall gate:
1. Select anchor memory (highest confidence × importance × accessCount).
2. Merge novel sentences from supporting episodes (embedding similarity < 0.85 to anchor).
3. Generate summary via TextRank + TF-IDF hybrid (CX14 Step 4).
4. Union all metadata (tags, files, patterns, functions).
5. Compute consolidated confidence with cluster size boost.

**Phase 5 — Integration**: Merge new semantic memories with existing semantic memories. If a new consolidation overlaps significantly (embedding similarity > 0.9) with an existing semantic memory, UPDATE the existing one rather than creating a duplicate (Mem0-inspired deduplication from CX4).

**Phase 6 — Pruning + Strengthening**: Archive consolidated episodic memories. Boost confidence of frequently accessed memories. Track tokensFreed metric.

**Optional LLM Polish**: When an LLM is available, offer a post-consolidation polish step — rephrase the algorithmically generated content into more natural language. The LLM does NOT do consolidation logic. Track whether polished memories have higher retrieval rates to validate value.

**Monitoring**: All consolidation events tracked via CX15 metrics (precision, compression ratio, retrieval lift, contradiction rate, stability). Auto-tuning feedback loop adjusts thresholds based on aggregate metrics.

**Adaptive scheduling** (same as v1): Token pressure, memory count, confidence degradation, contradiction density triggers.

**Evidence**:
- Algorithmic consolidation: CX14 (TextRank, TF-IDF, HDBSCAN, recall gate)
- Consolidation quality monitoring: CX15 (EDM metric-guided approach)
- Evidence-based promotion: https://www.csharp.com/article/the-gdel-autonomous-memory-fabric-db-layer-the-database-substrate-that-makes-c/
- Recall-gated consolidation: https://elifesciences.org/articles/90793
- Retrieval-difficulty triggers: https://arxiv.org/html/2503.18371
- HDBSCAN: https://docs.rs/hdbscan
- TextRank + TF-IDF: https://towardsai.net/p/machine-learning/mastering-extractive-summarization-a-theoretical-and-practical-guide-to-tf-idf-and-textrank

---

### R8: Multi-Factor Decay with Adaptive Half-Lives

**Priority**: P1
**Effort**: Low

**What to Build**:
Same 5-factor decay formula as v1, with per-memory adaptive half-lives.

**Enhancement**: Instead of fixed type-based half-lives, compute per-memory adaptive half-lives:
```
adaptiveHalfLife = baseHalfLife × accessFrequencyFactor × validationFactor × linkageFactor
```
- `accessFrequencyFactor`: Frequently accessed memories decay slower (1.0 - 2.0×)
- `validationFactor`: Recently validated memories decay slower (1.0 - 1.5×)
- `linkageFactor`: Memories linked to active patterns/constraints decay slower (1.0 - 1.3×)

This means a tribal memory that's accessed daily and linked to active patterns might have an effective half-life of 365 × 2.0 × 1.5 × 1.3 = 1,423 days, while an unlinked, rarely-accessed tribal memory decays at the base 365 days.

**Evidence**:
- Adaptive forgetting curves: https://link.springer.com/chapter/10.1007%2F978-3-030-52240-7_65
- Human-like forgetting: https://arxiv.org/html/2506.12034v2

---

### R9: Contradiction Detection with Graph Propagation

**Priority**: P1
**Effort**: Medium

**What to Build**:
Same contradiction detection as v1, with these enhancements:

1. **Semantic contradiction detection**: Use embedding similarity + negation pattern matching (same as v1). Add: cross-reference with linked patterns — if two memories link to the same pattern but have opposing content, flag as contradiction.

2. **Confidence propagation via in-memory graph**: Maintain a `petgraph::StableGraph` in memory (synced with SQLite). When a contradiction is detected, propagate confidence changes through the graph using BFS with decay factor. This is O(V+E) instead of repeated SQLite queries.

3. **Consensus detection**: When ≥3 memories support the same conclusion, boost all of them (+0.2) and mark as consensus. Consensus memories resist contradiction from single opposing memories.

4. **Temporal supersession**: Automatically detect when a newer memory supersedes an older one on the same topic. Use embedding similarity + temporal ordering.

**Propagation rules** (same as v1):
- Direct contradiction: -0.3
- Partial contradiction: -0.15
- Supersession: -0.5
- Confirmation: +0.1
- Consensus (≥3 supporters): +0.2
- Supporting propagation factor: 0.5×
- Archival threshold: 0.15

**Evidence**:
- petgraph for graph operations: https://docs.rs/petgraph/
- Mem0 contradiction handling: https://arxiv.org/html/2504.19413

---

### R10: 4-Dimension Validation with Healing

**Priority**: P1
**Effort**: Medium

**What to Build**:
Same 4-dimension validation as v1 (citation, temporal, contradiction, pattern alignment), with these enhancements:

1. **Citation validation**: Check file existence + content hash. NEW: If file was renamed/moved (detected via git), auto-update the citation instead of flagging as stale.

2. **Temporal validation**: Check validUntil expiry. NEW: For memories linked to specific code versions (git commits), check if the code has changed significantly since the memory was created.

3. **Contradiction validation**: Run contradiction detector. NEW: Check for consensus — if a memory has consensus support, it's more resistant to contradiction.

4. **Pattern alignment**: Check if linked patterns still exist and are still approved. NEW: If a pattern was removed or its confidence dropped significantly, flag linked memories for review.

**Healing strategies** (enhanced):
- Confidence adjustment (same as v1)
- Citation auto-update via git rename detection (NEW)
- Embedding refresh — re-embed memories whose content context has changed (NEW)
- Archival with reason tracking (same as v1)
- Flagging for human review (same as v1)

---

## Phase 4: Causal Intelligence

### R11: Causal Graph with DAG Enforcement

**Priority**: P1
**Effort**: High

**What to Build**:
Full causal system from v1, with these enhancements:

1. **In-memory graph**: Maintain a `petgraph::StableGraph<CausalNode, CausalEdge>` synced with SQLite. All traversals operate on the in-memory graph for speed. SQLite is the persistence layer.

2. **DAG enforcement**: Detect cycles before adding causal edges. If a cycle would be created, reject the edge or flag for review. Use petgraph's built-in cycle detection.

3. **8 relation types** (same as v1): caused, enabled, prevented, contradicts, supersedes, supports, derived_from, triggered_by.

4. **6 inference strategies** (same as v1): temporal proximity, semantic similarity, entity overlap, explicit reference, pattern matching, file co-occurrence. Weighted scoring with configurable weights.

5. **Narrative generation**: Template-based narrative builder that produces human-readable "why" explanations from causal chains. Include confidence scores and evidence references.

6. **Counterfactual queries** (NEW): "If we hadn't adopted pattern X, what memories would be affected?" — traverse the causal graph from the pattern's linked memories and identify all downstream effects.

7. **Intervention queries** (NEW): "If we change convention X, what needs to be updated?" — identify all memories causally dependent on the convention.

**Evidence**:
- petgraph: https://docs.rs/petgraph/
- Causal knowledge graphs: https://www.researchgate.net/publication/357765711_CausalKG_Causal_Knowledge_Graph_Explainability_using_interventional_and_counterfactual_reasoning

---

### R12: "Why" System with Causal Narratives

**Priority**: P1
**Effort**: Medium

**What to Build**:
The "killer feature" — synthesizes complete explanations of WHY things are the way they are.

**Pipeline**:
1. Gather pattern rationales for the focus area
2. Gather decision contexts (ADRs, decision memories)
3. Gather tribal knowledge (warnings, consequences)
4. Gather code smells (anti-patterns to avoid)
5. Traverse causal graph from relevant memories (R11)
6. Generate narrative from causal chains
7. Aggregate warnings from all sources
8. Compress to fit token budget

**Output**:
```rust
pub struct WhyContext {
    pub patterns: Vec<PatternContext>,
    pub decisions: Vec<DecisionContext>,
    pub tribal: Vec<TribalContext>,
    pub anti_patterns: Vec<AntiPatternContext>,
    pub narrative: Option<CausalNarrative>,
    pub warnings: Vec<Warning>,
    pub summary: String,
    pub confidence: f64,
    pub token_count: usize,
}
```

**Key difference from v1**: Integrated counterfactual reasoning ("what would happen if...") and intervention analysis ("what needs to change if...").

---

## Phase 5: Learning & Prediction

### R13: Correction Analysis with Principle Extraction

**Priority**: P1
**Effort**: High

**What to Build**:
Full learning pipeline from v1 with these enhancements:

1. **10 correction categories** (same as v1): pattern_violation, tribal_miss, constraint_violation, style_preference, naming_convention, architecture_mismatch, security_issue, performance_issue, api_misuse, other.

2. **Category → Memory Type mapping** (same as v1): pattern_violation→pattern_rationale, tribal_miss→tribal, security_issue→tribal(critical), etc.

3. **Diff analysis**: Compare original vs corrected code. Extract additions, removals, modifications, semantic changes.

4. **Principle extraction**: Generalize the correction into a reusable rule. For air-gapped environments, use rule-based extraction (keyword matching, pattern templates). For connected environments, optionally use LLM for higher-quality extraction.

5. **Automatic causal inference**: When a correction creates a new memory, automatically infer causal relationships with existing memories (R11).

6. **Deduplication before storage** (NEW, inspired by Mem0): Before creating a new memory from a correction, check for existing memories with high similarity. If found, UPDATE the existing memory instead of creating a duplicate. Use the same ADD/UPDATE/NOOP decision pattern as Mem0.

**Evidence**:
- Mem0 extraction/update pipeline: https://arxiv.org/html/2504.19413

---

### R14: Active Learning Loop

**Priority**: P2
**Effort**: Medium

**What to Build**:
Same active learning loop as v1:

1. Identify memories needing validation (low confidence + high importance, old + never validated, contradicted but unresolved)
2. Generate validation prompts for the user
3. Process feedback (confirm/reject/modify)
4. Update confidence based on response
5. Store validation feedback for calibration

**Enhancement**: Prioritize validation candidates by impact — memories that are frequently retrieved but have uncertain confidence should be validated first (they affect the most AI interactions).

---

### R15: Predictive Memory Preloading

**Priority**: P2
**Effort**: Medium

**What to Build**:
Same 4-strategy prediction system as v1:

1. **FileBasedPredictor**: Memories linked to active file and its imports
2. **PatternBasedPredictor**: Memories linked to detected patterns in active file
3. **TemporalPredictor**: Time-of-day and day-of-week patterns from usage history
4. **BehavioralPredictor**: Recent queries, intents, frequent memories

**Enhancements**:
- **Adaptive TTL**: Instead of fixed 5-minute cache TTL, adapt based on file change frequency. Rapidly changing files get shorter TTL.
- **Git-aware prediction**: If on a feature branch, predict memories related to the feature's domain (from branch name and recent commits).
- **Pre-embed queries**: For predicted memories, pre-compute the hybrid search results so retrieval is instant when the query arrives.

**Dependencies**: `moka` for prediction cache with per-entry TTL.

---

## Phase 6: Integration & Observability

### R16: Session Management with Token Efficiency Tracking

**Priority**: P1
**Effort**: Low

**What to Build**:
Same session management as v1 (deduplication, token tracking, cleanup), with enhanced observability:

1. **Deduplication** (same as v1): Track loaded memories per session. Skip already-sent memories. 30-50% token savings.

2. **Token efficiency metrics** (NEW): Track per-session:
   - `tokens_sent`: Total tokens sent to AI
   - `tokens_useful`: Tokens from memories that were actually referenced in AI output (requires feedback)
   - `efficiency_ratio`: useful / sent
   - `deduplication_savings`: Tokens saved by not re-sending

3. **Session analytics** (NEW): Aggregate across sessions to identify:
   - Most frequently retrieved memories (candidates for pinning)
   - Least useful memories (candidates for archival)
   - Intent distribution (what are users doing most?)
   - Average retrieval latency by intent type

---

### R17: Privacy Sanitization with Expanded Patterns

**Priority**: P1
**Effort**: Low-Medium

**What to Build**:
Expand from 10 patterns to 50+ patterns, organized by category:

**PII Patterns** (15+):
- Email, phone, SSN, credit card, IP address (same as v1)
- NEW: Passport numbers, driver's license, date of birth, physical addresses, national ID numbers

**Secret Patterns** (35+):
- API keys, AWS keys, JWT, private keys, passwords (same as v1)
- NEW: Azure keys, GCP service accounts, GitHub tokens (ghp_, gho_, ghs_), GitLab tokens (glpat-), npm tokens, PyPI tokens, Slack tokens (xoxb-, xoxp-), Stripe keys (sk_live_, pk_live_), Twilio tokens, SendGrid keys, Heroku API keys, DigitalOcean tokens, Datadog API keys
- NEW: Connection strings (PostgreSQL, MySQL, MongoDB, Redis URLs with embedded credentials)
- NEW: Base64-encoded secrets (detect base64 strings assigned to sensitive variables)

**Context-aware scoring** (NEW):
- In test file: -0.20 confidence
- In comment: -0.30 confidence
- In .env file: +0.10 confidence
- Placeholder detected: skip entirely
- Sensitive variable name: +0.10 confidence

**Evidence**:
- Layered PII detection: https://www.elastic.co/observability-labs/blog/pii-ner-regex-assess-redact-part-2
- PII redaction best practices: https://synthmetric.com/pii-redaction-tactics-for-safer-datasets/

---

### R18: Generation Context with Provenance

**Priority**: P1
**Effort**: Medium

**What to Build**:
Same generation context system as v1 (pattern gatherer, tribal gatherer, constraint gatherer, anti-pattern gatherer), with these enhancements:

1. **Token budget allocation** (configurable):
   - Patterns: 30%
   - Tribal: 25%
   - Constraints: 20%
   - Anti-patterns: 15%
   - Related: 10%

2. **Provenance tracking**: Record what influenced generated code (pattern_followed, tribal_applied, constraint_enforced, antipattern_avoided).

3. **Feedback loop**: Process generation outcomes (accepted/modified/rejected). Adjust confidence of influencing memories based on outcome.

4. **Validation**: Check generated code against patterns, tribal knowledge, and anti-patterns before returning context.

5. **Provenance comments** (NEW): Generate inline code comments explaining why certain patterns were followed:
   ```
   // [drift:tribal] Always use bcrypt with 12 salt rounds for password hashing
   // [drift:pattern] auth-password-hashing (confidence: 0.92)
   ```

---

### R19: MCP Tool Layer

**Priority**: P0
**Effort**: Medium

**What to Build**:
33 MCP tools (same as v1) as thin TypeScript wrappers over the Rust Cortex engine via NAPI.

**Key tools**:
- `drift_memory_add` — Create memory with auto-deduplication (R13) and causal inference (R11)
- `drift_memory_search` — Hybrid search (FA1) with session deduplication (R16)
- `drift_why` — Full "why" context with causal narratives (R12)
- `drift_memory_learn` — Correction analysis with principle extraction (R13)
- `drift_context` — Orchestrated context retrieval (R4) with generation context (R18)

**The MCP tools stay in TypeScript**. They are thin JSON-RPC wrappers that call Rust via NAPI. No performance-critical logic in the tool layer.

---

### R20: Observability Dashboard

**Priority**: P2
**Effort**: Medium

**What to Build**:
Comprehensive health and observability for the memory system:

1. **Health report** (enhanced from v1):
   - Total memories by type
   - Average confidence by type
   - Stale memory count and trend
   - Contradiction count and resolution rate
   - Consolidation frequency and effectiveness
   - Storage size and growth rate
   - Embedding cache hit rates (L1/L2/L3)
   - Retrieval latency percentiles (p50, p95, p99)

2. **Retrieval effectiveness** (NEW):
   - Per-intent hit rate
   - Token efficiency ratio
   - Most/least useful memories
   - Query expansion effectiveness

3. **Recommendations** (NEW):
   - "5 memories need validation" (low confidence + high importance)
   - "3 contradictions unresolved" (flagged for review)
   - "Consolidation recommended" (high episodic count)
   - "Embedding cache cold" (low L1 hit rate)

---

### R21: Memory Versioning

**Priority**: P2
**Effort**: Medium

**What to Build**:
Track how memory content evolves over time, not just confidence changes.

```sql
CREATE TABLE memory_versions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  memory_id TEXT NOT NULL,
  version INTEGER NOT NULL,
  content TEXT NOT NULL,        -- JSON: full memory content at this version
  summary TEXT NOT NULL,
  confidence REAL NOT NULL,
  changed_by TEXT NOT NULL,     -- system|user|consolidation|learning
  change_reason TEXT,
  created_at TEXT NOT NULL,
  UNIQUE(memory_id, version)
);
```

**Use cases**:
- "How has our understanding of the auth pattern evolved?"
- "What did this memory say before the last correction?"
- "Roll back a memory to a previous version"
- Audit trail for compliance

---

### R22: Rust Crate Structure

**Priority**: P0
**Effort**: Architecture decision

**What to Build**:
Organize the Rust Cortex implementation into focused crates:

```
crates/cortex/
├── cortex-core/        # Types, traits, BaseMemory, 23 memory types, errors
├── cortex-storage/     # SQLite storage, migrations, FTS5, audit log
├── cortex-embeddings/  # ONNX provider, cache (moka), enrichment
├── cortex-retrieval/   # Hybrid search, RRF, re-ranking, intent weighting
├── cortex-causal/      # petgraph, inference, traversal, narrative
├── cortex-learning/    # Correction analysis, principle extraction, calibration
├── cortex-decay/       # Decay calculation, adaptive half-lives
├── cortex-validation/  # 4-dimension validation, healing
├── cortex-compression/ # 4-level compression, token budgeting
├── cortex-prediction/  # Signal gathering, 4 strategies, cache
├── cortex-session/     # Session management, deduplication, analytics
├── cortex-privacy/     # PII/secret sanitization (50+ patterns)
├── cortex-consolidation/ # 5-phase pipeline, adaptive scheduling
└── cortex-napi/        # NAPI bindings for TypeScript interop
```

**Key Rust crate mappings**:
| Dependency | Purpose |
|---|---|
| `rusqlite` (bundled) | SQLite storage + FTS5 |
| `ort` | ONNX Runtime for embedding inference |
| `petgraph` | Causal graph operations |
| `moka` | Concurrent caching (L1, prediction) |
| `tiktoken-rs` | Accurate token counting |
| `blake3` | Content hashing |
| `uuid` | Memory ID generation |
| `chrono` | Bitemporal time handling |
| `serde` + `serde_json` | Typed serialization |
| `thiserror` | Structured errors |
| `rayon` | Parallel batch operations |
| `tokio` | Async embedding inference |
| `regex` | Privacy sanitization |
| `hdbscan` | Density-based clustering for consolidation (CX14) |
| `dashmap` | Concurrent hashmap for session contexts (CX20) |
| `proptest` | Property-based testing (CX17, dev dependency) |
| `criterion` | Performance benchmarking (CX17, dev dependency) |

---

## Build Order

```
Phase 0 (Architecture):  FA1 + FA2 + FA3 + R22      [Decisions before code]
Phase 1 (Storage):       R1 → R2 → R3                [Storage, Embeddings, Tokens]
Phase 2 (Retrieval):     R4 → R5 → R6                [Hybrid Search, Compression, Intents]
Phase 3 (Knowledge):     R7 → R8 → R9 → R10          [Algorithmic Consolidation, Decay, Contradiction, Validation]
Phase 4 (Causal):        R11 → R12                    [Causal Graph, Why System]
Phase 5 (Learning):      R13 → R14 → R15              [Corrections, Active Learning, Prediction]
Phase 6 (Integration):   R16 → R17 → R18 → R19 → R20 → R21  [Session, Privacy, Generation, MCP, Observability, Versioning]
```

Note: R7 (Algorithmic Consolidation) is now P0 and depends on R1 (Storage) + R2 (Embeddings) + R3 (Tokens). It uses HDBSCAN for clustering, TextRank + TF-IDF for summarization, and the recall gate requires the embedding index from R2. CX15 (Consolidation Quality Monitoring) is built alongside R7 as its monitoring layer.

Note: Phase 6 items R16-R18 should be built alongside Phases 2-5 as they provide cross-cutting concerns. Listed separately for clarity.

---

## Dependency Graph

```
FA1 (Hybrid DB) ──────→ R1 (Storage) ──→ R4 (Retrieval) ──→ R12 (Why)
FA2 (Code Embeddings) ─→ R2 (Embedding Engine) ──→ R4       │
FA3 (Errors + Audit) ──→ ALL subsystems                      ↓
R22 (Crate Structure) ─→ ALL subsystems               R18 (Generation)
                                                              │
R3 (Token Counting) ───→ R5 (Compression) ──→ R4             ↓
                                                       R19 (MCP Tools)
R1 (Storage) ──────────→ R7 (Algorithmic Consolidation)
R2 (Embedding Engine) ─→ R7 (HDBSCAN clustering + recall gate)
                    ├───→ R8 (Decay)
                    ├───→ R9 (Contradiction) ──→ R11 (Causal Graph)
                    ├───→ R10 (Validation)
                    ├───→ R13 (Learning) ──→ R14 (Active Learning)
                    ├───→ R15 (Prediction)
                    ├───→ R16 (Session)
                    ├───→ R17 (Privacy)
                    └───→ R21 (Versioning)

R7 (Consolidation) ───→ CX15 (Quality Monitoring, built alongside)
R11 (Causal) ──────────→ R12 (Why System)
R4 (Retrieval) ────────→ R15 (Prediction, pre-compute)
R16 (Session) ─────────→ R20 (Observability)
```

---

## Risk Assessment

| Risk | Mitigation |
|---|---|
| ONNX model loading is slow on first run | Pre-download models during `drift setup`. Cache loaded models in L3. |
| sqlite-vec brute-force search too slow at scale | Pre-filter by type/importance. Use Matryoshka truncation for fast search. |
| Causal graph grows unbounded | Prune weak edges (strength < 0.2) and old unvalidated edges periodically. |
| Algorithmic consolidation quality lower than LLM | CX15 monitoring detects quality issues. Optional LLM polish available. Recall gate (CX14) prevents bad consolidations. Auto-tuning feedback loop improves thresholds over time. |
| HDBSCAN clustering produces too many noise points | Tune min_cluster_size and min_samples. Noise points are deferred, not lost — they consolidate when more supporting episodes arrive. |
| NAPI bridge complexity for Rust ↔ TS | Use napi-rs with typed bindings. Keep MCP tools in TS as thin wrappers. |
| Memory versioning storage growth | Limit to last 10 versions per memory. Compress old versions. |
| Hybrid search query complexity | Abstract behind a `HybridSearcher` that encapsulates the FTS5 + vec + RRF logic. |
| Token counting overhead | Cache counts per content hash (R3). Amortized cost is near-zero. |
| Cloud sync conflicts | Local SQLite is source of truth. Sync log tracks mutations. Conflict resolution: last-write-wins with audit trail. |
| Embedding model change breaks retrieval | CX19 migration pipeline: FTS5-only fallback during transition, background re-embedding, no downtime. |
| Concurrent write contention | CX20: single write connection behind Mutex, serialized writes. Reads never blocked (WAL mode). |
| cortex.db grows too large (>1GB) | CX21: archived cleanup, audit rotation, incremental VACUUM, storage health reporting. |
| Importance oscillation from auto-reclassification | CX22: max 1 reclassification/month, 2-3 month consistency requirement, never auto-downgrade user-set critical. |
| SQLite corruption | CX18: WAL recovery → rebuild from backup → fresh start with warning. Audit log preserved separately. |

---

## Quality Checklist

- [x] All 25 source documents in 06-cortex/ accounted for
- [x] All v2 notes from every source document addressed
- [x] All 12 limitations from RECAP resolved in recommendations
- [x] Every recommendation framed as "build new" not "migrate/port"
- [x] External evidence cited for every architectural decision
- [x] Build order defined with dependency graph
- [x] No feature deferred to "add later" — everything built into the right phase
- [x] Traceability: every source doc maps to at least one recommendation
- [x] Risk assessment with mitigations (15 risks identified)
- [x] Rust crate structure defined with all dependencies
- [x] NAPI boundary clearly defined (MCP tools in TS, everything else in Rust)
- [x] Consolidation is fully algorithmic — no LLM dependency for core functionality (CX14)
- [x] Consolidation quality monitoring with auto-tuning feedback loop (CX15)
- [x] Embedding provider hierarchy updated with Codestral Embed SOTA (CX16)
- [x] Testing strategy: property-based + golden datasets + performance benchmarks + integration (CX17)
- [x] Graceful degradation matrix for every failure mode (CX18)
- [x] Embedding migration pipeline for model changes (CX19)
- [x] Concurrency model: RW pool + state synchronization + background task scheduling (CX20)
- [x] Data budget with storage projections and compaction strategy (CX21)
- [x] Memory importance auto-reclassification (CX22)
- [x] CLI surface defined as contract for 10-cli research (CX23)
- [x] Cloud sync boundary identified (local SQLite as source of truth)
- [x] Offline-first architecture — all core features work without cloud or API keys
