# Cortex Memory System — Unified Implementation Specification

> **Version:** 2.0.0
> **Status:** APPROVED FOR IMPLEMENTATION
> **Workspace:** `crates/cortex/` (Rust) + `packages/cortex/` (TypeScript MCP layer)
> **Last Updated:** 2026-02-06
> **Research Corpus:** 25 v1 subsystem documents, 15 external research papers (R1-R15), 23 recommendations (CX1-CX23), RECAP, DIRECTORY-MAP
> **Supersedes:** CORTEX-IMPLEMENTATION-SPEC v1.0.0, individual subsystem docs as implementation authority
> **File Count:** ~334 files across 19 Rust crates + 1 TypeScript package + test infrastructure
> **Directory Map:** DIRECTORY-MAP.md (structural blueprint — this spec is the behavioral blueprint)

## What This Document Is

This is the single source of truth for building Drift's Cortex memory system in Rust. An agent reading this document should be able to implement every crate, every module, every file — understand every connection, and know why every decision was made. No source code is included — only specifications, interfaces, data shapes, and rationale.

This document accounts for 100% of the ~334 files defined in DIRECTORY-MAP.md. Every file in that map has a corresponding specification section here. If it's in the map, it's in this spec.

This document synthesizes:
- The v1 TypeScript implementation (~150 files, 18 subsystems) documented in `06-cortex/*.md`
- External research (R1-R15) validating architectural decisions
- 23 concrete recommendations (CX1-CX23) addressing all 12 identified v1 limitations
- The DIRECTORY-MAP structural blueprint for the Rust workspace (~334 files)

## Why This System Exists

Cortex is Drift's persistent AI memory system — the "brain" that maintains knowledge across sessions. It replaces static `AGENTS.md` files with living memory that decays, learns, contradicts itself, and consolidates over time — modeled after human cognitive processes.

The core questions this system answers:
1. **"What do we know?"** — 23 typed memories with confidence scoring and bitemporal tracking
2. **"Why is it this way?"** — Causal graph with narrative generation, counterfactual and intervention queries
3. **"What's relevant right now?"** — Intent-aware hybrid retrieval with session deduplication
4. **"What did we learn?"** — Correction analysis, principle extraction, active learning
5. **"Is our knowledge still valid?"** — 4-dimension validation with automatic healing

---

## Technology Stack

| Concern | Choice | Why | Evidence |
|---------|--------|-----|----------|
| Core Language | Rust | 3-5x faster than TS for embedding inference, memory safety, zero-cost abstractions | R4 |
| Storage | SQLite (rusqlite, bundled) | Single-file, WAL mode, FTS5 + sqlite-vec, no external DB | R8 |
| Vector Search | sqlite-vec | Brute-force KNN, SIMD acceleration, cosine/L2/inner product | R8 |
| Full-Text Search | FTS5 | BM25 scoring, snippet extraction, built into SQLite | R2 |
| Embedding Inference | ort (ONNX Runtime) | 3-5x faster than Transformers.js, GPU support, quantized models | R4 |
| Default Embedding Model | Jina Code v2 (1024-dim) | Code-specific, Apache 2.0, 8192 context, Matryoshka support | R3, CX2 |
| Graph Engine | petgraph (StableGraph) | Stable indices after removal, built-in Tarjan's SCC, DFS/BFS iterators | R5 |
| Caching | moka | TinyLFU + LRU, thread-safe, per-entry TTL, size-aware eviction | R6 |
| Token Counting | tiktoken-rs | Exact cl100k_base tokenization, not string-length approximation | R12, CX7 |
| Content Hashing | blake3 | Fastest cryptographic hash, used for embedding cache keys and dedup | — |
| Clustering | hdbscan | Density-based, no predefined cluster count, handles noise points | CX14 |
| Concurrency | dashmap | Fine-grained per-key locking for session contexts | CX20 |
| Serialization | serde + serde_json | Typed struct serialization, not JSON blobs | — |
| Errors | thiserror | Structured error hierarchy with context | CX18 |
| Async Runtime | tokio | Async embedding inference, background task scheduling | — |
| Parallelism | rayon | Data-parallel batch operations (embedding, decay) | — |
| Testing | proptest + criterion | Property-based testing + performance benchmarks | CX17 |
| TS Interop | napi-rs | NAPI bindings for TypeScript MCP tool layer | — |
| MCP Tools | TypeScript | Thin JSON-RPC wrappers over Rust via NAPI — no perf-critical logic | — |
| Testing (TS) | Vitest | Speed, ESM support, matches monorepo | — |

---

## Architecture: 19 Rust Crates + 1 TypeScript Package

The system is organized as a Rust workspace with focused crates and a thin TypeScript MCP layer. Each crate has a single responsibility. Dependencies flow downward — lower crates cannot import from higher crates.

```
crates/cortex/
├── cortex-core/              # Types, traits, errors, config, constants (depends on: nothing)
├── cortex-tokens/            # Accurate token counting via tiktoken-rs (depends on: core)
├── cortex-storage/           # SQLite persistence, migrations, audit log (depends on: core)
├── cortex-embeddings/        # ONNX providers, 3-tier cache, enrichment (depends on: core)
├── cortex-privacy/           # PII/secret sanitization, 50+ patterns (depends on: core)
├── cortex-compression/       # 4-level hierarchical compression (depends on: core, tokens)
├── cortex-decay/             # Multi-factor decay, adaptive half-lives (depends on: core)
├── cortex-causal/            # petgraph DAG, inference, traversal, narrative (depends on: core, storage)
├── cortex-retrieval/         # Hybrid search, RRF, re-ranking, intent, generation, why (depends on: core, storage, embeddings, compression, tokens)
├── cortex-validation/        # 4-dimension validation, contradiction, healing (depends on: core, storage, embeddings)
├── cortex-learning/          # Correction analysis, principle extraction (depends on: core, storage, embeddings, causal)
├── cortex-consolidation/     # HDBSCAN pipeline, quality monitoring (depends on: core, storage, embeddings)
├── cortex-prediction/        # Signal gathering, 4 strategies, cache (depends on: core, storage)
├── cortex-session/           # Session management, deduplication (depends on: core)
├── cortex-reclassification/  # Importance auto-reclassification (depends on: core, storage)
├── cortex-observability/     # Health, metrics, tracing, degradation (depends on: core)
├── cortex-cloud/             # Cloud sync, conflict resolution, auth (depends on: core, storage) [feature-gated]
├── cortex-napi/              # NAPI bindings for TypeScript interop (depends on: ALL crates)
└── test-fixtures/            # Golden datasets, benchmark data

packages/cortex/              # TypeScript layer — 33 MCP tools + NAPI consumer
├── src/
│   ├── tools/                # 33 MCP tool definitions
│   ├── bridge/               # NAPI bridge consumer
│   ├── cli/                  # CLI commands (drift cortex ...)
│   └── index.ts              # Public exports
├── tests/                    # TS integration tests
└── package.json
```

---

## Rust Workspace Root (~4 files)

```
crates/cortex/
├── Cargo.toml                  # Workspace manifest — all member crates
├── rust-toolchain.toml         # Pin Rust version for reproducible builds
├── .cargo/
│   └── config.toml             # Workspace-level cargo config (linker, target opts)
└── deny.toml                   # cargo-deny config — license + advisory audit
```

### Cargo.toml (Workspace Manifest)

All 19 crates listed as workspace members. Shared dependency versions via `[workspace.dependencies]`. Profile settings for release (LTO, codegen-units=1) and dev (incremental, debug=2).

### rust-toolchain.toml

Pin to stable Rust channel with specific version for reproducible builds across all contributors.

### .cargo/config.toml

Platform-specific linker settings (mold on Linux, default on macOS/Windows). Target-specific optimizations. Environment variable defaults.

### deny.toml

cargo-deny configuration: license allowlist (MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, Zlib), advisory database checks, duplicate dependency detection.

---

## Incremental Testing & Quality Gates Philosophy

Every crate is tested in isolation BEFORE the next crate in the dependency chain is built. This is the primary defense against silent failures that compound across subsystems.

**Why this matters for a memory system:** A silent failure in the embedding layer (wrong dimensions stored) propagates to retrieval (similarity scores are garbage) which propagates to consolidation (wrong clusters formed) which propagates to the user (irrelevant memories surfaced, relevant ones missed). The cost of catching bugs increases exponentially with distance from the source.

**The rule:** No crate N+1 code is written until all crate N tests pass. No phase N+1 begins until the phase N quality gate is satisfied.

### Quality Gate Summary

| Gate | Crate/Phase | Key Validation |
|------|-------------|----------------|
| QG-0 | cortex-core | Types compile, error hierarchy works, config loads, all traits defined |
| QG-1 | cortex-tokens | Exact token counts match tiktoken reference, caching works |
| QG-2 | cortex-storage | Full CRUD, migrations run, FTS5 + sqlite-vec operational, audit log appends, versioning works |
| QG-3 | cortex-embeddings | ONNX inference works, 3-tier cache operational, enrichment prepends metadata |
| QG-4 | cortex-privacy | 50+ patterns compile, sanitization idempotent, no false positives on code |
| QG-5 | cortex-compression | Level ordering correct, budget never exceeded, L3 is lossless |
| QG-6 | cortex-decay | Monotonically decreasing, bounded 0-1, adaptive half-lives compute correctly |
| QG-7 | cortex-causal | DAG enforced, traversal depth-limited, narrative generates, no cycles |
| QG-8 | cortex-retrieval | Hybrid search returns results, RRF fusion correct, budget respected, generation context builds, why system synthesizes |
| QG-9 | cortex-validation | 4 dimensions run, contradictions detected, healing triggers, consensus works |
| QG-10 | cortex-learning | Corrections categorized, principles extracted, dedup works, active learning selects |
| QG-11 | cortex-consolidation | HDBSCAN clusters, recall gate filters, quality metrics tracked, auto-tuning works |
| QG-12 | cortex-prediction | 4 strategies produce candidates, cache invalidates on file change |
| QG-13 | cortex-session | Deduplication saves tokens, cleanup removes stale sessions |
| QG-14 | cortex-napi | Rust ↔ JS roundtrip works for all 33 MCP tool signatures |
| QG-15 | Integration | Full lifecycle: create → retrieve → consolidate → decay → validate |

### Silent Failure Detection Strategy

| Crate | Silent Failure Risk | Detection Test |
|-------|-------------------|----------------|
| core | Missing trait method → downstream compile error | Implement mock for every trait, compile |
| storage | FTS5 index not created → keyword search returns nothing | Insert memory, FTS5 search by keyword → must find it |
| embeddings | Wrong dimensions stored → similarity scores meaningless | Assert embedding.len() == configured dimensions |
| embeddings | Enrichment not applied → embeddings lack context signal | Assert embedded text starts with metadata prefix |
| retrieval | RRF fusion drops results → relevant memories missed | Known-relevant memory must appear in top-5 for matching query |
| consolidation | Recall gate always passes → bad consolidations accepted | Feed poorly-encoded cluster → gate must reject |
| consolidation | HDBSCAN noise points lost → memories disappear | Noise points must remain in pending state, not deleted |
| decay | Importance anchor exceeds cap → confidence > 1.0 | Assert 0.0 ≤ confidence ≤ 1.0 for all decay outputs |
| privacy | Pattern regex fails to compile → secrets leak | Compile all patterns at startup, fail fast on error |
| causal | Cycle inserted → infinite traversal loop | Insert edge that would create cycle → must be rejected |
| validation | Contradiction missed → conflicting knowledge served | Two directly contradicting memories → contradiction detected |

---

## Memory Type System — 23 Types Across 3 Categories

Every memory extends `BaseMemory` — the universal struct with 20+ fields.

### BaseMemory Fields

```
BaseMemory:
  id: String (UUID v4)
  memory_type: MemoryType (enum, 23 variants)
  content: TypedContent (serde-serialized per-type struct, NOT JSON blob)
  summary: String (~20 tokens, for Level 1 compression)
  transaction_time: DateTime (when we learned it — bitemporal)
  valid_time: DateTime (when it was/is true — bitemporal)
  valid_until: Option<DateTime> (expiry, if known)
  confidence: f64 (0.0-1.0, decays over time)
  importance: Importance (low | normal | high | critical)
  last_accessed: DateTime
  access_count: u64
  linked_patterns: Vec<PatternLink>
  linked_constraints: Vec<ConstraintLink>
  linked_files: Vec<FileLink> (with citation: line_start, line_end, content_hash)
  linked_functions: Vec<FunctionLink>
  tags: Vec<String>
  archived: bool
  superseded_by: Option<String> (memory ID)
  supersedes: Option<String> (memory ID)
  content_hash: String (blake3 hash for dedup and embedding cache)
```

### Category 1 — Domain-Agnostic (9 types)

| Type | Half-Life | Purpose |
|------|-----------|---------|
| `core` | ∞ | Project/workspace metadata |
| `tribal` | 365d | Institutional knowledge with severity, warnings, consequences |
| `procedural` | 180d | How-to procedures with ordered steps and checklists |
| `semantic` | 90d | Consolidated knowledge from episodic memories |
| `episodic` | 7d | Raw interaction records, material for consolidation |
| `decision` | 180d | Standalone decisions with alternatives considered |
| `insight` | 90d | Learned observations |
| `reference` | 60d | External references/citations |
| `preference` | 120d | User/team preferences |

### Category 2 — Code-Specific (4 types)

| Type | Half-Life | Purpose |
|------|-----------|---------|
| `pattern_rationale` | 180d | Why patterns exist, with business context |
| `constraint_override` | 90d | Approved exceptions to constraints |
| `decision_context` | 180d | Code decision context linked to ADRs |
| `code_smell` | 90d | Anti-patterns with bad/good examples |

### Category 3 — Universal V2 (10 types)

| Type | Half-Life | Purpose |
|------|-----------|---------|
| `agent_spawn` | 365d | Reusable agent configurations |
| `entity` | 180d | Projects, products, teams, systems |
| `goal` | 90d | Objectives with progress tracking |
| `feedback` | 120d | Corrections and learning signals |
| `workflow` | 180d | Step-by-step processes |
| `conversation` | 30d | Summarized past discussions |
| `incident` | 365d | Postmortems with root cause |
| `meeting` | 60d | Meeting notes and action items |
| `skill` | 180d | Knowledge domains and proficiency |
| `environment` | 90d | System/environment configurations |

### Relationship Types (13)

Core: `supersedes`, `supports`, `contradicts`, `related`, `derived_from`
Semantic V2: `owns`, `affects`, `blocks`, `requires`, `references`, `learned_from`, `assigned_to`, `depends_on`

Each relationship carries a `strength` (0.0-1.0) and optional `evidence` array.

---

## Crate 1: cortex-core — Types, Traits, Errors, Config, Constants (~35 files)

The foundation crate. Every other crate depends on this. Zero heavy external dependencies — just serde, chrono, uuid, thiserror.

**Deps:** serde, serde_json, chrono, uuid, thiserror

### Directory Structure

```
crates/cortex/cortex-core/
├── Cargo.toml
├── src/
│   ├── lib.rs                          # Re-exports all public modules
│   ├── memory/
│   │   ├── mod.rs                      # Module declarations
│   │   ├── base.rs                     # BaseMemory struct — 20+ fields
│   │   ├── types/
│   │   │   ├── mod.rs                  # Memory type enum (23 variants) + dispatch
│   │   │   ├── domain_agnostic.rs      # 9 types: core, tribal, procedural, semantic,
│   │   │   │                           #   episodic, decision, insight, reference, preference
│   │   │   ├── code_specific.rs        # 4 types: pattern_rationale, constraint_override,
│   │   │   │                           #   decision_context, code_smell
│   │   │   └── universal.rs            # 10 types: agent_spawn, entity, goal, feedback,
│   │   │                               #   workflow, conversation, incident, meeting,
│   │   │                               #   skill, environment
│   │   ├── importance.rs               # Importance enum (low/normal/high/critical) + weight constants + ordering
│   │   ├── confidence.rs               # Confidence newtype (f64, 0.0-1.0) + clamping + arithmetic + thresholds
│   │   ├── relationships.rs            # 13 relationship types + RelationshipEdge struct
│   │   ├── links.rs                    # PatternLink, ConstraintLink, FileLink (with citation), FunctionLink
│   │   └── half_lives.rs              # Per-type half-life constants (days)
│   ├── traits/
│   │   ├── mod.rs                      # Re-exports all traits
│   │   ├── storage.rs                  # IMemoryStorage — full CRUD + bulk + query + vector + bitemporal + relationships + links + aggregation + maintenance
│   │   ├── embedding.rs                # IEmbeddingProvider — embed, embedBatch, dimensions, name, isAvailable
│   │   ├── causal_storage.rs           # ICausalStorage — CRUD + strength + evidence + validation + statistics + cleanup
│   │   ├── retriever.rs                # IRetriever — retrieve(context, budget) -> Vec<CompressedMemory>
│   │   ├── consolidator.rs             # IConsolidator — consolidate(candidates) -> ConsolidationResult
│   │   ├── decay_engine.rs             # IDecayEngine — calculate(memory) -> f64
│   │   ├── validator.rs                # IValidator — validate(memory) -> ValidationResult
│   │   ├── compressor.rs               # ICompressor — compress(memory, level) -> CompressedMemory
│   │   ├── sanitizer.rs                # ISanitizer — sanitize(text) -> SanitizedText
│   │   ├── predictor.rs                # IPredictor — predict(signals) -> Vec<PredictedMemory>
│   │   ├── learner.rs                  # ILearner — analyze(correction) -> LearningResult
│   │   └── health_reporter.rs          # IHealthReporter — report() -> HealthReport
│   ├── errors/
│   │   ├── mod.rs                      # Re-exports, From impls, error conversion
│   │   ├── cortex_error.rs             # Top-level CortexError enum — all error variants
│   │   ├── storage_error.rs            # StorageError — SqliteError, MigrationFailed, CorruptionDetected, ConnectionPoolExhausted
│   │   ├── embedding_error.rs          # EmbeddingError — ModelLoadFailed, InferenceFailed, DimensionMismatch, ProviderUnavailable, CacheMiss
│   │   ├── retrieval_error.rs          # RetrievalError — BudgetExceeded, NoResults, SearchFailed, RankingFailed
│   │   ├── causal_error.rs             # CausalError — CycleDetected, TraversalDepthExceeded, InvalidRelation, GraphInconsistency
│   │   ├── consolidation_error.rs      # ConsolidationError — ClusteringFailed, RecallGateFailed, MergeFailed, QualityBelowThreshold
│   │   └── cloud_error.rs              # CloudError — AuthFailed, SyncConflict, NetworkError, QuotaExceeded, VersionMismatch
│   ├── config/
│   │   ├── mod.rs                      # CortexConfig — top-level config struct
│   │   ├── storage_config.rs           # DB path, WAL mode, mmap size, cache size, pragmas
│   │   ├── embedding_config.rs         # Provider selection, model path, dimensions, matryoshka dims, batch size, cache sizes
│   │   ├── retrieval_config.rs         # Default budget, RRF k-value, re-rank top-K, intent weights path, query expansion toggle
│   │   ├── consolidation_config.rs     # Min cluster size, similarity threshold, novelty threshold, recall gate params, scheduling intervals, LLM polish toggle
│   │   ├── decay_config.rs             # Half-life overrides, adaptive factors, archival threshold, processing interval
│   │   ├── privacy_config.rs           # Pattern overrides, NER toggle, context scoring
│   │   ├── cloud_config.rs             # Endpoint URL, auth method, sync interval, conflict resolution strategy, offline mode
│   │   ├── observability_config.rs     # Metrics export interval, log level, tracing toggle, health check interval
│   │   └── defaults.rs                 # All default values as constants
│   ├── constants.rs                    # Global constants — version, magic numbers, default thresholds, feature flags
│   ├── intent/
│   │   ├── mod.rs                      # Intent enum (18 variants) + classification
│   │   ├── taxonomy.rs                 # Domain-agnostic (7), Code-specific (8), Universal (3)
│   │   └── weights.rs                  # Intent → MemoryType boost matrix, configurable via TOML with defaults
│   └── models/
│       ├── mod.rs                      # Re-exports all shared models
│       ├── compressed_memory.rs        # CompressedMemory — 4 levels with metadata
│       ├── retrieval_context.rs        # RetrievalContext — focus, intent, files, budget
│       ├── consolidation_result.rs     # ConsolidationResult — created, archived, metrics
│       ├── validation_result.rs        # ValidationResult — dimension scores, healing actions
│       ├── learning_result.rs          # LearningResult — category, principle, memory created
│       ├── health_report.rs            # HealthReport — all subsystem statuses + metrics
│       ├── causal_narrative.rs         # CausalNarrative — sections, summary, confidence
│       ├── why_context.rs              # WhyContext — patterns, decisions, tribal, warnings
│       ├── generation_context.rs       # GenerationContext — budget allocation, provenance
│       ├── prediction_result.rs        # PredictionResult — memories, signals, confidence
│       ├── session_context.rs          # SessionContext — loaded sets, token tracking
│       ├── audit_entry.rs              # AuditEntry — memory_id, operation, details, actor
│       ├── embedding_info.rs           # EmbeddingModelInfo — name, dimensions, status
│       ├── contradiction.rs            # Contradiction — type, memories, confidence delta
│       ├── consolidation_metrics.rs    # Precision, compression ratio, lift, stability
│       └── degradation_event.rs        # DegradationEvent — component, failure, fallback used
```

### Traits (12 interfaces)

Every subsystem implements a trait defined here. This enables testing with mocks and swapping implementations.

| Trait | Purpose | Key Methods |
|-------|---------|-------------|
| `IMemoryStorage` | Full CRUD + bulk + query + vector + bitemporal + relationships + links + aggregation + maintenance | `create`, `get`, `update`, `delete`, `search_fts5`, `search_vector`, `query_by_type`, `get_relationships`, `vacuum` |
| `IEmbeddingProvider` | Embedding generation | `embed`, `embed_batch`, `dimensions`, `name`, `is_available` |
| `ICausalStorage` | Causal edge CRUD + strength + evidence | `add_edge`, `get_edges`, `update_strength`, `add_evidence` |
| `IRetriever` | Context retrieval | `retrieve(context, budget) -> Vec<CompressedMemory>` |
| `IConsolidator` | Memory consolidation | `consolidate(candidates) -> ConsolidationResult` |
| `IDecayEngine` | Confidence decay | `calculate(memory) -> f64` |
| `IValidator` | Memory validation | `validate(memory) -> ValidationResult` |
| `ICompressor` | Hierarchical compression | `compress(memory, level) -> CompressedMemory` |
| `ISanitizer` | PII/secret sanitization | `sanitize(text) -> SanitizedText` |
| `IPredictor` | Predictive preloading | `predict(signals) -> Vec<PredictedMemory>` |
| `ILearner` | Correction analysis | `analyze(correction) -> LearningResult` |
| `IHealthReporter` | System health | `report() -> HealthReport` |

### Error Hierarchy

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
    StorageError(#[from] StorageError),
    #[error("causal cycle detected: {path}")]
    CausalCycle { path: String },
    #[error("token budget exceeded: needed {needed}, available {available}")]
    TokenBudgetExceeded { needed: usize, available: usize },
    #[error("migration error: {0}")]
    MigrationError(String),
    #[error("sanitization error: {0}")]
    SanitizationError(String),
    #[error("consolidation error: {0}")]
    ConsolidationError(#[from] ConsolidationError),
    #[error("validation error: {0}")]
    ValidationError(String),
    #[error("serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("concurrency error: {0}")]
    ConcurrencyError(String),
    #[error("cloud sync error: {0}")]
    CloudSyncError(#[from] CloudError),
    #[error("config error: {0}")]
    ConfigError(String),
    #[error("degraded mode: {component} using fallback: {fallback}")]
    DegradedMode { component: String, fallback: String },
}
```

Sub-errors: `StorageError` (SqliteError, MigrationFailed, CorruptionDetected, ConnectionPoolExhausted), `EmbeddingError` (ModelLoadFailed, InferenceFailed, DimensionMismatch, ProviderUnavailable), `ConsolidationError` (ClusteringFailed, RecallGateFailed, MergeFailed), `CloudError` (AuthFailed, SyncConflict, NetworkError, QuotaExceeded).

### Config

Top-level `CortexConfig` struct with sub-configs for every subsystem:
- `StorageConfig` (`storage_config.rs`): db_path, wal_mode, mmap_size (256MB), cache_size (64MB), pragmas
- `EmbeddingConfig` (`embedding_config.rs`): provider selection, model_path, dimensions, matryoshka_dims, batch_size, cache sizes
- `RetrievalConfig` (`retrieval_config.rs`): default_budget (2000 tokens), rrf_k (60), rerank_top_k, intent_weights_path
- `ConsolidationConfig` (`consolidation_config.rs`): min_cluster_size (2), similarity_threshold, novelty_threshold (0.85), recall_gate_params, scheduling intervals
- `DecayConfig` (`decay_config.rs`): half_life_overrides, adaptive_factors, archival_threshold (0.15)
- `PrivacyConfig` (`privacy_config.rs`): pattern_overrides, ner_toggle, context_scoring
- `CloudConfig` (`cloud_config.rs`): endpoint_url, auth_method, sync_interval, conflict_resolution_strategy, offline_mode
- `ObservabilityConfig` (`observability_config.rs`): metrics_export_interval, log_level, tracing_toggle
- `defaults.rs`: All default values as constants — single source for every default

### Intent Taxonomy (18 intents)

**Domain-agnostic (7):** create, investigate, decide, recall, learn, summarize, compare
**Code-specific (8):** add_feature, fix_bug, refactor, security_audit, understand_code, add_test, review_code, deploy, migrate
**Universal (3):** spawn_agent, execute_workflow, track_progress

`weights.rs`: Intent → MemoryType boost matrix. Configurable via TOML, with hardcoded defaults as fallback.

### Models (16 shared data structures)

All in `models/` — these are the data shapes that flow between crates:

| Model | File | Purpose |
|-------|------|---------|
| CompressedMemory | `compressed_memory.rs` | 4 levels with metadata |
| RetrievalContext | `retrieval_context.rs` | focus, intent, files, budget |
| ConsolidationResult | `consolidation_result.rs` | created, archived, metrics |
| ValidationResult | `validation_result.rs` | dimension scores, healing actions |
| LearningResult | `learning_result.rs` | category, principle, memory created |
| HealthReport | `health_report.rs` | all subsystem statuses + metrics |
| CausalNarrative | `causal_narrative.rs` | sections, summary, confidence |
| WhyContext | `why_context.rs` | patterns, decisions, tribal, warnings |
| GenerationContext | `generation_context.rs` | budget allocation, provenance |
| PredictionResult | `prediction_result.rs` | memories, signals, confidence |
| SessionContext | `session_context.rs` | loaded sets, token tracking |
| AuditEntry | `audit_entry.rs` | memory_id, operation, details, actor, timestamp |
| EmbeddingModelInfo | `embedding_info.rs` | name, dimensions, status |
| Contradiction | `contradiction.rs` | type, memories, confidence delta |
| ConsolidationMetrics | `consolidation_metrics.rs` | precision, compression ratio, lift, stability |
| DegradationEvent | `degradation_event.rs` | component, failure, fallback used |

### QG-0: Core Quality Gate

| Test | Pass Criteria |
|------|---------------|
| All type files compile with zero errors | `cargo check` exits 0 |
| Every trait is implementable (mock compiles) | Create mock struct implementing each trait — compiles |
| All error variants carry correct context | Pattern match every variant, extract fields |
| Config loads from TOML with defaults | Load empty TOML → all defaults populated |
| 23 memory types have correct half-lives | Assert each type's half-life matches spec |
| 13 relationship types defined | Assert enum variant count |
| 18 intent types defined | Assert enum variant count |
| Serde roundtrip for BaseMemory | Serialize → deserialize → assert equality |
| Content hash is deterministic | Same content → same blake3 hash |

---

## Crate 2: cortex-tokens — Accurate Token Counting (~3 files)

**Purpose:** Replace string-length approximation with exact tokenizer-based counting. Cache results per content hash.

**Why it exists:** v1 used `text.length / 4` which causes budget overflows (truncation) or underutilization (wasted context window). Accurate counting is critical for compression packing and retrieval budgeting.

**Evidence:** R12 (tiktoken, tiktoken-rs), CX7

**Deps:** tiktoken-rs, blake3, moka

### Directory Structure

```
crates/cortex/cortex-tokens/
├── Cargo.toml
├── src/
│   ├── lib.rs                          # Re-exports
│   ├── counter.rs                      # TokenCounter — cl100k_base (GPT-4/Claude)
│   │                                   #   count(text) → usize
│   │                                   #   count_cached(text) → usize (content-hash keyed)
│   │                                   #   Cache: moka::sync::Cache<String, usize>
│   └── budget.rs                       # TokenBudget — budget tracking helpers
│                                       #   remaining(total, used) → usize
│                                       #   fits(text, budget) → bool
│                                       #   allocate(items, budget) → Vec<Allocation>
```

### Key Components

- `TokenCounter`: Wraps `tiktoken_rs::cl100k_base`. `count(text) -> usize`. `count_cached(text) -> usize` with blake3 content-hash keyed moka cache.
- `TokenBudget`: `remaining(total, used) -> usize`, `fits(text, budget) -> bool`, `allocate(items, budget) -> Vec<Allocation>`

### QG-1: Token Quality Gate

| Test | Pass Criteria |
|------|---------------|
| count("") == 0 | Empty string is zero tokens |
| count matches tiktoken reference | Compare against Python tiktoken for 100 test strings |
| count(a + b) ≤ count(a) + count(b) + 1 | Subadditivity property |
| Cached count == uncached count | Cache doesn't corrupt results |
| CJK characters count correctly | "你好世界" ≈ 4-6 tokens, not 1 |

---

## Crate 3: cortex-storage — SQLite Persistence, Migrations, Audit, Versioning (~30 files)

**Purpose:** The data layer. Owns `cortex.db`. Implements `IMemoryStorage` and `ICausalStorage`. Single write connection + read pool (CX20). Also owns memory versioning (content evolution tracking).

**Evidence:** R2 (hybrid search), R8 (sqlite-vec), CX20 (concurrency model)

**Deps:** rusqlite (bundled), serde, serde_json, chrono, uuid, cortex-core, tokio::sync

### Directory Structure

```
crates/cortex/cortex-storage/
├── Cargo.toml
├── src/
│   ├── lib.rs                          # Re-exports, StorageEngine init
│   ├── engine.rs                       # StorageEngine — owns ConnectionPool,
│   │                                   #   implements IMemoryStorage + ICausalStorage,
│   │                                   #   startup pragma configuration, shutdown cleanup
│   ├── pool/
│   │   ├── mod.rs                      # ConnectionPool — manages read/write connections
│   │   ├── write_connection.rs         # Single write connection behind tokio::sync::Mutex
│   │   ├── read_pool.rs               # Pool of 4-8 read connections (concurrent, never blocked by writer)
│   │   └── pragmas.rs                  # PRAGMA configuration per connection
│   ├── migrations/
│   │   ├── mod.rs                      # Migration runner — version tracking, forward-only, transactional
│   │   ├── v001_initial_schema.rs      # Core tables: memories, memory_relationships, memory_patterns, memory_constraints, memory_files, memory_functions, schema_version
│   │   ├── v002_vector_tables.rs       # sqlite-vec virtual table: memory_embeddings, memory_embedding_link
│   │   ├── v003_fts5_index.rs          # FTS5 virtual table on content + summary + tags
│   │   ├── v004_causal_tables.rs       # causal_edges, causal_evidence
│   │   ├── v005_session_tables.rs      # session_contexts, session_analytics
│   │   ├── v006_audit_tables.rs        # memory_audit_log, consolidation_metrics, degradation_log
│   │   ├── v007_validation_tables.rs   # memory_validation_history, memory_contradictions
│   │   ├── v008_versioning_tables.rs   # memory_versions (content evolution tracking)
│   │   ├── v009_embedding_migration.rs # embedding_model_info, model_version column
│   │   ├── v010_cloud_sync.rs          # sync_log, sync_state, conflict_log
│   │   ├── v011_reclassification.rs    # reclassification_history, reclassification_signals
│   │   └── v012_observability.rs       # metric_snapshots, query_performance_log
│   ├── queries/
│   │   ├── mod.rs                      # Query builder helpers
│   │   ├── memory_crud.rs              # Insert, update, get, delete, bulk ops
│   │   ├── memory_query.rs             # By type, pattern, constraint, file, function, importance, confidence range, date range
│   │   ├── memory_search.rs            # FTS5 full-text search queries
│   │   ├── vector_search.rs            # sqlite-vec similarity search queries
│   │   ├── relationship_ops.rs         # Relationship CRUD, strength updates
│   │   ├── link_ops.rs                 # Pattern/constraint/file/function link CRUD
│   │   ├── causal_ops.rs              # Causal edge CRUD, evidence management
│   │   ├── audit_ops.rs               # Audit log insert, query by memory/time/actor
│   │   ├── session_ops.rs             # Session CRUD, analytics aggregation
│   │   ├── version_ops.rs             # Memory version insert, query, rollback
│   │   ├── aggregation.rs             # Count by type, avg confidence, stale count, storage stats, growth rate
│   │   └── maintenance.rs             # VACUUM, checkpoint, integrity check, archived cleanup, audit rotation
│   ├── audit/
│   │   ├── mod.rs                      # AuditLogger — append-only mutation log
│   │   ├── logger.rs                   # Log every memory mutation (create, update, archive, restore, link, unlink, decay, validate, consolidate, reclassify)
│   │   └── rotation.rs                # Monthly rotation: entries > 1 year compressed into monthly summary records
│   ├── versioning/
│   │   ├── mod.rs                      # VersionManager
│   │   ├── tracker.rs                  # Track content changes: on every memory update, snapshot current content as new version
│   │   ├── query.rs                    # Version queries: get history, get at version, diff between versions
│   │   ├── rollback.rs                 # Rollback memory to previous version with audit log entry
│   │   └── retention.rs               # Version retention policy: max 10 versions per memory, compress old, delete beyond limit
│   ├── compaction/
│   │   ├── mod.rs                      # Compaction orchestrator
│   │   ├── archived_cleanup.rs         # Memories archived > 90 days, confidence < 0.1, zero access → permanent delete (keep tombstone)
│   │   ├── incremental_vacuum.rs       # Weekly: PRAGMA incremental_vacuum(1000)
│   │   ├── full_vacuum.rs              # Quarterly: only if fragmentation > 30%
│   │   ├── embedding_dedup.rs          # Share embedding rows for identical content hashes
│   │   └── storage_health.rs           # DB file size, active vs archived count, embedding storage size, FTS5 index size, fragmentation %, projected growth rate, time-to-threshold estimates
│   └── recovery/
│       ├── mod.rs                      # Recovery orchestrator (CX18 degradation)
│       ├── wal_recovery.rs             # Attempt WAL checkpoint recovery on corruption
│       ├── backup.rs                   # Periodic backup creation + restore from backup
│       ├── fts5_rebuild.rs             # Rebuild FTS5 index from memory content
│       └── integrity_check.rs          # PRAGMA integrity_check, detect corruption early
```

### Connection Pool (CX20)

```
Write Connection (1, exclusive):
  Behind tokio::sync::Mutex
  Used by: consolidation, decay, validation, learning, memory CRUD
  Serialized writes, no contention

Read Connections (4-8, concurrent):
  Pool of connections
  Used by: retrieval, search, MCP queries, prediction, health checks
  Fully concurrent, never blocked by writer (WAL mode)
```

### SQLite Pragmas (set on every connection via `pragmas.rs`)

```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA mmap_size = 268435456;    -- 256MB memory-mapped I/O
PRAGMA cache_size = -64000;       -- 64MB page cache
PRAGMA busy_timeout = 5000;       -- 5s retry on lock
PRAGMA foreign_keys = ON;
PRAGMA auto_vacuum = INCREMENTAL;
```

### Schema Migrations (12 versions)

| Migration | File | Tables Created |
|-----------|------|---------------|
| v001 | `v001_initial_schema.rs` | memories, memory_relationships, memory_patterns, memory_constraints, memory_files, memory_functions, schema_version |
| v002 | `v002_vector_tables.rs` | memory_embeddings (sqlite-vec virtual table), memory_embedding_link |
| v003 | `v003_fts5_index.rs` | FTS5 virtual table on content + summary + tags |
| v004 | `v004_causal_tables.rs` | causal_edges, causal_evidence |
| v005 | `v005_session_tables.rs` | session_contexts, session_analytics |
| v006 | `v006_audit_tables.rs` | memory_audit_log, consolidation_metrics, degradation_log |
| v007 | `v007_validation_tables.rs` | memory_validation_history, memory_contradictions |
| v008 | `v008_versioning_tables.rs` | memory_versions (content evolution tracking) |
| v009 | `v009_embedding_migration.rs` | embedding_model_info, model_version column on embedding_link |
| v010 | `v010_cloud_sync.rs` | sync_log, sync_state, conflict_log |
| v011 | `v011_reclassification.rs` | reclassification_history, reclassification_signals |
| v012 | `v012_observability.rs` | metric_snapshots, query_performance_log |

### Audit Log (`audit/`)

Every memory mutation logged to `memory_audit_log` via `logger.rs`:
- Operations: create, update, archive, restore, link, unlink, decay, validate, consolidate, reclassify
- Fields: memory_id, operation, details (JSON), actor (system|user|consolidation|decay|validation|learning|reclassification), timestamp
- Monthly rotation via `rotation.rs`: entries > 1 year compressed into monthly summaries

### Versioning System (`versioning/`)

Memory content evolution tracking — lives in cortex-storage since it's a persistence concern:
- `tracker.rs`: On every memory update, snapshot current content as a new version. Fields: memory_id, version, content, summary, confidence, changed_by, reason
- `query.rs`: Get version history for memory, get memory at specific version, diff between versions
- `rollback.rs`: Rollback memory to previous version with audit log entry
- `retention.rs`: Max 10 versions per memory, compress old versions, delete beyond retention limit

### Compaction Strategy (CX21, `compaction/`)

- `archived_cleanup.rs`: Monthly — memories archived > 90 days, confidence < 0.1, zero access → permanent delete (keep tombstone)
- `embedding_dedup.rs`: Identical content hashes share embedding rows
- `incremental_vacuum.rs`: Weekly — `PRAGMA incremental_vacuum(1000)`
- `full_vacuum.rs`: Quarterly — only if fragmentation > 30%
- `storage_health.rs`: DB file size, active vs archived count, embedding storage size, FTS5 index size, fragmentation %, projected growth rate, time-to-threshold estimates

### Recovery (CX18, `recovery/`)

- `wal_recovery.rs`: Attempt WAL checkpoint recovery on corruption
- `backup.rs`: Periodic backup creation + restore from backup
- `fts5_rebuild.rs`: Rebuild FTS5 index from memory content (background)
- `integrity_check.rs`: `PRAGMA integrity_check`, detect corruption early

### QG-2: Storage Quality Gate

| Test | Pass Criteria |
|------|---------------|
| All 12 migrations run on fresh DB | No errors, schema_version = 12 |
| Memory CRUD roundtrip | Create → get → update → delete, all fields preserved |
| Bulk insert 100 memories | All 100 retrievable, correct types |
| FTS5 search finds keyword match | Insert "bcrypt password hashing" → search "bcrypt" → found |
| sqlite-vec similarity search works | Insert embedding → query with similar vector → found |
| Relationship CRUD | Create edge → get → update strength → delete |
| Audit log records mutations | Create memory → audit log has entry with actor + operation |
| Concurrent reads during write | 4 read threads + 1 write thread → no errors, no corruption |
| WAL mode active | `PRAGMA journal_mode` returns "wal" |
| Content hash dedup for embeddings | Two memories with same content → share embedding row |
| Version tracking on update | Update memory → version history has 2 entries |
| Version rollback works | Update → rollback → content matches original |
| Version retention enforced | 11 updates → only 10 versions retained |

---

## Crate 4: cortex-embeddings — ONNX Providers, Cache, Enrichment (~15 files)

**Purpose:** All embedding generation. Multi-provider with 3-tier cache. Matryoshka support for dimension truncation.

**Evidence:** R3 (code embedding models), R4 (ort crate), R6 (moka cache), CX2, CX3, CX16, CX19

**Deps:** ort, moka, blake3, reqwest, tokio, cortex-core

### Directory Structure

```
crates/cortex/cortex-embeddings/
├── Cargo.toml
├── src/
│   ├── lib.rs                          # Re-exports, EmbeddingEngine init
│   ├── engine.rs                       # EmbeddingEngine — provider selection, fallback chain, cache coordination, implements IEmbeddingProvider
│   ├── providers/
│   │   ├── mod.rs                      # Provider registry + auto-detection
│   │   ├── onnx_provider.rs            # OnnxProvider — loads ONNX models via `ort`, default Jina Code v2 (1024-dim), quantized INT8, batch inference with padding
│   │   ├── api_provider.rs             # ApiProvider — HTTP client for cloud APIs (Codestral Embed, VoyageCode3, OpenAI text-embedding-3-large), rate limiting, retry with backoff
│   │   ├── ollama_provider.rs          # OllamaProvider — local Ollama instance, configurable model, health check
│   │   └── tfidf_fallback.rs           # TfIdfFallback — sparse vector generation for air-gapped environments, no external dependencies
│   ├── cache/
│   │   ├── mod.rs                      # CacheCoordinator — L1/L2/L3 orchestration
│   │   ├── l1_memory.rs                # L1: moka::sync::Cache — in-process, TinyLFU admission, size-aware eviction, per-entry TTL
│   │   ├── l2_sqlite.rs                # L2: SQLite table — content_hash → embedding, survives restarts, millisecond access
│   │   └── l3_precomputed.rs           # L3: Memory-mapped precomputed embeddings for frequently-accessed content, loaded at startup, zero-latency
│   ├── enrichment.rs                   # Embedding enrichment — prepend structured metadata: [{type}|{importance}|{category}] {summary} Files: {linkedFiles} Patterns: {linkedPatterns}
│   ├── matryoshka.rs                   # Matryoshka dimension management: store full dims (1024/2048), truncate to 384/256 for fast search, full dims for re-ranking, dimension validation + conversion
│   ├── migration/
│   │   ├── mod.rs                      # EmbeddingMigration orchestrator (CX19)
│   │   ├── detector.rs                 # Detect model change on startup: compare configured model vs embedding_model_info
│   │   ├── worker.rs                   # Background re-embedding worker: batch size 50, 100ms throttle, priority by importance + access frequency, resumable via model_version column
│   │   └── progress.rs                 # Migration progress tracking: total, completed, remaining, ETA, status (pending|in_progress|complete)
│   └── degradation.rs                  # Fallback chain (CX18): ONNX → fallback model → cached embeddings → TF-IDF sparse vectors → error. Every fallback logged to degradation_log
```

### Provider Hierarchy (CX16)

**API providers (cloud-connected)**:
1. Codestral Embed (Mistral) — SOTA on SWE-Bench, Matryoshka support
2. VoyageCode3 — 32K context, 2048 dims, 300+ languages
3. OpenAI text-embedding-3-large — general purpose fallback

**Local providers (offline)**:
1. Jina Code v2 (137M params, Apache 2.0, 8192 context) via `ort` — default
2. CodeRankEmbed (137M, MIT, 8192 context) via `ort` — alternative

**Fallback (air-gapped, no ONNX)**:
1. TF-IDF sparse vectors — no external dependencies

### 3-Tier Cache (CX12)

| Tier | File | Implementation | Characteristics |
|------|------|---------------|-----------------|
| L1 | `l1_memory.rs` | `moka::sync::Cache` | In-process, TinyLFU admission, size-aware eviction, per-entry TTL |
| L2 | `l2_sqlite.rs` | SQLite table | content_hash → embedding, survives restarts, millisecond access |
| L3 | `l3_precomputed.rs` | Memory-mapped file | Precomputed for frequently-accessed content, loaded at startup, zero-latency |

### Embedding Enrichment (CX3, `enrichment.rs`)

Before embedding, prepend structured metadata:
```
[{type}|{importance}|{category}] {summary}
Files: {linkedFiles}
Patterns: {linkedPatterns}
```

### Matryoshka Strategy (`matryoshka.rs`)

Store embeddings at full model dimensions (1024 for Jina, 2048 for Voyage/Codestral). Use truncated dimensions (384 or 256) for fast candidate search in sqlite-vec. Use full dimensions for re-ranking (CX6).

### Embedding Migration Pipeline (CX19, `migration/`)

When embedding model changes (dimension change or model upgrade):
1. `detector.rs`: Detect on startup — compare configured model vs `embedding_model_info` table
2. During migration: FTS5-only fallback for un-migrated memories
3. `worker.rs`: Background re-embedding — batch size 50, 100ms throttle, priority by importance + access frequency, resumable via `model_version` column
4. `progress.rs`: Track total, completed, remaining, ETA, status

### Degradation Chain (CX18, `degradation.rs`)

```
ONNX provider → fallback model → cached embeddings → TF-IDF sparse vectors → error
```
Every fallback logged to degradation_log.

### QG-3: Embedding Quality Gate

| Test | Pass Criteria |
|------|---------------|
| ONNX model loads and produces embeddings | embed("test") returns Vec<f32> with correct dimensions |
| Batch embedding works | embed_batch(10 texts) returns 10 vectors |
| L1 cache hit on repeated embed | Second call returns cached result (verify via timing) |
| L2 cache survives restart | Embed → restart → embed same text → L2 hit |
| Enrichment prepends metadata | Embedded text starts with `[type|importance|category]` |
| Matryoshka truncation preserves quality | Truncated 384-dim cosine similarity correlates with full 1024-dim |
| Fallback chain works | Disable ONNX → falls back to TF-IDF → still returns vector |
| Dimension mismatch detected | Configure 1024-dim model with 384-dim DB → migration triggered |

---

## Crate 5: cortex-privacy — PII/Secret Sanitization (~7 files)

**Purpose:** Privacy-first. Sanitizes all content before storage or transmission. 50+ patterns organized by category.

**Evidence:** R9 (layered PII detection), CX9

**Deps:** cortex-core, regex

### Directory Structure

```
crates/cortex/cortex-privacy/
├── Cargo.toml
├── src/
│   ├── lib.rs                          # Re-exports, PrivacyEngine init
│   ├── engine.rs                       # PrivacyEngine — implements ISanitizer, runs all pattern categories, context-aware scoring, idempotent
│   ├── patterns/
│   │   ├── mod.rs                      # Pattern registry + category dispatch
│   │   ├── pii.rs                      # 15+ PII patterns: email, phone, SSN, credit card, IP address, passport, driver's license, date of birth, physical address, national ID
│   │   ├── secrets.rs                  # 35+ secret patterns: API keys, AWS keys (AKIA...), JWT tokens, private keys (PEM), passwords, Azure/GCP/GitHub/GitLab/npm/PyPI/Slack/Stripe/Twilio/SendGrid/Heroku/DigitalOcean/Datadog
│   │   └── connection_strings.rs       # Connection string patterns: PostgreSQL, MySQL, MongoDB, Redis URLs with embedded credentials, Base64-encoded secrets
│   ├── context_scoring.rs              # Context-aware confidence adjustment: test file (-0.20), comment (-0.30), .env file (+0.10), placeholder (skip), sensitive variable name (+0.10)
│   └── degradation.rs                  # Graceful degradation (CX18): if regex compilation fails, skip pattern, log warning, continue with remaining patterns, audit log records the gap
```

### Pattern Categories

**PII Patterns (15+, `pii.rs`):** email, phone, SSN, credit card, IP address, passport, driver's license, date of birth, physical address, national ID. Replacements: `[EMAIL]`, `[PHONE]`, `[SSN]`, etc.

**Secret Patterns (35+, `secrets.rs`):** API keys, AWS keys (AKIA...), JWT tokens, private keys (PEM), passwords, Azure keys, GCP service accounts, GitHub tokens (ghp_, gho_, ghs_), GitLab tokens (glpat-), npm tokens, PyPI tokens, Slack tokens (xoxb-, xoxp-), Stripe keys (sk_live_, pk_live_), Twilio, SendGrid, Heroku, DigitalOcean, Datadog API keys.

**Connection Strings (`connection_strings.rs`):** PostgreSQL, MySQL, MongoDB, Redis URLs with embedded credentials. Base64-encoded secrets.

### Context-Aware Scoring (`context_scoring.rs`)

| Context | Confidence Adjustment |
|---------|----------------------|
| In test file | -0.20 |
| In comment | -0.30 |
| In .env file | +0.10 |
| Placeholder detected | Skip entirely |
| Sensitive variable name | +0.10 |

### QG-4: Privacy Quality Gate

| Test | Pass Criteria |
|------|---------------|
| All 50+ patterns compile | No regex compilation errors at startup |
| Known PII strings sanitized | Email, phone, SSN → replaced with placeholders |
| Known secrets sanitized | AWS key, JWT, GitHub token → replaced |
| Sanitization is idempotent | sanitize(sanitize(x)) == sanitize(x) |
| False positives on code are minimal | Common code patterns (hex strings, UUIDs) not flagged |
| Context scoring adjusts confidence | Same pattern in test file vs .env file → different confidence |
| Degradation handles regex failure | Invalid pattern → skipped, warning logged, other patterns still run |

---

## Crate 6: cortex-compression — 4-Level Hierarchical Compression (~6 files)

**Purpose:** Token-efficient memory representation. 4 levels from IDs-only to full context.

**Deps:** cortex-core, cortex-tokens

### Directory Structure

```
crates/cortex/cortex-compression/
├── Cargo.toml
├── src/
│   ├── lib.rs                          # Re-exports
│   ├── engine.rs                       # CompressionEngine — implements ICompressor
│   │                                   #   compress(memory, level) → CompressedMemory
│   │                                   #   compressToFit(memory, maxTokens) → CompressedMemory
│   │                                   #   compressBatchToFit(memories[], budget) → Vec<CompressedMemory>
│   ├── levels/
│   │   ├── mod.rs                      # Level enum + dispatch
│   │   ├── level0.rs                   # IDs only — ~5 tokens, max 10
│   │   ├── level1.rs                   # One-liners + tags — ~50 tokens, max 75
│   │   ├── level2.rs                   # With examples + evidence — ~200 tokens, max 300
│   │   └── level3.rs                   # Full context + causal + links — ~500 tokens, max 1000
│   └── packing.rs                      # Priority-weighted bin-packing
```

### Compression Levels

| Level | File | Content | Target Tokens | Max Tokens |
|-------|------|---------|---------------|------------|
| 0 | `level0.rs` | IDs only | 5 | 10 |
| 1 | `level1.rs` | One-liners + tags | 50 | 75 |
| 2 | `level2.rs` | With examples + evidence | 200 | 300 |
| 3 | `level3.rs` | Full context + causal chains + links | 500 | 1000 |

### Packing Algorithm (`packing.rs`)

Priority-weighted bin-packing (replaces v1 greedy approach):
1. Sort memories by `importance × relevance_score` (descending)
2. For each memory, try Level 3 → 2 → 1 → 0 until it fits remaining budget
3. Critical memories always get at least Level 1
4. Track actual token counts (via cortex-tokens), not estimates

### QG-5: Compression Quality Gate

| Test | Pass Criteria |
|------|---------------|
| Level ordering: tokens(L0) < tokens(L1) < tokens(L2) < tokens(L3) | Strict ordering for any memory |
| Level 3 is lossless | All content preserved at L3 |
| Level 0 contains only ID | Minimal representation |
| compressToFit never exceeds budget | For any memory and budget, output ≤ budget |
| compressBatchToFit respects total budget | Sum of all compressed ≤ total budget |
| Critical memories get at least L1 | Even under tight budget, critical memories not dropped to L0 |

---

## Crate 7: cortex-decay — Multi-Factor Decay, Adaptive Half-Lives (~8 files)

**Purpose:** Confidence decay modeling memory relevance over time.

**Evidence:** R7 (neuroscience-inspired), CX8

**Deps:** cortex-core (lightweight crate)

### Directory Structure

```
crates/cortex/cortex-decay/
├── Cargo.toml
├── src/
│   ├── lib.rs                          # Re-exports, DecayEngine init
│   ├── engine.rs                       # DecayEngine — implements IDecayEngine, processes all memories, applies decay, triggers archival
│   ├── formula.rs                      # 5-factor decay formula (see below)
│   ├── factors/
│   │   ├── mod.rs                      # Factor trait + registry
│   │   ├── temporal.rs                 # e^(-daysSinceAccess / halfLife) — exponential, type-specific half-lives
│   │   ├── citation.rs                 # Content hash comparison — stale citations reduce confidence
│   │   ├── usage.rs                    # min(1.5, 1 + log10(accessCount + 1) × 0.2) — capped at 1.5×
│   │   ├── importance.rs               # critical=2.0×, high=1.5×, normal=1.0×, low=0.8×
│   │   └── pattern.rs                  # Linked to active patterns = 1.3×, else 1.0×
│   ├── adaptive.rs                     # Per-memory adaptive half-lives (CX8): adaptiveHalfLife = baseHalfLife × accessFrequencyFactor × validationFactor × linkageFactor
│   └── archival.rs                     # Archival logic — confidence below type-specific minimum → eligible for archival, audit log entry
```

### 5-Factor Decay Formula (`formula.rs`)

```
finalConfidence = baseConfidence
  × temporalDecay
  × citationDecay
  × usageBoost
  × importanceAnchor
  × patternBoost
```

| Factor | File | Formula | Range |
|--------|------|---------|-------|
| Temporal | `temporal.rs` | `e^(-daysSinceAccess / halfLife)` | 0.0 - 1.0 |
| Citation | `citation.rs` | Content hash comparison — stale citations reduce confidence | 0.5 - 1.0 |
| Usage | `usage.rs` | `min(1.5, 1 + log10(accessCount + 1) × 0.2)` | 1.0 - 1.5 |
| Importance | `importance.rs` | critical=2.0×, high=1.5×, normal=1.0×, low=0.8× | 0.8 - 2.0 |
| Pattern | `pattern.rs` | Linked to active patterns = 1.3×, else 1.0× | 1.0 - 1.3 |

### Adaptive Half-Lives (CX8, `adaptive.rs`)

Per-memory adaptive half-lives instead of fixed type-based:
```
adaptiveHalfLife = baseHalfLife × accessFrequencyFactor × validationFactor × linkageFactor
```
- `accessFrequencyFactor`: 1.0 - 2.0× (frequently accessed → slower decay)
- `validationFactor`: 1.0 - 1.5× (recently validated → slower decay)
- `linkageFactor`: 1.0 - 1.3× (linked to active patterns → slower decay)

### QG-6: Decay Quality Gate

| Test | Pass Criteria |
|------|---------------|
| Monotonically decreasing over time without access | confidence(t+1) ≤ confidence(t) |
| Bounded: 0.0 ≤ confidence ≤ 1.0 | No overflow from multiplicative factors |
| Importance anchor capped | critical memory confidence ≤ base × 2.0 |
| Usage boost capped at 1.5× | High access count doesn't exceed cap |
| Adaptive half-life computes correctly | Frequently accessed tribal memory → effective half-life > 365d |
| Archival triggers at threshold | Confidence below 0.15 → archived flag set |

---

## Crate 8: cortex-causal — petgraph DAG, Inference, Traversal, Narrative (~18 files)

**Purpose:** The "why" engine. Maintains an in-memory DAG synced with SQLite. Causal inference, traversal, counterfactual queries, and human-readable narrative generation.

**Evidence:** R5 (petgraph), R11 (CausalKG), CX5, CX11

**Deps:** petgraph, cortex-core, cortex-storage

### Directory Structure

```
crates/cortex/cortex-causal/
├── Cargo.toml
├── src/
│   ├── lib.rs                          # Re-exports, CausalEngine init
│   ├── engine.rs                       # CausalEngine — owns the graph, coordinates inference + traversal + narrative, syncs graph ↔ SQLite
│   ├── graph/
│   │   ├── mod.rs                      # GraphManager — Arc<RwLock<StableGraph>>
│   │   ├── stable_graph.rs             # petgraph::StableGraph<CausalNode, CausalEdge> — handles frequent add/remove
│   │   ├── dag_enforcement.rs          # DAG constraint — cycle detection before every edge insertion (Tarjan's SCC)
│   │   ├── sync.rs                     # Bidirectional sync: graph ↔ causal_edges table, rebuild on startup, persist on mutation
│   │   └── pruning.rs                  # Prune weak edges (strength < 0.2), prune old unvalidated edges, periodic cleanup
│   ├── inference/
│   │   ├── mod.rs                      # InferenceEngine — multi-strategy causal discovery
│   │   ├── strategies/
│   │   │   ├── mod.rs                  # Strategy registry + weighted scoring
│   │   │   ├── temporal_proximity.rs   # Weight: 0.2 — time-based correlation
│   │   │   ├── semantic_similarity.rs  # Weight: 0.3 — embedding cosine similarity
│   │   │   ├── entity_overlap.rs       # Weight: 0.25 — shared files/patterns/functions
│   │   │   ├── explicit_reference.rs   # Weight: 0.4 — direct mention in content
│   │   │   ├── pattern_matching.rs     # Weight: 0.15 — shared pattern links
│   │   │   └── file_co_occurrence.rs   # Weight: 0.1 — same file context
│   │   └── scorer.rs                   # Composite causal strength scoring — weighted sum, threshold for edge creation
│   ├── traversal/
│   │   ├── mod.rs                      # TraversalEngine — graph walking
│   │   ├── trace_origins.rs            # Backward traversal — "what caused this?"
│   │   ├── trace_effects.rs            # Forward traversal — "what did this cause?"
│   │   ├── bidirectional.rs            # Union of forward + backward
│   │   ├── neighbors.rs               # Direct neighbors (depth=1)
│   │   ├── counterfactual.rs           # "What if we hadn't adopted pattern X?" — traverse from pattern's linked memories, identify all downstream effects
│   │   └── intervention.rs             # "If we change convention X, what needs updating?" — identify all causally dependent memories
│   ├── narrative/
│   │   ├── mod.rs                      # NarrativeGenerator — human-readable "why"
│   │   ├── builder.rs                  # Template-based narrative construction: Sections (Origins, Effects, Support, Conflicts), Summary, key points, confidence score, evidence references
│   │   ├── templates.rs                # Narrative templates per relation type: "X was caused by Y because...", "This decision led to...", "Warning: this contradicts..."
│   │   └── confidence.rs               # Chain confidence calculation: 60% min edge strength + 40% average, depth penalty for long chains
│   └── relations.rs                    # 8 relation types with semantics: caused, enabled, prevented, contradicts, supersedes, supports, derived_from, triggered_by
```

### Graph Model

`petgraph::StableGraph<CausalNode, CausalEdge>` behind `Arc<RwLock<>>`.

- `CausalNode`: memory_id, type, summary
- `CausalEdge`: relation (8 types), strength (0.0-1.0), evidence array, inferred flag

### 8 Relation Types (`relations.rs`)

`caused`, `enabled`, `prevented`, `contradicts`, `supersedes`, `supports`, `derived_from`, `triggered_by`

### 6 Inference Strategies (`inference/strategies/`)

| Strategy | File | Weight | Signal |
|----------|------|--------|--------|
| Temporal proximity | `temporal_proximity.rs` | 0.2 | Time-based correlation |
| Semantic similarity | `semantic_similarity.rs` | 0.3 | Embedding cosine similarity |
| Entity overlap | `entity_overlap.rs` | 0.25 | Shared files/patterns/functions |
| Explicit reference | `explicit_reference.rs` | 0.4 | Direct mention in content |
| Pattern matching | `pattern_matching.rs` | 0.15 | Shared pattern links |
| File co-occurrence | `file_co_occurrence.rs` | 0.1 | Same file context |

### Traversal (`traversal/`)

| Mode | File | Description |
|------|------|-------------|
| trace_origins | `trace_origins.rs` | Backward — "what caused this?" |
| trace_effects | `trace_effects.rs` | Forward — "what did this cause?" |
| bidirectional | `bidirectional.rs` | Union of forward + backward |
| neighbors | `neighbors.rs` | Direct neighbors (depth=1) |
| counterfactual | `counterfactual.rs` | "What if we hadn't adopted pattern X?" |
| intervention | `intervention.rs` | "If we change convention X, what needs updating?" |

Configurable: maxDepth (5), minStrength (0.3), maxNodes (50).

### Narrative Generation (`narrative/`)

- `builder.rs`: Template-based narrative builder producing human-readable "why" explanations with sections (Origins, Effects, Support, Conflicts), summary, key points, confidence score, evidence references per claim
- `templates.rs`: Narrative templates per relation type
- `confidence.rs`: Chain confidence: 60% min edge strength + 40% average, depth penalty for long chains

### Graph ↔ SQLite Sync (`graph/sync.rs`)

Rebuild graph from `causal_edges` table on startup. Persist graph changes to SQLite on mutation. Prune weak edges (strength < 0.2) periodically via `graph/pruning.rs`.

### QG-7: Causal Quality Gate

| Test | Pass Criteria |
|------|---------------|
| DAG enforcement: no cycles after any insertion | Insert edge creating cycle → rejected |
| Traversal depth ≤ maxDepth | Set maxDepth=3, graph has depth 10 → only 3 levels returned |
| Traversal nodes ≤ maxNodes | Set maxNodes=5, graph has 100 nodes → ≤ 5 returned |
| Bidirectional = union of forward + backward | Assert set equality |
| Narrative generates readable text | Non-empty string with sections |
| Counterfactual identifies downstream effects | Remove pattern → affected memories listed |
| Graph rebuilds from SQLite | Clear in-memory graph → rebuild → same edges |
| Inference scorer produces valid strengths | All strengths in 0.0-1.0 range |

---

## Crate 9: cortex-retrieval — Hybrid Search, RRF, Re-Ranking, Intent, Generation, Why (~25 files)

**Purpose:** The query engine. Two-stage pipeline: fast candidate gathering → precise re-ranking. Hybrid search (FTS5 + sqlite-vec + RRF). Also houses the generation context builder and "why" orchestrator — these live here because they coordinate retrieval + causal + compression.

**Evidence:** R2 (RRF), R10 (RAG best practices), CX1, CX6, CX13

**Deps:** cortex-core, cortex-storage, cortex-embeddings, cortex-compression, cortex-tokens

### Directory Structure

```
crates/cortex/cortex-retrieval/
├── Cargo.toml
├── src/
│   ├── lib.rs                          # Re-exports, RetrievalEngine init
│   ├── engine.rs                       # RetrievalEngine — implements IRetriever, orchestrates full 2-stage pipeline
│   ├── search/
│   │   ├── mod.rs                      # HybridSearcher — coordinates FTS5 + vec + RRF
│   │   ├── fts5_search.rs              # FTS5 full-text search — keyword matching, BM25 scoring, snippet extraction
│   │   ├── vector_search.rs            # sqlite-vec similarity search — cosine distance, pre-filter by type/importance, Matryoshka truncated dims
│   │   ├── rrf_fusion.rs               # Reciprocal Rank Fusion: score = Σ 1/(k + rank_i), k=60
│   │   └── entity_search.rs            # Linked entity expansion — find candidates by shared patterns, files, functions
│   ├── ranking/
│   │   ├── mod.rs                      # RankingPipeline — multi-factor scoring
│   │   ├── scorer.rs                   # Multi-factor relevance scorer (8 factors — see below)
│   │   ├── reranker.rs                 # Cross-encoder re-ranking (CX6): optional ONNX cross-encoder, falls back to scorer
│   │   └── deduplication.rs            # Session-aware deduplication: skip already-sent, merge duplicate candidates
│   ├── intent/
│   │   ├── mod.rs                      # IntentEngine — classification + weighting
│   │   ├── classifier.rs               # Intent classification from query context: keyword matching, file type heuristics, recent action patterns
│   │   └── weight_matrix.rs            # Intent → MemoryType boost matrix, loaded from TOML config, default weights hardcoded
│   ├── expansion/
│   │   ├── mod.rs                      # QueryExpander — generates query variants
│   │   ├── synonym_expander.rs         # Synonym/related term expansion, code-aware: "auth" → "authentication middleware"
│   │   └── hyde.rs                     # Hypothetical Document Embedding (CX13): generate hypothetical answer, embed that
│   ├── budget/
│   │   ├── mod.rs                      # BudgetManager — token budget orchestration
│   │   └── packer.rs                   # Priority-weighted bin-packing: sort by importance × relevance_score, try L3→2→1→0, critical ≥ L1
│   ├── generation/
│   │   ├── mod.rs                      # GenerationOrchestrator
│   │   ├── context_builder.rs          # Build generation context with token budget allocation: Patterns 30%, Tribal 25%, Constraints 20%, Anti-patterns 15%, Related 10%
│   │   ├── gatherers/
│   │   │   ├── mod.rs                  # Gatherer trait + registry
│   │   │   ├── pattern_gatherer.rs     # Gather pattern rationales for focus area
│   │   │   ├── tribal_gatherer.rs      # Gather tribal knowledge + warnings
│   │   │   ├── constraint_gatherer.rs  # Gather active constraints
│   │   │   └── antipattern_gatherer.rs # Gather code smells to avoid
│   │   ├── provenance.rs               # Provenance tracking: pattern_followed, tribal_applied, constraint_enforced, antipattern_avoided + inline comment generation
│   │   ├── feedback.rs                 # Generation outcome tracking: accepted/modified/rejected → adjust confidence
│   │   └── validation.rs               # Pre-generation validation: check against patterns, tribal, anti-patterns
│   └── why/
│       ├── mod.rs                      # WhySynthesizer — the "killer feature"
│       ├── synthesizer.rs              # Full "why" pipeline (8 steps — see below)
│       └── aggregator.rs               # Warning aggregation from all sources, dedup warnings, rank by severity
```

### Stage 1 — Candidate Gathering (fast, broad)

1. Pre-filter by memory type based on intent weighting
2. Pre-filter by importance (skip low-importance for tight budgets)
3. Run hybrid search: FTS5 (`fts5_search.rs`) + sqlite-vec (`vector_search.rs`) in parallel
4. Fuse results with RRF (`rrf_fusion.rs`): `score = Σ 1/(60 + rank_i)`
5. Gather additional candidates by linked entities (`entity_search.rs`)
6. Deduplicate candidates

### Stage 2 — Re-Ranking (precise, narrow) (CX6)

Multi-factor relevance scorer (`ranking/scorer.rs`):
- Semantic similarity (from vector search)
- Keyword match score (from FTS5)
- File proximity (same file/directory as active context)
- Pattern alignment (linked to relevant patterns)
- Recency (last accessed, last validated)
- Confidence level
- Importance level
- Intent-type match (boosted types for current intent)

Optional cross-encoder re-ranker (`ranking/reranker.rs`) via `ort` for highest precision.

### Intent Engine (18 intents, `intent/`)

**Domain-agnostic (7):** create, investigate, decide, recall, learn, summarize, compare
**Code-specific (8):** add_feature, fix_bug, refactor, security_audit, understand_code, add_test, review_code, deploy, migrate
**Universal (3):** spawn_agent, execute_workflow, track_progress

`weight_matrix.rs`: Intent → MemoryType boost matrix configurable via TOML. Default weights hardcoded as fallback.

### Query Expansion (CX13, `expansion/`)

Generate 2-3 query variants before searching:
- Original query
- `synonym_expander.rs`: Synonym/related term expansion (code-aware: "auth" → "authentication middleware")
- `hyde.rs`: Optional HyDE — generate hypothetical answer, embed that

### Token Budget Management (`budget/`)

`packer.rs`: Priority-weighted bin-packing using cortex-compression:
- Sort by importance × relevance_score
- Try Level 3→2→1→0 until fits
- Critical memories always ≥ Level 1
- Accurate token counts via cortex-tokens

### Generation Context Builder (`generation/`)

`context_builder.rs`: Token budget allocation (configurable):
- Patterns: 30%, Tribal: 25%, Constraints: 20%, Anti-patterns: 15%, Related: 10%

`gatherers/`: 4 specialized gatherers that collect memories by category:
- `pattern_gatherer.rs`: Gather pattern rationales for focus area
- `tribal_gatherer.rs`: Gather tribal knowledge + warnings
- `constraint_gatherer.rs`: Gather active constraints
- `antipattern_gatherer.rs`: Gather code smells to avoid

`provenance.rs`: Provenance tracking — `pattern_followed`, `tribal_applied`, `constraint_enforced`, `antipattern_avoided`. Inline provenance comments:
```
// [drift:tribal] Always use bcrypt with 12 salt rounds
// [drift:pattern] auth-password-hashing (confidence: 0.92)
```

`feedback.rs`: Generation outcome tracking — accepted/modified/rejected → adjust confidence of influencing memories.

`validation.rs`: Pre-generation validation — check against patterns, tribal, anti-patterns before generating.

### "Why" System (`why/`)

`synthesizer.rs`: Full "why" pipeline — the killer feature:
1. Gather pattern rationales for focus area
2. Gather decision contexts (ADRs, decision memories)
3. Gather tribal knowledge (warnings, consequences)
4. Gather code smells (anti-patterns to avoid)
5. Traverse causal graph from relevant memories
6. Generate narrative from causal chains
7. Aggregate warnings via `aggregator.rs`
8. Compress to fit token budget

Output: `WhyContext` with patterns, decisions, tribal, anti_patterns, narrative, warnings, summary, confidence, token_count.

### QG-8: Retrieval Quality Gate

| Test | Pass Criteria |
|------|---------------|
| Hybrid search returns results for keyword query | "bcrypt" → finds memory containing "bcrypt" |
| Hybrid search returns results for semantic query | "password security" → finds memory about bcrypt |
| RRF scores are monotonically decreasing | score[i] ≥ score[i+1] for all i |
| FTS5 results + vector results ⊆ RRF results | No results lost in fusion |
| Token budget never exceeded | Sum of compressed memories ≤ budget |
| Higher importance ranks above at equal similarity | Critical memory outranks normal at same cosine score |
| Session deduplication filters already-sent | Mark memory as sent → not returned again |
| Intent weighting boosts correct types | fix_bug intent → tribal/incident memories boosted |
| Generation context respects budget allocation | Patterns ≈ 30% of budget |
| Empty query returns empty results | No crash, no random results |
| Why synthesizer produces WhyContext | Non-empty patterns, narrative, warnings |
| Provenance comments generated | Output contains `[drift:tribal]` or `[drift:pattern]` markers |
| Generation feedback adjusts confidence | Rejected generation → influencing memory confidence decreases |

---

## Crate 10: cortex-validation — 4-Dimension Validation, Contradiction, Healing (~16 files)

**Purpose:** Periodic validation across 4 dimensions with automatic healing strategies.

**Evidence:** CX9 (contradiction), CX11 (causal improvements)

**Deps:** cortex-core, cortex-storage, cortex-embeddings

### Directory Structure

```
crates/cortex/cortex-validation/
├── Cargo.toml
├── src/
│   ├── lib.rs                          # Re-exports, ValidationEngine init
│   ├── engine.rs                       # ValidationEngine — implements IValidator, runs all 4 dimensions, aggregates results, triggers healing
│   ├── dimensions/
│   │   ├── mod.rs                      # Dimension trait + runner
│   │   ├── citation.rs                 # Citation validation: file existence, content hash drift, line number validity, git rename detection → auto-update
│   │   ├── temporal.rs                 # Temporal validation: validUntil expiry, code version change detection (git), age vs expected lifetime
│   │   ├── contradiction.rs            # Contradiction validation: run detector, check consensus support
│   │   └── pattern_alignment.rs        # Pattern alignment: linked patterns still exist? confidence changed? pattern removed → flag
│   ├── contradiction/
│   │   ├── mod.rs                      # ContradictionDetector — multi-strategy
│   │   ├── detection/
│   │   │   ├── mod.rs                  # Detection strategy registry
│   │   │   ├── semantic.rs             # Embedding similarity + negation patterns
│   │   │   ├── absolute_statement.rs   # "always"/"never" conflict detection
│   │   │   ├── temporal_supersession.rs # Newer memory supersedes older on same topic
│   │   │   ├── feedback.rs             # Feedback contradictions
│   │   │   └── cross_pattern.rs        # Same pattern, opposing content
│   │   ├── propagation.rs              # Graph-based confidence propagation via petgraph BFS — O(V+E)
│   │   └── consensus.rs                # Consensus detection: ≥3 memories supporting same conclusion → boost +0.2, resist single contradictions
│   └── healing/
│       ├── mod.rs                      # HealingEngine — strategy selection
│       ├── confidence_adjust.rs        # Adjust confidence based on validation score
│       ├── citation_update.rs          # Auto-update citations via git rename detection
│       ├── embedding_refresh.rs        # Re-embed memories whose context changed
│       ├── archival.rs                 # Archive with reason tracking
│       └── flagging.rs                 # Flag for human review when auto-fix isn't safe
```

### 4 Validation Dimensions (`dimensions/`)

1. **Citation** (`citation.rs`): File existence, content hash drift, line number validity. Git rename detection → auto-update citation.
2. **Temporal** (`temporal.rs`): validUntil expiry, code version change detection (git), age vs expected lifetime.
3. **Contradiction** (`contradiction.rs`): Run contradiction detector, check consensus support. Consensus memories resist single contradictions.
4. **Pattern Alignment** (`pattern_alignment.rs`): Linked patterns still exist? Pattern confidence changed significantly? Pattern removed → flag linked memories.

### Contradiction Detection (`contradiction/detection/`)

5 detection strategies:
- `semantic.rs`: Semantic similarity + negation patterns
- `absolute_statement.rs`: "always"/"never" conflict detection
- `temporal_supersession.rs`: Newer supersedes older on same topic
- `feedback.rs`: Feedback contradictions
- `cross_pattern.rs`: Same pattern, opposing content

### Confidence Propagation (`contradiction/propagation.rs`)

Graph-based via petgraph BFS — O(V+E):

| Event | Confidence Change |
|-------|------------------|
| Direct contradiction | -0.3 |
| Partial contradiction | -0.15 |
| Supersession | -0.5 |
| Confirmation | +0.1 |
| Consensus (≥3 supporters) | +0.2 |
| Propagation factor | 0.5× |

### Consensus Detection (`contradiction/consensus.rs`)

≥3 memories supporting same conclusion → boost all +0.2, mark as consensus. Consensus resists single contradictions.

### Healing Strategies (`healing/`)

| Strategy | File | Action |
|----------|------|--------|
| Confidence adjustment | `confidence_adjust.rs` | Adjust based on validation score |
| Citation auto-update | `citation_update.rs` | Git rename detection → update file references |
| Embedding refresh | `embedding_refresh.rs` | Re-embed memories whose context changed |
| Archival | `archival.rs` | Archive with reason tracking |
| Human review flagging | `flagging.rs` | Flag when auto-fix isn't safe |

### QG-9: Validation Quality Gate

| Test | Pass Criteria |
|------|---------------|
| Citation validation detects missing file | File deleted → citation invalid |
| Citation validation detects content drift | File modified → content hash mismatch flagged |
| Temporal validation detects expired memory | validUntil in past → flagged |
| Contradiction detected between opposing memories | "always use X" vs "never use X" → contradiction |
| Consensus resists single contradiction | 3 supporting memories → single contradiction doesn't override |
| Confidence propagation ripples correctly | Contradiction → connected memories lose confidence |
| Healing triggers archival below threshold | Confidence < 0.15 → archived |
| Git rename detection updates citation | File renamed → citation auto-updated |

---

## Crate 11: cortex-learning — Correction Analysis, Principle Extraction (~12 files)

**Purpose:** Learns from user corrections. Analyzes diffs, categorizes corrections, extracts reusable principles, creates new memories.

**Evidence:** R1 (Mem0 dedup), CX4, CX8

**Deps:** cortex-core, cortex-storage, cortex-embeddings, cortex-causal

### Directory Structure

```
crates/cortex/cortex-learning/
├── Cargo.toml
├── src/
│   ├── lib.rs                          # Re-exports, LearningEngine init
│   ├── engine.rs                       # LearningEngine — implements ILearner, orchestrates full learning pipeline
│   ├── analysis/
│   │   ├── mod.rs                      # CorrectionAnalyzer — entry point
│   │   ├── diff_analyzer.rs            # Compare original vs corrected: additions, removals, modifications, semantic changes
│   │   ├── categorizer.rs              # 10 correction categories (see below) — keyword matching + pattern heuristics
│   │   └── category_mapping.rs         # Category → MemoryType mapping
│   ├── extraction/
│   │   ├── mod.rs                      # PrincipleExtractor — generalize corrections
│   │   ├── rule_based.rs               # Rule-based extraction for offline: keyword matching, pattern templates, negation detection, generalization rules
│   │   └── llm_enhanced.rs             # Optional LLM-assisted extraction: higher quality, only when API key configured, falls back to rule_based
│   ├── deduplication.rs                # Mem0-inspired dedup before storage: check existing memories with high similarity → ADD, UPDATE, or NOOP
│   ├── calibration.rs                  # Confidence calibration — 5 factors: base, evidence, usage, temporal, validation
│   └── active_learning/
│       ├── mod.rs                      # ActiveLearningLoop — identifies uncertain memories
│       ├── candidate_selector.rs       # Select validation candidates: low confidence + high importance, old + never validated, contradicted but unresolved
│       ├── prompt_generator.rs         # Generate validation prompts for user
│       └── feedback_processor.rs       # Process user feedback: confirm/reject/modify → update confidence
```

### 10 Correction Categories (`analysis/categorizer.rs`)

`pattern_violation`, `tribal_miss`, `constraint_violation`, `style_preference`, `naming_convention`, `architecture_mismatch`, `security_issue`, `performance_issue`, `api_misuse`, `other`

### Category → Memory Type Mapping (`analysis/category_mapping.rs`)

pattern_violation → pattern_rationale, tribal_miss → tribal, security_issue → tribal(critical), performance_issue → code_smell, constraint_violation → constraint_override, etc.

### Pipeline

1. `diff_analyzer.rs`: Analyze correction (additions, removals, modifications, semantic changes)
2. `categorizer.rs`: Categorize (keyword matching + pattern heuristics)
3. `extraction/`: Extract principle (rule-based for offline, optional LLM for higher quality)
4. `deduplication.rs`: Dedup before storage (Mem0-inspired) — check existing memories → ADD, UPDATE, or NOOP
5. Create memory with correct type
6. Infer causal relationships with existing memories
7. Check for contradictions

### Active Learning Loop (`active_learning/`)

1. `candidate_selector.rs`: Identify memories needing validation (low confidence + high importance, old + never validated, contradicted but unresolved)
2. `prompt_generator.rs`: Generate validation prompts for user
3. `feedback_processor.rs`: Process feedback (confirm/reject/modify), update confidence
4. Priority: frequently retrieved + uncertain memories first

### QG-10: Learning Quality Gate

| Test | Pass Criteria |
|------|---------------|
| Correction categorized correctly | Known pattern violation → category = pattern_violation |
| Principle extracted from correction | Non-empty principle string |
| Dedup prevents duplicate memory | Similar correction twice → UPDATE, not second CREATE |
| Causal link inferred | Correction creates memory → causal edge to related memory |
| Active learning selects uncertain memories | Low confidence + high importance → selected for validation |
| Category mapping produces correct type | security_issue → tribal with critical importance |

---

## Crate 12: cortex-consolidation — HDBSCAN Pipeline, Quality Monitoring (~18 files)

**Purpose:** The algorithmic consolidation engine. Fully offline, deterministic, auditable. No LLM required. This is the core differentiator.

**Evidence:** R7 (neuroscience), R16 (TextRank), R17 (HDBSCAN), CX14, CX15

**Deps:** cortex-core, cortex-storage, cortex-embeddings, hdbscan, rayon

### Directory Structure

```
crates/cortex/cortex-consolidation/
├── Cargo.toml
├── src/
│   ├── lib.rs                          # Re-exports, ConsolidationEngine init
│   ├── engine.rs                       # ConsolidationEngine — implements IConsolidator, Arc<AtomicBool> is_running guard
│   ├── pipeline/
│   │   ├── mod.rs                      # Pipeline orchestrator — phase sequencing
│   │   ├── phase1_selection.rs         # Candidate selection: episodic, age > 7d, pending, confidence > 0.3
│   │   ├── phase2_clustering.rs        # HDBSCAN on composite similarity (5 signals, see below)
│   │   ├── phase3_recall_gate.rs       # Recall gate: TF-IDF key phrases → embedding query → top-10 check
│   │   ├── phase4_abstraction.rs       # Algorithmic abstraction: anchor selection, novel merge, TextRank summary, metadata union
│   │   ├── phase5_integration.rs       # Integration: overlap > 0.9 → UPDATE existing, else CREATE new
│   │   └── phase6_pruning.rs           # Archive consolidated episodics, boost frequent, track tokensFreed
│   ├── algorithms/
│   │   ├── mod.rs                      # Algorithm implementations
│   │   ├── textrank.rs                 # TextRank graph — sentences as nodes, cosine similarity as edges, PageRank iteration
│   │   ├── tfidf.rs                    # TF-IDF across cluster — distinctive key phrases
│   │   ├── sentence_splitter.rs        # Split content into sentences for dedup and TextRank
│   │   └── similarity.rs              # Cosine similarity helpers, novelty threshold (0.85), overlap detection (0.9)
│   ├── scheduling/
│   │   ├── mod.rs                      # Adaptive scheduler
│   │   ├── triggers.rs                 # Consolidation triggers: token pressure, memory count, confidence degradation, contradiction density, scheduled (6h)
│   │   └── throttle.rs                 # Yield between batches to prevent write-starvation
│   ├── monitoring/
│   │   ├── mod.rs                      # ConsolidationMonitor (CX15)
│   │   ├── metrics.rs                  # 5 core metrics (see below)
│   │   ├── auto_tuning.rs              # Feedback loop — every 100 events or weekly: adjust thresholds, log adjustments
│   │   └── dashboard.rs                # Surface metrics through observability system
│   └── llm_polish.rs                   # Optional LLM enhancement: rephrase into natural language, LLM does NOT do consolidation logic, track polished vs unpolished rates
```

### 6-Phase Pipeline (`pipeline/`)

**Phase 1 — Candidate Selection (`phase1_selection.rs`):** Episodic memories, age > 7 days, status = pending, confidence > 0.3. Filter out already consolidated/archived.

**Phase 2 — Clustering (`phase2_clustering.rs`):** HDBSCAN on composite similarity:
- Embedding cosine similarity (weight 0.5)
- Shared linked files (weight 0.2)
- Shared linked patterns (weight 0.15)
- Shared linked functions (weight 0.1)
- Shared tags (weight 0.05)
- Min cluster size = 2. Noise points deferred (not lost).

**Phase 3 — Recall Gate (`phase3_recall_gate.rs`):** Extract top-3 TF-IDF key phrases per cluster. Query embedding index. Episodes must rank top-10 for ≥2/3 queries. Fail → refresh embeddings → re-test. Still fail → defer + flag.

**Phase 4 — Algorithmic Abstraction (`phase4_abstraction.rs`):**
1. Anchor selection: highest `confidence × importance_weight × log2(accessCount + 1)`
2. Merge novel sentences: embedding similarity < 0.85 to anchor = novel
3. Summary: TextRank graph + TF-IDF key phrases
4. Metadata union: tags, files, patterns, functions. Confidence with cluster size boost: `min(1.3, 1.0 + (cluster_size - 2) × 0.05)`

**Phase 5 — Integration (`phase5_integration.rs`):** If overlap > 0.9 with existing semantic memory → UPDATE (Mem0-inspired dedup). Otherwise → CREATE new.

**Phase 6 — Pruning (`phase6_pruning.rs`):** Archive consolidated episodics. Boost frequently accessed. Track tokensFreed.

### Algorithms (`algorithms/`)

| Algorithm | File | Purpose |
|-----------|------|---------|
| TextRank | `textrank.rs` | Sentences as nodes, cosine similarity as edges, PageRank iteration for centrality |
| TF-IDF | `tfidf.rs` | Identify distinctive key phrases (frequent in cluster, rare globally) |
| Sentence Splitter | `sentence_splitter.rs` | Split content into sentences for dedup and TextRank |
| Similarity | `similarity.rs` | Cosine similarity helpers, novelty threshold (0.85), overlap detection (0.9) |

### Quality Monitoring (CX15, `monitoring/`)

5 core metrics tracked per consolidation event (`metrics.rs`):

| Metric | Target | Auto-Tune Action (`auto_tuning.rs`) |
|--------|--------|-------------------------------------|
| Memory Precision | ≥ 0.7 | Below → increase min cluster size, tighten similarity |
| Compression Ratio | 3:1 to 5:1 | Above 5:1 → lower novelty threshold |
| Retrieval Lift | ≥ 1.5 | Below 1.0 → investigate |
| Contradiction Rate | ≤ 0.05 | Above → add pre-consolidation contradiction check |
| Stability Score | ≥ 0.85 | Below → consolidated memory being challenged |

`auto_tuning.rs`: Feedback loop every 100 events or weekly — compute aggregates, adjust thresholds, log all adjustments to audit trail.

`dashboard.rs`: Surface metrics through observability system.

### Adaptive Scheduling (`scheduling/`)

`triggers.rs`: Token pressure, memory count threshold, confidence degradation trend, contradiction density spike, scheduled fallback (every 6h).

`throttle.rs`: Yield between batches to prevent write-starvation of foreground ops.

Only one consolidation at a time (`Arc<AtomicBool>` guard in `engine.rs`).

### QG-11: Consolidation Quality Gate

| Test | Pass Criteria |
|------|---------------|
| HDBSCAN clusters related episodes | 3 episodes about same topic → 1 cluster |
| Noise points deferred, not lost | Unique episode → remains in pending state |
| Recall gate rejects poorly-encoded cluster | Bad embeddings → gate fails → cluster deferred |
| Anchor selection picks highest-scoring memory | Verify anchor has max composite score |
| Novel sentences merged, duplicates dropped | Unique detail from episode 2 appears in output |
| Summary generated via TextRank | Non-empty summary with key phrases |
| Integration dedup works | Consolidation overlapping existing semantic → UPDATE not CREATE |
| Consolidation is deterministic | Same inputs → same output (run twice, compare) |
| Consolidation is idempotent | Consolidating already-consolidated → no change |
| Quality metrics tracked | After consolidation → metrics table has new entry |
| Auto-tuning adjusts thresholds | Precision < 0.7 → min_cluster_size increased |

---

## Crate 13: cortex-prediction — Signal Gathering, 4 Strategies, Cache (~10 files)

**Purpose:** Predictive memory preloading. Anticipates what memories will be needed based on file, pattern, temporal, and behavioral signals.

**Deps:** cortex-core, cortex-storage, moka

### Directory Structure

```
crates/cortex/cortex-prediction/
├── Cargo.toml
├── src/
│   ├── lib.rs                          # Re-exports, PredictionEngine init
│   ├── engine.rs                       # PredictionEngine — implements IPredictor, coordinates strategies, deduplicates, manages cache
│   ├── signals/
│   │   ├── mod.rs                      # Signal types + gathering
│   │   ├── file_signals.rs             # Active file, imports, symbols, directory
│   │   ├── temporal_signals.rs         # Time of day, day of week, session duration
│   │   ├── behavioral_signals.rs       # Recent queries, intents, frequent memories
│   │   └── git_signals.rs              # Branch name, modified files, commit messages — feature branch → predict domain memories
│   ├── strategies/
│   │   ├── mod.rs                      # Strategy trait + multi-strategy dedup (duplicate → keep highest confidence + merge signals + boost +0.05)
│   │   ├── file_based.rs               # Memories linked to active file + imports
│   │   ├── pattern_based.rs            # Memories linked to detected patterns
│   │   ├── temporal.rs                 # Time-of-day and day-of-week usage patterns
│   │   └── behavioral.rs              # Recent queries, intents, frequent memories
│   ├── cache.rs                        # Prediction cache — moka::sync::Cache, adaptive TTL based on file change frequency, tracks hits/misses/rate, invalidated on file change or new session, first to evict under memory pressure (CX18)
│   └── precompute.rs                   # Pre-compute hybrid search results for predicted memories, triggered on file change events
```

### 4 Prediction Strategies (`strategies/`)

| Strategy | File | Signal Source |
|----------|------|--------------|
| File-based | `file_based.rs` | Memories linked to active file + imports |
| Pattern-based | `pattern_based.rs` | Memories linked to detected patterns in active file |
| Temporal | `temporal.rs` | Time-of-day and day-of-week usage patterns |
| Behavioral | `behavioral.rs` | Recent queries, intents, frequent memories |

### Signal Gathering (`signals/`)

| Signal Type | File | Data |
|-------------|------|------|
| File signals | `file_signals.rs` | Active file, imports, symbols, directory |
| Temporal signals | `temporal_signals.rs` | Time of day, day of week, session duration |
| Behavioral signals | `behavioral_signals.rs` | Recent queries, intents, frequent memories |
| Git signals | `git_signals.rs` | Branch name, modified files, commit messages |

### Multi-Strategy Deduplication (`strategies/mod.rs`)

When memory appears in multiple strategies: keep highest confidence + merge signals + apply +0.05 boost (capped at 1.0).

### Prediction Cache (`cache.rs`)

`moka::sync::Cache` with adaptive TTL based on file change frequency (rapidly changing files → shorter TTL). Tracks: hits, misses, hit rate, avg prediction time. Invalidated on file change or new session. First to evict under memory pressure (CX18).

### Precompute (`precompute.rs`)

Pre-compute hybrid search results for predicted memories so retrieval is instant. Triggered on file change events.

### QG-12: Prediction Quality Gate

| Test | Pass Criteria |
|------|---------------|
| File-based prediction returns linked memories | Active file has linked memories → predicted |
| Pattern-based prediction returns pattern memories | Detected pattern → related memories predicted |
| Cache invalidates on file change | Change file → cache miss on next predict |
| Dedup across strategies works | Same memory from 2 strategies → single entry with boost |
| Git-aware prediction works | Feature branch → domain-related memories predicted |

---

## Crate 14: cortex-session — Session Management, Deduplication (~7 files)

**Purpose:** Tracks loaded context per conversation. Prevents re-sending memories. Token efficiency tracking.

**Deps:** cortex-core, dashmap

### Directory Structure

```
crates/cortex/cortex-session/
├── Cargo.toml
├── src/
│   ├── lib.rs                          # Re-exports, SessionManager init
│   ├── manager.rs                      # SessionManager — Arc<DashMap<SessionId, SessionContext>>, concurrent per-session access
│   ├── context.rs                      # SessionContext — loaded sets: loadedMemories, loadedPatterns, loadedFiles, loadedConstraints, token tracking
│   ├── deduplication.rs                # Session-aware deduplication: filter already-sent, mark duplicates, 30-50% token savings
│   ├── analytics.rs                    # Session analytics: most frequently retrieved, least useful, intent distribution, avg retrieval latency
│   ├── efficiency.rs                   # Token efficiency metrics: tokens_sent, tokens_useful, efficiency_ratio, deduplication_savings
│   └── cleanup.rs                      # Session lifecycle: inactivity timeout, max duration, max tokens, delete sessions > 7 days
```

### Session Context (`context.rs`)

`SessionContext`: loadedMemories (Set), loadedPatterns (Set), loadedFiles (Set), loadedConstraints (Set), tokensSent, queriesMade.

### QG-13: Session Quality Gate

| Test | Pass Criteria |
|------|---------------|
| Deduplication filters already-sent | Send memory → mark sent → not returned again |
| Token tracking accurate | Send 3 memories → tokensSent = sum of their tokens |
| Session cleanup removes stale | Session inactive > 7 days → cleaned up |
| Concurrent session access safe | 4 threads accessing different sessions → no corruption |
| Analytics aggregation works | Multiple queries → correct intent distribution |

---

## Crate 15: cortex-reclassification — Importance Auto-Reclassification (~5 files)

**Purpose:** Automatically adjusts memory importance based on observed usage patterns. (CX22)

**Deps:** cortex-core, cortex-storage

### Directory Structure

```
crates/cortex/cortex-reclassification/
├── Cargo.toml
├── src/
│   ├── lib.rs                          # Re-exports
│   ├── engine.rs                       # ReclassificationEngine — monthly background task, evaluates all memories, max 1 per memory per month
│   ├── signals.rs                      # 5 reclassification signals (see below)
│   ├── rules.rs                        # Upgrade/downgrade rules with score thresholds and cooldown periods
│   └── safeguards.rs                   # Never auto-downgrade user-set critical, max 1 per month, all changes logged with composite score + signals
```

### 5 Reclassification Signals (`signals.rs`)

| Signal | Weight | Logic |
|--------|--------|-------|
| Access frequency (30-day) | 0.35 | > 20/month → upgrade candidate |
| Retrieval rank (30-day avg) | 0.25 | Consistently top-5 → important |
| Linked entity count | 0.15 | ≥ 3 active links → structurally important |
| Contradiction involvement | 0.10 | Frequently "wins" contradictions → authoritative |
| User feedback | 0.15 | Explicitly confirmed → boost |

### Rules (`rules.rs`)

**Upgrade:** low→normal (score>0.7, 2 months), normal→high (score>0.85, 2 months), high→critical (score>0.95, 3 months).
**Downgrade:** critical→high (score<0.5, 3 months), high→normal (score<0.3, 3 months), normal→low (score<0.15, 3 months).

### Safeguards (`safeguards.rs`)

- Never auto-downgrade user-set critical
- Max 1 reclassification per memory per month
- All changes logged to audit trail with composite score + contributing signals

---

## Crate 16: cortex-observability — Health, Metrics, Tracing, Degradation (~14 files)

**Purpose:** Enterprise-grade observability. Health checks, performance metrics, degradation tracking.

**Deps:** cortex-core, tracing, tracing-subscriber

### Directory Structure

```
crates/cortex/cortex-observability/
├── Cargo.toml
├── src/
│   ├── lib.rs                          # Re-exports, ObservabilityEngine init
│   ├── health/
│   │   ├── mod.rs                      # HealthChecker — implements IHealthReporter
│   │   ├── reporter.rs                 # Aggregate health report (see below)
│   │   ├── subsystem_checks.rs         # Per-subsystem health: storage, embeddings, causal graph, privacy — each returns healthy|degraded|unavailable
│   │   └── recommendations.rs          # Actionable recommendations: "5 memories need validation", "3 contradictions unresolved", etc.
│   ├── metrics/
│   │   ├── mod.rs                      # MetricsCollector — central metrics registry
│   │   ├── retrieval_metrics.rs        # Per-intent hit rate, token efficiency, most/least useful, query expansion effectiveness
│   │   ├── consolidation_metrics.rs    # CX15 metrics exposure (precision, lift, etc.)
│   │   ├── storage_metrics.rs          # DB size, fragmentation, growth rate, time-to-threshold
│   │   ├── embedding_metrics.rs        # Cache hit rates, inference latency, migration progress, provider usage
│   │   └── session_metrics.rs          # Active sessions, avg duration, dedup savings, intent distribution
│   ├── tracing/
│   │   ├── mod.rs                      # Tracing setup — structured logging
│   │   ├── spans.rs                    # Span definitions per operation: retrieval, consolidation, decay, validation, learning, embedding
│   │   └── events.rs                   # Structured log events: memory_created, memory_archived, consolidation_completed, contradiction_detected, degradation_triggered, migration_progress
│   ├── degradation/
│   │   ├── mod.rs                      # DegradationTracker
│   │   ├── tracker.rs                  # Record every degradation event: component, failure mode, fallback used, timestamp, recovery status
│   │   └── alerting.rs                 # Alert thresholds: >3 in 1 hour → warning, same component >24h → critical
│   └── query_log.rs                    # Query performance logging: query text, intent, latency, result count, token budget used, cache hits
```

### Health Report (`health/reporter.rs`)

- Total memories by type, average confidence by type
- Stale memory count + trend
- Contradiction count + resolution rate
- Consolidation frequency + effectiveness
- Storage size + growth rate
- Embedding cache hit rates (L1/L2/L3)
- Retrieval latency percentiles (p50/p95/p99)

### Per-Subsystem Health Checks (`health/subsystem_checks.rs`)

Storage, Embeddings, Causal graph, Privacy — each returns: healthy | degraded | unavailable.

### Metrics (`metrics/`)

| Metric Domain | File | Key Metrics |
|---------------|------|-------------|
| Retrieval | `retrieval_metrics.rs` | Per-intent hit rate, token efficiency, most/least useful, query expansion effectiveness |
| Consolidation | `consolidation_metrics.rs` | CX15 metrics (precision, compression ratio, lift, contradiction rate, stability) |
| Storage | `storage_metrics.rs` | DB size, fragmentation, growth rate, time-to-threshold |
| Embedding | `embedding_metrics.rs` | Cache hit rates (L1/L2/L3), inference latency, migration progress, provider usage |
| Session | `session_metrics.rs` | Active sessions, avg duration, dedup savings, intent distribution |

### Tracing (`tracing/`)

- `spans.rs`: Span definitions per operation (retrieval, consolidation, decay, validation, learning, embedding) — each carries duration, result, metadata
- `events.rs`: Structured log events (memory_created, memory_archived, consolidation_completed, contradiction_detected, degradation_triggered, migration_progress)

### Degradation Tracking (CX18, `degradation/`)

- `tracker.rs`: Record every degradation event — component, failure mode, fallback used, timestamp, recovery status. Persisted to degradation_log table.
- `alerting.rs`: >3 degradations in 1 hour → warning, same component degraded >24h → critical. Surfaced through health report.

### Query Performance Logging (`query_log.rs`)

Every retrieval query logged: query text, intent, latency, result count, token budget used, cache hits. Used for retrieval effectiveness analysis.

---

## Crate 17: cortex-cloud — Cloud Sync, Conflict Resolution, Auth (~14 files)

**Purpose:** Cloud-readiness layer. Local SQLite is always source of truth. Cloud is optional push/pull. Offline-first.

Entire crate is feature-gated: `#[cfg(feature = "cloud")]`. OSS builds compile without this crate.

**Deps:** cortex-core, cortex-storage, reqwest, serde, tokio

### Directory Structure

```
crates/cortex/cortex-cloud/
├── Cargo.toml
├── src/
│   ├── lib.rs                          # Re-exports, CloudEngine init, #[cfg(feature = "cloud")]
│   ├── engine.rs                       # CloudEngine — sync orchestrator, auth state, scheduling, conflict resolution, offline detection
│   ├── auth/
│   │   ├── mod.rs                      # AuthManager — authentication state machine
│   │   ├── token_manager.rs            # Token storage, refresh, expiry detection, OS keychain integration
│   │   ├── login_flow.rs               # Browser-based OAuth or API key
│   │   └── offline_mode.rs             # Offline detection + graceful transition, queue mutations when offline, replay when online
│   ├── sync/
│   │   ├── mod.rs                      # SyncManager — bidirectional sync
│   │   ├── push.rs                     # Push local changes: read sync_log for unpushed, batch upload with retry + backoff, mark synced
│   │   ├── pull.rs                     # Pull remote changes: fetch since last timestamp, apply to local, detect conflicts
│   │   ├── sync_log.rs                 # Mutation log: memory_id, operation, timestamp, synced (bool) — used for incremental push
│   │   └── delta.rs                    # Delta computation — content hash comparison, embedding sync optional
│   ├── conflict/
│   │   ├── mod.rs                      # ConflictResolver
│   │   ├── detection.rs                # Detect conflicts: same memory_id modified on both sides since last sync
│   │   ├── resolution.rs               # Strategies: last-write-wins (default), local-wins, remote-wins, manual
│   │   └── conflict_log.rs             # Log every conflict: memory_id, local_version, remote_version, strategy, resolved_by, timestamp
│   ├── transport/
│   │   ├── mod.rs                      # Transport layer abstraction
│   │   ├── http_client.rs              # reqwest with retry, backoff, timeout, compression (gzip)
│   │   └── protocol.rs                 # Wire protocol — JSON serialization, versioned for forward compatibility
│   └── quota.rs                        # Cloud quota management: memory count limits, storage size limits, sync frequency limits, graceful handling
```

### Sync Model (`sync/`)

- `push.rs`: Read sync_log for unpushed mutations → batch upload with retry + backoff
- `pull.rs`: Fetch changes since last sync timestamp → apply to local → detect conflicts
- `delta.rs`: Only sync what changed (content hash comparison)

### Conflict Resolution Strategies (`conflict/resolution.rs`)

- last-write-wins (default)
- local-wins (offline-first preference)
- remote-wins (team authority)
- manual (flag for user resolution)

All conflicts logged via `conflict_log.rs`.

### Auth (`auth/`)

- `token_manager.rs`: Secure token storage (OS keychain integration), refresh, expiry detection
- `login_flow.rs`: Browser-based OAuth or API key
- `offline_mode.rs`: Offline detection, queue mutations when offline, replay when back online

### Transport (`transport/`)

- `http_client.rs`: reqwest with retry, backoff, timeout, compression (gzip)
- `protocol.rs`: Versioned wire protocol for forward compatibility

---

## Crate 18: cortex-napi — NAPI Bindings for TypeScript Interop (~16 files)

**Purpose:** The bridge. Exposes the Rust engine to TypeScript via napi-rs. Thin binding layer — no business logic.

**Deps:** napi, napi-derive, tokio, ALL other cortex crates

### Directory Structure

```
crates/cortex/cortex-napi/
├── Cargo.toml
├── build.rs                            # napi-rs build script
├── src/
│   ├── lib.rs                          # #[napi] module registration, tokio runtime init, global CortexRuntime singleton
│   ├── runtime.rs                      # CortexRuntime — owns all engines (see below), background task scheduler, graceful shutdown
│   ├── bindings/
│   │   ├── mod.rs                      # All NAPI-exported functions
│   │   ├── memory.rs                   # Memory CRUD: create, get, update, delete, search, list, archive, restore
│   │   ├── retrieval.rs                # Retrieval: retrieve, search, getContext
│   │   ├── causal.rs                   # Causal: inferCause, traverse, getWhy, counterfactual, intervention
│   │   ├── learning.rs                 # Learning: analyzeCorrection, learn, getValidationCandidates, processFeedback
│   │   ├── consolidation.rs            # Consolidation: consolidate, getMetrics, getStatus
│   │   ├── session.rs                  # Session: create, get, cleanup, analytics
│   │   ├── health.rs                   # Health: getHealth, getMetrics, getDegradations
│   │   ├── generation.rs               # Generation: buildContext, trackOutcome
│   │   ├── prediction.rs               # Prediction: predict, preload, getCacheStats
│   │   ├── privacy.rs                  # Privacy: sanitize, getPatternStats
│   │   ├── cloud.rs                    # Cloud: sync, getStatus, resolveConflict
│   │   └── lifecycle.rs                # Lifecycle: initialize, shutdown, configure
│   └── conversions/
│       ├── mod.rs                      # Rust ↔ JS type conversions
│       ├── memory_types.rs             # BaseMemory ↔ JsObject, 23 type variants
│       ├── search_types.rs             # RetrievalContext, CompressedMemory ↔ JsObject
│       ├── causal_types.rs             # CausalNarrative, WhyContext ↔ JsObject
│       ├── health_types.rs             # HealthReport, Metrics ↔ JsObject
│       └── error_types.rs              # CortexError → JsError with structured info
```

### CortexRuntime (`runtime.rs`)

Owns all engines: StorageEngine, EmbeddingEngine, RetrievalEngine, CausalEngine, LearningEngine, DecayEngine, ValidationEngine, CompressionEngine, PredictionEngine, SessionManager, PrivacyEngine, ConsolidationEngine, ObservabilityEngine, CloudEngine (optional).

Background task scheduler (tokio). Graceful shutdown coordination.

### NAPI Bindings (`bindings/`, grouped by domain)

| Domain | File | Functions |
|--------|------|-----------|
| Memory | `memory.rs` | create, get, update, delete, search, list, archive, restore |
| Retrieval | `retrieval.rs` | retrieve, search, getContext |
| Causal | `causal.rs` | inferCause, traverse, getWhy, counterfactual, intervention |
| Learning | `learning.rs` | analyzeCorrection, learn, getValidationCandidates, processFeedback |
| Consolidation | `consolidation.rs` | consolidate, getMetrics, getStatus |
| Session | `session.rs` | create, get, cleanup, analytics |
| Health | `health.rs` | getHealth, getMetrics, getDegradations |
| Generation | `generation.rs` | buildContext, trackOutcome |
| Prediction | `prediction.rs` | predict, preload, getCacheStats |
| Privacy | `privacy.rs` | sanitize, getPatternStats |
| Cloud | `cloud.rs` | sync, getStatus, resolveConflict |
| Lifecycle | `lifecycle.rs` | initialize, shutdown, configure |

### Type Conversions (`conversions/`)

| File | Conversions |
|------|-------------|
| `memory_types.rs` | BaseMemory ↔ JsObject (23 type variants) |
| `search_types.rs` | RetrievalContext, CompressedMemory ↔ JsObject |
| `causal_types.rs` | CausalNarrative, WhyContext ↔ JsObject |
| `health_types.rs` | HealthReport, Metrics ↔ JsObject |
| `error_types.rs` | CortexError → JsError with structured info |

### QG-14: NAPI Quality Gate

| Test | Pass Criteria |
|------|---------------|
| Rust ↔ JS roundtrip for BaseMemory | Create in JS → passes to Rust → returns to JS → all fields match |
| All 33 MCP tool signatures callable | Each tool function exists and accepts correct params |
| Error mapping works | Rust CortexError → JS Error with structured info |
| Async operations complete | Embedding generation (async in Rust) → resolves in JS |
| All 23 memory type variants convert | Each type variant roundtrips correctly |

---

## TypeScript Layer — 33 MCP Tools + CLI + Tests (~45 files)

**Purpose:** Thin TypeScript wrappers over the Rust engine. No performance-critical logic. JSON-RPC MCP tool definitions that call Rust via NAPI.

### Directory Structure

```
packages/cortex/
├── package.json                        # Dependencies: @napi-rs/cli, drift-cortex-napi
├── tsconfig.json
├── vitest.config.ts
├── src/
│   ├── index.ts                        # Public exports — CortexClient, tool registrations
│   ├── bridge/
│   │   ├── index.ts                    # NAPI bridge consumer — loads native module
│   │   ├── client.ts                   # CortexClient — typed wrapper over NAPI bindings, error mapping, async wrapper
│   │   └── types.ts                    # TypeScript type definitions matching Rust types
│   ├── tools/
│   │   ├── index.ts                    # Tool registry — registers all 33 MCP tools
│   │   ├── memory/
│   │   │   ├── drift_memory_add.ts     # Create memory with auto-dedup + causal inference
│   │   │   ├── drift_memory_search.ts  # Hybrid search with session dedup
│   │   │   ├── drift_memory_get.ts     # Get memory by ID with full details
│   │   │   ├── drift_memory_update.ts  # Update memory content/metadata
│   │   │   ├── drift_memory_delete.ts  # Soft delete (archive) with audit
│   │   │   ├── drift_memory_list.ts    # List memories with filters (type, importance, date)
│   │   │   ├── drift_memory_link.ts    # Link memory to pattern/constraint/file/function
│   │   │   └── drift_memory_unlink.ts  # Remove link
│   │   ├── retrieval/
│   │   │   ├── drift_context.ts        # Orchestrated context retrieval
│   │   │   ├── drift_search.ts         # Direct hybrid search (no orchestration)
│   │   │   └── drift_related.ts        # Find related memories by entity links
│   │   ├── why/
│   │   │   ├── drift_why.ts            # Full "why" context with causal narratives
│   │   │   ├── drift_explain.ts        # Explain single memory with causal chain
│   │   │   ├── drift_counterfactual.ts # "What if we hadn't done X?"
│   │   │   └── drift_intervention.ts   # "If we change X, what needs updating?"
│   │   ├── learning/
│   │   │   ├── drift_memory_learn.ts   # Correction analysis + principle extraction
│   │   │   ├── drift_feedback.ts       # Process user feedback (confirm/reject/modify)
│   │   │   └── drift_validate.ts       # Get validation candidates for active learning
│   │   ├── generation/
│   │   │   ├── drift_gen_context.ts    # Build generation context with provenance
│   │   │   └── drift_gen_outcome.ts    # Track generation outcome (accepted/rejected)
│   │   ├── system/
│   │   │   ├── drift_cortex_status.ts  # Health dashboard
│   │   │   ├── drift_cortex_metrics.ts # Consolidation quality + retrieval metrics
│   │   │   ├── drift_cortex_consolidate.ts  # Manual consolidation trigger
│   │   │   ├── drift_cortex_validate.ts     # Run validation across all memories
│   │   │   ├── drift_cortex_gc.ts      # Run compaction (cleanup + vacuum)
│   │   │   ├── drift_cortex_export.ts  # Export memories as JSON
│   │   │   ├── drift_cortex_import.ts  # Import memories from JSON
│   │   │   └── drift_cortex_reembed.ts # Trigger re-embedding pipeline
│   │   └── prediction/
│   │       ├── drift_predict.ts        # Predictive preloading for current context
│   │       └── drift_preload.ts        # Manual preload for specific file/pattern
│   └── cli/
│       ├── index.ts                    # CLI command registration (CX23), subcommands under `drift cortex`
│       ├── status.ts                   # drift cortex status
│       ├── search.ts                   # drift cortex search <query>
│       ├── why.ts                      # drift cortex why <file|pattern>
│       ├── explain.ts                  # drift cortex explain <memory-id>
│       ├── add.ts                      # drift cortex add <type>
│       ├── learn.ts                    # drift cortex learn
│       ├── consolidate.ts              # drift cortex consolidate
│       ├── validate.ts                 # drift cortex validate
│       ├── export.ts                   # drift cortex export
│       ├── import.ts                   # drift cortex import <file>
│       ├── gc.ts                       # drift cortex gc
│       ├── metrics.ts                  # drift cortex metrics
│       └── reembed.ts                  # drift cortex reembed
└── tests/
    ├── bridge.test.ts                  # NAPI bridge integration tests
    ├── tools/
    │   ├── memory_tools.test.ts        # Memory CRUD tool tests
    │   ├── retrieval_tools.test.ts     # Retrieval tool tests
    │   ├── why_tools.test.ts           # Why/causal tool tests
    │   └── system_tools.test.ts        # System tool tests
    └── cli/
        └── commands.test.ts            # CLI command integration tests
```

### MCP Tools (33 total)

| Category | Count | Tools |
|----------|-------|-------|
| Memory | 8 | drift_memory_add, drift_memory_search, drift_memory_get, drift_memory_update, drift_memory_delete, drift_memory_list, drift_memory_link, drift_memory_unlink |
| Retrieval | 3 | drift_context, drift_search, drift_related |
| Why | 4 | drift_why, drift_explain, drift_counterfactual, drift_intervention |
| Learning | 3 | drift_memory_learn, drift_feedback, drift_validate |
| Generation | 2 | drift_gen_context, drift_gen_outcome |
| System | 8 | drift_cortex_status, drift_cortex_metrics, drift_cortex_consolidate, drift_cortex_validate, drift_cortex_gc, drift_cortex_export, drift_cortex_import, drift_cortex_reembed |
| Prediction | 2 | drift_predict, drift_preload |

### CLI Commands (CX23, `cli/`)

```
drift cortex status              # Health dashboard
drift cortex search <query>      # Hybrid search with RRF
drift cortex why <file|pattern>  # Causal narrative
drift cortex explain <memory-id> # Full memory with causal chain
drift cortex add <type>          # Interactive memory creation
drift cortex learn               # Trigger learning from corrections
drift cortex consolidate         # Manual consolidation trigger
drift cortex validate            # Run validation across all memories
drift cortex export              # Export memories as JSON
drift cortex import <file>       # Import memories from JSON
drift cortex gc                  # Run compaction
drift cortex metrics             # Consolidation quality metrics
drift cortex reembed             # Trigger re-embedding pipeline
```

### TypeScript Tests (`tests/`)

| Test File | Coverage |
|-----------|----------|
| `bridge.test.ts` | NAPI bridge integration — load native module, basic roundtrip |
| `tools/memory_tools.test.ts` | Memory CRUD tool tests — all 8 memory tools |
| `tools/retrieval_tools.test.ts` | Retrieval tool tests — context, search, related |
| `tools/why_tools.test.ts` | Why/causal tool tests — why, explain, counterfactual, intervention |
| `tools/system_tools.test.ts` | System tool tests — status, metrics, consolidate, validate, gc, export, import, reembed |
| `cli/commands.test.ts` | CLI command integration tests — all 13 commands |

---

## Test Infrastructure — Golden Datasets, Benchmarks, Integration (~30 files)

Shared across all crates. Located in `crates/cortex/test-fixtures/`.

### Directory Structure

```
crates/cortex/test-fixtures/
├── README.md                           # Test fixture documentation
├── golden/
│   ├── consolidation/
│   │   ├── cluster_2_basic.json        # 2 episodic memories → expected semantic output
│   │   ├── cluster_3_overlapping.json  # 3 episodes with high overlap → dedup test
│   │   ├── cluster_5_diverse.json      # 5 episodes, diverse content → novel extraction
│   │   ├── cluster_with_noise.json     # Cluster + noise points → noise deferred
│   │   ├── anchor_selection.json       # Verify correct anchor chosen
│   │   ├── summary_generation.json     # TextRank + TF-IDF expected output
│   │   ├── metadata_union.json         # Tags, files, patterns union verification
│   │   ├── confidence_boost.json       # Cluster size boost calculation
│   │   ├── integration_dedup.json      # New consolidation overlaps existing semantic
│   │   └── recall_gate_fail.json       # Cluster that should fail recall gate
│   ├── retrieval/
│   │   ├── keyword_match.json          # FTS5 should find exact keyword
│   │   ├── semantic_match.json         # Vector search should find semantic match
│   │   ├── hybrid_rrf.json             # RRF should combine both correctly
│   │   ├── intent_weighting.json       # fix_bug intent boosts tribal/incident
│   │   ├── importance_ranking.json     # Higher importance ranks above at equal similarity
│   │   ├── session_dedup.json          # Already-sent memories filtered
│   │   ├── budget_packing.json         # Bin-packing respects token budget
│   │   ├── empty_query.json            # Empty query returns empty results
│   │   ├── file_proximity.json         # Same-file memories boosted
│   │   └── reranking.json              # Re-ranker reorders candidates correctly
│   ├── contradiction/
│   │   ├── direct_conflict.json        # Two memories directly contradict
│   │   ├── partial_conflict.json       # Partial contradiction
│   │   ├── temporal_supersession.json  # Newer supersedes older
│   │   ├── consensus_resistance.json   # Consensus resists single contradiction
│   │   └── propagation_chain.json      # Confidence ripple through graph
│   ├── causal/
│   │   ├── simple_chain.json           # A caused B caused C
│   │   ├── branching.json              # A caused B and C
│   │   ├── cycle_rejection.json        # Cycle should be rejected
│   │   ├── counterfactual.json         # "What if X didn't happen?"
│   │   └── narrative_output.json       # Expected narrative text
│   └── privacy/
│       ├── pii_samples.json            # Known PII strings → expected sanitized output
│       ├── secret_samples.json         # Known secrets → expected sanitized output
│       ├── false_positives.json        # Strings that look like secrets but aren't
│       └── idempotency.json            # Sanitize(sanitize(x)) == sanitize(x)
├── benchmarks/
│   ├── memories_100.json               # 100 memories for small-scale benchmarks
│   ├── memories_1k.json                # 1K memories for medium-scale benchmarks
│   ├── memories_10k.json              # 10K memories for large-scale benchmarks
│   ├── embeddings_1024dim.bin          # Pre-computed embeddings for benchmark memories
│   ├── queries_50.json                 # 50 benchmark queries with expected results
│   └── causal_graph_1k_edges.json      # 1K-edge causal graph for traversal benchmarks
└── integration/
    ├── full_lifecycle.json             # Create → consolidate → retrieve → decay → validate
    ├── concurrent_access.json          # 10 parallel reads + 1 write scenario
    ├── embedding_migration.json        # Model swap mid-operation scenario
    └── degradation_scenarios.json      # Each component failure + expected fallback
```

### Golden Dataset Tests (Layer 2)

| Category | Count | Files |
|----------|-------|-------|
| Consolidation | 10 | cluster formation, anchor selection, summary generation, dedup, recall gate |
| Retrieval | 10 | keyword match, semantic match, hybrid, intent weighting, importance ranking |
| Contradiction | 5 | direct, partial, temporal, consensus, propagation |
| Causal | 5 | simple chain, branching, cycle rejection, counterfactual, narrative |
| Privacy | 4 | PII, secrets, false positives, idempotency |

### Benchmark Data (Layer 3)

| File | Purpose |
|------|---------|
| `memories_100.json` | Small-scale benchmarks |
| `memories_1k.json` | Medium-scale benchmarks |
| `memories_10k.json` | Large-scale benchmarks |
| `embeddings_1024dim.bin` | Pre-computed embeddings |
| `queries_50.json` | Benchmark queries with expected results |
| `causal_graph_1k_edges.json` | Traversal benchmarks |

### Integration Test Scenarios

| File | Scenario |
|------|----------|
| `full_lifecycle.json` | Create → consolidate → retrieve → decay → validate |
| `concurrent_access.json` | 10 parallel reads + 1 write |
| `embedding_migration.json` | Model swap mid-operation |
| `degradation_scenarios.json` | Each component failure + expected fallback |

---

## Per-Crate Test and Bench Directories

Every crate follows the same test structure internally. This section specifies the test files that live inside each crate (not in test-fixtures).

### Test Pattern (repeated in every crate)

```
crates/cortex/<crate-name>/
├── tests/
│   ├── integration/                    # Integration tests
│   └── property/                       # Property-based tests (proptest)
└── benches/                            # Performance benchmarks (criterion)
```

### Property-Based Tests (proptest, Layer 1)

| Crate | File | Properties Tested |
|-------|------|-------------------|
| cortex-tokens | `tests/property/token_properties.rs` | count(a+b) ≤ count(a)+count(b)+1, count("")=0, cached=uncached |
| cortex-storage | `tests/property/storage_properties.rs` | insert→get roundtrip, bulk ops consistency, query correctness |
| cortex-compression | `tests/property/compression_properties.rs` | Level ordering L0<L1<L2<L3, L3 lossless, compressToFit ≤ budget |
| cortex-decay | `tests/property/decay_properties.rs` | Monotonically decreasing, bounded 0.0-1.0, importance anchor capped, usage boost capped |
| cortex-causal | `tests/property/causal_properties.rs` | DAG enforcement (no cycles), depth ≤ maxDepth, nodes ≤ maxNodes, bidirectional = union |
| cortex-retrieval | `tests/property/retrieval_properties.rs` | RRF monotonically decreasing, budget never exceeded, higher importance ranks above |
| cortex-privacy | `tests/property/privacy_properties.rs` | Sanitized output never contains raw PII, idempotent (sanitize twice = once) |
| cortex-consolidation | `tests/property/consolidation_properties.rs` | Idempotent, deterministic, monotonic confidence, no orphaned links, output < input tokens |

### Integration Tests (per crate)

| Crate | File | Tests |
|-------|------|-------|
| cortex-storage | `tests/integration/memory_crud_test.rs` | Full CRUD lifecycle |
| cortex-storage | `tests/integration/migration_test.rs` | All migrations run cleanly on fresh DB |
| cortex-storage | `tests/integration/concurrent_access_test.rs` | Read pool + write connection under load |
| cortex-storage | `tests/integration/recovery_test.rs` | WAL recovery, backup restore |
| cortex-storage | `tests/integration/compaction_test.rs` | Archived cleanup, vacuum, dedup |

### Performance Benchmarks (criterion, Layer 3)

| Crate | File | Targets |
|-------|------|---------|
| cortex-retrieval | `benches/retrieval_bench.rs` | 100 memories < 5ms p95, 10K < 50ms p95, hybrid 10K < 30ms p95 |
| cortex-consolidation | `benches/consolidation_bench.rs` | Cluster of 5 < 10ms |
| cortex-embeddings | `benches/embedding_bench.rs` | Single (local ONNX) < 100ms, batch of 10 < 500ms |
| cortex-decay | `benches/decay_bench.rs` | 1K memories < 1ms |
| cortex-causal | `benches/causal_bench.rs` | Traversal depth 5, 1K edges < 5ms |
| cortex-storage | `benches/storage_bench.rs` | Insert latency, query latency, bulk insert throughput, FTS5 search speed |

---

## Graceful Degradation Matrix (CX18)

| Component | Failure Mode | Fallback | User Impact |
|-----------|-------------|----------|-------------|
| ONNX embedding model | Model missing/corrupt | Fallback model → cached embeddings → TF-IDF → error | Retrieval quality degrades but works |
| SQLite database | File corruption | WAL recovery → backup restore → fresh start with warning | If recovery succeeds: no data loss |
| sqlite-vec extension | Fails to load | FTS5-only retrieval → metadata-only filtering | Loses semantic similarity, keyword search works |
| FTS5 index | Index corruption | Rebuild from memory content (background) | Brief keyword-search-only degradation |
| Causal graph (petgraph) | Inconsistent with SQLite | Rebuild from causal_edges table | Causal traversal briefly unavailable |
| Embedding dimension mismatch | Model change | Background re-embedding + FTS5-only for un-migrated | Quality improves as re-embedding progresses |
| HDBSCAN clustering | Edge case failure | Metadata-based grouping (shared files + patterns) | Consolidation quality slightly lower |
| Token counter (tiktoken) | Model file missing | Character-length approximation (length/4) | Budget management less accurate |
| Privacy sanitizer | Regex compilation failure | Skip failing pattern, log warning, continue | One pattern type unsanitized |
| Prediction cache (moka) | Memory pressure | Evict prediction cache first (regenerable) | Prediction preloading disabled |

Every degradation event logged to audit trail with: component, failure mode, fallback used, timestamp, recovery status.

---

## Concurrency Model (CX20)

### Foreground (responds to queries)

- Retrieval (read pool)
- Search (read pool)
- MCP tool handlers (read pool)
- Memory CRUD (write connection)

### Background (periodic tasks)

| Task | Frequency | Crate |
|------|-----------|-------|
| Consolidation | Every 6h or triggered by pressure | cortex-consolidation |
| Decay processing | Every 1h | cortex-decay |
| Validation | Every 4h | cortex-validation |
| Prediction preloading | On file change | cortex-prediction |
| Re-embedding migration | When model changes | cortex-embeddings |
| Compaction | Weekly | cortex-storage |
| Reclassification | Monthly | cortex-reclassification |

### State Synchronization

| State | Type | Access Pattern |
|-------|------|---------------|
| Causal graph | `Arc<RwLock<StableGraph>>` | Many concurrent readers, exclusive writer |
| Embedding cache L1 | `moka::sync::Cache` | Thread-safe internally |
| Prediction cache | `moka::sync::Cache` | Thread-safe internally |
| Session contexts | `Arc<DashMap<SessionId, SessionContext>>` | Fine-grained per-key locking |
| Consolidation state | `Arc<AtomicBool>` | Only one at a time |
| Health metrics | `Arc<RwLock<HealthMetrics>>` | Frequent reads, infrequent writes |

**Key principle:** Reads never wait for writes. Writes are serialized but fast. Background tasks yield between batches to prevent write-starvation.

---

## Data Budget and Storage Projections (CX21)

### Per-Memory Storage

| Component | Size |
|-----------|------|
| Content (typed struct) | ~2KB |
| Embedding (1024-dim f32) | 4KB |
| Embedding (384-dim truncated) | 1.5KB |
| Metadata + indexes | ~1KB |
| FTS5 index contribution | ~0.5KB |
| Audit log (per lifetime) | ~2.5KB |
| **Total** | **~11.5KB** |

### Growth Projections

| Usage | Memories/Day | 1 Year | 3 Years | 5 Years |
|-------|-------------|--------|---------|---------|
| Light (solo) | 5 | 14MB | 42MB | 70MB |
| Normal (active) | 15 | 42MB | 126MB | 210MB |
| Heavy (team) | 50 | 140MB | 420MB | 700MB |
| Extreme (CI + multi) | 100 | 280MB | 840MB | 1.4GB |

---

## Implementation Phases — File-Level Build Order

This is the order you build. Each phase depends on the previous. No phase N+1 begins until phase N quality gate passes.

### Phase 0: Architecture Decisions (Week 0, no code — just config)

```
crates/cortex/Cargo.toml              # Workspace manifest
crates/cortex/rust-toolchain.toml     # Pin Rust version
crates/cortex/.cargo/config.toml      # Cargo config
crates/cortex/deny.toml               # cargo-deny config
```

Decisions finalized: Rust crate structure (R22), hybrid search DB schema (FA1), embedding model + ONNX config (FA2), error hierarchy + audit log schema (FA3).

### Phase 1: Foundation — cortex-core + cortex-tokens (Week 1-2)

```
cortex-core/src/errors/*              # Error types FIRST — everything uses these
cortex-core/src/memory/base.rs        # BaseMemory
cortex-core/src/memory/types/*        # 23 memory types
cortex-core/src/memory/*.rs           # Importance, confidence, relationships, links, half-lives
cortex-core/src/traits/*              # All 12 trait definitions
cortex-core/src/config/*              # All config structs + defaults
cortex-core/src/intent/*              # Intent taxonomy + weights
cortex-core/src/models/*              # All 16 shared models
cortex-core/src/constants.rs          # Global constants
cortex-tokens/src/*                   # Token counter + budget helpers
```

**Gate:** QG-0 + QG-1 must pass.

### Phase 2: Storage (Weeks 2-3)

```
cortex-storage/src/pool/*             # Connection pool FIRST
cortex-storage/src/migrations/*       # All 12 schema migrations
cortex-storage/src/queries/*          # All 12 query modules
cortex-storage/src/audit/*            # Audit logger + rotation
cortex-storage/src/versioning/*       # Memory versioning (tracker, query, rollback, retention)
cortex-storage/src/compaction/*       # Compaction + storage health
cortex-storage/src/recovery/*         # Recovery + backup
cortex-storage/src/engine.rs          # StorageEngine (ties it all together)
```

**Gate:** QG-2 must pass.

### Phase 3: Embeddings (Weeks 3-4)

```
cortex-embeddings/src/providers/*     # All 4 providers + TF-IDF fallback
cortex-embeddings/src/cache/*         # 3-tier cache (L1/L2/L3)
cortex-embeddings/src/enrichment.rs   # Metadata enrichment
cortex-embeddings/src/matryoshka.rs   # Dimension management
cortex-embeddings/src/migration/*     # Embedding migration pipeline
cortex-embeddings/src/degradation.rs  # Fallback chain
cortex-embeddings/src/engine.rs       # EmbeddingEngine
```

**Gate:** QG-3 must pass.

**Phase 1-3 Exit Criteria:**
- [ ] QG-0 through QG-3 all pass
- [ ] Memory CRUD works end-to-end: create → embed → store → retrieve by vector → retrieve by keyword
- [ ] Audit log records all mutations
- [ ] Version tracking works on updates
- [ ] `cargo clippy` clean, zero warnings

### Phase 4: Privacy + Compression + Decay (Weeks 5-6, lightweight crates)

```
cortex-privacy/src/*                  # All privacy modules (engine, patterns, context scoring, degradation)
cortex-compression/src/*              # All compression modules (engine, levels, packing)
cortex-decay/src/*                    # All decay modules (engine, formula, factors, adaptive, archival)
```

**Gate:** QG-4 + QG-5 + QG-6 must pass.

### Phase 5: Retrieval (Weeks 6-7)

```
cortex-retrieval/src/search/*         # Hybrid search + RRF (fts5, vector, rrf_fusion, entity)
cortex-retrieval/src/ranking/*        # Scoring + re-ranking + deduplication
cortex-retrieval/src/intent/*         # Intent classification + weight matrix
cortex-retrieval/src/expansion/*      # Query expansion (synonym, HyDE)
cortex-retrieval/src/budget/*         # Token budget packing
cortex-retrieval/src/generation/*     # Generation context (context_builder, gatherers/*, provenance, feedback, validation)
cortex-retrieval/src/why/*            # "Why" synthesizer + aggregator
cortex-retrieval/src/engine.rs        # RetrievalEngine
```

**Gate:** QG-8 must pass.

**Phase 4-5 Exit Criteria:**
- [ ] QG-4 through QG-8 all pass (QG-7 deferred to Phase 6)
- [ ] Full retrieval pipeline: query → hybrid search → RRF → re-rank → compress → return
- [ ] Privacy sanitization runs before storage
- [ ] Generation context builds with provenance
- [ ] Why system synthesizes complete WhyContext

### Phase 6: Validation + Contradiction (Weeks 8-9)

```
cortex-validation/src/contradiction/* # Detection (5 strategies) + propagation + consensus
cortex-validation/src/dimensions/*    # 4 validation dimensions
cortex-validation/src/healing/*       # 5 healing strategies
cortex-validation/src/engine.rs       # ValidationEngine
```

**Gate:** QG-9 must pass.

### Phase 7: Causal Intelligence (Weeks 8-9)

```
cortex-causal/src/graph/*             # StableGraph + DAG enforcement + sync + pruning
cortex-causal/src/inference/*         # 6 inference strategies + scorer
cortex-causal/src/traversal/*         # 6 traversal modes (forward, backward, bidirectional, neighbors, counterfactual, intervention)
cortex-causal/src/narrative/*         # Narrative generation + templates + confidence
cortex-causal/src/relations.rs        # 8 relation types
cortex-causal/src/engine.rs           # CausalEngine
```

**Gate:** QG-7 must pass.

### Phase 8: Knowledge Management (Weeks 10-12)

```
cortex-consolidation/src/pipeline/*   # 6-phase pipeline
cortex-consolidation/src/algorithms/* # TextRank, TF-IDF, sentence splitter, similarity
cortex-consolidation/src/scheduling/* # Adaptive scheduler + triggers + throttle
cortex-consolidation/src/monitoring/* # CX15 quality metrics + auto-tuning + dashboard
cortex-consolidation/src/llm_polish.rs # Optional LLM enhancement
cortex-consolidation/src/engine.rs    # ConsolidationEngine

cortex-learning/src/analysis/*        # Correction analysis (diff, categorizer, mapping)
cortex-learning/src/extraction/*      # Principle extraction (rule-based, LLM-enhanced)
cortex-learning/src/deduplication.rs  # Mem0-inspired dedup
cortex-learning/src/calibration.rs    # Confidence calibration
cortex-learning/src/active_learning/* # Active learning loop (selector, prompt generator, feedback processor)
cortex-learning/src/engine.rs         # LearningEngine
```

**Gate:** QG-10 + QG-11 must pass.

**Phase 6-8 Exit Criteria:**
- [ ] QG-6 through QG-11 all pass
- [ ] Full knowledge lifecycle: create → decay → validate → learn → consolidate
- [ ] Contradictions detected and propagated
- [ ] Consolidation produces semantic memories from episodic clusters
- [ ] Quality metrics tracked and auto-tuning operational
- [ ] Causal graph enforces DAG, generates narratives

### Phase 9: Prediction + Session + Reclassification (Weeks 13-14)

```
cortex-prediction/src/signals/*       # 4 signal types (file, temporal, behavioral, git)
cortex-prediction/src/strategies/*    # 4 strategies + dedup
cortex-prediction/src/cache.rs        # Prediction cache
cortex-prediction/src/precompute.rs   # Pre-compute search results
cortex-prediction/src/engine.rs       # PredictionEngine

cortex-session/src/*                  # All session modules (manager, context, dedup, analytics, efficiency, cleanup)

cortex-reclassification/src/*         # All reclassification modules (engine, signals, rules, safeguards)
```

**Gate:** QG-12 + QG-13 must pass.

### Phase 10: Observability (Week 14-15)

```
cortex-observability/src/health/*     # Health checks + recommendations
cortex-observability/src/metrics/*    # All 5 metric collectors
cortex-observability/src/tracing/*    # Structured logging (spans + events)
cortex-observability/src/degradation/* # Degradation tracking + alerting
cortex-observability/src/query_log.rs # Query performance logging
```

**Phase 9-10 Exit Criteria:**
- [ ] QG-12 and QG-13 pass
- [ ] Prediction preloads relevant memories on file change
- [ ] Session deduplication saves 30-50% tokens
- [ ] Health report shows all subsystem statuses
- [ ] Degradation tracking operational

### Phase 11: Cloud (Week 16, feature-gated)

```
cortex-cloud/src/auth/*               # Auth + token management + offline mode
cortex-cloud/src/sync/*               # Push/pull + sync log + delta
cortex-cloud/src/conflict/*           # Conflict detection + resolution + logging
cortex-cloud/src/transport/*          # HTTP client + wire protocol
cortex-cloud/src/quota.rs             # Quota management
cortex-cloud/src/engine.rs            # CloudEngine
```

### Phase 12: NAPI Bridge (Weeks 16-17)

```
cortex-napi/src/runtime.rs            # CortexRuntime — owns all engines
cortex-napi/src/bindings/*            # All 12 NAPI binding modules
cortex-napi/src/conversions/*         # All 5 type conversion modules
cortex-napi/src/lib.rs                # Module registration
cortex-napi/build.rs                  # napi-rs build script
```

**Gate:** QG-14 must pass.

### Phase 13: TypeScript Layer (Weeks 17-18)

```
packages/cortex/src/bridge/*          # NAPI consumer + typed client + types
packages/cortex/src/tools/index.ts    # Tool registry
packages/cortex/src/tools/memory/*    # 8 memory tools
packages/cortex/src/tools/retrieval/* # 3 retrieval tools
packages/cortex/src/tools/why/*       # 4 why tools
packages/cortex/src/tools/learning/*  # 3 learning tools
packages/cortex/src/tools/generation/* # 2 generation tools
packages/cortex/src/tools/system/*    # 8 system tools
packages/cortex/src/tools/prediction/* # 2 prediction tools
packages/cortex/src/cli/*             # 13 CLI commands
packages/cortex/src/index.ts          # Public exports
```

### Phase 14: Test Infrastructure + Integration (Weeks 18-19)

```
crates/cortex/test-fixtures/**        # All golden datasets + benchmarks + integration scenarios
All crate tests/ and benches/         # Property tests + integration tests + benchmarks
packages/cortex/tests/**              # TypeScript tests
```

**Gate:** QG-15 must pass.

**Phase 12-14 Exit Criteria:**
- [ ] QG-14 and QG-15 pass
- [ ] All 33 MCP tools callable from TypeScript
- [ ] Full lifecycle integration test passes
- [ ] Graceful degradation verified for all failure modes
- [ ] All property-based tests pass
- [ ] All golden dataset tests pass
- [ ] Performance benchmarks meet targets

---

## Testing Strategy (CX17)

### Layer 1 — Property-Based Tests (proptest)

| Subsystem | Properties |
|-----------|-----------|
| Token counting | count(a+b) ≤ count(a)+count(b)+1, count("")=0, cached=uncached |
| Storage | insert→get roundtrip, bulk ops consistency, query correctness |
| Compression | Level ordering L0<L1<L2<L3, L3 lossless, compressToFit ≤ budget |
| Decay | Monotonically decreasing, bounded 0.0-1.0, importance anchor capped, usage boost capped |
| Causal graph | DAG enforcement (no cycles), depth ≤ maxDepth, nodes ≤ maxNodes |
| Retrieval | Higher importance ranks above at equal similarity, budget never exceeded, RRF monotonically decreasing |
| Hybrid search | FTS5 + vector ⊆ RRF |
| Privacy | Sanitized output never contains raw PII, idempotent |
| Consolidation | Idempotent, deterministic, monotonic confidence, no orphaned links, output < input tokens |

### Layer 2 — Golden Dataset Tests

Located in `crates/cortex/test-fixtures/golden/`:
- 10 consolidation scenarios
- 10 retrieval scenarios
- 5 contradiction scenarios
- 5 causal scenarios
- 4 privacy scenarios

### Layer 3 — Performance Benchmarks (criterion)

| Benchmark | Target |
|-----------|--------|
| Retrieval (100 memories) | < 5ms p95 |
| Retrieval (10K memories) | < 50ms p95 |
| Hybrid search (FTS5+vec+RRF, 10K) | < 30ms p95 |
| Consolidation (cluster of 5) | < 10ms |
| Embedding (single, local ONNX) | < 100ms |
| Embedding (batch of 10, local ONNX) | < 500ms |
| Decay (1K memories) | < 1ms |
| Causal traversal (depth 5, 1K edges) | < 5ms |
| Storage insert latency | < 1ms |
| Storage FTS5 search | < 5ms |

### Layer 4 — Integration Tests

- Full lifecycle: create 50 episodic → consolidate → retrieve → decay → validate
- Concurrent access: 10 parallel reads + 1 write → no corruption
- Embedding model swap: create with model A → switch to B → re-embedding → retrieval works during transition
- Degradation scenarios: each component failure + expected fallback

---

## Dependency Graph

```
cortex-core ──────────→ ALL crates depend on this
cortex-tokens ─────────→ cortex-compression, cortex-retrieval
cortex-storage ────────→ cortex-retrieval, cortex-causal, cortex-validation,
                         cortex-learning, cortex-consolidation, cortex-prediction,
                         cortex-reclassification, cortex-cloud
cortex-embeddings ─────→ cortex-retrieval, cortex-validation, cortex-learning,
                         cortex-consolidation
cortex-privacy ────────→ cortex-napi (sanitize before storage)
cortex-compression ────→ cortex-retrieval
cortex-decay ──────────→ cortex-napi (background task)
cortex-causal ─────────→ cortex-retrieval (why system), cortex-learning
cortex-retrieval ──────→ cortex-napi, cortex-prediction
cortex-validation ─────→ cortex-napi (background task)
cortex-learning ───────→ cortex-napi
cortex-consolidation ──→ cortex-napi (background task)
cortex-prediction ─────→ cortex-napi
cortex-session ────────→ cortex-napi
cortex-reclassification → cortex-napi (background task)
cortex-observability ──→ cortex-napi
cortex-cloud ──────────→ cortex-napi [feature-gated]
cortex-napi ───────────→ packages/cortex (TypeScript MCP tools)
```

---

## External Dependency Map

| Crate | External Deps | Purpose |
|---|---|---|
| cortex-core | serde, serde_json, chrono, uuid, thiserror | Serialization, time, IDs, errors |
| cortex-tokens | tiktoken-rs, blake3, moka | Tokenization, hashing, caching |
| cortex-storage | rusqlite (bundled), tokio::sync | SQLite + connection pool |
| cortex-embeddings | ort, moka, blake3, reqwest, tokio | ONNX Runtime, caching, API calls |
| cortex-retrieval | (uses cortex-compression, cortex-tokens) | No unique external deps |
| cortex-causal | petgraph | Graph operations |
| cortex-learning | (no unique external deps) | Uses cortex-embeddings, cortex-causal |
| cortex-decay | (no unique external deps) | Pure computation on cortex-core types |
| cortex-validation | (no unique external deps) | Uses cortex-embeddings for refresh |
| cortex-compression | (no unique external deps) | Pure computation on cortex-core types |
| cortex-prediction | moka | Prediction cache |
| cortex-session | dashmap | Concurrent session map |
| cortex-privacy | regex | Pattern matching |
| cortex-consolidation | hdbscan, rayon | Clustering, parallel batch ops |
| cortex-reclassification | (no unique external deps) | Pure computation |
| cortex-observability | tracing, tracing-subscriber | Structured logging |
| cortex-cloud | reqwest, tokio | HTTP client, async runtime |
| cortex-napi | napi, napi-derive, tokio | NAPI bindings, async runtime |

---

## File Count Summary

| Layer | Crate | Estimated Files |
|---|---|---|
| Foundation | cortex-core | ~35 |
| Foundation | cortex-tokens | ~3 |
| Storage | cortex-storage | ~30 |
| Embeddings | cortex-embeddings | ~15 |
| Retrieval | cortex-retrieval | ~25 |
| Causal | cortex-causal | ~18 |
| Learning | cortex-learning | ~12 |
| Decay | cortex-decay | ~8 |
| Validation | cortex-validation | ~16 |
| Compression | cortex-compression | ~6 |
| Prediction | cortex-prediction | ~10 |
| Session | cortex-session | ~7 |
| Privacy | cortex-privacy | ~7 |
| Consolidation | cortex-consolidation | ~18 |
| Reclassification | cortex-reclassification | ~5 |
| Observability | cortex-observability | ~14 |
| Cloud | cortex-cloud | ~14 |
| NAPI | cortex-napi | ~16 |
| Test Fixtures | test-fixtures | ~30 |
| TypeScript | packages/cortex | ~45 |
| **Total** | | **~334 files** |

---

## Key Design Principles

1. **Single Responsibility**: Every crate owns exactly one concern. No crate reaches into another's internals.
2. **Trait-Driven**: All cross-crate communication happens through traits defined in cortex-core. Implementations are swappable.
3. **Error Propagation**: Every crate has its own error type that converts into CortexError via `From` impls. No panics in library code.
4. **Offline-First**: Every feature works without network. Cloud is feature-gated and optional.
5. **Deterministic Core**: Consolidation, decay, validation, compression — all deterministic. Same inputs → same outputs. Testable, reproducible.
6. **Graceful Degradation**: Every component has a fallback. The system never crashes — it degrades and tells you what happened.
7. **Audit Everything**: Every mutation logged. Every degradation logged. Every reclassification logged. Full traceability.
8. **Performance by Default**: Read-heavy workload optimized with WAL mode, read pool, moka caches, Matryoshka embeddings. Writes serialized but fast.

---

## Research Cross-Reference

| Spec Component | Research Source | Key Insight |
|----------------|---------------|-------------|
| Hybrid search (FTS5 + RRF) | R2 (Simon Willison, Azure) | RRF combines keyword + semantic without score normalization |
| Code-specific embeddings | R3 (Modal, Jina, CodeXEmbed) | Code models dramatically outperform general-purpose |
| ONNX inference in Rust | R4 (ort crate) | 3-5x faster than Transformers.js |
| Causal graph (petgraph) | R5 (petgraph docs) | StableGraph for frequent add/remove, built-in Tarjan's SCC |
| Concurrent caching (moka) | R6 (moka docs) | TinyLFU + LRU, thread-safe, size-aware eviction |
| Consolidation (neuroscience) | R7 (spaced repetition, forgetting curves) | Retrieval-difficulty triggers, adaptive decay |
| sqlite-vec best practices | R8 (Alex Garcia) | Pre-filter before vector search, enrichment improves quality |
| PII detection (layered) | R9 (Elastic, Protecto) | Regex + context scoring, 50+ patterns |
| RAG production patterns | R10 (enterprise RAG guides) | Two-stage retrieval, query expansion, re-ranking |
| Causal knowledge graphs | R11 (CausalKG paper) | DAG enforcement, counterfactual/intervention queries |
| Token counting (tiktoken) | R12 (OpenAI tiktoken) | Exact counts prevent budget overflow/underutilization |
| Memory observability | R13 (Salesforce, enterprise RAG) | Retrieval effectiveness tracking, feedback loops |
| Embedding enrichment | R14 (RAG optimization) | Prepend metadata before embedding for better discrimination |
| Governed memory fabric | R15 (epistemic identity) | Evidence-based promotion, audit trails |
| Mem0 architecture | R1 (Mem0 paper) | Two-phase pipeline, dedup before storage, graph memory |
| TextRank summarization | R16 | Graph-based extractive summarization |
| HDBSCAN clustering | R17 | Density-based, no predefined cluster count |

---

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| ONNX model loading slow on first run | Medium | Low | Pre-download during `drift setup`, cache in L3 |
| sqlite-vec brute-force slow at scale | Low | Medium | Pre-filter by type/importance, Matryoshka truncation |
| Causal graph grows unbounded | Medium | Medium | Prune weak edges periodically, depth limits |
| Algorithmic consolidation quality < LLM | Medium | Medium | CX15 monitoring, optional LLM polish, recall gate, auto-tuning |
| HDBSCAN too many noise points | Low | Low | Tune min_cluster_size, noise deferred not lost |
| NAPI bridge complexity | Medium | High | napi-rs typed bindings, keep MCP tools thin |
| Embedding model change breaks retrieval | Medium | High | CX19 migration pipeline, FTS5 fallback during transition |
| Concurrent write contention | Low | Medium | Single write connection behind Mutex, WAL mode |
| cortex.db grows > 1GB | Low | Medium | CX21 compaction strategy, storage health reporting |
| SQLite corruption | Low | Critical | CX18 WAL recovery → backup → fresh start |

---

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-02-06 | Initial unified implementation specification. Synthesized from: 25 v1 subsystem docs, 15 external research papers (R1-R15), 23 recommendations (CX1-CX23), RECAP (12 limitations addressed), DIRECTORY-MAP (structural blueprint). Covers all 19 Rust crates + TypeScript MCP layer. 15 quality gates, 6 implementation phases, property-based + golden dataset + benchmark testing strategy. |
| 2.0.0 | 2026-02-06 | Complete rewrite to account for 100% of ~334 files in DIRECTORY-MAP.md. Added: full directory structures for all 19 crates + TS layer, versioning system (cortex-storage/versioning/), generation context sub-modules (cortex-retrieval/generation/ with gatherers, provenance, feedback, validation), "why" system sub-modules (cortex-retrieval/why/ with synthesizer, aggregator), per-crate test/bench file specifications, test-fixtures golden datasets + benchmarks + integration scenarios, TypeScript test structure, file-level build order (14 phases), external dependency map, file count summary (~334), key design principles, expanded quality gates with file-level traceability. Every file in DIRECTORY-MAP.md now has a corresponding specification entry. |
