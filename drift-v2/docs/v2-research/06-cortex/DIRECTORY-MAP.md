# Cortex — Complete Directory Map

> The full structural blueprint for building Drift's Cortex memory system.
> Every crate, every module, every file. No source code — just the map.
>
> This is the script. Build it in this order, file by file.

---

## Overview

```
crates/cortex/                  # Rust workspace — the engine
├── cortex-core/                # Types, traits, errors, constants
├── cortex-storage/             # SQLite persistence, migrations, audit log
├── cortex-embeddings/          # ONNX providers, cache, enrichment
├── cortex-retrieval/           # Hybrid search, RRF, re-ranking, intent
├── cortex-causal/              # petgraph, inference, traversal, narrative
├── cortex-learning/            # Correction analysis, principle extraction
├── cortex-decay/               # Decay calculation, adaptive half-lives
├── cortex-validation/          # 4-dimension validation, healing
├── cortex-compression/         # 4-level compression, token budgeting
├── cortex-prediction/          # Signal gathering, 4 strategies, cache
├── cortex-session/             # Session management, deduplication
├── cortex-privacy/             # PII/secret sanitization (50+ patterns)
├── cortex-consolidation/       # HDBSCAN pipeline, quality monitoring
├── cortex-observability/       # Health, metrics, dashboards, tracing
├── cortex-cloud/               # Cloud sync, conflict resolution, auth
├── cortex-napi/                # NAPI bindings for TypeScript interop
└── test-fixtures/              # Golden datasets, benchmark data

packages/cortex/                # TypeScript layer — MCP tools + NAPI consumer
├── src/
│   ├── tools/                  # 33 MCP tool definitions
│   ├── bridge/                 # NAPI bridge consumer
│   └── index.ts                # Public exports
└── package.json
```

---

## Rust Workspace Root

```
crates/cortex/
├── Cargo.toml                  # Workspace manifest — all member crates
├── rust-toolchain.toml         # Pin Rust version for reproducible builds
├── .cargo/
│   └── config.toml             # Workspace-level cargo config (linker, target opts)
└── deny.toml                   # cargo-deny config — license + advisory audit
```


---

## 1. cortex-core — Types, Traits, Errors, Constants

The foundation crate. Every other crate depends on this. Zero external heavy dependencies — just serde, chrono, uuid, thiserror.

```
crates/cortex/cortex-core/
├── Cargo.toml
├── src/
│   ├── lib.rs                          # Re-exports all public modules
│   │
│   ├── memory/
│   │   ├── mod.rs                      # Module declarations
│   │   ├── base.rs                     # BaseMemory struct — 20+ fields
│   │   │                               #   id, type, transactionTime, validTime,
│   │   │                               #   confidence, importance, lastAccessed,
│   │   │                               #   accessCount, summary, linkedPatterns[],
│   │   │                               #   linkedConstraints[], linkedFiles[],
│   │   │                               #   linkedFunctions[], tags[], archived,
│   │   │                               #   supersededBy, supersedes, contentHash
│   │   │
│   │   ├── types/
│   │   │   ├── mod.rs                  # Memory type enum (23 variants) + dispatch
│   │   │   ├── domain_agnostic.rs      # 9 types: core, tribal, procedural, semantic,
│   │   │   │                           #   episodic, decision, insight, reference, preference
│   │   │   ├── code_specific.rs        # 4 types: pattern_rationale, constraint_override,
│   │   │   │                           #   decision_context, code_smell
│   │   │   └── universal.rs            # 10 types: agent_spawn, entity, goal, feedback,
│   │   │                               #   workflow, conversation, incident, meeting,
│   │   │                               #   skill, environment
│   │   │
│   │   ├── importance.rs               # Importance enum (low/normal/high/critical)
│   │   │                               #   + weight constants + ordering
│   │   ├── confidence.rs               # Confidence newtype (f64, 0.0-1.0)
│   │   │                               #   + clamping + arithmetic + thresholds
│   │   ├── relationships.rs            # 13 relationship types + RelationshipEdge struct
│   │   │                               #   Core: supersedes, supports, contradicts,
│   │   │                               #   related, derived_from
│   │   │                               #   Semantic: owns, affects, blocks, requires,
│   │   │                               #   references, learned_from, assigned_to, depends_on
│   │   ├── links.rs                    # PatternLink, ConstraintLink, FileLink (with
│   │   │                               #   citation: line_start, line_end, content_hash),
│   │   │                               #   FunctionLink structs
│   │   └── half_lives.rs               # Per-type half-life constants (days)
│   │                                   #   core=∞, tribal=365, procedural=180,
│   │                                   #   semantic=90, episodic=7, etc.
│   │
│   ├── traits/
│   │   ├── mod.rs                      # Re-exports all traits
│   │   ├── storage.rs                  # IMemoryStorage — full CRUD + bulk + query
│   │   │                               #   + vector similarity + bitemporal + relationships
│   │   │                               #   + links + aggregation + maintenance
│   │   ├── embedding.rs                # IEmbeddingProvider — embed, embedBatch,
│   │   │                               #   dimensions, name, isAvailable
│   │   ├── causal_storage.rs           # ICausalStorage — CRUD + strength + evidence
│   │   │                               #   + validation + statistics + cleanup
│   │   ├── retriever.rs                # IRetriever — retrieve(context, budget) -> Vec<CompressedMemory>
│   │   ├── consolidator.rs             # IConsolidator — consolidate(candidates) -> ConsolidationResult
│   │   ├── decay_engine.rs             # IDecayEngine — calculate(memory) -> f64
│   │   ├── validator.rs                # IValidator — validate(memory) -> ValidationResult
│   │   ├── compressor.rs               # ICompressor — compress(memory, level) -> CompressedMemory
│   │   ├── sanitizer.rs                # ISanitizer — sanitize(text) -> SanitizedText
│   │   ├── predictor.rs                # IPredictor — predict(signals) -> Vec<PredictedMemory>
│   │   ├── learner.rs                  # ILearner — analyze(correction) -> LearningResult
│   │   └── health_reporter.rs          # IHealthReporter — report() -> HealthReport
│   │
│   ├── errors/
│   │   ├── mod.rs                      # Re-exports, From impls, error conversion
│   │   ├── cortex_error.rs             # Top-level CortexError enum — all error variants:
│   │   │                               #   MemoryNotFound, InvalidType, EmbeddingError,
│   │   │                               #   StorageError, CausalCycle, TokenBudgetExceeded,
│   │   │                               #   MigrationError, SanitizationError,
│   │   │                               #   ConsolidationError, ValidationError,
│   │   │                               #   SerializationError, ConcurrencyError,
│   │   │                               #   CloudSyncError, ConfigError, DegradedMode
│   │   ├── storage_error.rs            # StorageError — SqliteError, MigrationFailed,
│   │   │                               #   CorruptionDetected, ConnectionPoolExhausted
│   │   ├── embedding_error.rs          # EmbeddingError — ModelLoadFailed, InferenceFailed,
│   │   │                               #   DimensionMismatch, ProviderUnavailable, CacheMiss
│   │   ├── retrieval_error.rs          # RetrievalError — BudgetExceeded, NoResults,
│   │   │                               #   SearchFailed, RankingFailed
│   │   ├── causal_error.rs             # CausalError — CycleDetected, TraversalDepthExceeded,
│   │   │                               #   InvalidRelation, GraphInconsistency
│   │   ├── consolidation_error.rs      # ConsolidationError — ClusteringFailed, RecallGateFailed,
│   │   │                               #   MergeFailed, QualityBelowThreshold
│   │   └── cloud_error.rs              # CloudError — AuthFailed, SyncConflict, NetworkError,
│   │                                   #   QuotaExceeded, VersionMismatch
│   │
│   ├── config/
│   │   ├── mod.rs                      # CortexConfig — top-level config struct
│   │   ├── storage_config.rs           # DB path, WAL mode, mmap size, cache size, pragmas
│   │   ├── embedding_config.rs         # Provider selection, model path, dimensions,
│   │   │                               #   matryoshka dims, batch size, cache sizes
│   │   ├── retrieval_config.rs         # Default budget, RRF k-value, re-rank top-K,
│   │   │                               #   intent weights path, query expansion toggle
│   │   ├── consolidation_config.rs     # Min cluster size, similarity threshold,
│   │   │                               #   novelty threshold, recall gate params,
│   │   │                               #   scheduling intervals, LLM polish toggle
│   │   ├── decay_config.rs             # Half-life overrides, adaptive factors,
│   │   │                               #   archival threshold, processing interval
│   │   ├── privacy_config.rs           # Pattern overrides, NER toggle, context scoring
│   │   ├── cloud_config.rs             # Endpoint URL, auth method, sync interval,
│   │   │                               #   conflict resolution strategy, offline mode
│   │   ├── observability_config.rs     # Metrics export interval, log level,
│   │   │                               #   tracing toggle, health check interval
│   │   └── defaults.rs                 # All default values as constants
│   │
│   ├── constants.rs                    # Global constants — version, magic numbers,
│   │                                   #   default thresholds, feature flags
│   │
│   ├── intent/
│   │   ├── mod.rs                      # Intent enum (18 variants) + classification
│   │   ├── taxonomy.rs                 # Domain-agnostic: create, investigate, decide,
│   │   │                               #   recall, learn, summarize, compare
│   │   │                               # Code-specific: add_feature, fix_bug, refactor,
│   │   │                               #   security_audit, understand_code, add_test,
│   │   │                               #   review_code, deploy, migrate
│   │   │                               # Universal: spawn_agent, execute_workflow, track_progress
│   │   └── weights.rs                  # Intent → MemoryType boost matrix
│   │                                   #   Configurable via TOML, with defaults
│   │
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


---

## 2. cortex-storage — SQLite Persistence, Migrations, Audit

The data layer. Owns cortex.db. Implements IMemoryStorage and ICausalStorage. Single write connection + read pool (CX20).

```
crates/cortex/cortex-storage/
├── Cargo.toml                          # Deps: rusqlite (bundled), serde, serde_json,
│                                       #   chrono, uuid, cortex-core
├── src/
│   ├── lib.rs                          # Re-exports, StorageEngine init
│   │
│   ├── engine.rs                       # StorageEngine — owns ConnectionPool,
│   │                                   #   implements IMemoryStorage + ICausalStorage,
│   │                                   #   startup pragma configuration, shutdown cleanup
│   │
│   ├── pool/
│   │   ├── mod.rs                      # ConnectionPool — manages read/write connections
│   │   ├── write_connection.rs         # Single write connection behind tokio::sync::Mutex
│   │   │                               #   Serialized writes, no contention
│   │   ├── read_pool.rs               # Pool of 4-8 read connections (concurrent)
│   │   │                               #   Never blocked by writer (WAL mode)
│   │   └── pragmas.rs                  # PRAGMA configuration per connection:
│   │                                   #   journal_mode=WAL, synchronous=NORMAL,
│   │                                   #   mmap_size=256MB, cache_size=64MB,
│   │                                   #   busy_timeout=5000, foreign_keys=ON,
│   │                                   #   auto_vacuum=INCREMENTAL
│   │
│   ├── migrations/
│   │   ├── mod.rs                      # Migration runner — version tracking,
│   │   │                               #   forward-only, transactional per migration
│   │   ├── v001_initial_schema.rs      # Core tables: memories, memory_relationships,
│   │   │                               #   memory_patterns, memory_constraints,
│   │   │                               #   memory_files, memory_functions,
│   │   │                               #   schema_version
│   │   ├── v002_vector_tables.rs       # sqlite-vec virtual table: memory_embeddings,
│   │   │                               #   memory_embedding_link
│   │   ├── v003_fts5_index.rs          # FTS5 virtual table on content + summary + tags
│   │   ├── v004_causal_tables.rs       # causal_edges, causal_evidence
│   │   ├── v005_session_tables.rs      # session_contexts, session_analytics
│   │   ├── v006_audit_tables.rs        # memory_audit_log, consolidation_metrics,
│   │   │                               #   degradation_log
│   │   ├── v007_validation_tables.rs   # memory_validation_history, memory_contradictions
│   │   ├── v008_versioning_tables.rs   # memory_versions (content evolution tracking)
│   │   ├── v009_embedding_migration.rs # embedding_model_info, model_version column
│   │   ├── v010_cloud_sync.rs          # sync_log, sync_state, conflict_log
│   │   ├── v011_reclassification.rs    # reclassification_history, reclassification_signals
│   │   └── v012_observability.rs       # metric_snapshots, query_performance_log
│   │
│   ├── queries/
│   │   ├── mod.rs                      # Query builder helpers
│   │   ├── memory_crud.rs              # Insert, update, get, delete, bulk ops
│   │   ├── memory_query.rs             # By type, pattern, constraint, file, function,
│   │   │                               #   importance, confidence range, date range
│   │   ├── memory_search.rs            # FTS5 full-text search queries
│   │   ├── vector_search.rs            # sqlite-vec similarity search queries
│   │   ├── relationship_ops.rs         # Relationship CRUD, strength updates
│   │   ├── link_ops.rs                 # Pattern/constraint/file/function link CRUD
│   │   ├── causal_ops.rs              # Causal edge CRUD, evidence management
│   │   ├── audit_ops.rs               # Audit log insert, query by memory/time/actor
│   │   ├── session_ops.rs             # Session CRUD, analytics aggregation
│   │   ├── version_ops.rs             # Memory version insert, query, rollback
│   │   ├── aggregation.rs             # Count by type, avg confidence, stale count,
│   │   │                               #   storage stats, growth rate
│   │   └── maintenance.rs             # VACUUM, checkpoint, integrity check,
│   │                                   #   archived cleanup, audit rotation
│   │
│   ├── audit/
│   │   ├── mod.rs                      # AuditLogger — append-only mutation log
│   │   ├── logger.rs                   # Log every memory mutation: create, update,
│   │   │                               #   archive, restore, link, unlink, decay,
│   │   │                               #   validate, consolidate, reclassify
│   │   │                               #   Fields: memory_id, operation, details (JSON),
│   │   │                               #   actor (system|user|consolidation|decay|
│   │   │                               #   validation|learning|reclassification), timestamp
│   │   └── rotation.rs                # Monthly rotation: entries > 1 year compressed
│   │                                   #   into monthly summary records
│   │
│   ├── compaction/
│   │   ├── mod.rs                      # Compaction orchestrator
│   │   ├── archived_cleanup.rs         # Memories archived > 90 days, confidence < 0.1,
│   │   │                               #   zero access → permanent delete (keep tombstone)
│   │   ├── incremental_vacuum.rs       # Weekly: PRAGMA incremental_vacuum(1000)
│   │   ├── full_vacuum.rs              # Quarterly: only if fragmentation > 30%
│   │   ├── embedding_dedup.rs          # Share embedding rows for identical content hashes
│   │   └── storage_health.rs           # DB file size, active vs archived count,
│   │                                   #   embedding storage size, FTS5 index size,
│   │                                   #   fragmentation %, projected growth rate,
│   │                                   #   time-to-threshold estimates
│   │
│   └── recovery/
│       ├── mod.rs                      # Recovery orchestrator (CX18 degradation)
│       ├── wal_recovery.rs             # Attempt WAL checkpoint recovery on corruption
│       ├── backup.rs                   # Periodic backup creation + restore from backup
│       ├── fts5_rebuild.rs             # Rebuild FTS5 index from memory content
│       └── integrity_check.rs          # PRAGMA integrity_check, detect corruption early
```


---

## 3. cortex-embeddings — ONNX Providers, Cache, Enrichment

Owns all embedding generation. Multi-provider with 3-tier cache. Matryoshka support for dimension truncation.

```
crates/cortex/cortex-embeddings/
├── Cargo.toml                          # Deps: ort, moka, blake3, cortex-core
├── src/
│   ├── lib.rs                          # Re-exports, EmbeddingEngine init
│   │
│   ├── engine.rs                       # EmbeddingEngine — provider selection,
│   │                                   #   fallback chain, cache coordination,
│   │                                   #   implements IEmbeddingProvider
│   │
│   ├── providers/
│   │   ├── mod.rs                      # Provider registry + auto-detection
│   │   ├── onnx_provider.rs            # OnnxProvider — loads ONNX models via `ort`
│   │   │                               #   Default: Jina Code v2 (1024-dim)
│   │   │                               #   Supports quantized INT8 models
│   │   │                               #   Batch inference with padding
│   │   ├── api_provider.rs             # ApiProvider — HTTP client for cloud APIs
│   │   │                               #   Codestral Embed (Mistral) — SOTA
│   │   │                               #   VoyageCode3 — fallback
│   │   │                               #   OpenAI text-embedding-3-large — general
│   │   │                               #   Rate limiting, retry with backoff
│   │   ├── ollama_provider.rs          # OllamaProvider — local Ollama instance
│   │   │                               #   Configurable model, health check
│   │   └── tfidf_fallback.rs           # TfIdfFallback — sparse vector generation
│   │                                   #   For air-gapped environments with no ML runtime
│   │                                   #   No external dependencies
│   │
│   ├── cache/
│   │   ├── mod.rs                      # CacheCoordinator — L1/L2/L3 orchestration
│   │   ├── l1_memory.rs                # L1: moka::sync::Cache — in-process,
│   │   │                               #   size-aware eviction (embeddings are large),
│   │   │                               #   TinyLFU admission, per-entry TTL
│   │   ├── l2_sqlite.rs                # L2: SQLite table — content_hash → embedding,
│   │   │                               #   survives restarts, millisecond access
│   │   └── l3_precomputed.rs           # L3: Memory-mapped precomputed embeddings
│   │                                   #   for frequently-accessed content,
│   │                                   #   loaded at startup, zero-latency
│   │
│   ├── enrichment.rs                   # Embedding enrichment — prepend structured
│   │                                   #   metadata before embedding generation:
│   │                                   #   [{type}|{importance}|{category}] {summary}
│   │                                   #   Files: {linkedFiles}
│   │                                   #   Patterns: {linkedPatterns}
│   │
│   ├── matryoshka.rs                   # Matryoshka dimension management:
│   │                                   #   Store full dims (1024/2048)
│   │                                   #   Truncate to 384/256 for fast search
│   │                                   #   Full dims for re-ranking
│   │                                   #   Dimension validation + conversion
│   │
│   ├── migration/
│   │   ├── mod.rs                      # EmbeddingMigration orchestrator (CX19)
│   │   ├── detector.rs                 # Detect model change on startup:
│   │   │                               #   compare configured model vs embedding_model_info
│   │   ├── worker.rs                   # Background re-embedding worker:
│   │   │                               #   Batch size 50, 100ms throttle between batches,
│   │   │                               #   priority: high-importance + frequently-accessed first,
│   │   │                               #   resumable via model_version column
│   │   └── progress.rs                 # Migration progress tracking:
│   │                                   #   total, completed, remaining, ETA,
│   │                                   #   status (pending|in_progress|complete)
│   │
│   └── degradation.rs                  # Fallback chain (CX18):
│                                       #   ONNX → fallback model → cached embeddings
│                                       #   → TF-IDF sparse vectors → error
│                                       #   Every fallback logged to degradation_log
```

---

## 4. cortex-retrieval — Hybrid Search, RRF, Re-Ranking, Intent

The query engine. Two-stage pipeline: fast candidate gathering → precise re-ranking. Hybrid search (FTS5 + sqlite-vec + RRF).

```
crates/cortex/cortex-retrieval/
├── Cargo.toml                          # Deps: cortex-core, cortex-storage,
│                                       #   cortex-embeddings, cortex-compression
├── src/
│   ├── lib.rs                          # Re-exports, RetrievalEngine init
│   │
│   ├── engine.rs                       # RetrievalEngine — implements IRetriever
│   │                                   #   Orchestrates the full 2-stage pipeline
│   │
│   ├── search/
│   │   ├── mod.rs                      # HybridSearcher — coordinates FTS5 + vec + RRF
│   │   ├── fts5_search.rs              # FTS5 full-text search — keyword matching,
│   │   │                               #   BM25 scoring, snippet extraction
│   │   ├── vector_search.rs            # sqlite-vec similarity search — cosine distance,
│   │   │                               #   pre-filter by type/importance,
│   │   │                               #   Matryoshka truncated dims for speed
│   │   ├── rrf_fusion.rs               # Reciprocal Rank Fusion:
│   │   │                               #   score = Σ 1/(k + rank_i), k=60
│   │   │                               #   Combines FTS5 + vector results
│   │   │                               #   No score normalization needed
│   │   └── entity_search.rs            # Linked entity expansion — find candidates
│   │                                   #   by shared patterns, files, functions
│   │
│   ├── ranking/
│   │   ├── mod.rs                      # RankingPipeline — multi-factor scoring
│   │   ├── scorer.rs                   # Multi-factor relevance scorer:
│   │   │                               #   semantic_similarity, keyword_match,
│   │   │                               #   file_proximity, pattern_alignment,
│   │   │                               #   recency, confidence, importance,
│   │   │                               #   intent_type_match
│   │   │                               #   Configurable weights per factor
│   │   ├── reranker.rs                 # Cross-encoder re-ranking (CX6):
│   │   │                               #   Optional ONNX cross-encoder model
│   │   │                               #   Scores each candidate against query
│   │   │                               #   Falls back to scorer if unavailable
│   │   └── deduplication.rs            # Session-aware deduplication:
│   │                                   #   Skip already-sent memories
│   │                                   #   Merge duplicate candidates from
│   │                                   #   multiple search paths
│   │
│   ├── intent/
│   │   ├── mod.rs                      # IntentEngine — classification + weighting
│   │   ├── classifier.rs               # Intent classification from query context:
│   │   │                               #   keyword matching, file type heuristics,
│   │   │                               #   recent action patterns
│   │   └── weight_matrix.rs            # Intent → MemoryType boost matrix
│   │                                   #   Loaded from TOML config (CX23 intents)
│   │                                   #   Default weights hardcoded as fallback
│   │
│   ├── expansion/
│   │   ├── mod.rs                      # QueryExpander — generates query variants
│   │   ├── synonym_expander.rs         # Synonym/related term expansion
│   │   │                               #   Code-aware: "auth" → "authentication middleware"
│   │   └── hyde.rs                     # Hypothetical Document Embedding (CX13):
│   │                                   #   Generate hypothetical answer, embed that
│   │                                   #   Optional — requires LLM or template
│   │
│   └── budget/
│       ├── mod.rs                      # BudgetManager — token budget orchestration
│       └── packer.rs                   # Priority-weighted bin-packing:
│                                       #   Sort by importance × relevance_score
│                                       #   Try Level 3→2→1→0 until fits
│                                       #   Critical memories always ≥ Level 1
│                                       #   Accurate token counts (not estimates)
```


---

## 5. cortex-causal — petgraph, Inference, Traversal, Narrative

The "why" engine. Maintains an in-memory DAG synced with SQLite. Causal inference, traversal, counterfactual queries, and human-readable narrative generation.

```
crates/cortex/cortex-causal/
├── Cargo.toml                          # Deps: petgraph, cortex-core, cortex-storage
├── src/
│   ├── lib.rs                          # Re-exports, CausalEngine init
│   │
│   ├── engine.rs                       # CausalEngine — owns the graph,
│   │                                   #   coordinates inference + traversal + narrative,
│   │                                   #   syncs in-memory graph ↔ SQLite
│   │
│   ├── graph/
│   │   ├── mod.rs                      # GraphManager — Arc<RwLock<StableGraph>>
│   │   ├── stable_graph.rs             # petgraph::StableGraph<CausalNode, CausalEdge>
│   │   │                               #   Handles frequent add/remove of edges
│   │   │                               #   CausalNode: memory_id, type, summary
│   │   │                               #   CausalEdge: relation, strength, evidence[], inferred
│   │   ├── dag_enforcement.rs          # DAG constraint — cycle detection before
│   │   │                               #   every edge insertion (Tarjan's SCC)
│   │   │                               #   Reject edge if cycle would be created
│   │   ├── sync.rs                     # Bidirectional sync: graph ↔ causal_edges table
│   │   │                               #   Rebuild graph from SQLite on startup
│   │   │                               #   Persist graph changes to SQLite on mutation
│   │   └── pruning.rs                  # Prune weak edges (strength < 0.2)
│   │                                   #   Prune old unvalidated edges
│   │                                   #   Periodic cleanup to prevent unbounded growth
│   │
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
│   │   └── scorer.rs                   # Composite causal strength scoring
│   │                                   #   Weighted sum of strategy scores
│   │                                   #   Threshold for edge creation (configurable)
│   │
│   ├── traversal/
│   │   ├── mod.rs                      # TraversalEngine — graph walking
│   │   ├── trace_origins.rs            # Backward traversal — "what caused this?"
│   │   ├── trace_effects.rs            # Forward traversal — "what did this cause?"
│   │   ├── bidirectional.rs            # Union of forward + backward
│   │   ├── neighbors.rs               # Direct neighbors (depth=1)
│   │   ├── counterfactual.rs           # "What if we hadn't adopted pattern X?"
│   │   │                               #   Traverse from pattern's linked memories,
│   │   │                               #   identify all downstream effects
│   │   └── intervention.rs             # "If we change convention X, what needs updating?"
│   │                                   #   Identify all causally dependent memories
│   │
│   ├── narrative/
│   │   ├── mod.rs                      # NarrativeGenerator — human-readable "why"
│   │   ├── builder.rs                  # Template-based narrative construction:
│   │   │                               #   Sections: Origins, Effects, Support, Conflicts
│   │   │                               #   Summary, key points, confidence score
│   │   │                               #   Evidence references per claim
│   │   ├── templates.rs                # Narrative templates per relation type
│   │   │                               #   "X was caused by Y because..."
│   │   │                               #   "This decision led to..."
│   │   │                               #   "Warning: this contradicts..."
│   │   └── confidence.rs               # Chain confidence calculation:
│   │                                   #   60% min edge strength + 40% average
│   │                                   #   Depth penalty for long chains
│   │
│   └── relations.rs                    # 8 relation types with semantics:
│                                       #   caused, enabled, prevented, contradicts,
│                                       #   supersedes, supports, derived_from, triggered_by
│                                       #   Strength scoring, evidence requirements
```

---

## 6. cortex-learning — Correction Analysis, Principle Extraction

Learns from user corrections. Analyzes diffs, categorizes corrections, extracts reusable principles, creates new memories.

```
crates/cortex/cortex-learning/
├── Cargo.toml                          # Deps: cortex-core, cortex-storage,
│                                       #   cortex-embeddings, cortex-causal
├── src/
│   ├── lib.rs                          # Re-exports, LearningEngine init
│   │
│   ├── engine.rs                       # LearningEngine — implements ILearner
│   │                                   #   Orchestrates the full learning pipeline
│   │
│   ├── analysis/
│   │   ├── mod.rs                      # CorrectionAnalyzer — entry point
│   │   ├── diff_analyzer.rs            # Compare original vs corrected code:
│   │   │                               #   additions, removals, modifications,
│   │   │                               #   semantic changes (not just text diff)
│   │   ├── categorizer.rs              # 10 correction categories:
│   │   │                               #   pattern_violation, tribal_miss,
│   │   │                               #   constraint_violation, style_preference,
│   │   │                               #   naming_convention, architecture_mismatch,
│   │   │                               #   security_issue, performance_issue,
│   │   │                               #   api_misuse, other
│   │   │                               #   Keyword matching + pattern heuristics
│   │   └── category_mapping.rs         # Category → MemoryType mapping:
│   │                                   #   pattern_violation → pattern_rationale
│   │                                   #   tribal_miss → tribal
│   │                                   #   security_issue → tribal (critical)
│   │                                   #   performance_issue → code_smell
│   │                                   #   etc.
│   │
│   ├── extraction/
│   │   ├── mod.rs                      # PrincipleExtractor — generalize corrections
│   │   ├── rule_based.rs               # Rule-based extraction for offline:
│   │   │                               #   keyword matching, pattern templates,
│   │   │                               #   negation detection, generalization rules
│   │   └── llm_enhanced.rs             # Optional LLM-assisted extraction:
│   │                                   #   Higher quality principle extraction
│   │                                   #   Only when API key configured
│   │                                   #   Falls back to rule_based if unavailable
│   │
│   ├── deduplication.rs                # Mem0-inspired dedup before storage:
│   │                                   #   Check existing memories with high similarity
│   │                                   #   Decision: ADD, UPDATE, or NOOP
│   │                                   #   Prevents memory bloat from repeated corrections
│   │
│   ├── calibration.rs                  # Confidence calibration — 5 factors:
│   │                                   #   base, evidence, usage, temporal, validation
│   │                                   #   Adjusts confidence based on correction history
│   │
│   └── active_learning/
│       ├── mod.rs                      # ActiveLearningLoop — identifies uncertain memories
│       ├── candidate_selector.rs       # Select validation candidates:
│       │                               #   low confidence + high importance,
│       │                               #   old + never validated,
│       │                               #   contradicted but unresolved
│       │                               #   Priority: frequently retrieved + uncertain
│       ├── prompt_generator.rs         # Generate validation prompts for user
│       └── feedback_processor.rs       # Process user feedback: confirm/reject/modify
│                                       #   Update confidence based on response
```


---

## 7. cortex-decay — Decay Calculation, Adaptive Half-Lives

Confidence decay modeling. Multi-factor formula with per-memory adaptive half-lives.

```
crates/cortex/cortex-decay/
├── Cargo.toml                          # Deps: cortex-core (lightweight crate)
├── src/
│   ├── lib.rs                          # Re-exports, DecayEngine init
│   │
│   ├── engine.rs                       # DecayEngine — implements IDecayEngine
│   │                                   #   Processes all memories, applies decay,
│   │                                   #   triggers archival when below threshold
│   │
│   ├── formula.rs                      # 5-factor decay formula:
│   │                                   #   finalConfidence = baseConfidence
│   │                                   #     × temporalDecay
│   │                                   #     × citationDecay
│   │                                   #     × usageBoost
│   │                                   #     × importanceAnchor
│   │                                   #     × patternBoost
│   │
│   ├── factors/
│   │   ├── mod.rs                      # Factor trait + registry
│   │   ├── temporal.rs                 # e^(-daysSinceAccess / halfLife)
│   │   │                               #   Exponential, type-specific half-lives
│   │   ├── citation.rs                 # Content hash comparison — stale citations
│   │   │                               #   reduce confidence
│   │   ├── usage.rs                    # min(1.5, 1 + log10(accessCount + 1) × 0.2)
│   │   │                               #   Capped at 1.5×
│   │   ├── importance.rs               # critical=2.0×, high=1.5×, normal=1.0×, low=0.8×
│   │   └── pattern.rs                  # Linked to active patterns = 1.3×, else 1.0×
│   │
│   ├── adaptive.rs                     # Per-memory adaptive half-lives (CX8/R8):
│   │                                   #   adaptiveHalfLife = baseHalfLife
│   │                                   #     × accessFrequencyFactor (1.0-2.0×)
│   │                                   #     × validationFactor (1.0-1.5×)
│   │                                   #     × linkageFactor (1.0-1.3×)
│   │                                   #   Frequently accessed + validated + linked
│   │                                   #   memories decay much slower
│   │
│   └── archival.rs                     # Archival logic — when confidence drops
│                                       #   below type-specific minimum threshold,
│                                       #   memory is eligible for archival
│                                       #   Audit log entry on every archival
```

---

## 8. cortex-validation — 4-Dimension Validation, Healing

Periodic validation across 4 dimensions with automatic healing strategies.

```
crates/cortex/cortex-validation/
├── Cargo.toml                          # Deps: cortex-core, cortex-storage,
│                                       #   cortex-embeddings
├── src/
│   ├── lib.rs                          # Re-exports, ValidationEngine init
│   │
│   ├── engine.rs                       # ValidationEngine — implements IValidator
│   │                                   #   Runs all 4 dimensions, aggregates results,
│   │                                   #   triggers healing actions
│   │
│   ├── dimensions/
│   │   ├── mod.rs                      # Dimension trait + runner
│   │   ├── citation.rs                 # Citation validation:
│   │   │                               #   File existence check
│   │   │                               #   Content hash drift detection
│   │   │                               #   Line number validity
│   │   │                               #   Git rename detection → auto-update citation
│   │   ├── temporal.rs                 # Temporal validation:
│   │   │                               #   validUntil expiry check
│   │   │                               #   Code version change detection (git)
│   │   │                               #   Age vs expected lifetime
│   │   ├── contradiction.rs            # Contradiction validation:
│   │   │                               #   Run contradiction detector
│   │   │                               #   Check consensus support
│   │   │                               #   Consensus memories resist single contradictions
│   │   └── pattern_alignment.rs        # Pattern alignment:
│   │                                   #   Linked patterns still exist?
│   │                                   #   Pattern confidence changed significantly?
│   │                                   #   Pattern removed → flag linked memories
│   │
│   ├── contradiction/
│   │   ├── mod.rs                      # ContradictionDetector — multi-strategy
│   │   ├── detection/
│   │   │   ├── mod.rs                  # Detection strategy registry
│   │   │   ├── semantic.rs             # Embedding similarity + negation patterns
│   │   │   ├── absolute_statement.rs   # "always"/"never" conflict detection
│   │   │   ├── temporal_supersession.rs # Newer memory supersedes older on same topic
│   │   │   ├── feedback.rs             # Feedback contradictions
│   │   │   └── cross_pattern.rs        # Same pattern, opposing content
│   │   │
│   │   ├── propagation.rs              # Graph-based confidence propagation:
│   │   │                               #   Direct contradiction: -0.3
│   │   │                               #   Partial: -0.15
│   │   │                               #   Supersession: -0.5
│   │   │                               #   Confirmation: +0.1
│   │   │                               #   Consensus (≥3): +0.2
│   │   │                               #   Propagation factor: 0.5×
│   │   │                               #   BFS through petgraph (O(V+E))
│   │   │
│   │   └── consensus.rs                # Consensus detection:
│   │                                   #   ≥3 memories supporting same conclusion
│   │                                   #   Boost all +0.2, mark as consensus
│   │                                   #   Consensus resists single contradictions
│   │
│   └── healing/
│       ├── mod.rs                      # HealingEngine — strategy selection
│       ├── confidence_adjust.rs        # Adjust confidence based on validation score
│       ├── citation_update.rs          # Auto-update citations via git rename detection
│       ├── embedding_refresh.rs        # Re-embed memories whose context changed
│       ├── archival.rs                 # Archive with reason tracking
│       └── flagging.rs                 # Flag for human review when auto-fix isn't safe
```

---

## 9. cortex-compression — 4-Level Compression, Token Budgeting

Hierarchical compression for token-efficient retrieval. 4 levels from IDs-only to full context.

```
crates/cortex/cortex-compression/
├── Cargo.toml                          # Deps: cortex-core
├── src/
│   ├── lib.rs                          # Re-exports
│   │
│   ├── engine.rs                       # CompressionEngine — implements ICompressor
│   │                                   #   compress(memory, level) → CompressedMemory
│   │                                   #   compressToFit(memory, maxTokens) → CompressedMemory
│   │                                   #   compressBatchToFit(memories[], budget) → Vec<CompressedMemory>
│   │
│   ├── levels/
│   │   ├── mod.rs                      # Level enum + dispatch
│   │   ├── level0.rs                   # IDs only — ~5 tokens, max 10
│   │   ├── level1.rs                   # One-liners + tags — ~50 tokens, max 75
│   │   ├── level2.rs                   # With examples + evidence — ~200 tokens, max 300
│   │   └── level3.rs                   # Full context + causal + links — ~500 tokens, max 1000
│   │
│   └── packing.rs                      # Priority-weighted bin-packing:
│                                       #   Sort by importance × relevance_score (desc)
│                                       #   For each: try L3→2→1→0 until fits
│                                       #   Critical memories always ≥ L1
│                                       #   Track actual token counts via cortex-core TokenCounter
```


---

## 10. cortex-prediction — Signal Gathering, 4 Strategies, Cache

Predictive memory preloading. Anticipates what memories will be needed based on file, pattern, temporal, and behavioral signals.

```
crates/cortex/cortex-prediction/
├── Cargo.toml                          # Deps: cortex-core, cortex-storage, moka
├── src/
│   ├── lib.rs                          # Re-exports, PredictionEngine init
│   │
│   ├── engine.rs                       # PredictionEngine — implements IPredictor
│   │                                   #   Coordinates all strategies, deduplicates,
│   │                                   #   manages prediction cache
│   │
│   ├── signals/
│   │   ├── mod.rs                      # Signal types + gathering
│   │   ├── file_signals.rs             # Active file, imports, symbols, directory
│   │   ├── temporal_signals.rs         # Time of day, day of week, session duration
│   │   ├── behavioral_signals.rs       # Recent queries, intents, frequent memories
│   │   └── git_signals.rs              # Branch name, modified files, commit messages
│   │                                   #   Feature branch → predict domain memories
│   │
│   ├── strategies/
│   │   ├── mod.rs                      # Strategy trait + multi-strategy dedup
│   │   │                               #   Duplicate across strategies: keep highest
│   │   │                               #   confidence + merge signals + boost +0.05
│   │   ├── file_based.rs               # Memories linked to active file + imports
│   │   ├── pattern_based.rs            # Memories linked to detected patterns
│   │   ├── temporal.rs                 # Time-of-day and day-of-week usage patterns
│   │   └── behavioral.rs              # Recent queries, intents, frequent memories
│   │
│   ├── cache.rs                        # Prediction cache — moka::sync::Cache
│   │                                   #   Adaptive TTL based on file change frequency
│   │                                   #   (rapidly changing files → shorter TTL)
│   │                                   #   Tracks: hits, misses, hit rate, avg prediction time
│   │                                   #   Invalidated on file change or new session
│   │                                   #   First to evict under memory pressure (CX18)
│   │
│   └── precompute.rs                   # Pre-compute hybrid search results for
│                                       #   predicted memories so retrieval is instant
│                                       #   Triggered on file change events
```

---

## 11. cortex-session — Session Management, Deduplication

Tracks loaded context per conversation. Prevents re-sending memories. Token efficiency tracking.

```
crates/cortex/cortex-session/
├── Cargo.toml                          # Deps: cortex-core, dashmap
├── src/
│   ├── lib.rs                          # Re-exports, SessionManager init
│   │
│   ├── manager.rs                      # SessionManager — Arc<DashMap<SessionId, SessionContext>>
│   │                                   #   Concurrent per-session access
│   │                                   #   DashMap provides fine-grained locking per key
│   │
│   ├── context.rs                      # SessionContext — loaded sets:
│   │                                   #   loadedMemories, loadedPatterns,
│   │                                   #   loadedFiles, loadedConstraints
│   │                                   #   Token tracking: tokensSent, queriesMade
│   │
│   ├── deduplication.rs                # Session-aware deduplication:
│   │                                   #   Filter out already-sent memories
│   │                                   #   Mark duplicates with alreadySent flag
│   │                                   #   30-50% token savings
│   │
│   ├── analytics.rs                    # Session analytics aggregation:
│   │                                   #   Most frequently retrieved memories
│   │                                   #   Least useful memories
│   │                                   #   Intent distribution
│   │                                   #   Average retrieval latency by intent
│   │
│   ├── efficiency.rs                   # Token efficiency metrics per session:
│   │                                   #   tokens_sent, tokens_useful,
│   │                                   #   efficiency_ratio (useful/sent),
│   │                                   #   deduplication_savings
│   │
│   └── cleanup.rs                      # Session lifecycle:
│   │                                   #   Inactivity timeout, max duration,
│   │                                   #   max tokens per session
│   │                                   #   Delete sessions older than retention (7 days)
```

---

## 12. cortex-privacy — PII/Secret Sanitization (50+ Patterns)

Privacy-first. Sanitizes all content before storage or transmission. 50+ patterns organized by category.

```
crates/cortex/cortex-privacy/
├── Cargo.toml                          # Deps: cortex-core, regex
├── src/
│   ├── lib.rs                          # Re-exports, PrivacyEngine init
│   │
│   ├── engine.rs                       # PrivacyEngine — implements ISanitizer
│   │                                   #   Runs all pattern categories
│   │                                   #   Context-aware scoring
│   │                                   #   Idempotent (sanitizing twice = once)
│   │
│   ├── patterns/
│   │   ├── mod.rs                      # Pattern registry + category dispatch
│   │   ├── pii.rs                      # 15+ PII patterns:
│   │   │                               #   email, phone, SSN, credit card, IP address,
│   │   │                               #   passport, driver's license, date of birth,
│   │   │                               #   physical address, national ID
│   │   │                               #   Replacements: [EMAIL], [PHONE], [SSN], etc.
│   │   │
│   │   ├── secrets.rs                  # 35+ secret patterns:
│   │   │                               #   API keys, AWS keys (AKIA...), JWT tokens,
│   │   │                               #   private keys (PEM), passwords,
│   │   │                               #   Azure keys, GCP service accounts,
│   │   │                               #   GitHub tokens (ghp_, gho_, ghs_),
│   │   │                               #   GitLab tokens (glpat-), npm tokens,
│   │   │                               #   PyPI tokens, Slack tokens (xoxb-, xoxp-),
│   │   │                               #   Stripe keys (sk_live_, pk_live_),
│   │   │                               #   Twilio, SendGrid, Heroku, DigitalOcean,
│   │   │                               #   Datadog API keys
│   │   │
│   │   └── connection_strings.rs       # Connection string patterns:
│   │                                   #   PostgreSQL, MySQL, MongoDB, Redis URLs
│   │                                   #   with embedded credentials
│   │                                   #   Base64-encoded secrets
│   │
│   ├── context_scoring.rs              # Context-aware confidence adjustment:
│   │                                   #   In test file: -0.20
│   │                                   #   In comment: -0.30
│   │                                   #   In .env file: +0.10
│   │                                   #   Placeholder detected: skip entirely
│   │                                   #   Sensitive variable name: +0.10
│   │
│   └── degradation.rs                  # Graceful degradation (CX18):
│                                       #   If regex compilation fails for a pattern,
│                                       #   skip that pattern, log warning,
│                                       #   continue with remaining patterns
│                                       #   Audit log records the gap
```


---

## 13. cortex-consolidation — HDBSCAN Pipeline, Quality Monitoring

The algorithmic consolidation engine. Fully offline, deterministic, auditable. No LLM required. This is the core differentiator.

```
crates/cortex/cortex-consolidation/
├── Cargo.toml                          # Deps: cortex-core, cortex-storage,
│                                       #   cortex-embeddings, hdbscan, rayon
├── src/
│   ├── lib.rs                          # Re-exports, ConsolidationEngine init
│   │
│   ├── engine.rs                       # ConsolidationEngine — implements IConsolidator
│   │                                   #   Orchestrates the 6-phase pipeline
│   │                                   #   Arc<AtomicBool> is_running guard
│   │                                   #   (only one consolidation at a time)
│   │
│   ├── pipeline/
│   │   ├── mod.rs                      # Pipeline orchestrator — phase sequencing
│   │   │
│   │   ├── phase1_selection.rs         # Candidate selection:
│   │   │                               #   Episodic memories, age > 7 days,
│   │   │                               #   status = pending, confidence > 0.3
│   │   │                               #   Filter out already consolidated/archived
│   │   │
│   │   ├── phase2_clustering.rs        # HDBSCAN clustering on composite similarity:
│   │   │                               #   Embedding cosine similarity (weight 0.5)
│   │   │                               #   Shared linked files (weight 0.2)
│   │   │                               #   Shared linked patterns (weight 0.15)
│   │   │                               #   Shared linked functions (weight 0.1)
│   │   │                               #   Shared tags (weight 0.05)
│   │   │                               #   Min cluster size = 2
│   │   │                               #   Noise points deferred (not lost)
│   │   │
│   │   ├── phase3_recall_gate.rs       # Recall gate — quality check before consolidation:
│   │   │                               #   Extract top-3 TF-IDF key phrases per cluster
│   │   │                               #   Query embedding index with key phrases
│   │   │                               #   Episodes must rank top-10 for ≥2/3 queries
│   │   │                               #   Fail → refresh embeddings → re-test
│   │   │                               #   Still fail → defer + flag for review
│   │   │
│   │   ├── phase4_abstraction.rs       # Algorithmic abstraction:
│   │   │                               #   Step 1: Anchor selection (highest
│   │   │                               #     confidence × importance × log2(accessCount+1))
│   │   │                               #   Step 2: Merge novel sentences
│   │   │                               #     (embedding similarity < 0.85 to anchor)
│   │   │                               #   Step 3: TextRank + TF-IDF summary generation
│   │   │                               #   Step 4: Metadata union (tags, files, patterns,
│   │   │                               #     functions, confidence with cluster boost)
│   │   │
│   │   ├── phase5_integration.rs       # Integration with existing semantic memories:
│   │   │                               #   If new consolidation overlaps (similarity > 0.9)
│   │   │                               #   with existing semantic memory → UPDATE existing
│   │   │                               #   (Mem0-inspired deduplication)
│   │   │                               #   Otherwise → CREATE new semantic memory
│   │   │
│   │   └── phase6_pruning.rs           # Pruning + strengthening:
│   │                                   #   Archive consolidated episodic memories
│   │                                   #   Boost frequently accessed memories
│   │                                   #   Track tokensFreed metric
│   │
│   ├── algorithms/
│   │   ├── mod.rs                      # Algorithm implementations
│   │   ├── textrank.rs                 # TextRank graph — sentences as nodes,
│   │   │                               #   embedding cosine similarity as edges,
│   │   │                               #   PageRank iteration for centrality
│   │   ├── tfidf.rs                    # TF-IDF across cluster — identify distinctive
│   │   │                               #   key phrases (frequent in cluster, rare globally)
│   │   ├── sentence_splitter.rs        # Split content into sentences for
│   │   │                               #   deduplication and TextRank
│   │   └── similarity.rs              # Cosine similarity helpers,
│   │                                   #   novelty threshold (0.85),
│   │                                   #   overlap detection (0.9)
│   │
│   ├── scheduling/
│   │   ├── mod.rs                      # Adaptive scheduler
│   │   ├── triggers.rs                 # Consolidation triggers:
│   │   │                               #   Token pressure (too many episodic memories)
│   │   │                               #   Memory count threshold
│   │   │                               #   Confidence degradation trend
│   │   │                               #   Contradiction density spike
│   │   │                               #   Scheduled fallback (every 6h)
│   │   └── throttle.rs                 # Yield between batches to prevent
│   │                                   #   write-starvation of foreground ops
│   │
│   ├── monitoring/
│   │   ├── mod.rs                      # ConsolidationMonitor (CX15)
│   │   ├── metrics.rs                  # 5 core metrics:
│   │   │                               #   Memory Precision (target ≥ 0.7)
│   │   │                               #   Compression Ratio (target 3:1 to 5:1)
│   │   │                               #   Retrieval Lift (target ≥ 1.5)
│   │   │                               #   Contradiction Rate (target ≤ 0.05)
│   │   │                               #   Stability Score (target ≥ 0.85)
│   │   ├── auto_tuning.rs              # Feedback loop — every 100 events or weekly:
│   │   │                               #   Precision < 0.7 → increase min cluster size,
│   │   │                               #     tighten similarity threshold
│   │   │                               #   Compression > 5:1 → lower novelty threshold
│   │   │                               #   Contradiction > 0.05 → add pre-consolidation
│   │   │                               #     contradiction check
│   │   │                               #   Log all threshold adjustments to audit trail
│   │   └── dashboard.rs                # Surface metrics through observability system
│   │
│   └── llm_polish.rs                   # Optional LLM enhancement:
│                                       #   Take algorithmically consolidated memory
│                                       #   Ask LLM to rephrase into natural language
│                                       #   LLM does NOT do consolidation logic
│                                       #   Track polished vs unpolished retrieval rates
│                                       #   Only available when API key configured
```

---

## 14. cortex-observability — Health, Metrics, Tracing

Enterprise-grade observability. Health checks, performance metrics, degradation tracking, query performance logging.

```
crates/cortex/cortex-observability/
├── Cargo.toml                          # Deps: cortex-core, tracing, tracing-subscriber
├── src/
│   ├── lib.rs                          # Re-exports, ObservabilityEngine init
│   │
│   ├── health/
│   │   ├── mod.rs                      # HealthChecker — implements IHealthReporter
│   │   ├── reporter.rs                 # Aggregate health report:
│   │   │                               #   Total memories by type
│   │   │                               #   Average confidence by type
│   │   │                               #   Stale memory count + trend
│   │   │                               #   Contradiction count + resolution rate
│   │   │                               #   Consolidation frequency + effectiveness
│   │   │                               #   Storage size + growth rate
│   │   │                               #   Embedding cache hit rates (L1/L2/L3)
│   │   │                               #   Retrieval latency percentiles (p50/p95/p99)
│   │   ├── subsystem_checks.rs         # Per-subsystem health checks:
│   │   │                               #   Storage: connection alive, integrity
│   │   │                               #   Embeddings: model loaded, inference working
│   │   │                               #   Causal graph: in-memory ↔ SQLite consistent
│   │   │                               #   Privacy: all patterns compiled
│   │   │                               #   Each returns: healthy|degraded|unavailable
│   │   └── recommendations.rs          # Actionable recommendations:
│   │                                   #   "5 memories need validation"
│   │                                   #   "3 contradictions unresolved"
│   │                                   #   "Consolidation recommended"
│   │                                   #   "Embedding cache cold"
│   │
│   ├── metrics/
│   │   ├── mod.rs                      # MetricsCollector — central metrics registry
│   │   ├── retrieval_metrics.rs        # Per-intent hit rate, token efficiency,
│   │   │                               #   most/least useful memories,
│   │   │                               #   query expansion effectiveness
│   │   ├── consolidation_metrics.rs    # CX15 metrics exposure (precision, lift, etc.)
│   │   ├── storage_metrics.rs          # DB size, fragmentation, growth rate,
│   │   │                               #   time-to-threshold estimates
│   │   ├── embedding_metrics.rs        # Cache hit rates, inference latency,
│   │   │                               #   migration progress, provider usage
│   │   └── session_metrics.rs          # Active sessions, avg duration,
│   │                                   #   deduplication savings, intent distribution
│   │
│   ├── tracing/
│   │   ├── mod.rs                      # Tracing setup — structured logging
│   │   ├── spans.rs                    # Span definitions per operation:
│   │   │                               #   retrieval, consolidation, decay,
│   │   │                               #   validation, learning, embedding
│   │   │                               #   Each span carries: duration, result, metadata
│   │   └── events.rs                   # Structured log events:
│   │                                   #   memory_created, memory_archived,
│   │                                   #   consolidation_completed, contradiction_detected,
│   │                                   #   degradation_triggered, migration_progress
│   │
│   ├── degradation/
│   │   ├── mod.rs                      # DegradationTracker
│   │   ├── tracker.rs                  # Record every degradation event:
│   │   │                               #   component, failure mode, fallback used,
│   │   │                               #   timestamp, recovery status
│   │   │                               #   Persisted to degradation_log table
│   │   └── alerting.rs                 # Alert thresholds:
│   │                                   #   >3 degradations in 1 hour → warning
│   │                                   #   Same component degraded >24h → critical
│   │                                   #   Surfaced through health report
│   │
│   └── query_log.rs                    # Query performance logging:
│                                       #   Every retrieval query logged with:
│                                       #   query text, intent, latency, result count,
│                                       #   token budget used, cache hits
│                                       #   Used for retrieval effectiveness analysis
```


---

## 15. cortex-cloud — Cloud Sync, Conflict Resolution, Auth

Cloud-readiness layer. Local SQLite is always source of truth. Cloud is optional push/pull. Offline-first.

```
crates/cortex/cortex-cloud/
├── Cargo.toml                          # Deps: cortex-core, cortex-storage,
│                                       #   reqwest, serde, tokio
├── src/
│   ├── lib.rs                          # Re-exports, CloudEngine init
│   │                                   #   Entire crate is feature-gated:
│   │                                   #   #[cfg(feature = "cloud")]
│   │                                   #   OSS builds compile without this crate
│   │
│   ├── engine.rs                       # CloudEngine — sync orchestrator
│   │                                   #   Manages auth state, sync scheduling,
│   │                                   #   conflict resolution, offline detection
│   │
│   ├── auth/
│   │   ├── mod.rs                      # AuthManager — authentication state machine
│   │   ├── token_manager.rs            # Token storage, refresh, expiry detection
│   │   │                               #   Secure token storage (OS keychain integration)
│   │   ├── login_flow.rs               # Login flow — browser-based OAuth or API key
│   │   └── offline_mode.rs             # Offline detection + graceful transition
│   │                                   #   Queue mutations when offline
│   │                                   #   Replay queue when back online
│   │
│   ├── sync/
│   │   ├── mod.rs                      # SyncManager — bidirectional sync
│   │   ├── push.rs                     # Push local changes to cloud:
│   │   │                               #   Read sync_log for unpushed mutations
│   │   │                               #   Batch upload with retry + backoff
│   │   │                               #   Mark as synced on success
│   │   ├── pull.rs                     # Pull remote changes to local:
│   │   │                               #   Fetch changes since last sync timestamp
│   │   │                               #   Apply to local SQLite
│   │   │                               #   Detect conflicts (same memory modified both sides)
│   │   ├── sync_log.rs                 # Mutation log for sync tracking:
│   │   │                               #   Every local mutation logged with:
│   │   │                               #   memory_id, operation, timestamp, synced (bool)
│   │   │                               #   Used for incremental push
│   │   └── delta.rs                    # Delta computation — only sync what changed
│   │                                   #   Content hash comparison for efficiency
│   │                                   #   Embedding sync is optional (can re-generate)
│   │
│   ├── conflict/
│   │   ├── mod.rs                      # ConflictResolver
│   │   ├── detection.rs                # Detect conflicts: same memory_id modified
│   │   │                               #   on both local and remote since last sync
│   │   ├── resolution.rs               # Resolution strategies:
│   │   │                               #   last-write-wins (default)
│   │   │                               #   local-wins (offline-first preference)
│   │   │                               #   remote-wins (team authority)
│   │   │                               #   manual (flag for user resolution)
│   │   └── conflict_log.rs             # Log every conflict with:
│   │                                   #   memory_id, local_version, remote_version,
│   │                                   #   resolution_strategy, resolved_by, timestamp
│   │
│   ├── transport/
│   │   ├── mod.rs                      # Transport layer abstraction
│   │   ├── http_client.rs              # HTTP client — reqwest with retry, backoff,
│   │   │                               #   timeout, compression (gzip)
│   │   └── protocol.rs                 # Wire protocol — JSON serialization format
│   │                                   #   for memory sync payloads
│   │                                   #   Versioned protocol for forward compatibility
│   │
│   └── quota.rs                        # Cloud quota management:
│                                       #   Memory count limits per plan
│                                       #   Storage size limits
│                                       #   Sync frequency limits
│                                       #   Graceful handling when quota exceeded
```

---

## 16. cortex-napi — NAPI Bindings for TypeScript Interop

The bridge. Exposes the Rust engine to TypeScript via napi-rs. Thin binding layer — no business logic here.

```
crates/cortex/cortex-napi/
├── Cargo.toml                          # Deps: napi, napi-derive, cortex-core,
│                                       #   cortex-storage, cortex-embeddings,
│                                       #   cortex-retrieval, cortex-causal,
│                                       #   cortex-learning, cortex-decay,
│                                       #   cortex-validation, cortex-compression,
│                                       #   cortex-prediction, cortex-session,
│                                       #   cortex-privacy, cortex-consolidation,
│                                       #   cortex-observability, cortex-cloud,
│                                       #   tokio (runtime for async bridge)
├── build.rs                            # napi-rs build script
├── src/
│   ├── lib.rs                          # #[napi] module registration
│   │                                   #   Tokio runtime initialization
│   │                                   #   Global CortexRuntime singleton
│   │
│   ├── runtime.rs                      # CortexRuntime — owns all engines:
│   │                                   #   StorageEngine, EmbeddingEngine,
│   │                                   #   RetrievalEngine, CausalEngine,
│   │                                   #   LearningEngine, DecayEngine,
│   │                                   #   ValidationEngine, CompressionEngine,
│   │                                   #   PredictionEngine, SessionManager,
│   │                                   #   PrivacyEngine, ConsolidationEngine,
│   │                                   #   ObservabilityEngine, CloudEngine (optional)
│   │                                   #   Background task scheduler (tokio)
│   │                                   #   Graceful shutdown coordination
│   │
│   ├── bindings/
│   │   ├── mod.rs                      # All NAPI-exported functions
│   │   ├── memory.rs                   # Memory CRUD: create, get, update, delete,
│   │   │                               #   search, list, archive, restore
│   │   ├── retrieval.rs                # Retrieval: retrieve, search, getContext
│   │   ├── causal.rs                   # Causal: inferCause, traverse, getWhy,
│   │   │                               #   counterfactual, intervention
│   │   ├── learning.rs                 # Learning: analyzeCorrection, learn,
│   │   │                               #   getValidationCandidates, processFeedback
│   │   ├── consolidation.rs            # Consolidation: consolidate, getMetrics,
│   │   │                               #   getStatus
│   │   ├── session.rs                  # Session: create, get, cleanup, analytics
│   │   ├── health.rs                   # Health: getHealth, getMetrics, getDegradations
│   │   ├── generation.rs               # Generation: buildContext, trackOutcome
│   │   ├── prediction.rs               # Prediction: predict, preload, getCacheStats
│   │   ├── privacy.rs                  # Privacy: sanitize, getPatternStats
│   │   ├── cloud.rs                    # Cloud: sync, getStatus, resolveConflict
│   │   └── lifecycle.rs                # Lifecycle: initialize, shutdown, configure
│   │
│   └── conversions/
│       ├── mod.rs                      # Rust ↔ JS type conversions
│       ├── memory_types.rs             # BaseMemory ↔ JsObject, 23 type variants
│       ├── search_types.rs             # RetrievalContext, CompressedMemory ↔ JsObject
│       ├── causal_types.rs             # CausalNarrative, WhyContext ↔ JsObject
│       ├── health_types.rs             # HealthReport, Metrics ↔ JsObject
│       └── error_types.rs              # CortexError → JsError with structured info
```


---

## 17. cortex-reclassification — Memory Importance Auto-Reclassification

Standalone crate for CX22. Automatically adjusts memory importance based on observed usage patterns.

```
crates/cortex/cortex-reclassification/
├── Cargo.toml                          # Deps: cortex-core, cortex-storage
├── src/
│   ├── lib.rs                          # Re-exports
│   │
│   ├── engine.rs                       # ReclassificationEngine — monthly background task
│   │                                   #   Evaluates all memories against reclassification rules
│   │                                   #   Max 1 reclassification per memory per month
│   │
│   ├── signals.rs                      # 5 reclassification signals:
│   │                                   #   Access frequency (30-day) — weight 0.35
│   │                                   #   Retrieval rank (30-day avg) — weight 0.25
│   │                                   #   Linked entity count — weight 0.15
│   │                                   #   Contradiction involvement — weight 0.10
│   │                                   #   User feedback — weight 0.15
│   │
│   ├── rules.rs                        # Reclassification rules:
│   │                                   #   Upgrade: low→normal (score>0.7, 2 months)
│   │                                   #   Upgrade: normal→high (score>0.85, 2 months)
│   │                                   #   Upgrade: high→critical (score>0.95, 3 months)
│   │                                   #   Downgrade: critical→high (score<0.5, 3 months)
│   │                                   #   Downgrade: high→normal (score<0.3, 3 months)
│   │                                   #   Downgrade: normal→low (score<0.15, 3 months)
│   │
│   └── safeguards.rs                   # Safeguards:
│                                       #   Never auto-downgrade user-set critical
│                                       #   Max 1 reclassification per memory per month
│                                       #   All changes logged to audit trail
│                                       #   Composite score + contributing signals recorded
```

---

## 18. cortex-tokens — Accurate Token Counting

Lightweight crate for tiktoken-based token counting with caching.

```
crates/cortex/cortex-tokens/
├── Cargo.toml                          # Deps: tiktoken-rs, blake3, moka
├── src/
│   ├── lib.rs                          # Re-exports
│   │
│   ├── counter.rs                      # TokenCounter — cl100k_base (GPT-4/Claude)
│   │                                   #   count(text) → usize
│   │                                   #   count_cached(text) → usize (content-hash keyed)
│   │                                   #   Cache: moka::sync::Cache<String, usize>
│   │
│   └── budget.rs                       # TokenBudget — budget tracking helpers
│                                       #   remaining(total, used) → usize
│                                       #   fits(text, budget) → bool
│                                       #   allocate(items, budget) → Vec<Allocation>
```

---

## 19. Test Infrastructure

Golden datasets, benchmark data, integration test harnesses. Shared across all crates.

```
crates/cortex/test-fixtures/
├── README.md                           # Test fixture documentation
│
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
│   │
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
│   │
│   ├── contradiction/
│   │   ├── direct_conflict.json        # Two memories directly contradict
│   │   ├── partial_conflict.json       # Partial contradiction
│   │   ├── temporal_supersession.json  # Newer supersedes older
│   │   ├── consensus_resistance.json   # Consensus resists single contradiction
│   │   └── propagation_chain.json      # Confidence ripple through graph
│   │
│   ├── causal/
│   │   ├── simple_chain.json           # A caused B caused C
│   │   ├── branching.json              # A caused B and C
│   │   ├── cycle_rejection.json        # Cycle should be rejected
│   │   ├── counterfactual.json         # "What if X didn't happen?"
│   │   └── narrative_output.json       # Expected narrative text
│   │
│   └── privacy/
│       ├── pii_samples.json            # Known PII strings → expected sanitized output
│       ├── secret_samples.json         # Known secrets → expected sanitized output
│       ├── false_positives.json        # Strings that look like secrets but aren't
│       └── idempotency.json            # Sanitize(sanitize(x)) == sanitize(x)
│
├── benchmarks/
│   ├── memories_100.json               # 100 memories for small-scale benchmarks
│   ├── memories_1k.json                # 1K memories for medium-scale benchmarks
│   ├── memories_10k.json               # 10K memories for large-scale benchmarks
│   ├── embeddings_1024dim.bin          # Pre-computed embeddings for benchmark memories
│   ├── queries_50.json                 # 50 benchmark queries with expected results
│   └── causal_graph_1k_edges.json      # 1K-edge causal graph for traversal benchmarks
│
└── integration/
    ├── full_lifecycle.json             # Create → consolidate → retrieve → decay → validate
    ├── concurrent_access.json          # 10 parallel reads + 1 write scenario
    ├── embedding_migration.json        # Model swap mid-operation scenario
    └── degradation_scenarios.json      # Each component failure + expected fallback
```


---

## 20. Per-Crate Test and Bench Directories

Every crate follows the same test structure internally.

```
# Pattern repeated in EVERY crate (cortex-storage shown as example):

crates/cortex/cortex-storage/
├── tests/
│   ├── integration/
│   │   ├── memory_crud_test.rs         # Full CRUD lifecycle
│   │   ├── migration_test.rs           # All migrations run cleanly on fresh DB
│   │   ├── concurrent_access_test.rs   # Read pool + write connection under load
│   │   ├── recovery_test.rs            # WAL recovery, backup restore
│   │   └── compaction_test.rs          # Archived cleanup, vacuum, dedup
│   └── property/
│       └── storage_properties.rs       # proptest: insert→get roundtrip,
│                                       #   bulk ops consistency, query correctness
├── benches/
│   └── storage_bench.rs                # criterion: insert latency, query latency,
│                                       #   bulk insert throughput, FTS5 search speed

# Key property tests per crate (CX17):

cortex-consolidation/tests/property/
└── consolidation_properties.rs         # Idempotent, deterministic, monotonic confidence,
                                        #   no orphaned links, output < input tokens

cortex-decay/tests/property/
└── decay_properties.rs                 # Monotonically decreasing, bounded 0.0-1.0,
                                        #   importance anchor capped, usage boost capped

cortex-compression/tests/property/
└── compression_properties.rs           # Level ordering: L0 < L1 < L2 < L3 tokens,
                                        #   L3 is lossless, compressToFit ≤ budget

cortex-retrieval/tests/property/
└── retrieval_properties.rs             # RRF monotonically decreasing, budget never
                                        #   exceeded, higher importance ranks above

cortex-causal/tests/property/
└── causal_properties.rs                # DAG enforcement (no cycles), depth ≤ maxDepth,
                                        #   nodes ≤ maxNodes, bidirectional = union

cortex-privacy/tests/property/
└── privacy_properties.rs               # Sanitized output never contains raw PII,
                                        #   idempotent (sanitize twice = once)

cortex-tokens/tests/property/
└── token_properties.rs                 # count(a+b) ≤ count(a)+count(b)+1,
                                        #   count("") = 0, cached = uncached

# Key benchmarks per crate (CX17):

cortex-retrieval/benches/
└── retrieval_bench.rs                  # 100 memories < 5ms p95
                                        #   10K memories < 50ms p95
                                        #   Hybrid search (FTS5+vec+RRF) 10K < 30ms p95

cortex-consolidation/benches/
└── consolidation_bench.rs              # Cluster of 5 < 10ms

cortex-embeddings/benches/
└── embedding_bench.rs                  # Single (local ONNX) < 100ms
                                        #   Batch of 10 (local ONNX) < 500ms

cortex-decay/benches/
└── decay_bench.rs                      # 1K memories < 1ms

cortex-causal/benches/
└── causal_bench.rs                     # Traversal depth 5, 1K edges < 5ms
```

---

## 21. TypeScript Layer — MCP Tools + NAPI Consumer

Thin TypeScript wrappers over the Rust engine. No performance-critical logic here. JSON-RPC MCP tool definitions that call Rust via NAPI.

```
packages/cortex/
├── package.json                        # Dependencies: @napi-rs/cli, drift-cortex-napi
├── tsconfig.json                       # TypeScript config
├── vitest.config.ts                    # Test config
│
├── src/
│   ├── index.ts                        # Public exports — CortexClient, tool registrations
│   │
│   ├── bridge/
│   │   ├── index.ts                    # NAPI bridge consumer — loads native module
│   │   ├── client.ts                   # CortexClient — typed wrapper over NAPI bindings
│   │   │                               #   Handles JS ↔ Rust type conversion
│   │   │                               #   Error mapping (Rust CortexError → JS Error)
│   │   │                               #   Async wrapper for Rust async operations
│   │   └── types.ts                    # TypeScript type definitions matching Rust types
│   │                                   #   BaseMemory, CompressedMemory, WhyContext,
│   │                                   #   HealthReport, CausalNarrative, etc.
│   │
│   ├── tools/
│   │   ├── index.ts                    # Tool registry — registers all 33 MCP tools
│   │   │
│   │   ├── memory/
│   │   │   ├── drift_memory_add.ts     # Create memory with auto-dedup + causal inference
│   │   │   ├── drift_memory_search.ts  # Hybrid search with session dedup
│   │   │   ├── drift_memory_get.ts     # Get memory by ID with full details
│   │   │   ├── drift_memory_update.ts  # Update memory content/metadata
│   │   │   ├── drift_memory_delete.ts  # Soft delete (archive) with audit
│   │   │   ├── drift_memory_list.ts    # List memories with filters (type, importance, date)
│   │   │   ├── drift_memory_link.ts    # Link memory to pattern/constraint/file/function
│   │   │   └── drift_memory_unlink.ts  # Remove link
│   │   │
│   │   ├── retrieval/
│   │   │   ├── drift_context.ts        # Orchestrated context retrieval
│   │   │   ├── drift_search.ts         # Direct hybrid search (no orchestration)
│   │   │   └── drift_related.ts        # Find related memories by entity links
│   │   │
│   │   ├── why/
│   │   │   ├── drift_why.ts            # Full "why" context with causal narratives
│   │   │   ├── drift_explain.ts        # Explain single memory with causal chain
│   │   │   ├── drift_counterfactual.ts # "What if we hadn't done X?"
│   │   │   └── drift_intervention.ts   # "If we change X, what needs updating?"
│   │   │
│   │   ├── learning/
│   │   │   ├── drift_memory_learn.ts   # Correction analysis + principle extraction
│   │   │   ├── drift_feedback.ts       # Process user feedback (confirm/reject/modify)
│   │   │   └── drift_validate.ts       # Get validation candidates for active learning
│   │   │
│   │   ├── generation/
│   │   │   ├── drift_gen_context.ts    # Build generation context with provenance
│   │   │   └── drift_gen_outcome.ts    # Track generation outcome (accepted/rejected)
│   │   │
│   │   ├── system/
│   │   │   ├── drift_cortex_status.ts  # Health dashboard
│   │   │   ├── drift_cortex_metrics.ts # Consolidation quality + retrieval metrics
│   │   │   ├── drift_cortex_consolidate.ts  # Manual consolidation trigger
│   │   │   ├── drift_cortex_validate.ts     # Run validation across all memories
│   │   │   ├── drift_cortex_gc.ts      # Run compaction (cleanup + vacuum)
│   │   │   ├── drift_cortex_export.ts  # Export memories as JSON
│   │   │   ├── drift_cortex_import.ts  # Import memories from JSON
│   │   │   └── drift_cortex_reembed.ts # Trigger re-embedding pipeline
│   │   │
│   │   └── prediction/
│   │       ├── drift_predict.ts        # Predictive preloading for current context
│   │       └── drift_preload.ts        # Manual preload for specific file/pattern
│   │
│   └── cli/
│       ├── index.ts                    # CLI command registration (CX23)
│       │                               #   Subcommands under `drift cortex`
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
│
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


---

## 22. Generation Context & "Why" System (within cortex-retrieval)

These are orchestration modules that live inside cortex-retrieval since they coordinate retrieval + causal + compression.

```
crates/cortex/cortex-retrieval/src/

├── generation/
│   ├── mod.rs                          # GenerationOrchestrator
│   ├── context_builder.rs              # Build generation context:
│   │                                   #   Token budget allocation:
│   │                                   #     Patterns 30%, Tribal 25%,
│   │                                   #     Constraints 20%, Anti-patterns 15%,
│   │                                   #     Related 10%
│   ├── gatherers/
│   │   ├── mod.rs                      # Gatherer trait + registry
│   │   ├── pattern_gatherer.rs         # Gather pattern rationales for focus area
│   │   ├── tribal_gatherer.rs          # Gather tribal knowledge + warnings
│   │   ├── constraint_gatherer.rs      # Gather active constraints
│   │   └── antipattern_gatherer.rs     # Gather code smells to avoid
│   ├── provenance.rs                   # Provenance tracking:
│   │                                   #   pattern_followed, tribal_applied,
│   │                                   #   constraint_enforced, antipattern_avoided
│   │                                   #   Inline comment generation:
│   │                                   #   // [drift:tribal] Always use bcrypt...
│   │                                   #   // [drift:pattern] auth-password-hashing
│   ├── feedback.rs                     # Generation outcome tracking:
│   │                                   #   accepted/modified/rejected
│   │                                   #   Adjust confidence of influencing memories
│   └── validation.rs                   # Pre-generation validation:
│                                       #   Check against patterns, tribal, anti-patterns

├── why/
│   ├── mod.rs                          # WhySynthesizer — the "killer feature"
│   ├── synthesizer.rs                  # Full "why" pipeline:
│   │                                   #   1. Gather pattern rationales
│   │                                   #   2. Gather decision contexts (ADRs)
│   │                                   #   3. Gather tribal knowledge
│   │                                   #   4. Gather code smells
│   │                                   #   5. Traverse causal graph
│   │                                   #   6. Generate narrative from chains
│   │                                   #   7. Aggregate warnings
│   │                                   #   8. Compress to fit budget
│   │                                   #   Output: WhyContext
│   └── aggregator.rs                   # Warning aggregation from all sources
│                                       #   Dedup warnings, rank by severity
```

---

## 23. Versioning System (within cortex-storage)

Memory content evolution tracking. Lives in cortex-storage since it's a persistence concern.

```
crates/cortex/cortex-storage/src/

├── versioning/
│   ├── mod.rs                          # VersionManager
│   ├── tracker.rs                      # Track content changes:
│   │                                   #   On every memory update, snapshot current
│   │                                   #   content as a new version
│   │                                   #   Fields: memory_id, version, content,
│   │                                   #   summary, confidence, changed_by, reason
│   ├── query.rs                        # Version queries:
│   │                                   #   Get version history for memory
│   │                                   #   Get memory at specific version
│   │                                   #   Diff between versions
│   ├── rollback.rs                     # Rollback memory to previous version
│   │                                   #   Audit log entry on rollback
│   └── retention.rs                    # Version retention policy:
│                                       #   Max 10 versions per memory
│                                       #   Compress old versions
│                                       #   Delete versions beyond retention limit
```

---

## Build Order — File-Level Sequence

This is the order you build. Each phase depends on the previous.

```
PHASE 0 — Architecture Decisions (no code, just config)
  crates/cortex/Cargo.toml              # Workspace manifest
  crates/cortex/rust-toolchain.toml
  crates/cortex/.cargo/config.toml
  crates/cortex/deny.toml

PHASE 1 — Foundation (cortex-core + cortex-tokens)
  cortex-core/src/errors/*              # Error types FIRST — everything uses these
  cortex-core/src/memory/base.rs        # BaseMemory
  cortex-core/src/memory/types/*        # 23 memory types
  cortex-core/src/memory/*.rs           # Importance, confidence, relationships, links, half-lives
  cortex-core/src/traits/*              # All trait definitions
  cortex-core/src/config/*              # All config structs
  cortex-core/src/intent/*              # Intent taxonomy + weights
  cortex-core/src/models/*              # Shared models
  cortex-core/src/constants.rs          # Global constants
  cortex-tokens/src/*                   # Token counter + budget helpers

PHASE 2 — Storage (cortex-storage)
  cortex-storage/src/pool/*             # Connection pool FIRST
  cortex-storage/src/migrations/*       # Schema migrations
  cortex-storage/src/queries/*          # All query modules
  cortex-storage/src/audit/*            # Audit logger
  cortex-storage/src/versioning/*       # Memory versioning
  cortex-storage/src/compaction/*       # Compaction + storage health
  cortex-storage/src/recovery/*         # Recovery + backup
  cortex-storage/src/engine.rs          # StorageEngine (ties it all together)

PHASE 3 — Embeddings (cortex-embeddings)
  cortex-embeddings/src/providers/*     # All providers
  cortex-embeddings/src/cache/*         # 3-tier cache
  cortex-embeddings/src/enrichment.rs   # Metadata enrichment
  cortex-embeddings/src/matryoshka.rs   # Dimension management
  cortex-embeddings/src/migration/*     # Embedding migration pipeline
  cortex-embeddings/src/degradation.rs  # Fallback chain
  cortex-embeddings/src/engine.rs       # EmbeddingEngine

PHASE 4 — Privacy + Compression + Decay (lightweight crates)
  cortex-privacy/src/*                  # All privacy modules
  cortex-compression/src/*              # All compression modules
  cortex-decay/src/*                    # All decay modules

PHASE 5 — Retrieval (cortex-retrieval)
  cortex-retrieval/src/search/*         # Hybrid search + RRF
  cortex-retrieval/src/ranking/*        # Scoring + re-ranking
  cortex-retrieval/src/intent/*         # Intent classification
  cortex-retrieval/src/expansion/*      # Query expansion
  cortex-retrieval/src/budget/*         # Token budget packing
  cortex-retrieval/src/generation/*     # Generation context
  cortex-retrieval/src/why/*            # "Why" synthesizer
  cortex-retrieval/src/engine.rs        # RetrievalEngine

PHASE 6 — Validation + Contradiction (cortex-validation)
  cortex-validation/src/contradiction/* # Detection + propagation + consensus
  cortex-validation/src/dimensions/*    # 4 validation dimensions
  cortex-validation/src/healing/*       # Healing strategies
  cortex-validation/src/engine.rs       # ValidationEngine

PHASE 7 — Causal Intelligence (cortex-causal)
  cortex-causal/src/graph/*             # StableGraph + DAG + sync + pruning
  cortex-causal/src/inference/*         # 6 inference strategies
  cortex-causal/src/traversal/*         # Forward, backward, counterfactual, intervention
  cortex-causal/src/narrative/*         # Narrative generation + templates
  cortex-causal/src/engine.rs           # CausalEngine

PHASE 8 — Knowledge Management (cortex-consolidation + cortex-learning)
  cortex-consolidation/src/pipeline/*   # 6-phase pipeline
  cortex-consolidation/src/algorithms/* # TextRank, TF-IDF, sentence splitter
  cortex-consolidation/src/scheduling/* # Adaptive scheduler
  cortex-consolidation/src/monitoring/* # CX15 quality metrics + auto-tuning
  cortex-consolidation/src/engine.rs    # ConsolidationEngine
  cortex-learning/src/analysis/*        # Correction analysis
  cortex-learning/src/extraction/*      # Principle extraction
  cortex-learning/src/active_learning/* # Active learning loop
  cortex-learning/src/engine.rs         # LearningEngine

PHASE 9 — Prediction + Session + Reclassification
  cortex-prediction/src/*               # All prediction modules
  cortex-session/src/*                  # All session modules
  cortex-reclassification/src/*         # All reclassification modules

PHASE 10 — Observability (cortex-observability)
  cortex-observability/src/health/*     # Health checks + recommendations
  cortex-observability/src/metrics/*    # All metric collectors
  cortex-observability/src/tracing/*    # Structured logging
  cortex-observability/src/degradation/* # Degradation tracking + alerting
  cortex-observability/src/query_log.rs # Query performance logging

PHASE 11 — Cloud (cortex-cloud) [feature-gated]
  cortex-cloud/src/auth/*               # Auth + token management
  cortex-cloud/src/sync/*               # Push/pull + sync log + delta
  cortex-cloud/src/conflict/*           # Conflict detection + resolution
  cortex-cloud/src/transport/*          # HTTP client + wire protocol
  cortex-cloud/src/engine.rs            # CloudEngine

PHASE 12 — NAPI Bridge (cortex-napi)
  cortex-napi/src/runtime.rs            # CortexRuntime — owns all engines
  cortex-napi/src/bindings/*            # All NAPI-exported functions
  cortex-napi/src/conversions/*         # Rust ↔ JS type conversions
  cortex-napi/src/lib.rs                # Module registration

PHASE 13 — TypeScript Layer (packages/cortex)
  packages/cortex/src/bridge/*          # NAPI consumer + typed client
  packages/cortex/src/tools/*           # 33 MCP tool definitions
  packages/cortex/src/cli/*             # CLI commands

PHASE 14 — Test Infrastructure
  crates/cortex/test-fixtures/**        # Golden datasets + benchmarks
  All crate tests/ and benches/         # Property tests + integration + benchmarks
```


---

## Crate Dependency Graph

```
cortex-core ─────────────────────────────────────────────────────────┐
  │                                                                  │
  ├── cortex-tokens                                                  │
  │                                                                  │
  ├── cortex-storage ←── cortex-core                                 │
  │     │                                                            │
  │     ├── cortex-embeddings ←── cortex-core, cortex-storage        │
  │     │                                                            │
  │     ├── cortex-privacy ←── cortex-core                           │
  │     ├── cortex-compression ←── cortex-core, cortex-tokens        │
  │     ├── cortex-decay ←── cortex-core                             │
  │     │                                                            │
  │     ├── cortex-retrieval ←── cortex-core, cortex-storage,        │
  │     │     cortex-embeddings, cortex-compression, cortex-tokens   │
  │     │                                                            │
  │     ├── cortex-validation ←── cortex-core, cortex-storage,       │
  │     │     cortex-embeddings                                      │
  │     │                                                            │
  │     ├── cortex-causal ←── cortex-core, cortex-storage            │
  │     │                                                            │
  │     ├── cortex-consolidation ←── cortex-core, cortex-storage,    │
  │     │     cortex-embeddings                                      │
  │     │                                                            │
  │     ├── cortex-learning ←── cortex-core, cortex-storage,         │
  │     │     cortex-embeddings, cortex-causal                       │
  │     │                                                            │
  │     ├── cortex-prediction ←── cortex-core, cortex-storage        │
  │     ├── cortex-session ←── cortex-core                           │
  │     ├── cortex-reclassification ←── cortex-core, cortex-storage  │
  │     │                                                            │
  │     ├── cortex-observability ←── cortex-core                     │
  │     │                                                            │
  │     └── cortex-cloud ←── cortex-core, cortex-storage             │
  │                                                                  │
  └── cortex-napi ←── ALL crates above                               │
                                                                     │
  packages/cortex (TypeScript) ←── cortex-napi (native module)       │
```

---

## External Dependency Map

| Crate | External Deps | Purpose |
|---|---|---|
| cortex-core | serde, serde_json, chrono, uuid, thiserror | Serialization, time, IDs, errors |
| cortex-tokens | tiktoken-rs, blake3, moka | Tokenization, hashing, caching |
| cortex-storage | rusqlite (bundled), tokio::sync | SQLite + connection pool |
| cortex-embeddings | ort, moka, blake3, reqwest, tokio | ONNX Runtime, caching, API calls |
| cortex-retrieval | cortex-compression, cortex-tokens | Compression + token counting |
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
