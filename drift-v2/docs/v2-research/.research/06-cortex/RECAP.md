# 06 Cortex Memory System — Research Recap

## Executive Summary

Cortex is Drift's persistent AI memory system — the "brain" that maintains knowledge across sessions, learns from corrections, explains decisions through causal reasoning, and provides intent-aware context retrieval for AI agents. It is 100% TypeScript (~150 source files) organized into 15+ subsystems spanning storage, embeddings, retrieval, consolidation, decay, validation, contradiction detection, causal inference, compression, learning, prediction, session management, privacy, linking, and generation context building. Cortex replaces static `AGENTS.md` files with living memory that decays, learns, contradicts itself, and consolidates over time — modeled after human cognitive processes.

## Current Implementation

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    CortexV2 Orchestrator                 │
│  (cortex-v2.ts — unified API for all operations)        │
├──────────┬──────────┬──────────┬────────────────────────┤
│ Retrieval│ Learning │Generation│   Why / Narrative       │
│ Orch.    │ Orch.    │ Orch.    │   Synthesizer           │
├──────────┴──────────┴──────────┴────────────────────────┤
│                    Core Engines                          │
│  Retrieval │ Consolidation │ Validation │ Prediction     │
├─────────────────────────────────────────────────────────┤
│                  Support Systems                         │
│  Decay │ Contradiction │ Compression │ Session │ Privacy │
├─────────────────────────────────────────────────────────┤
│                  Causal System                           │
│  Inference │ Traversal │ Narrative │ Causal Storage      │
├─────────────────────────────────────────────────────────┤
│                  Embedding Layer                         │
│  Local │ OpenAI │ Ollama │ Hybrid (Lex+Sem+Struct)      │
├─────────────────────────────────────────────────────────┤
│                  Storage Layer                           │
│  SQLite + sqlite-vec (384-dim vectors)                  │
└─────────────────────────────────────────────────────────┘
```

### Entry Points
- `cortex.ts` — `Cortex` class: low-level access to all engines
- `orchestrators/cortex-v2.ts` — `CortexV2` class: high-level unified API (primary consumer interface)
- `index.ts` — Public exports

---

## Subsystem Deep Dives

### 1. Memory Type System (`types/`)

23 memory types organized into 3 categories, all extending `BaseMemory`:

**BaseMemory fields**: id, type, transactionTime (bitemporal), validTime (bitemporal), confidence (0.0-1.0), importance (low/normal/high/critical), lastAccessed, accessCount, summary (~20 tokens), linkedPatterns[], linkedConstraints[], linkedFiles[], linkedFunctions[], tags[], archived, supersededBy, supersedes.

**Category 1 — Domain-Agnostic (9 types)**:
- `core` (∞ half-life) — Project/workspace metadata
- `tribal` (365d) — Institutional knowledge with severity, warnings, consequences
- `procedural` (180d) — How-to procedures with ordered steps and checklists
- `semantic` (90d) — Consolidated knowledge from episodic memories
- `episodic` (7d) — Raw interaction records, material for consolidation
- `decision` (180d) — Standalone decisions with alternatives
- `insight` (90d) — Learned observations
- `reference` (60d) — External references/citations
- `preference` (120d) — User/team preferences

**Category 2 — Code-Specific (4 types)**:
- `pattern_rationale` (180d) — Why patterns exist, with business context
- `constraint_override` (90d) — Approved exceptions to constraints
- `decision_context` (180d) — Code decision context linked to ADRs
- `code_smell` (90d) — Anti-patterns with bad/good examples

**Category 3 — Universal V2 (10 types)**:
- `agent_spawn` (365d) — Reusable agent configurations with tools, triggers, pinned memories
- `entity` (180d) — Projects, products, teams, systems with relationships
- `goal` (90d) — Objectives with progress tracking, success criteria, blockers
- `feedback` (120d) — Corrections and learning signals with extracted rules
- `workflow` (180d) — Step-by-step processes with tools, duration, verification
- `conversation` (30d) — Summarized past discussions
- `incident` (365d) — Postmortems with root cause, resolution, prevention measures
- `meeting` (60d) — Meeting notes and action items
- `skill` (180d) — Knowledge domains and proficiency
- `environment` (90d) — System/environment configurations

**Bitemporal Tracking**: Every memory tracks transaction time (when we learned it) and valid time (when it was/is true). Enables temporal queries like "What did we know about X as of last Tuesday?"

---

### 2. Storage Layer (`storage/`)

SQLite-backed persistence using `better-sqlite3` with `sqlite-vec` for vector operations.

**Core Table**: `memories` — id, type, content (JSON blob), summary, recorded_at, valid_from, valid_until, confidence, importance, last_accessed, access_count, tags (JSON array), archived, superseded_by.

**Relationship Tables**: `memory_relationships` (memory-to-memory edges with strength), `memory_patterns`, `memory_constraints`, `memory_files` (with citation: line_start, line_end, content_hash), `memory_functions`.

**Vector Table**: `memory_embeddings` — 384-dimensional vectors via sqlite-vec. `memory_embedding_link` maps memory IDs to embedding row IDs.

**V2 Tables**: `causal_edges`, `session_contexts`, `memory_validation_history`, `memory_usage_history`, `memory_contradictions`, `consolidation_triggers`, `token_usage_snapshots`, `memory_clusters`.

**20+ indexes** covering type, confidence, validity, importance, timestamps, patterns, constraints, files, functions, relationships, causal edges.

**Migration System**: 5 schema versions tracked via `schema_version` table.

**IMemoryStorage Interface**: Full CRUD, bulk operations, query operations (by type/pattern/constraint/file/function), vector similarity search, bitemporal operations, relationship management, link operations, aggregation, maintenance (vacuum, checkpoint).

**Relationship Types**: Core (supersedes, supports, contradicts, related, derived_from) + Semantic V2 (owns, affects, blocks, requires, references, learned_from, assigned_to, depends_on).

---

### 3. Embedding System (`embeddings/`)

Multi-strategy embedding system producing 384-dimensional vectors.

**IEmbeddingProvider Interface**: name, dimensions (384), maxTokens, initialize(), embed(text), embedBatch(texts), isAvailable().

**Providers**:
- `Local` — Transformers.js (@xenova/transformers), runs in-process, no external API
- `OpenAI` — OpenAI Embeddings API, requires OPENAI_API_KEY
- `Ollama` — Local Ollama instance, configurable model
- `Hybrid` — Fuses 3 strategies:
  - Lexical: TF-IDF based embeddings (keyword matching)
  - Semantic: CodeBERT model integration (code semantics)
  - Structural: AST-based feature extraction (code structure)
  - Fusion: Weighted combination of all 3

**Auto-Detection Priority**: OpenAI → Ollama → Local (Transformers.js fallback)

**3-Tier Cache**:
- L1: In-process Map (microsecond access, LRU eviction, lost on restart)
- L2: SQLite-backed (millisecond access, survives restarts)
- L3: Precomputed shards (zero-latency, loaded at startup)
- Write-through: new embeddings written to all levels
- Invalidation on content change via content hash

---

### 4. Retrieval Engine (`retrieval/`)

Intent-aware memory retrieval with multi-factor scoring.

**Flow**: Receive context → Gather candidates (by pattern, constraint, file, function, topic) → Score each candidate → Apply intent weighting → Rank → Compress to fit token budget → Return CompressedMemory[].

**Intent Types**: Domain-agnostic (create, investigate, decide, recall, learn), Code-specific (add_feature, fix_bug, refactor, security_audit, understand_code, add_test), Universal V2 (spawn_agent, execute_workflow, track_progress, diagnose_issue).

**Scoring Factors**: Semantic similarity to focus query, file proximity, pattern alignment, recency of access, confidence level, importance level, intent-type match.

**Intent Weighting**: Each intent boosts certain memory types. E.g., `fix_bug` boosts tribal, episodic, code_smell, incident. `add_feature` boosts pattern_rationale, procedural, tribal.

**Token Budget**: Default 2000 tokens. Memories compressed via hierarchical compression. Higher-importance memories get more allocation.

---

### 5. Consolidation Engine (`consolidation/`)

Sleep-inspired 5-phase memory consolidation.

**Phase 1 — Replay**: Select episodic memories eligible for consolidation (age > 7 days, status = pending). Group related episodes by topic/context.

**Phase 2 — Abstraction**: Extract generalizable patterns from episode groups. Create candidate semantic memories.

**Phase 3 — Integration**: Merge new semantic candidates with existing semantic memories. Update or create as needed.

**Phase 4 — Pruning**: Remove consolidated episodic memories. Track tokensFreed metric.

**Phase 5 — Strengthening**: Boost confidence of frequently accessed memories.

**Adaptive Scheduler (V2)**: Token-aware scheduling triggered by: token pressure, memory count, confidence degradation, contradiction density, or scheduled fallback. Tracks TokenUsage and QualityMetrics.

---

### 6. Decay System (`decay/`)

Multi-factor confidence decay modeling memory relevance over time.

**Formula**: `finalConfidence = baseConfidence × temporalDecay × citationDecay × usageBoost × importanceAnchor × patternBoost`

- **Temporal Decay**: `e^(-daysSinceAccess / halfLife)` — exponential, type-specific half-lives
- **Citation Decay**: Content hash comparison detects file drift, stale citations reduce confidence
- **Usage Boost**: `min(1.5, 1 + log10(accessCount + 1) × 0.2)` — capped at 1.5×
- **Importance Anchor**: critical=2.0×, high=1.5×, normal=1.0×, low=0.8×
- **Pattern Boost**: Linked to active patterns = 1.3×, otherwise 1.0×

**Archival**: When confidence drops below type-specific minimum, memory is eligible for archival.

---

### 7. Validation Engine (`validation/`)

4-dimension periodic validation with healing.

**Dimensions**:
1. Citation Validation — File existence, content hash drift, line number validity
2. Temporal Validation — validUntil expiry, outdated references, age vs expected lifetime
3. Contradiction Detection — Semantic similarity + rule-based heuristics for conflicting memories
4. Pattern Alignment — Memory-pattern consistency, detect when patterns changed but memories didn't

**Healing Strategies**: Confidence adjustment, citation update (re-link moved files), archival (below threshold), flagging (human review when auto-fix isn't safe).

---

### 8. Contradiction Detection & Propagation (`contradiction/`)

**Detection Strategies**: Semantic similarity, negation patterns, absolute statement conflicts, temporal supersession, feedback contradictions, topic conflicts.

**Contradiction Types**: direct, partial, supersedes, temporal.

**Confidence Propagation**: When contradiction detected, confidence changes ripple through the memory graph. Direct contradiction = -0.3, partial = -0.15, supersession = -0.5. Supporting memories also lose confidence at 0.5× propagation factor. Confirmation boosts +0.1. Consensus (≥3 supporters) boosts +0.2.

**Batch Recalculation**: `recalculateConfidences()` rebalances all memories based on relationship balance.

---

### 9. Causal System (`causal/`)

Automatic causal relationship discovery, graph traversal, and narrative generation.

**8 Relation Types**: caused, enabled, prevented, contradicts, supersedes, supports, derived_from, triggered_by.

**Inference Strategies** (weighted): temporal_proximity (0.2), semantic_similarity (0.3), entity_overlap (0.25), explicit_reference (0.4), pattern_matching (0.15), file_co_occurrence (0.1).

**Graph Traversal**: traceOrigins (backward), traceEffects (forward), traceBidirectional, getNeighbors. Configurable maxDepth (5), minStrength (0.3), maxNodes (50). Chain confidence = 60% min edge strength + 40% average.

**Narrative Generator**: Produces human-readable text with sections (Origins, Effects, Support, Conflicts), summary, key points, and confidence score.

**Causal Storage**: SQLite-backed with full CRUD, bulk operations, strength management, evidence management, validation tracking, statistics, cleanup.

---

### 10. Compression System (`compression/`)

4-level hierarchical compression for token-efficient retrieval.

| Level | Content | Target Tokens | Max Tokens |
|-------|---------|---------------|------------|
| 0 | IDs only | 5 | 10 |
| 1 | One-liners + tags | 50 | 75 |
| 2 | With examples + evidence | 200 | 300 |
| 3 | Full context + causal chains + links | 500 | 1000 |

**HierarchicalCompressorV2**: compress(memory, level), compressToFit(memory, maxTokens), compressBatchToFit(memories[], totalBudget). Greedy approach: sorts by importance (critical first), compresses each to fit remaining budget.

---

### 11. Learning System (`learning/`)

Correction analysis, principle extraction, confidence calibration, active learning.

**10 Correction Categories**: pattern_violation, tribal_miss, constraint_violation, style_preference, naming_convention, architecture_mismatch, security_issue, performance_issue, api_misuse, other.

**Pipeline**: Analyze correction → Categorize → Diff analysis → Extract principle → Create memory → Infer causal links → Check contradictions.

**Category → Memory Type Mapping**: pattern_violation→pattern_rationale, tribal_miss→tribal, security_issue→tribal(critical), performance_issue→code_smell, etc.

**Active Learning Loop**: Identifies uncertain memories → Generates validation prompts → Processes user feedback (confirm/reject/modify) → Updates confidence.

**Confidence Calibration**: 5 factors — base, evidence, usage, temporal, validation history.

---

### 12. Prediction System (`prediction/`)

Predictive memory preloading based on 4 signal types.

**Signals**: FileSignals (active file, imports, symbols), TemporalSignals (time of day, session duration), BehavioralSignals (recent queries, intents, frequent memories), GitSignals (branch, modified files, commit messages).

**4 Prediction Strategies**: FileBasedPredictor, PatternBasedPredictor, TemporalPredictor, BehavioralPredictor.

**Multi-Strategy Deduplication**: When memory appears in multiple strategies, keep highest confidence + merge signals + apply +0.05 boost (capped at 1.0).

**Cache**: Default TTL 5 minutes. Tracks hits, misses, hit rate, avg prediction time. Invalidated on file change or new session.

---

### 13. Session Management (`session/`)

Tracks loaded context per conversation to avoid re-sending. Saves 30-50% tokens through deduplication.

**SessionContext**: loadedMemories (Set), loadedPatterns (Set), loadedFiles (Set), loadedConstraints (Set), tokensSent, queriesMade.

**Deduplicator**: Filters out already-sent memories. Marks duplicates with `alreadySent: true`.

**Session Validity**: Inactivity timeout, max duration, max tokens per session. Cleanup deletes sessions older than retention period (default 7 days).

---

### 14. Generation Context (`generation/`)

Builds rich context for code generation with provenance tracking.

**Context Gathering**: Pattern gatherer, tribal gatherer, constraint gatherer, anti-pattern gatherer. Each scored by relevance, compressed to fit token budget allocation (patterns 30%, tribal 25%, constraints 20%, anti-patterns 15%, related 10%).

**Provenance Tracking**: Records what influenced generated code (pattern_followed, tribal_applied, constraint_enforced, antipattern_avoided, example_used, style_matched).

**Feedback Loop**: Processes generation outcomes (accepted/modified/rejected). Feeds back into learning system.

**Validation**: Checks generated code against patterns, tribal knowledge, and anti-patterns.

---

### 15. Privacy System (`privacy/`)

PII and secret sanitization before storage or transmission.

**PII Patterns**: Email, phone, SSN, credit card, IP address → replaced with `[EMAIL]`, `[PHONE]`, etc.

**Secret Patterns**: API keys, AWS keys (AKIA...), JWT tokens, private keys (PEM), passwords → replaced with `[API_KEY]`, `[AWS_KEY]`, etc.

---

### 16. Linking System (`linking/`)

Links memories to Drift entities for cross-referencing.

**Link Types**: Pattern links (memory_patterns), constraint links (memory_constraints), file links with citations (memory_files — line_start, line_end, content_hash), function links (memory_functions), decision links.

---

### 17. "Why" System (`why/`)

Synthesizes "why" context by gathering pattern rationales, decision contexts, tribal knowledge, and warnings. Powers the `drift_why` MCP tool.

**WhySynthesizer**: Gathers from all sources in parallel → Returns WhyContext (patterns, decisions, tribal, warnings, summary).

**V2 Enhancement**: Combines with causal system for narrative generation, causal chains, and narrative confidence.

---

### 18. Orchestrators (`orchestrators/`)

High-level workflow orchestrators — primary API surface.

**CortexV2** (main entry point): getContext(), getWhy(), learn(), processFeedback(), getValidationCandidates(), buildGenerationContext(), trackGenerationOutcome(), predict(), getHealth(), consolidate(), validate().

**RetrievalOrchestrator**: Session deduplication + prediction integration + hierarchical compression + token efficiency metrics.

**LearningOrchestrator**: Correction analysis → memory creation → causal inference → decay application.

**GenerationOrchestrator**: Token budget allocation → context gathering → validation → outcome tracking.

---

## Key Algorithms

1. **Confidence Decay**: Exponential temporal decay with 5 multiplicative factors (temporal, citation, usage, importance, pattern)
2. **Confidence Scoring**: Weighted formula — frequency×0.40 + consistency×0.30 + age×0.15 + spread×0.15
3. **Contradiction Propagation**: Graph-based confidence ripple with configurable deltas and propagation factors
4. **Causal Inference**: Multi-strategy weighted scoring (temporal proximity, semantic similarity, entity overlap, explicit reference)
5. **Hierarchical Compression**: 4-level greedy bin-packing sorted by importance
6. **Consolidation**: 5-phase sleep-inspired pipeline (replay, abstraction, integration, pruning, strengthening)
7. **Intent Weighting**: Memory type boosting based on user intent classification
8. **Prediction**: Multi-signal, multi-strategy memory preloading with deduplication and caching

---

## Data Models

### Core Types
- `BaseMemory` — 20+ fields including bitemporal tracking, confidence, importance, linking
- `CausalEdge` — source, target, relation (8 types), strength, evidence[], inferred flag
- `CompressedMemory` — 4 levels with progressive detail
- `SessionContext` — loaded sets, token tracking, query counting
- `GenerationContext` — patterns, tribal, constraints, anti-patterns, token budget
- `CodeProvenance` — influences, warnings, applied constraints, avoided anti-patterns

### Key Interfaces
- `IMemoryStorage` — Full CRUD + vector + bitemporal + relationships + links
- `IEmbeddingProvider` — embed, embedBatch, isAvailable
- `ICausalStorage` — Full CRUD + strength + evidence + validation + statistics

---

## Capabilities

- 23 typed memories with bitemporal tracking and confidence decay
- Intent-aware retrieval with session deduplication (30-50% token savings)
- 4-level hierarchical compression for token budget management
- Sleep-inspired consolidation (episodic → semantic)
- Multi-factor contradiction detection with graph-based confidence propagation
- Automatic causal inference with 6 strategies and narrative generation
- Predictive memory preloading from file, pattern, temporal, and behavioral signals
- Active learning loop with correction analysis and principle extraction
- Generation context building with provenance tracking and feedback loops
- PII/secret sanitization
- 33 MCP tools exposing full Cortex functionality to AI agents
- 3-tier embedding cache (memory, SQLite, precomputed)
- Multi-provider embeddings (local, OpenAI, Ollama, hybrid)

---

## Limitations

1. **Embedding quality**: 384-dimensional vectors from Transformers.js are adequate but not state-of-the-art for code understanding. No code-specific embedding model.
2. **No hybrid search**: Vector-only retrieval. No combination of full-text search + vector search (Reciprocal Rank Fusion).
3. **Consolidation is LLM-dependent**: The abstraction phase (extracting generalizable patterns from episodes) likely needs LLM calls, creating an external dependency for a core operation.
4. **Token estimation is approximate**: Uses string length approximation, not actual tokenizer. Can lead to budget overflows or underutilization.
5. **Privacy patterns are limited**: Only 10 PII/secret patterns. Missing: Slack tokens, GitHub tokens, Azure keys, GCP service accounts, npm tokens, PyPI tokens, and many more.
6. **No graph-based memory representation**: Unlike Mem0's graph memory variant, Cortex stores memories as flat records with relationship edges. No entity-relationship graph for multi-hop reasoning.
7. **Causal inference is heuristic**: No formal causal model (e.g., Pearl's do-calculus). Inference strategies are weighted heuristics, not statistically grounded.
8. **No memory versioning**: Memories are updated in-place. No history of how a memory's content evolved over time (only confidence changes are tracked via validation history).
9. **Prediction cache TTL is static**: 5-minute TTL regardless of context. No adaptive TTL based on file change frequency or session activity.
10. **Single-node only**: No distributed memory. Cannot share memories across team members or CI environments.
11. **No memory importance auto-classification**: Importance is set at creation time. No automatic reclassification based on usage patterns.
12. **Embedding dimension is fixed at 384**: Cannot leverage higher-dimensional models (1024, 2048) that provide better separation for code semantics.

---

## Integration Points

| Connects To | How |
|---|---|
| **07-mcp** | 33 MCP tools expose all Cortex functionality to AI agents |
| **08-storage** | cortex.db (SQLite + sqlite-vec) for all persistence |
| **22-context-generation** | Memory retrieval feeds into context generation pipeline |
| **23-pattern-repository** | Memories link to patterns via memory_patterns table |
| **04-call-graph** | Memories link to functions via memory_functions table |
| **18-constraints** | Memories link to constraints via memory_constraints table |
| **21-security** | Privacy sanitizer protects sensitive data in memories |

---

## V2 Migration Status

### Current State
- 100% TypeScript (~150 source files)
- Well-structured with clean interfaces (IMemoryStorage, IEmbeddingProvider, ICausalStorage)
- Comprehensive test suite (unit, integration, stress, adversarial, property-based)

### Recommended Rust Migration (from rust-migration.md)
- **Phase 1**: Storage + Embeddings (highest ROI) — rusqlite, candle/ort, moka cache
- **Phase 2**: Graph + Analysis — petgraph for causal, contradiction, compression, validation
- **Phase 3**: Orchestration — retrieval, consolidation, prediction, learning
- **Phase 4**: Full migration — orchestrators, session, generation, privacy, why, linking

### Stays in TypeScript
- MCP tools (thin JSON-RPC wrappers)
- LLM-dependent features (principle extraction, some narrative generation)

---

## Open Questions

1. Should Cortex support distributed/shared memory for team environments?
2. Should memory versioning track content evolution, not just confidence changes?
3. Should the embedding dimension be configurable to support higher-dimensional models?
4. Should consolidation have a non-LLM fallback for air-gapped environments?
5. Should importance be auto-reclassified based on usage patterns over time?
6. Should Cortex adopt graph-based memory representation (like Mem0g) for multi-hop reasoning?
7. Should hybrid search (vector + full-text via RRF) replace vector-only retrieval?
8. What is the right balance between local embedding quality and inference speed?

---

## Quality Checklist

- [x] All 25 files in 06-cortex/ have been read
- [x] Architecture clearly described with diagram
- [x] All 18 subsystems documented with key algorithms
- [x] All data models listed with fields
- [x] All 23 memory types documented with half-lives
- [x] Limitations honestly assessed (12 identified)
- [x] Integration points mapped to other categories
- [x] V2 migration status documented
- [x] Open questions identified (8)
