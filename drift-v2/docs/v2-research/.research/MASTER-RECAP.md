# Drift V1 → V2 Master Recap

> A complete synthesis of all v1 research across all 27 categories (00-26). This document captures everything important about Drift v1 in one place, serving as the definitive requirements specification for the v2 greenfield enterprise build.

---

## 1. What Drift Is

Drift is a codebase convention discovery and indexing tool. It scans codebases to automatically discover patterns (how the team actually writes code), indexes them in SQLite, and exposes them to AI agents via MCP (Model Context Protocol).

**Core thesis**: If you can discover and index a codebase's conventions offline (no AI), you can expose them to AI at query time, giving it exactly the context it needs without wasting tokens on discovery.

**Four-phase operation**:
1. **SCAN** — Parse codebase with tree-sitter (10 languages), discover conventions across 16 categories, score statistically
2. **INDEX** — Store everything in SQLite (patterns, call graph, boundaries). No AI involved — pure static analysis
3. **EXPOSE** — MCP server with 87+ tools lets AI query what it needs. One call replaces 3-5 discovery calls
4. **LEARN** — Cortex memory system replaces static AGENTS.md with living memory that decays, learns, and contradicts itself

**What makes Drift different**:
- Learns, doesn't prescribe — discovers YOUR conventions
- Statistical, not binary — confidence scores, not pass/fail
- Offline indexing — no AI needed for scanning
- MCP-native — built for AI consumption from day one
- Living memory — Cortex replaces static docs
- Multi-language — 10 languages, 28+ ORMs, 21+ frameworks
- Call graph aware — understands function relationships, data flow, reachability
- 100% local — no code leaves the machine

---

## 2. Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│ PRESENTATION    CLI │ MCP Server (87+ tools) │ VSCode │ Dashboard│
├─────────────────────────────────────────────────────────────────┤
│ ORCHESTRATION   Commands │ Services │ Quality Gates │ Workspace │
├─────────────────────────────────────────────────────────────────┤
│ INTELLIGENCE    Detectors (350+) │ Analyzers │ Cortex Memory    │
├─────────────────────────────────────────────────────────────────┤
│ ANALYSIS        Call Graph │ Boundaries │ Reachability │ etc.   │
├─────────────────────────────────────────────────────────────────┤
│ PARSING         Tree-sitter (10 languages) │ Regex fallback     │
├─────────────────────────────────────────────────────────────────┤
│ STORAGE         drift.db (SQLite) │ cortex.db (SQLite + vectors)│
├─────────────────────────────────────────────────────────────────┤
│ RUST CORE       Native parsers │ Scanner │ Call graph │ NAPI    │
└─────────────────────────────────────────────────────────────────┘
```

**Strictly layered** — no circular dependencies:
- Layer 1 (Foundation): Parsers, Storage, Scanner
- Layer 2 (Analysis): Detectors, Call Graph, Boundaries, Constants, Environment, Error Handling, Test Topology
- Layer 3 (Intelligence): Patterns (aggregated), Cortex, Constraints, Wrappers, Coupling
- Layer 4 (Enforcement): Rules Engine, Quality Gates, Audit, DNA System
- Layer 5 (Presentation): MCP, CLI, VSCode, Dashboard
- Layer 6 (Advanced): Simulation Engine, Decision Mining, Context Generation

**Language split**: ~65 Rust files (performance-critical), ~500+ TypeScript files (orchestration, UI, memory). V2 consolidates all parsing, detection, and analysis to Rust. TypeScript becomes thin orchestration/presentation.

---

## 3. The 27 Categories — Complete Inventory

| # | Category | What It Covers | Language | Files |
|---|----------|----------------|----------|-------|
| 00 | overview | System architecture, pipelines, data models, configuration | Docs | 8 |
| 01 | rust-core | Native Rust: parsers, scanner, call graph, 8 analyzers, NAPI bridge | Rust | ~65 |
| 02 | parsers | Tree-sitter parsing for 10 languages, AST extraction, Pydantic, Java annotations | Rust+TS | ~58 |
| 03 | detectors | 350+ pattern detectors across 16 categories, 7 framework extensions | TS | ~350 |
| 04 | call-graph | Function relationship mapping, reachability, impact analysis, dead code | Rust+TS | ~35 |
| 05 | analyzers | AST, type, semantic, flow analyzers + rules engine + unified provider | TS | ~40 |
| 06 | cortex | AI memory: 23 memory types, embeddings, retrieval, learning, causal inference | TS | ~150 |
| 07 | mcp | MCP server: 87+ tools across 10 categories for AI agents | TS | ~90 |
| 08 | storage | 6 fragmented backends → 2 SQLite databases, 40+ tables, 50+ indexes | Rust+TS | ~35 |
| 09 | quality-gates | CI/CD enforcement: 6 gate types, policy engine, 6 output formats | TS | ~30 |
| 10 | cli | 50+ commands, services, reporters, UI, worker threads | TS | ~50 |
| 11 | ide | VSCode extension, LSP server, dashboard, decorations | TS | ~40 |
| 12 | infrastructure | Build system, CI/CD, Docker, telemetry, licensing, native builds | Mixed | ~30 |
| 13 | advanced | DNA system (10 genes), decision mining, simulation engine, language intelligence | TS | ~45 |
| 14 | directory-map | File listings for all packages | Docs | 5 |
| 15 | migration | Rust migration strategy | Docs | 1 |
| 16 | gap-analysis | Documentation gaps and audit | Docs | 2 |
| 17 | test-topology | Test framework detection (35+), coverage mapping, quality scoring | Rust+TS | ~15 |
| 18 | constraints | Architectural constraint detection (12 types) and enforcement | TS | ~8 |
| 19 | error-handling | Error boundary detection, gap analysis, propagation chains | Rust+TS | ~6 |
| 20 | contracts | API contract tracking (BE↔FE mismatch detection), REST-only | TS | ~5 |
| 21 | security | Security boundaries, sensitive data detection, 28+ ORMs, reachability | Rust+TS | ~12 |
| 22 | context-generation | AI context generation, token budgeting, 11 package managers | TS | ~4 |
| 23 | pattern-repository | Pattern storage abstraction layer (Repository + Service pattern) | TS | ~13 |
| 24 | data-lake | Materialized views, indexes, query engine (DEPRECATED for v2) | TS | ~11 |
| 25 | services-layer | Scan pipeline, Piscina worker pools, aggregation | TS | ~3 |
| 26 | workspace | Project lifecycle, backup/restore, schema migration, context pre-loading | TS | ~5 |

---

## 4. Rust Core (Category 01) — Complete Summary

### Crate Structure
```
crates/drift-core/src/
├── parsers/          # Tree-sitter parsers for 10 languages
├── scanner/          # Parallel filesystem walking (rayon + walkdir)
├── call_graph/       # Call graph building, storage, querying (SQLite)
├── unified/          # Core pattern detection engine (AST + regex)
├── boundaries/       # Data access point & sensitive field detection
├── coupling/         # Module coupling metrics (Martin's Ca/Ce/I/A/D)
├── constants/        # Constants, magic numbers, secret detection (21 patterns)
├── environment/      # Environment variable usage analysis
├── error_handling/   # Error boundary & gap detection
├── test_topology/    # Test file mapping, framework detection
├── reachability/     # Forward/inverse data flow reachability
└── wrappers/         # Framework wrapper detection & clustering

crates/drift-napi/    # N-API bridge (~25 exported functions)
```

### Key Capabilities
- **Scanner**: Parallel filesystem traversal via rayon, .gitignore/.driftignore support
- **Parsers**: Tree-sitter v0.23 for 10 languages, compile-time linked grammars
- **Call Graph**: Sharded parallel building, SQLite persistence with ParallelWriter, resolution pass with confidence scoring
- **Unified Analyzer**: 4-phase per-file pipeline (AST → string extraction → string analysis → resolution index), ~30 AST patterns across 9 languages
- **Boundaries**: Data access point detection, ORM model detection (28+ ORMs), sensitive field detection (PII, credentials, financial, health)
- **Coupling**: Robert C. Martin metrics (Ca, Ce, I, A, D), DFS cycle detection
- **Constants**: 21 secret detection patterns across 4 severity levels, Shannon entropy check, placeholder detection
- **Environment**: Env var extraction across 6 access patterns, sensitivity classification
- **Error Handling**: Boundary detection (6 types), gap detection (6 types), severity classification
- **Test Topology**: 13 framework detection, test type classification, mock detection
- **Reachability**: Forward/inverse BFS, in-memory + SQLite variants
- **Wrappers**: Framework primitive detection, confidence scoring, 12 categories

### Performance Infrastructure
- rayon (data parallelism), tree-sitter v0.23 (incremental, error-tolerant), rusqlite (bundled SQLite)
- xxhash (xxh3) for fast hashing, smallvec for ≤4 element vectors, FxHashMap for fast lookups
- Custom string interning (60-80% memory reduction), LTO enabled, codegen-units=1, opt-level=3
- Platform support: darwin-arm64/x64, linux-arm64/x64 (gnu+musl), win32-x64-msvc

### Critical Gaps in V1 Rust Core
1. No incremental scanning (full rescan every time)
2. No dependency graph building (done in TS)
3. Parsers extract significantly less detail than TS (no generics, no structured annotations, no Pydantic)
4. Only ~30 AST patterns vs 350+ TS detectors
5. Log patterns compiled but never used
6. Violation system defined but never populated
7. Resolution stats fields are TODO
8. Coupling uses DFS instead of Tarjan's SCC
9. Missing: Azure keys, GCP service accounts, npm/PyPI tokens in secret detection
10. No .env file parsing, no missing variable detection
11. No error propagation chain tracking
12. Wrapper registry is React-focused only
13. No cross-service reachability
14. No taint analysis


---

## 5. Parser Subsystem (Category 02) — Complete Summary

### Dual-Layer Architecture
- **Rust parsers** (~8,000 lines): 10 languages, compile-time linked tree-sitter grammars, basic metadata extraction
- **TypeScript parsers** (~10,000+ lines): 14 languages, richer framework-aware extraction, LRU caching, incremental parsing
- **NAPI bridge** (~2,200 lines): Manual field-by-field conversion, 3 parser-specific functions
- **Native adapter**: Fallback mechanism (Rust → TS tree-sitter → TS regex → null)

### Three Different ParseResult Shapes (V1 Problem)
1. **Rust ParseResult**: Contains extracted metadata (functions, classes, imports, exports, calls)
2. **TS ParseResult**: Contains raw AST tree (not extracted metadata)
3. **NAPI JsParseResult**: Third shape consumed by TS callers

### Feature Parity Gap (Rust vs TS)
| Feature | Rust | TS | Priority |
|---------|------|-----|----------|
| Generic type parameters | ❌ | ✅ | P0 |
| Pydantic model support | ❌ | ✅ | P0 |
| Structured annotation extraction | Partial (strings) | ✅ (objects with args) | P0 |
| Full inheritance chains | Partial (direct) | ✅ (multi-level) | P1 |
| Framework construct detection | Partial | ✅ | P1 |
| Namespace/package extraction | ❌ | ✅ | P1 |
| Incremental parsing | ❌ | ✅ (tree.edit()) | P2 |
| AST caching | ❌ | ✅ (LRU, 100 entries) | P2 |

### TS-Only Complex Features
- **Pydantic extraction** (9 files): Field extraction, type resolution (recursive with cycle detection), constraint parsing, validator extraction, config extraction, v1/v2 detection
- **Java annotation system** (5 files): First-class annotation extraction with structured arguments for Spring Boot pattern detection
- **TS ParserManager** (900 lines): LRU caching, incremental parsing, language detection for 14 languages

---

## 6. Detector System (Category 03) — Complete Summary

### Scale
- 350+ source files across 16 categories
- Each category has up to 3 variants: Base (regex/AST), Learning (adaptive), Semantic (deep)
- 7 framework extensions: Spring (12 categories), ASP.NET (11), Laravel (12), Django (1), Go (3), Rust (3), C++ (3)
- 100% TypeScript — zero Rust implementation

### 16 Detector Categories
security(7), auth(6), errors(7), api(7), components(8), config(7), contracts(4+), data-access(7+3), documentation(5), logging(7), performance(6), structural(9), styling(8), testing(7), types(7), accessibility(6)

### Key Algorithms

**1. Confidence Scoring** (heart of Drift):
```
score = frequency × 0.4 + consistency × 0.3 + ageFactor × 0.15 + spread × 0.15
```
Classification: high (≥0.85), medium (≥0.70), low (≥0.50), uncertain (<0.50)

**2. ValueDistribution** (convention learning):
```
if filePercentage >= 0.6 AND occurrences >= 3 → dominant convention
```

**3. Outlier Detection**: n ≥ 30 → Z-Score (|z| > 2.0), n < 30 → IQR (1.5× multiplier)

**4. Pattern Matching** (multi-strategy): AST depth-first traversal, Regex with named captures, Structural glob patterns. LRU cache: 1000 entries, 60s TTL

**5. Contract Matching**: Multi-factor weighted path similarity (Jaccard, segment count, suffix match)

### 8-Phase Detection Pipeline
```
1. FILE SCANNING → FileMetadata[]
2. PARSING → DetectionContext[]
3. DETECTION → DetectionResult[] (per file per detector)
4. AGGREGATION → AggregatedMatchResult[]
5. CONFIDENCE SCORING → Pattern[] with ConfidenceScore
6. OUTLIER DETECTION → Pattern[] with outlier annotations
7. STORAGE → SQLite + JSON shards
8. VIOLATION GENERATION → Violation[]
```

### Critical Gaps
1. Performance: 350+ TS detectors running sequentially per file
2. No incremental detection (full re-detection every scan)
3. Rust parity gap: ~30 AST patterns vs 350+ TS detectors
4. No pattern decay (old patterns never lose confidence)
5. No pattern merging (similar patterns not consolidated)
6. No call graph integration for cross-function pattern analysis
7. No data flow analysis (structural/textual only)
8. No effective false-positive tracking or feedback loop
9. Django only has contracts — no learning/semantic detectors
10. Go/Rust/C++ only have api+auth+errors
11. No GraphQL/gRPC contract detection
12. SemanticLearningDetector is a stub

---

## 7. Call Graph System (Category 04) — Complete Summary

### Architecture
- **TypeScript** (~35 files): Per-language extractors (8 languages × 3 variants), graph builder, reachability, impact analysis, dead code detection, enrichment pipeline
- **Rust** (6 files): StreamingBuilder, UniversalExtractor, CallGraphDb (SQLite), ParallelWriter
- **Reachability** (4 Rust files): In-memory + SQLite-backed engines

### Per-Language Extractors (TS)
Each language has 3 extractor variants: Standard, Hybrid (tree-sitter + regex fallback), Data Access (ORM-aware, 28+ ORMs)

### Call Resolution (6 strategies in TS, 3 in Rust)
1. Same-file lookup (highest confidence)
2. Method resolution via class/receiver type
3. DI injection (FastAPI Depends, Spring @Autowired, NestJS @Inject)
4. Import-based lookup
5. Export-based lookup
6. Fuzzy matching (name similarity, lowest confidence)

Resolution rate: typically 60-85%

### Critical Gaps
1. Rust has only UniversalExtractor — needs per-language hybrid extractors
2. Impact analysis, dead code, coverage analysis need Rust implementations
3. Resolution algorithm needs more strategies in Rust
4. No incremental builds (full rebuild every time)
5. No taint analysis, no cross-service reachability

---

## 8. Analyzers (Category 05) — Complete Summary

### Four Core Analyzers (TS-only)
1. **AST Analyzer** (~800 lines): Structural pattern matching, subtree comparison, traversal
2. **Type Analyzer** (~1600 lines): Full TypeScript type system analysis, subtyping, coverage
3. **Semantic Analyzer** (~1350 lines): Scope analysis, symbol resolution, reference tracking, shadowed variable detection
4. **Flow Analyzer** (~1600 lines): Control flow graph construction, data flow analysis, unreachable code detection, null dereference detection

### Unified Language Provider (20 ORM matchers)
Composable extraction pipeline normalizing AST differences across 9 languages into universal `UnifiedCallChain` representation. 20 ORM/framework matchers detect data access patterns from normalized call chains (Prisma, Django, SQLAlchemy, Entity Framework, Eloquent, Spring Data, GORM, Diesel, SeaORM, SQLx, Supabase, TypeORM, Sequelize, Drizzle, Knex, Mongoose, raw SQL, database/sql).

### Rules Engine
- **Evaluator**: Core evaluation pipeline (pattern → violations) with 3 violation sources (outliers, missing patterns, deviation details)
- **Rule Engine**: Higher-level orchestration with deduplication, limits, blocking detection
- **Severity Manager**: 4-level resolution (pattern → category → config → default), escalation rules
- **Quick Fix Generator**: 7 fix strategies (Replace, Wrap, Extract, Import, Rename, Move, Delete) with confidence scoring
- **Variant Manager**: Scoped pattern overrides (global/directory/file) with expiration and persistence

---

## 9. Cortex Memory System (Category 06) — Complete Summary

Cortex is Drift's persistent AI memory system — the "brain" that maintains knowledge across sessions, learns from corrections, explains decisions through causal reasoning, and provides intent-aware context retrieval for AI agents. It is 100% TypeScript (~150 source files) organized into 18 subsystems. Cortex replaces static `AGENTS.md` files with living memory that decays, learns, contradicts itself, and consolidates over time — modeled after human cognitive processes.

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

### 23 Memory Types in 3 Categories

All types extend `BaseMemory` (20+ fields: id, type, bitemporal timestamps, confidence 0.0-1.0, importance, access tracking, summary, linked patterns/constraints/files/functions, tags, archival state).

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

### 18 Subsystems — Deep Dive

**1. Storage Layer** — SQLite + sqlite-vec (384-dim vectors). Core table `memories` with JSON content blobs. Relationship tables (`memory_relationships` with strength), cross-domain link tables (`memory_patterns`, `memory_constraints`, `memory_files` with citation line ranges + content hashes, `memory_functions`). V2 tables: `causal_edges`, `session_contexts`, `memory_validation_history`, `memory_usage_history`, `memory_contradictions`, `consolidation_triggers`, `token_usage_snapshots`, `memory_clusters`. 20+ indexes. 5 schema versions with migration system. Full `IMemoryStorage` interface: CRUD, bulk ops, query by type/pattern/constraint/file/function, vector similarity search, bitemporal operations, relationship management, aggregation, maintenance.

**2. Embedding System** — Multi-provider: Local (Transformers.js, in-process), OpenAI (API), Ollama (local instance), Hybrid (fuses lexical TF-IDF + semantic CodeBERT + structural AST features). Auto-detection priority: OpenAI → Ollama → Local. 3-tier cache: L1 in-memory Map (microsecond, LRU), L2 SQLite-backed (millisecond, survives restarts), L3 precomputed shards (zero-latency, loaded at startup). Write-through to all levels. Invalidation on content change via content hash.

**3. Retrieval Engine** — Intent-aware with multi-factor scoring. Flow: context → gather candidates (by pattern, constraint, file, function, topic) → score (semantic similarity, file proximity, pattern alignment, recency, confidence, importance, intent-type match) → apply intent weighting → rank → compress to token budget → return. 15 intent types across 3 categories (domain-agnostic, code-specific, universal V2). Default 2000-token budget with hierarchical compression.

**4. Consolidation Engine** — Sleep-inspired 5-phase pipeline: (1) Replay — select eligible episodic memories, group by topic; (2) Abstraction — extract generalizable patterns; (3) Integration — merge with existing semantic memories; (4) Pruning — remove consolidated episodes, track tokensFreed; (5) Strengthening — boost frequently accessed memories. Adaptive scheduler triggered by token pressure, memory count, confidence degradation, contradiction density, or scheduled fallback.

**5. Decay System** — Multi-factor confidence decay: `finalConfidence = baseConfidence × temporalDecay × citationDecay × usageBoost × importanceAnchor × patternBoost`. Temporal: `e^(-days/halfLife)`. Citation: content hash drift detection. Usage: `min(1.5, 1 + log10(accessCount+1) × 0.2)`. Importance: critical=2.0×, high=1.5×, normal=1.0×, low=0.8×. Pattern: linked to active patterns = 1.3×. Archival when confidence drops below type-specific minimum.

**6. Validation Engine** — 4-dimension periodic validation: citation (file existence, content hash drift, line validity), temporal (expiry, outdated references), contradiction (semantic similarity + rule-based heuristics), pattern alignment (memory-pattern consistency). Healing strategies: confidence adjustment, citation update, archival, flagging for human review.

**7. Contradiction Detection** — Detection strategies: semantic similarity, negation patterns, absolute statement conflicts, temporal supersession, feedback contradictions, topic conflicts. Types: direct, partial, supersedes, temporal. Confidence propagation: direct=-0.3, partial=-0.15, supersession=-0.5. Supporting memories lose at 0.5× propagation factor. Confirmation boosts +0.1. Consensus (≥3 supporters) boosts +0.2. Batch recalculation rebalances all memories.

**8. Causal System** — 8 relation types (caused, enabled, prevented, contradicts, supersedes, supports, derived_from, triggered_by). 6 inference strategies (weighted): temporal_proximity (0.2), semantic_similarity (0.3), entity_overlap (0.25), explicit_reference (0.4), pattern_matching (0.15), file_co_occurrence (0.1). Graph traversal: traceOrigins (backward), traceEffects (forward), traceBidirectional, getNeighbors. Configurable maxDepth (5), minStrength (0.3), maxNodes (50). Chain confidence = 60% min edge + 40% average. Narrative generator produces human-readable text with sections, summary, key points, confidence. SQLite-backed causal storage with full CRUD.

**9. Compression System** — 4-level hierarchical: Level 0 (IDs only, 5 tokens), Level 1 (one-liners + tags, 50 tokens), Level 2 (with examples + evidence, 200 tokens), Level 3 (full context + causal chains + links, 500 tokens). Greedy bin-packing sorted by importance (critical first).

**10. Learning System** — 10 correction categories: pattern_violation, tribal_miss, constraint_violation, style_preference, naming_convention, architecture_mismatch, security_issue, performance_issue, api_misuse, other. Pipeline: analyze correction → categorize → diff analysis → extract principle → create memory → infer causal links → check contradictions. Active learning loop: identify uncertain memories → generate validation prompts → process feedback (confirm/reject/modify) → update confidence. 5-factor confidence calibration.

**11. Prediction System** — 4 signal types: FileSignals (active file, imports, symbols), TemporalSignals (time of day, session duration), BehavioralSignals (recent queries, intents, frequent memories), GitSignals (branch, modified files, commit messages). 4 strategies: FileBasedPredictor, PatternBasedPredictor, TemporalPredictor, BehavioralPredictor. Multi-strategy deduplication with +0.05 boost for cross-strategy hits. Cache: 5-minute TTL.

**12. Session Management** — Tracks loaded context per conversation (loadedMemories, loadedPatterns, loadedFiles, loadedConstraints, tokensSent, queriesMade). Deduplicator filters already-sent memories. Saves 30-50% tokens. Inactivity timeout, max duration, max tokens per session. Cleanup deletes sessions older than 7 days.

**13. Generation Context** — Builds rich context for code generation with provenance tracking. 4 gatherers (pattern, tribal, constraint, anti-pattern) scored by relevance. Token budget allocation: patterns 30%, tribal 25%, constraints 20%, anti-patterns 15%, related 10%. Provenance records influences (pattern_followed, tribal_applied, constraint_enforced, antipattern_avoided). Feedback loop processes outcomes (accepted/modified/rejected) back into learning.

**14. Privacy System** — PII patterns (email, phone, SSN, credit card, IP) → `[EMAIL]`, `[PHONE]`, etc. Secret patterns (API keys, AWS keys AKIA..., JWT tokens, private keys PEM, passwords) → `[API_KEY]`, `[AWS_KEY]`, etc. Only 10 patterns total — a critical gap.

**15. Linking System** — Links memories to Drift entities: pattern links (memory_patterns), constraint links (memory_constraints), file links with citations (memory_files — line_start, line_end, content_hash), function links (memory_functions), decision links.

**16. "Why" System** — Synthesizes "why" context by gathering pattern rationales, decision contexts, tribal knowledge, and warnings in parallel. Powers the `drift_why` MCP tool. V2 enhancement combines with causal system for narrative generation and causal chains.

**17. Orchestrators** — CortexV2 (main entry point): getContext(), getWhy(), learn(), processFeedback(), getValidationCandidates(), buildGenerationContext(), trackGenerationOutcome(), predict(), getHealth(), consolidate(), validate(). RetrievalOrchestrator: session dedup + prediction + compression + token metrics. LearningOrchestrator: correction → memory → causal → decay. GenerationOrchestrator: budget allocation → gathering → validation → outcome tracking.

**18. MCP Exposure** — 33 MCP tools expose all Cortex functionality to AI agents across memory CRUD, search, learning, consolidation, causal inference, validation, and health monitoring.

### Key Algorithms
1. **Confidence Decay**: Exponential temporal with 5 multiplicative factors
2. **Confidence Scoring**: frequency×0.40 + consistency×0.30 + age×0.15 + spread×0.15
3. **Contradiction Propagation**: Graph-based confidence ripple with configurable deltas
4. **Causal Inference**: Multi-strategy weighted scoring (6 strategies)
5. **Hierarchical Compression**: 4-level greedy bin-packing by importance
6. **Consolidation**: 5-phase sleep-inspired pipeline
7. **Intent Weighting**: Memory type boosting based on intent classification
8. **Prediction**: Multi-signal, multi-strategy preloading with dedup and caching

### Critical Limitations
1. 384-dim vectors from Transformers.js — not state-of-the-art for code understanding
2. No hybrid search (vector-only, no full-text + RRF)
3. Consolidation is LLM-dependent — no fallback for air-gapped environments
4. Token estimation is approximate (string length, not actual tokenizer)
5. Limited privacy patterns (only 10 PII/secret patterns)
6. No graph-based memory representation (flat records with edges, not entity-relationship graph)
7. Causal inference is heuristic — no formal causal model (Pearl's do-calculus)
8. No memory versioning — updated in-place, no content evolution history
9. Prediction cache TTL is static (5 min) — no adaptive TTL
10. Single-node only — no distributed/shared memory
11. No memory importance auto-reclassification based on usage
12. Fixed 384-dim embeddings — cannot leverage higher-dimensional models

### Integration Points
| Connects To | How |
|---|---|
| 07-mcp | 33 MCP tools expose all Cortex functionality |
| 08-storage | cortex.db (SQLite + sqlite-vec) for all persistence |
| 22-context-generation | Memory retrieval feeds context generation pipeline |
| 23-pattern-repository | Memories link to patterns via memory_patterns table |
| 04-call-graph | Memories link to functions via memory_functions table |
| 18-constraints | Memories link to constraints via memory_constraints table |
| 21-security | Privacy sanitizer protects sensitive data |

### V2 Migration Path
- Phase 1: Storage + Embeddings to Rust (highest ROI — rusqlite, ort/candle, moka cache)
- Phase 2: Graph + Analysis to Rust (petgraph for causal, contradiction, compression, validation)
- Phase 3: Orchestration to Rust (retrieval, consolidation, prediction, learning)
- Phase 4: Full migration (orchestrators, session, generation, privacy, why, linking)
- Stays in TypeScript: MCP tools (thin JSON-RPC wrappers), LLM-dependent features


---

## 10. MCP Server (Category 07) — Complete Summary

87+ tools organized across 10 categories:
- **Orchestration** (2): `drift_context` (curated context, one call replaces 3-5), `drift_package_context`
- **Discovery** (3): `drift_status`, `drift_capabilities`, `drift_projects`
- **Surgical** (12): `drift_callers`, `drift_signature`, `drift_type`, `drift_imports`, `drift_prevalidate`, etc.
- **Exploration** (5): `drift_patterns_list`, `drift_security_summary`, `drift_contracts_list`, etc.
- **Detail** (8): `drift_pattern_get`, `drift_code_examples`, `drift_impact_analysis`, etc.
- **Analysis** (18): `drift_coupling`, `drift_test_topology`, `drift_quality_gate`, + 8 language-specific
- **Generation** (3): `drift_explain`, `drift_validate_change`, `drift_suggest_changes`
- **Memory** (33): Full Cortex access — `drift_why`, `drift_memory_add`, `drift_memory_search`, etc.
- **Setup** (2): `drift_setup`, `drift_telemetry`
- **Curation** (1): `drift_curate` (6 actions with anti-hallucination verification)

Features: response caching, rate limiting, token estimation, pagination cursors, tool packs, feedback system, dual-path storage (JSON + SQLite), project auto-detection (13 markers), stdio + HTTP/SSE transports.

---

## 11. Storage (Category 08) — Complete Summary

### V1 Has 6 Fragmented Backends
1. JSON files (.drift/patterns/*.json) — 50+ files, O(n) reads, no concurrency
2. SQLite unified (drift.db) — 40+ tables, 50+ indexes, WAL mode
3. Data lake (materialized views, indexes, shards) — JSON-based query optimization
4. Rust SQLite (callgraph.db) — High-performance call graph with MPSC channel pattern
5. Cortex SQLite (cortex.db + sqlite-vec) — Memory system + 384-dim vector embeddings
6. Hybrid stores — Transitional bridges between JSON and SQLite

### V2 Consolidates to 2
- `drift.db` — All analysis data (Rust-owned, TS read-only via NAPI)
- `cortex.db` — Memory system + vector embeddings (TS-owned, attached via ATTACH DATABASE)

### Performance Improvement
| Operation | V1 JSON | V1 SQLite | V2 Rust SQLite |
|-----------|---------|-----------|----------------|
| Load all patterns | 200-800ms | 50-150ms | 10-30ms |
| Find pattern by ID | O(n) scan | O(1) index | O(1) index |
| Insert 1000 patterns | 500ms+ | 100-200ms | 20-50ms |
| Status query | 100-300ms | 5-10ms | 1-3ms |

---

## 12. Quality Gates (Category 09) — Complete Summary

### 6 Gate Types
1. **Pattern Compliance** — Are approved patterns being followed? (Blocking)
2. **Constraint Verification** — Do changes satisfy architectural constraints? (Blocking)
3. **Regression Detection** — Has pattern confidence dropped vs baseline? (Warning, Team tier)
4. **Impact Simulation** — How many files/functions affected? (Warning, Enterprise tier)
5. **Security Boundary** — Is sensitive data accessed without auth? (Blocking, Enterprise tier)
6. **Custom Rules** — User-defined checks (Disabled by default, Team tier)

### Policy Engine
4 built-in policies (default, strict, relaxed, ci-fast) with scope matching (branch patterns, path patterns). 4 aggregation modes (any, all, weighted, threshold). Scoring: error=-10, warning=-3, info=-1 penalty points from 100.

### Output Formats
GitHub PR annotations, GitLab MR annotations, SARIF, JSON, Text, extensible reporter interface.

---

## 13. CLI (Category 10) — Complete Summary

50+ commands via Commander.js, organized into Core (scan, check, approve, ignore, status, report), Analysis (call-graph, env, dna, coupling, constants, constraints), Language-specific (ts, py, java, go, php, rust, cpp), and Infrastructure (projects, backup, setup, memory, gate, telemetry).

Key features: Piscina worker thread pool for parallel detection, pluggable reporters (text, JSON, GitHub, GitLab, SARIF), interactive setup wizard with modular runners, git integration (staged files, hooks), native Rust tried first with TS fallback.

---

## 14. IDE (Category 11) — Complete Summary

VSCode extension with phased activation, LSP client with connection management, 6 command handler categories, code decorations (inline pattern indicators), tree views (patterns, violations, files, constants), webview panels, Redux-like state management, service container with event bus.

---

## 15. Infrastructure (Category 12) — Complete Summary

Monorepo: pnpm workspaces + Turborepo. Rust cross-compilation via NAPI-RS for 7 platform targets. GitHub Actions CI/CD (ci.yml, native-build.yml, release.yml, drift-check.yml). Docker for containerized MCP server. Cloudflare Workers for telemetry. CIBench benchmark framework. AI provider abstraction (OpenAI, Anthropic, Ollama). Galaxy 3D visualization library.

---

## 16. Advanced Systems (Category 13) — Complete Summary

### DNA System (10 genes)
Extracts "genetic fingerprint" of codebase styling/API conventions. 6 frontend genes (variant-handling, responsive-approach, state-styling, theming, spacing-philosophy, animation-approach) + 4 backend genes (api-response-format, error-response-format, logging-format, config-pattern). Health score: consistency(40%) + confidence(30%) + mutation penalty(20%) + dominant coverage(10%).

### Simulation Engine
Pre-flight simulation of code changes. Generates multiple implementation approaches, scores across 4 dimensions (friction 30%, pattern alignment 30%, impact 25%, security 15%), ranks and recommends. 13 task categories, 15 approach strategies, 5 language strategies. Enterprise-only feature.

### Decision Mining
Extracts architectural decisions from git history, code comments, and structural patterns. Links decisions to code locations and patterns.

### Language Intelligence
Framework detection, normalizers for 9 languages, tree-sitter query registry for language-specific patterns.

---

## 17. Specialized Analysis Systems (Categories 17-22)

### Test Topology (17)
Maps tests to production code across 35+ frameworks in 8 languages. Coverage mapping (direct + transitive via call graph), minimum test set calculation, mock analysis, test quality scoring (0-100), uncovered function detection with risk scoring.

### Constraints (18)
Discovers and enforces architectural invariants. 12 invariant types (must_have, must_not_have, must_precede, must_follow, must_colocate, must_separate, must_wrap, must_propagate, cardinality, data_flow, naming, structure). 10 constraint categories. Lifecycle: discovered → approved → enforced.

### Error Handling (19)
4-phase analysis: function profiling, boundary detection (React ErrorBoundary, Express middleware, NestJS filters, Spring @ExceptionHandler), propagation chain analysis (source → sink tracing), gap detection (no-try-catch, swallowed-error, unhandled-async, bare-catch, missing-boundary).

### Contracts (20)
BE↔FE API contract tracking. Backend endpoint extraction from 6+ frameworks, frontend API call extraction (fetch, axios, react-query). 5 mismatch types (missing_in_frontend, missing_in_backend, type_mismatch, optionality_mismatch, nullability_mismatch). REST-only — no GraphQL/gRPC.

### Security (21)
Two-phase learn-then-detect pipeline. 28+ ORM frameworks across 8 languages. 7 dedicated field extractors (Prisma, Django, SQLAlchemy, Supabase, GORM, Diesel, raw SQL). Sensitive data detection (PII, credentials, financial, health) with specificity scoring. Boundary rules enforcement. Security prioritization (4 tiers).

### Context Generation (22)
Powers `drift_context` and `drift_package_context` — the most important MCP tools. 9-step pipeline: detect package → load patterns → load constraints → extract entry points → extract data accessors → find key files → generate guidance → load dependency patterns → estimate & trim tokens. PackageDetector supports 11 package managers across all languages.

---

## 18. Data Infrastructure (Categories 23-26)

### Pattern Repository (23)
Repository + Service abstraction layer. `IPatternRepository` (CRUD, query, status transitions, events) with 5 implementations (UnifiedFile, LegacyFile, InMemory, Cached, Adapter). `IPatternService` (high-level consumer API). Event-driven architecture. MCP dual-path support.

### Data Lake (24) — DEPRECATED
JSON-based materialized views, sharded storage, pre-computed indexes, unified query engine. Replaced entirely by SQLite views and indexes in v2. Concepts preserved: query routing, single-read stats, selective rebuild.

### Services Layer (25)
Scan pipeline orchestration. Piscina worker thread pool (CPU cores - 1). 7-step pipeline: create pool → warmup → dispatch → collect → aggregate → outlier detect → manifest. Full metadata preservation from detector through to consumer.

### Workspace (26)
Project lifecycle management. WorkspaceManager (singleton orchestrator), BackupManager (SHA-256 checksums, gzip compression, retention policy), ContextLoader (2-tier cache with TTL), ProjectSwitcher (multi-project with health indicators), SchemaMigrator (sequential migrations with rollback).

---

## 19. Core Data Models

### Pattern (central entity)
```
Pattern { id, category (16 variants), subcategory, name, description,
  status: discovered|approved|ignored,
  confidence: { score, level, frequency, consistency, age, spread },
  severity: error|warning|info|hint,
  locations: [{ file, line, column, confidence, isOutlier }],
  outliers: [{ file, line, reason, deviationScore, significance }],
  metadata: { firstSeen, lastSeen, tags } }
```

### ParseResult (Rust)
```
ParseResult { language, tree, functions: [FunctionInfo], classes: [ClassInfo],
  imports: [ImportInfo], exports: [ExportInfo], calls: [CallSite],
  errors: [ParseError], parse_time_us }
```

### FunctionNode (Call Graph)
```
FunctionNode { id: "file:name:line", name, qualifiedName, file, startLine, endLine,
  language, calls: [CallSite], calledBy: [CallSite], dataAccess: [DataAccessPoint],
  className, isExported, isAsync, decorators, parameters, returnType }
```

### Memory (Cortex)
```
Memory { id, type (23 types), summary, confidence, importance,
  transactionTime, validTime, accessCount, linkedPatterns,
  linkedFiles, linkedFunctions, tags }
```

### Violation
```
Violation { id, patternId, severity, message, file, range,
  expected, actual, explanation, quickFixes, aiExplainAvailable }
```

---

## 20. Key Pipelines

### Scan Flow (Offline Indexing)
Files → Scanner (parallel) → Parser (tree-sitter) → Detectors (350+) → Aggregation → Confidence Scoring → Outlier Detection → Storage → History Snapshot

### Query Flow (Online — MCP)
AI request → Context generator → Pattern retrieval + Cortex memories + Call graph + Boundaries → Compression → Curated response (~2000 tokens)

### Enforcement Flow (CI/CD)
Code push → Quality gates (pattern compliance, security, constraints, impact) → Violations → PR annotations → Pass/fail

---

## 21. Subsystem Connection Map

### Critical Dependency Chains
```
02-parsers → feeds everything (detectors, call graph, boundaries, analyzers, test topology, error handling, contracts, security)
03-detectors → 23-pattern-repository → 07-mcp, 09-quality-gates
04-call-graph → 21-security, 17-test-topology, 09-quality-gates, 07-mcp, 19-error-handling
06-cortex → 07-mcp (33 tools), 22-context-generation
07-mcp → depends on 03, 04, 06, 21, 22, 23 (presentation layer for AI)
08-storage → foundation for all data-producing categories
09-quality-gates → depends on 03, 04, 18, 21 (enforcement layer)
22-context-generation → depends on 03, 04, 06, 21 (powers drift_context)
```

---

## 22. V2 Vision — What Changes

### Already in Rust (Solid Foundation)
- File scanning with parallel walking
- Tree-sitter parsing for 10 languages
- Call graph building, storage, querying
- Unified pattern detection (AST + regex, ~30 patterns)
- All 8 specialized analyzers
- Reachability (forward + inverse, in-memory + SQLite)
- String interning and resolution index

### Must Migrate TS → Rust
- 350+ pattern detectors (currently only ~30 AST patterns in Rust)
- Pattern matching and confidence scoring
- Storage operations (pattern CRUD, contract CRUD)
- Language intelligence (normalization, framework detection)
- Richer call graph queries (impact, dead code, coverage)
- Per-language call graph extractors (8 languages × 3 variants)
- Pydantic model extraction, structured annotation extraction
- Module roles, cycle break suggestions, refactor impact analysis
- Error propagation chains, error profiles
- Test quality scoring, minimum test set calculation
- .env file parsing, missing variable detection
- ORM-specific field extractors, risk scoring
- 20 ORM matchers from unified language provider

### Stays in TypeScript
- CLI, MCP server, VSCode extension, Dashboard
- Cortex (AI orchestration layer)
- Simulation engine, Decision mining
- Quality gate orchestration (thin wrapper)
- Context generation (orchestration)
- Workspace management

### Architectural Decisions for V2
1. Incremental-first architecture (not batch-only with retrofit)
2. Single canonical ParseResult shape (eliminate 3-shape problem)
3. Declarative pattern definitions (TOML/YAML, not hardcoded)
4. Trait-based language parser architecture
5. Single-pass visitor pattern for detection (not per-detector traversal)
6. Temporal confidence decay + momentum scoring
7. Bayesian convention learning (replace binary 60% threshold)
8. OWASP/CWE-aligned security detection
9. Generic AST normalization layer for language-agnostic detection
10. Enterprise-grade secret detection (100+ patterns, Shannon entropy)
11. Split MCP server (analysis vs memory) for token efficiency
12. Progressive disclosure meta-tool pattern
13. GraphQL + gRPC contract detection alongside REST
14. Effective false-positive tracking with feedback loops
15. Suggested fixes as first-class output

---

## 23. Business Model

Open core with 3 tiers:
- **Community** (free, Apache 2.0): All scanning, detection, analysis, CI, MCP, VSCode
- **Team** (BSL 1.1): Policy engine, regression detection, custom rules, trends, exports
- **Enterprise** (BSL 1.1): Multi-repo governance, impact simulation, security boundaries, audit trails

100% local. No code leaves the machine. All analysis happens locally.

---

## Quality Checklist

- [x] All 27 categories inventoried with file counts and language
- [x] Rust core fully documented (14 subsystems, all gaps identified)
- [x] Parser subsystem fully documented (dual-layer, feature parity gap)
- [x] Detector system fully documented (350+ detectors, 16 categories, 8-phase pipeline)
- [x] Call graph fully documented (extractors, resolution, gaps)
- [x] Analyzers fully documented (4 core analyzers, rules engine, unified provider)
- [x] Cortex fully documented (23 memory types, 18 subsystems, 12 limitations, all algorithms)
- [x] Storage fully documented (6 backends, Data Lake architecture, V2 consolidation plan)
- [x] MCP problem identified (monolithic, 87+ tools, token bloat)
- [x] Quality gates documented (6 types, policy engine, CI/CD integration)
- [x] All remaining categories documented (CLI, IDE, infrastructure, advanced, 14-26)
- [x] Core data models documented (Pattern, ParseResult, FunctionNode, Memory, Violation)
- [x] Key pipelines documented (scan, query, enforcement)
- [x] Subsystem connection map documented with critical dependency chains
- [x] Cross-cutting concerns documented (data flows, connection density, shared models, performance)
- [x] V2 vision documented (principles, changes, what stays)
- [x] Business model documented (3 tiers)
- [x] All critical gaps and limitations honestly assessed across all categories
