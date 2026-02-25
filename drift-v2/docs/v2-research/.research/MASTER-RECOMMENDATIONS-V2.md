# Drift V2 — Master Recommendations (Expanded)

> Enterprise-grade recommendations synthesized from the complete v1 recap (27 categories), master research encyclopedia (150+ sources), expanded research (§33-40), and master audit (80+ gaps, 15 non-negotiables). This document builds on the original MASTER-RECOMMENDATIONS.md (194 recommendations) with expanded coverage driven by audit findings and new research areas. Every recommendation traces to verified sources. Every audit gap has a concrete implementation path.

**Audit-Driven Expansion**: The MASTER-AUDIT identified 80+ gaps, 6 cross-cutting concerns (CC1-CC6), 5 data model inconsistencies (DM1-DM5), 6 performance bottlenecks (PB1-PB6), 5 security findings (SA1-SA5), and 15 v2 non-negotiables. The MASTER-RESEARCH-V2 added 8 new research areas (§33-40). This recommendations document provides concrete implementation guidance for every one of them.

**Priority Levels**:
- P0: Must be decided/built before anything else. Architectural foundations.
- P1: Core functionality. Required for v2 launch.
- P2: Important for enterprise adoption. Can follow initial launch.
- P3: Nice-to-have. Future roadmap.

**Recommendation Count**: 260+ (up from 194 in v1)

---

## Table of Contents

1. [Part 1: Architectural Decisions (AD1-AD12)](#part-1-architectural-decisions)
2. [Part 2: Category-Specific Recommendations](#part-2-category-specific-recommendations)
   - Rust Core (RC1-RC20)
   - Parsers (PA1-PA16)
   - Detectors (DE1-DE16)
   - Call Graph (CG1-CG10)
   - Analyzers (AN1-AN16)
   - Cortex Memory (CX1-CX16)
   - MCP Server (MC1-MC16)
   - Storage (ST1-ST10)
   - Quality Gates (QG1-QG8)
   - CLI (CL1-CL14)
   - IDE (ID1-ID14)
   - Infrastructure (IN1-IN8)
   - Advanced Systems (AV1-AV13)
   - Specialized Analysis (SP1-SP34)
   - Data Infrastructure (DI1-DI18)
3. [Part 3: New Research Area Recommendations (NR1-NR32)](#part-3-new-research-area-recommendations)
   - Taint Analysis (NR1-NR8)
   - OWASP 2025 Alignment (NR9-NR13)
   - Enterprise Secret Detection (NR14-NR18)
   - Observability & Structured Logging (NR19-NR23)
   - Bayesian Convention Learning (NR24-NR27)
   - Code Embedding Models (NR28-NR30)
   - Declarative Pattern Definitions (NR31-NR32)
4. [Part 4: Build Phases (Updated)](#part-4-build-phases)
5. [Part 5: V2 Target Metrics (Updated)](#part-5-v2-target-metrics)
6. [Part 6: Risk Register (Updated)](#part-6-risk-register)
7. [Part 7: Decision Log (Updated)](#part-7-decision-log)
8. [Part 8: Recommendation Cross-Reference Matrix (Expanded)](#part-8-recommendation-cross-reference-matrix)

---

## Part 1: Architectural Decisions (Decide Before Writing Code)

### AD1: Incremental-First Architecture

**Priority**: P0 | **Impact**: Every subsystem | **Evidence**: §1.1, §1.2 | **Audit**: CC1, PB2, RC-G1

Build the entire system around incremental computation from day one. Do NOT build batch-only and retrofit.

**Two-phase model** (proven by rust-analyzer, IntelliJ, Sorbet):
1. **Per-file indexing phase**: Parse file → extract patterns → produce file index entry. Embarrassingly parallel. Each entry is content-hashed (xxhash) and cached.
2. **Cross-file analysis phase**: Call graph resolution, coupling metrics, reachability — computed from the file index. Auto-invalidate when input entries change.

**Persistent index**: SQLite-backed, survives process restarts. On startup, hash-check files against stored index — only re-index changed files.

**Three-layer incrementality**:
- Layer 1 (Easy): Per-file detection — skip unchanged files via content hash
- Layer 2 (Medium): Confidence re-scoring — only re-score patterns with locations in changed files
- Layer 3 (Hard): Convention re-learning — threshold-based trigger (>10% files changed) for full re-learning

### AD2: Single Canonical Data Model

**Priority**: P0 | **Impact**: Every subsystem | **Evidence**: §2.1 | **Audit**: A3, PA-G8, DM1-DM5

One `ParseResult` type. One `Pattern` type. One `FunctionEntry` type. No more three-shape problem (Rust, TS, NAPI).

Rust defines the canonical types. NAPI serializes them. TypeScript consumes them. No re-interpretation, no re-parsing, no shape conversion.

### AD3: Declarative Pattern Definitions

**Priority**: P0 | **Impact**: Detectors, MCP, Quality Gates | **Evidence**: §3.4, §39 | **Audit**: Non-Negotiable #13

Ship with hardcoded defaults (all v1 patterns). Users add custom patterns via TOML without recompiling.

```toml
[[patterns]]
id = "spring-security"
language = "java"
category = "Auth"
confidence = 0.95
query = '(annotation name: (identifier) @name (#match? @name "^(PreAuthorize|Secured)$"))'
```

Tree-sitter query syntax serves as the pattern language. Graduated complexity: simple patterns → metavariables → cross-file.

### AD4: Visitor Pattern for Detection

**Priority**: P0 | **Impact**: Detection performance | **Evidence**: §3.2 | **Audit**: PB1, DE-G1, Non-Negotiable #4

Single-pass AST traversal with all detectors registered as visitors. Reduces traversals from O(detectors × files) to O(files). This is the single most impactful architectural change for detection performance.

### AD5: Split MCP Server Architecture

**Priority**: P0 | **Impact**: MCP, token efficiency, user experience | **Evidence**: §7.1-7.5 | **Audit**: A5, MC-G1-G4, Non-Negotiable #6

Split into two MCP servers plus implement progressive disclosure within each:

```
┌─────────────────────────────────────────────────────────────┐
│                    HOST APPLICATION                          │
├──────────────────────┬──────────────────────────────────────┤
│  drift-analysis      │  drift-memory (optional)             │
│  ~17-20 tools        │  ~15-20 tools                        │
│  Read-only drift.db  │  Read/Write cortex.db + Read drift.db│
│  ~5-8K tokens        │  ~5-8K tokens                        │
└──────────────────────┴──────────────────────────────────────┘
```

### AD6: Structured Error Handling Everywhere

**Priority**: P0 | **Impact**: Every Rust subsystem | **Evidence**: §40 | **Audit**: CC2, Non-Negotiable #8

Use `thiserror` for all error types from the first line of code. One error enum per subsystem with structured variants. Propagate meaningful errors through NAPI to TypeScript with error codes.

### AD7: SQLite WAL Mode as Default

**Priority**: P0 | **Impact**: All storage | **Evidence**: §8.1 | **Audit**: A4, Non-Negotiable #7

Every SQLite database opens with: WAL mode, `synchronous = NORMAL`, `mmap_size = 268435456` (256MB), `busy_timeout = 5000`.

### AD8: Temporal Confidence with Momentum

**Priority**: P0 | **Impact**: Confidence scoring, convention learning | **Evidence**: §5.1, §5.2, §37 | **Audit**: DM3, Non-Negotiable #10

Replace static confidence scoring with Bayesian posterior probability combined with momentum-aware scoring:

```
posterior_mean = (1 + k) / (2 + n)    // Beta(1,1) prior, k successes in n trials
momentum = (current_freq - prev_freq) / prev_freq  // normalized to [0, 1]
final_score = posterior_mean × 0.70 + consistency × 0.15 + momentum × 0.15
```

Graduated confidence tiers based on posterior credible interval width, not binary thresholds.

### AD9: Feedback Loop Architecture

**Priority**: P0 | **Impact**: Detection quality, enterprise adoption | **Evidence**: §3.1 | **Audit**: DE-G9, Non-Negotiable #5

Build Google Tricorder-style feedback from day one:
- "Not useful" / "Useful" signals on every violation
- Track effective false-positive rate per detector (<5% target)
- Detectors with high "not useful" rates get confidence reduction
- Developer action (fix, ignore, approve) feeds back into pattern confidence
- Project-level customization, not user-level

### AD10: Observability-First Infrastructure (NEW)

**Priority**: P0 | **Impact**: Every subsystem | **Evidence**: §36 | **Audit**: CC3, CC6

Use the `tracing` crate for structured logging and span-based instrumentation from the first line of code. Every subsystem emits structured events with timing, counts, and error context. Key metrics: parse time per language, detection time per category, cache hit rates, NAPI serialization time, MCP response time.

### AD11: Taint Analysis Foundation (NEW)

**Priority**: P0 | **Impact**: Security detection, call graph | **Evidence**: §33, §4.2 | **Audit**: SA2, RC-G14, Non-Negotiable #15

Build taint analysis as a first-class subsystem, not an afterthought:
1. Source/sink/sanitizer registry (TOML-configurable, per-framework defaults)
2. Intraprocedural taint tracking in Rust (Phase 1)
3. Interprocedural via call graph taint summaries (Phase 2)

### AD12: Bayesian Convention Learning (NEW)

**Priority**: P0 | **Impact**: Confidence scoring, pattern detection | **Evidence**: §37, §5.4 | **Audit**: DM3, Non-Negotiable #10

Replace binary 60% threshold with Beta distribution posterior probability. Prior: Beta(1,1). After observing k of n files: posterior = Beta(1+k, 1+n-k). Credible interval width naturally encodes sample size — eliminates need for separate minimum file thresholds.

---

## Part 2: Category-Specific Recommendations

### Rust Core (Category 01)

| # | Recommendation | Priority | Evidence | Audit Gap |
|---|---------------|----------|----------|-----------|
| RC1 | Scanner with incremental change detection (content hash, skip unchanged) | P0 | §1.1 | RC-G1, CC1 |
| RC2 | Parser layer with rich extraction (everything in one pass per file) | P0 | §2.1, §2.2 | RC-G3 |
| RC3 | String interning with `lasso` crate (ThreadedRodeo for build, RodeoReader for query) | P0 | §16.1 | — |
| RC4 | Unified analyzer with declarative patterns (tree-sitter queries + TOML config) | P0 | §3.4, §39 | RC-G4 |
| RC5 | Enterprise-grade secret detection (100+ patterns, Shannon entropy, contextual scoring) | P0 | §9.2, §35 | RC-G9, SA1 |
| RC6 | Call graph with full 6-strategy resolution algorithm | P0 | §4.1 | CG-G3 |
| RC7 | Coupling analyzer with Tarjan's SCC + zone classification + module roles | P1 | §4.1, §17.1 | RC-G8 |
| RC8 | Boundary analysis with ORM extractors + risk scoring (28+ ORMs) | P1 | Recap §21 | — |
| RC9 | Environment analyzer with .env cross-referencing + missing variable detection | P1 | Recap §5 | RC-G10 |
| RC10 | Error handling analyzer with propagation chain tracking (source → sink) | P1 | Recap §19 | RC-G11 |
| RC11 | Test topology with quality scoring (35+ frameworks, 8 languages) | P1 | Recap §17 | — |
| RC12 | Reachability with taint analysis foundation (intraprocedural first) | P1 | §4.2, §33 | RC-G14 |
| RC13 | Wrapper detector with multi-framework registry (not just React) | P2 | Recap §1 | RC-G12 |
| RC14 | Constants analyzer with fuzzy matching + dead constant detection | P2 | Recap §1 | — |
| RC15 | N-API bridge with batch and streaming support (parse_batch, stream results) | P0 | §16.5, §12.1 | PB3 |
| RC16 | Rayon parallelism with thread_local cleanup between scans | P1 | §16.4 | — |
| RC17 | Performance-optimized data structures (FxHashMap, SmallVec, xxhash) | P1 | Recap §4 | — |
| RC18 | Cross-service reachability for microservice architectures (NEW) | P2 | Recap §7 | RC-G13 |
| RC19 | Dependency graph building in Rust (currently TS-only) (NEW) | P1 | Recap §4 | RC-G2 |
| RC20 | Violation system fully populated and enforced (currently dead code) (NEW) | P1 | Audit §12 | TD2 |

### Parsers (Category 02)

| # | Recommendation | Priority | Evidence | Audit Gap |
|---|---------------|----------|----------|-----------|
| PA1 | Incremental parse cache (Moka, content-addressed, durable across restarts) | P0 | §16.2, §2.2 | PA-G7, CC1 |
| PA2 | Single canonical ParseResult shape (Rust-defined, NAPI-serialized, TS-consumed) | P0 | AD2 | PA-G8, A3 |
| PA3 | Structured decorator/annotation extraction (name + parsed arguments) | P0 | §2.4 | PA-G3 |
| PA4 | Pydantic model extraction in Rust (v1/v2 detection, type resolution with cycle detection) | P0 | §2.3 | PA-G2 |
| PA5 | Consolidated tree-sitter queries (2-4x fewer traversals via alternations) | P1 | §2.2 | PB1 |
| PA6 | Trait-based LanguageParser architecture (one trait per language) | P1 | Recap §5 | — |
| PA7 | Namespace/package extraction for all 10 languages | P1 | Recap §5 | PA-G5 |
| PA8 | NAPI batch/streaming APIs (amortize per-call overhead) | P1 | §16.5 | PB3 |
| PA9 | Error-tolerant extraction (handle tree-sitter error nodes gracefully) | P1 | §2.2 | — |
| PA10 | Generic type parameter extraction (generics, bounded types) | P1 | Recap §5 | PA-G1 |
| PA11 | Thread-safe parser pool (thread_local with cleanup, compiled queries reused) | P1 | §16.4 | — |
| PA12 | Framework construct extraction as composable extension layer | P2 | Recap §5 | — |
| PA13 | Structured error types with thiserror (per-language error variants) | P0 | AD6, §40 | CC2 |
| PA14 | Language addition scaffold (macro/codegen for adding new languages) | P2 | Recap §5 | — |
| PA15 | Full inheritance chain resolution in Rust (multi-level, not just direct) (NEW) | P1 | Recap §5 | PA-G4 |
| PA16 | Incremental parsing via tree.edit() for IDE integration (NEW) | P2 | §2.2 | PA-G6 |

### Detectors (Category 03)

| # | Recommendation | Priority | Evidence | Audit Gap |
|---|---------------|----------|----------|-----------|
| DE1 | Single-pass visitor pattern for detection (ESLint-style) | P0 | AD4, §3.2 | PB1, DE-G1 |
| DE2 | Incremental detection with content-hash skipping | P0 | §1.2 | DE-G2, CC1 |
| DE3 | Temporal confidence decay + momentum scoring | P0 | AD8, §5.2 | DE-G5 |
| DE4 | Generic AST normalization layer (GAST) for language-agnostic detection | P1 | §2.1 | — |
| DE5 | Effective false-positive tracking + feedback loop (Tricorder-style) | P0 | AD9, §3.1 | DE-G9 |
| DE6 | Outlier detection refinements (Z=2.5, min n=10, Grubbs' for n=10-30) | P1 | §5.3 | — |
| DE7 | OWASP/CWE-aligned security detection (map detectors to CWE IDs) | P1 | §9.1, §34 | SA4 |
| DE8 | Contract detection expansion (GraphQL schemas, gRPC protobuf, OpenAPI specs) | P1 | §13.1, §13.2 | DE-G12 |
| DE9 | Bayesian convention learning (replace binary 60% threshold with graduated confidence) | P0 | AD12, §37 | DM3 |
| DE10 | Suggested fixes as first-class output (7 fix strategies with confidence) | P1 | §3.1 | — |
| DE11 | Framework detection as composable middleware (easy to add new frameworks) | P2 | Recap §3 | — |
| DE12 | Detector testing and validation framework (golden file tests, regression suite) | P1 | §3.1 | — |
| DE13 | Pattern merging for similar/overlapping patterns (NEW) | P1 | Recap §6 | DE-G6 |
| DE14 | Call graph integration for cross-function pattern analysis (NEW) | P1 | Recap §6 | DE-G7 |
| DE15 | Data flow integration for security detection (NEW) | P1 | §3.3, §33 | DE-G8 |
| DE16 | Full framework coverage: Django learning/semantic, Go/Rust/C++ expansion (NEW) | P2 | Recap §6 | DE-G10, DE-G11 |

### Call Graph (Category 04)

| # | Recommendation | Priority | Evidence | Audit Gap |
|---|---------------|----------|----------|-----------|
| CG1 | Per-language hybrid extractors in Rust (8 languages × standard + data-access) | P0 | Recap §7 | CG-G1 |
| CG2 | Full 6-strategy resolution algorithm in Rust (same-file, method, DI, import, export, fuzzy) | P0 | Recap §7 | CG-G3 |
| CG3 | Impact analysis engine in Rust (forward/reverse impact, affected file count) | P1 | Recap §7 | CG-G2 |
| CG4 | Dead code detection in Rust (unreachable functions, unused exports) | P1 | Recap §7 | CG-G2 |
| CG5 | Incremental call graph updates (only rebuild affected subgraphs) | P1 | §1.1 | CG-G4 |
| CG6 | Enrichment pipeline (sensitivity classification, impact scoring, remediation) | P1 | Recap §7 | — |
| CG7 | Cross-service reachability (microservice API calls, HTTP/gRPC boundaries) | P2 | Recap §7 | CG-G6 |
| CG8 | In-memory graph with petgraph (StableGraph synced with SQLite) | P1 | §16.3 | — |
| CG9 | Polymorphism support in Rust (virtual dispatch, interface implementations) (NEW) | P1 | Recap §7 | CG-G7 |
| CG10 | DI resolution in Rust (FastAPI Depends, Spring @Autowired, NestJS @Inject) (NEW) | P1 | Recap §7 | CG-G8 |

### Analyzers (Category 05)

| # | Recommendation | Priority | Evidence | Audit Gap |
|---|---------------|----------|----------|-----------|
| AN1 | Unified language provider with 20 ORM matchers migrated to Rust | P1 | Recap §8 | AN-G9 |
| AN2 | Rules engine with deduplication, limits, blocking detection in Rust | P1 | Recap §8 | AN-G10 |
| AN3 | Quick fix generator (7 strategies) exposed via NAPI | P1 | Recap §8 | — |
| AN4 | Severity manager with 4-level resolution + escalation rules | P1 | Recap §8 | — |
| AN5 | Variant manager with scoped overrides (global/directory/file) | P2 | Recap §8 | — |
| AN6 | Basic intraprocedural data flow analysis (constant propagation, taint tracking) | P1 | §3.3, §18.3, §33 | AN-G11, AN-G12 |
| AN7 | Generic scope tree in Rust (per-language extractors populate, language-agnostic analysis) | P1 | §18.2 | — |
| AN8 | Type inference framework using union-find (ena crate) for cross-expression type tracking | P2 | §18.1 | AN-G3 |
| AN9 | CFG construction from normalized IR (not directly from tree-sitter AST) | P1 | §18.3 | — |
| AN10 | Forward/backward dataflow framework as generic Rust algorithms | P1 | §18.3 | AN-G5 |
| AN11 | Shadowed variable detection via scope tree walk-up | P1 | §18.2 | — |
| AN12 | Unreachable code detection via CFG dead-edge analysis | P2 | §18.3 | — |
| AN13 | Null dereference detection via forward dataflow (null propagation tracking) | P2 | §18.3 | — |
| AN14 | Per-language lowering to normalized IR (separate from analysis algorithms) | P1 | §18.1 | — |
| AN15 | Core analyzers (AST, Type, Semantic, Flow) migrated to Rust (NEW) | P1 | Recap §8 | AN-G1 |
| AN16 | Cross-file data flow analysis via call graph integration (NEW) | P2 | §33 | AN-G11 |

### Cortex Memory (Category 06)

| # | Recommendation | Priority | Evidence | Audit Gap |
|---|---------------|----------|----------|-----------|
| CX1 | Hybrid search: FTS5 + sqlite-vec with RRF fusion | P0 | §6.2 | CX-G2 |
| CX2 | Code-specific embedding model (Jina Code 0.5B, 896-dim, Apache 2.0) | P0 | §6.3, §38 | CX-G1, CX-G12 |
| CX3 | Rust embedding inference via ort crate (3-5x speedup over Transformers.js) | P1 | §6.4 | PB6 |
| CX4 | Two-phase memory pipeline (extraction → dedup/update before storage) | P1 | §6.1 | — |
| CX5 | Retrieval-difficulty-based consolidation triggers (not just time-based) | P1 | §6.5 | — |
| CX6 | Embedding enrichment (prepend type, category, file paths before embedding) | P1 | §17.3 | — |
| CX7 | Re-ranking stage after initial retrieval (cross-encoder or lightweight scorer) | P1 | §6.7 | — |
| CX8 | Accurate token counting via tiktoken-rs (replace string-length approximation) | P1 | §6.8 | CX-G4 |
| CX9 | Graph-based memory representation (petgraph for causal graph, entity relationships) | P2 | §6.6, §16.3 | CX-G6 |
| CX10 | DAG enforcement in causal system (cycle detection, counterfactual queries) | P2 | §6.6 | CX-G7 |
| CX11 | Memory observability (retrieval effectiveness, token efficiency, quality trends) | P2 | §17.4 | — |
| CX12 | Evidence-based memory promotion (not just time-based consolidation) | P2 | §17.2 | — |
| CX13 | PII detection expansion (50+ patterns, connection strings, base64) | P1 | §9.3 | CX-G5, SA3 |
| CX14 | Matryoshka embedding strategy: store 896-dim, search at 256-dim, re-rank at full (NEW) | P1 | §38 | CX-G12 |
| CX15 | Memory type consolidation from 23 to ~15 types (merge overlapping) (NEW) | P1 | Audit §5 | DM5 |
| CX16 | Air-gapped consolidation fallback (rule-based, no LLM dependency) (NEW) | P1 | Recap §9 | CX-G3 |

### MCP Server (Category 07)

| # | Recommendation | Priority | Evidence | Audit Gap |
|---|---------------|----------|----------|-----------|
| MC1 | Split into drift-analysis + drift-memory servers | P0 | AD5, §7.1 | A5, MC-G3 |
| MC2 | Progressive disclosure (3 entry points per server, not 17-20 tools) | P0 | §7.3 | MC-G2 |
| MC3 | Tool description optimization (reduce schema verbosity by 60-70%) | P1 | §7.2 | MC-G1 |
| MC4 | Workflow-oriented tools (drift_context handles 80% of queries) | P1 | §7.3, §19.1 | — |
| MC5 | Shared database coordination (drift.db + cortex.db, no server-to-server RPC) | P1 | §7.5 | — |
| MC6 | Response caching with content-hash invalidation (tool_name + params_hash + db_hash) | P1 | §19.2 | PB5 |
| MC7 | Token estimation in responses via tiktoken-rs (help AI budget context window) | P1 | §19.2, §6.8 | — |
| MC8 | Security separation (analysis=read-only/low-risk, memory=read-write/higher-risk) | P1 | §7.4 | SA5 |
| MC9 | Consistent JSON response schemas across all tools (structured, parseable) | P1 | §19.1 | — |
| MC10 | Workflow tools combining related operations (drift_analyze_function = signature + callers + callees + impact) | P1 | §19.1 | — |
| MC11 | Built-in pagination with cursor support for all list operations | P1 | §19.1 | SC3 |
| MC12 | Streaming responses for large result sets (pattern lists, call graph traversals) | P2 | §19.2 | MC-G4, SC4 |
| MC13 | Per-tool configurable rate limits (token-based, not request-count) | P2 | §19.2 | — |
| MC14 | Tool packs: pre-configured tool subsets for common workflows (security audit, code review, onboarding) | P2 | Recap §10 | — |
| MC15 | Optional authentication for MCP server (token-based access control) (NEW) | P2 | §7.4 | SA5 |
| MC16 | Cortex facade pattern: MCP tools call facade, not internal APIs directly (NEW) | P1 | Audit §10 | IC4 |

### Storage (Category 08)

| # | Recommendation | Priority | Evidence | Audit Gap |
|---|---------------|----------|----------|-----------|
| ST1 | Consolidate to 2 databases: drift.db (Rust-owned) + cortex.db (TS-owned) | P0 | Recap §11 | A4 |
| ST2 | WAL mode + NORMAL sync + 256MB mmap on all databases | P0 | AD7, §8.1 | — |
| ST3 | Prepared statement caching for repeated queries | P1 | §8.1 | ST-G2 |
| ST4 | Batch writes within single transactions (not per-row commits) | P1 | §8.1 | — |
| ST5 | Schema migration with rollback support (sequential, versioned) | P1 | Recap §26 | ST-G4 |
| ST6 | FTS5 indexes on cortex.db for hybrid search | P1 | §6.2 | — |
| ST7 | Content-hash-based cache invalidation for query results | P1 | §1.2 | — |
| ST8 | ATTACH DATABASE for cross-db queries (cortex reads from drift.db) | P2 | Recap §11 | ST-G5 |
| ST9 | Data integrity validation (periodic consistency checks, integrity_check on startup) (NEW) | P1 | Audit §8 | ST-G7, RE4 |
| ST10 | Configurable retention policies (daily/weekly/monthly for enterprise) (NEW) | P2 | Recap §26 | ST-G6 |

### Quality Gates (Category 09)

| # | Recommendation | Priority | Evidence | Audit Gap |
|---|---------------|----------|----------|-----------|
| QG1 | Transparent gates: rationale + suggested fix + documentation link per violation | P0 | §10.1 | — |
| QG2 | SARIF output enriched with CWE IDs, code flows, fix objects | P1 | §10.2, §34 | QG-G2 |
| QG3 | GitHub/GitLab PR annotations with inline fix suggestions | P1 | §10.2 | QG-G3 |
| QG4 | Policy engine with 4 built-in policies (default, strict, relaxed, ci-fast) | P1 | Recap §12 | — |
| QG5 | KPI dashboard: pattern compliance rate, convention drift velocity, health trends | P2 | §10.1 | QG-G4 |
| QG6 | Pre-merge simulation (impact analysis + quality gate dry-run) | P2 | §15.2 | — |
| QG7 | SQLite-backed snapshot storage (replace JSON-based) (NEW) | P1 | Audit §3 | QG-G1 |
| QG8 | Gate dependency ordering in parallel executor (NEW) | P2 | Audit §3 | QG-G5 |

### CLI (Category 10)

| # | Recommendation | Priority | Evidence | Audit Gap |
|---|---------------|----------|----------|-----------|
| CL1 | Rust-first execution via clap derive macros (native binary, no Node.js for core commands) | P1 | §20.1 | CL-G1 |
| CL2 | Incremental scan command (only re-analyze changed files) | P0 | AD1 | CL-G3 |
| CL3 | Interactive setup wizard generating both MCP server configs | P1 | AD5 | — |
| CL4 | Rayon replaces Piscina for all CPU-bound parallel work (parsing, detection, analysis) | P0 | §20.2 | CL-G2 |
| CL5 | Git integration: staged-file scanning, pre-commit/pre-push hooks | P1 | Recap §13 | — |
| CL6 | Pluggable reporters (text, JSON, SARIF, GitHub, GitLab) | P1 | §10.2 | — |
| CL7 | Nested subcommands via clap (e.g., `drift call-graph build`, `drift memory search`) | P1 | §20.1 | — |
| CL8 | Shell completion generation for bash/zsh/fish/PowerShell | P2 | §20.1 | — |
| CL9 | Environment variable fallbacks for all config options (CI-friendly) | P1 | §20.1 | — |
| CL10 | `--format` flag on all output commands (text/json/sarif) with consistent schemas | P1 | §20.1 | — |
| CL11 | Progress reporting with ETA for long scans (file count, parse rate, detection rate) | P1 | Recap §13 | SC4 |
| CL12 | Hybrid architecture: core commands native Rust, advanced commands (setup wizard, memory) in TS via NAPI | P1 | §20.1 | — |
| CL13 | `drift taint` command for on-demand taint analysis of specific functions (NEW) | P2 | §33 | SA2 |
| CL14 | `drift secrets` command for standalone secret scanning with entropy analysis (NEW) | P1 | §35 | SA1 |

### IDE (Category 11)

| # | Recommendation | Priority | Evidence | Audit Gap |
|---|---------------|----------|----------|-----------|
| ID1 | LSP server leveraging Rust core for heavy computation (thin TS protocol layer) | P1 | §11.1, §21.2 | ID-G1 |
| ID2 | Phased activation (register capabilities progressively, don't block on startup) | P1 | §11.1, §21.1 | — |
| ID3 | Real-time pattern violation highlighting via LSP publishDiagnostics | P1 | §21.2 | ID-G2 |
| ID4 | Code actions for quick fixes (7 strategies as WorkspaceEdit objects) | P1 | §21.2 | — |
| ID5 | Hover information showing pattern details, confidence scores, and rationale | P1 | §21.2 | — |
| ID6 | Code lenses showing function-level metrics (coupling, complexity, test coverage) | P2 | §21.2 | — |
| ID7 | Lazy activation on specific events only (onLanguage, onCommand), never `*` | P0 | §21.1 | — |
| ID8 | Bundle with esbuild for single-file distribution (reduce load time) | P1 | §21.1 | — |
| ID9 | FileSystemWatcher API for file change detection (not polling) | P1 | §21.1 | — |
| ID10 | Tree views: patterns, violations, files, constants (Redux-like state) | P2 | Recap §14 | — |
| ID11 | Webview dashboard with pattern trends and health metrics | P2 | Recap §14 | — |
| ID12 | Workspace symbols for pattern and constraint navigation | P2 | §21.2 | — |
| ID13 | Extension profiling integration (detect and report own performance impact) | P2 | §21.1 | — |
| ID14 | Taint analysis results as inline diagnostics with code flow visualization (NEW) | P2 | §33 | SA2 |

### Infrastructure (Category 12)

| # | Recommendation | Priority | Evidence | Audit Gap |
|---|---------------|----------|----------|-----------|
| IN1 | NAPI-RS v3 for cross-compilation (7+ platform targets from single CI) | P0 | §12.1 | — |
| IN2 | Turborepo task graph integrating Rust compilation with caching | P1 | §12.2 | — |
| IN3 | Affected-only CI execution (only test/build changed packages) | P1 | §12.2 | — |
| IN4 | Docker multi-stage build for containerized MCP server | P1 | Recap §15 | — |
| IN5 | Pre-compiled binary distribution via npm scope packages | P1 | §12.1 | — |
| IN6 | CIBench benchmark framework for performance regression detection | P2 | Recap §15 | — |
| IN7 | WebAssembly target via NAPI-RS v3 for browser-based Drift (future) (NEW) | P3 | §12.1 | — |
| IN8 | CI matrix testing across all 7 platform targets with automated regression (NEW) | P1 | Audit §14 | — |

### Advanced Systems (Category 13)

| # | Recommendation | Priority | Evidence | Audit Gap |
|---|---------------|----------|----------|-----------|
| AV1 | DNA system: 10 gene extractors migrated to Rust with structural fingerprinting | P2 | §15.1, §29.1 | AV-G1 |
| AV2 | Simulation engine integrated with call graph for precise impact analysis | P2 | §15.2, §29.3 | AV-G2 |
| AV3 | Decision mining from git history via git2 crate (NLP heuristics for decision extraction) | P3 | §29.2 | AV-G3 |
| AV4 | DORA-adjacent metrics: compliance rate, drift velocity, health trends | P3 | §15.1 | — |
| AV5 | DNA: add structural fingerprinting based on normalized AST features (not just pattern matching) | P2 | §29.1 | AV-G1 |
| AV6 | DNA: embedding-based similarity for cross-codebase comparison | P3 | §29.1 | — |
| AV7 | DNA: track gene evolution over time (mutation detection with temporal analysis) | P2 | §29.1 | — |
| AV8 | DNA: add backend genes for database access, authentication, logging, configuration patterns | P2 | §29.1 | — |
| AV9 | Simulation: multi-dimension scoring (convention alignment, test coverage impact, security, architecture, complexity) | P2 | §29.3 | — |
| AV10 | Simulation: sub-second execution using pre-computed indexes (call graph, pattern index, test mapping) | P2 | §29.3 | — |
| AV11 | Decision mining: link decisions to code locations via diff analysis | P3 | §29.2 | — |
| AV12 | Decision mining: detect ADRs in documentation and link to code | P3 | §29.2 | — |
| AV13 | Language intelligence: framework detection registry with composable matchers | P2 | Recap §16 | AV-G4 |

### Specialized Analysis (Categories 17-22)

| # | Recommendation | Priority | Evidence | Audit Gap |
|---|---------------|----------|----------|-----------|
| SP1 | Test topology: 35+ framework detection with 4-strategy test-to-code mapping (naming, imports, call graph, co-change) | P1 | §22.1 | — |
| SP2 | Test topology: produce test-to-source mapping file usable by CI systems (selective test execution) | P1 | §22.1 | — |
| SP3 | Test topology: quality scoring with convention consistency dimension + anti-pattern detection | P1 | §22.2 | — |
| SP4 | Test topology: minimum test set calculation using call-graph-based coverage mapping | P1 | §22.1 | — |
| SP5 | Test topology: detect framework migration patterns (Jest → Vitest) | P2 | §22.2 | — |
| SP6 | Constraints: 12 invariant types mapped to specific verification strategies (dependency graph, call graph, AST, data flow) | P1 | §30.1 | CN-G1 |
| SP7 | Constraints: change-aware verification (only verify constraints affected by current change) | P1 | §30.1 | — |
| SP8 | Constraints: declarative constraint format (TOML/YAML) that can be version-controlled | P1 | §30.1 | — |
| SP9 | Constraints: constraint inheritance (package-level constraints inherited by sub-packages) | P2 | §30.1 | — |
| SP10 | Error handling: error chain tracking linking manifestation location to fix location | P1 | §23.1 | — |
| SP11 | Error handling: cross-function chain detection via call graph integration | P1 | §23.1 | — |
| SP12 | Error handling: classify chains by type (exception, null, resource) with priority scoring | P1 | §23.1 | — |
| SP13 | Error handling: detect anti-patterns (empty catch, catch-and-rethrow, swallowed errors, overly broad catch) | P1 | §23.2 | — |
| SP14 | Error handling: map error boundaries to call graph to identify unprotected code paths | P2 | §23.2 | — |
| SP15 | Contracts: GraphQL schema parsing (.graphql files + SDL in code) + breaking change detection | P1 | §13.1, §31.1 | DE-G12 |
| SP16 | Contracts: gRPC protobuf parsing (.proto files) + breaking change detection | P1 | §13.2, §31.2 | DE-G12 |
| SP17 | Contracts: OpenAPI/Swagger spec parsing as first-class contract source | P1 | §13.1 | — |
| SP18 | Contracts: classify changes as breaking/non-breaking/deprecation across all protocols | P1 | §31.1, §31.2 | — |
| SP19 | Contracts: frontend usage detection for GraphQL (useQuery/useMutation) and gRPC (generated stubs) | P2 | §31.1, §31.2 | — |
| SP20 | Security: expand learn-then-detect to 40+ ORM frameworks | P1 | §24.1 | — |
| SP21 | Security: add unsafe API detection per ORM (raw SQL bypass patterns) | P1 | §24.2, §33.2 | — |
| SP22 | Security: cross-reference sensitive fields with data access points for unprotected access detection | P1 | §24.2 | — |
| SP23 | Security: OWASP Top 10 2025 coverage (9/10), CWE ID mapping per detector | P1 | §9.1, §34 | SA4 |
| SP24 | Security: track sensitive data flow through call graph (source → sink taint analysis) | P1 | §24.2, §33 | SA2 |
| SP25 | Context generation: place highest-importance context first (primacy bias — 3x weight in first 25%) | P1 | §25.1 | — |
| SP26 | Context generation: adaptive budgeting based on query intent (security queries get more security context) | P1 | §25.1 | — |
| SP27 | Context generation: context quality metrics (was context used? did it lead to correct output?) | P2 | §25.1 | — |
| SP28 | Context generation: scope pattern analysis per package, not just per repository | P1 | §25.2 | — |
| SP29 | Context generation: workspace root detection for all 11+ ecosystems | P1 | §25.2 | — |
| SP30 | Constraints: AST-based verification (replace regex-based) (NEW) | P1 | Audit §3 | CN-G2 |
| SP31 | Constraints: call graph integration in verifier (NEW) | P1 | Audit §3 | CN-G3 |
| SP32 | Constraints: data flow integration for data flow constraints (NEW) | P1 | Audit §3 | CN-G4 |
| SP33 | Constraints: cross-file verification for module-level invariants (NEW) | P1 | Audit §3 | CN-G5 |
| SP34 | Security: cryptographic failure detection (weak algorithms, insecure modes) (NEW) | P1 | §34 | OWASP A02 |

### Data Infrastructure (Categories 23-26)

| # | Recommendation | Priority | Evidence | Audit Gap |
|---|---------------|----------|----------|-----------|
| DI1 | Pattern repository: single IPatternRepository with SQLite backend + event sourcing for lifecycle | P1 | §26.1 | — |
| DI2 | Pattern repository: append-only event log (PatternDiscovered, Approved, Ignored, ConfidenceUpdated, Merged, Archived) | P1 | §26.1 | — |
| DI3 | Pattern repository: temporal queries for pattern evolution tracking ("when was this discovered?") | P2 | §26.1 | — |
| DI4 | Pattern repository: event log feeds DNA mutation detection and audit trails | P2 | §26.1 | — |
| DI5 | Data lake: DEPRECATED — replaced by SQLite views and indexes | P0 | Recap §24 | TD11 |
| DI6 | Services layer: rayon parallel iterators replace Piscina for scan pipeline | P0 | §27.1 | — |
| DI7 | Services layer: streaming pipeline (parse as files discovered, detect as files parsed) | P1 | §27.1 | SC4 |
| DI8 | Services layer: crossbeam channels for pipeline stage communication | P1 | §27.1 | — |
| DI9 | Services layer: DashMap for concurrent pattern counting during aggregation | P1 | §27.1 | — |
| DI10 | Workspace: SQLite Online Backup API for WAL-mode safe backups (not file copy) | P1 | §28.2 | — |
| DI11 | Workspace: user_version pragma for schema version tracking (atomic, no separate table) | P1 | §28.1 | — |
| DI12 | Workspace: savepoints for partial rollback within multi-step migrations | P1 | §28.1 | — |
| DI13 | Workspace: backup verification (restore to temp, run integrity check) | P1 | §28.2 | — |
| DI14 | Workspace: configurable retention policies (daily/weekly/monthly for enterprise) | P2 | §28.2 | — |
| DI15 | Workspace: multi-project registry with health indicators (last scan, pattern count, error count) | P2 | §28.2 | — |
| DI16 | Workspace: context pre-loading for frequently accessed projects | P2 | §28.2 | — |
| DI17 | Remove all JSON file storage, hybrid stores, and SyncService (NEW) | P0 | Audit §12 | TD8-TD12 |
| DI18 | Remove duplicate type definitions between call_graph and reachability modules (NEW) | P1 | Audit §12 | TD7, DM2 |

---

## Part 3: New Research Area Recommendations

These recommendations are derived from the 8 new research areas (§33-40) in MASTER-RESEARCH-V2.md. They represent capabilities that were not covered in the original MASTER-RECOMMENDATIONS.md and address the most critical audit gaps.

### Taint Analysis (§33)

| # | Recommendation | Priority | Evidence | Audit Gap |
|---|---------------|----------|----------|-----------|
| NR1 | Build source/sink/sanitizer registry as TOML configuration with per-framework defaults for all 28+ ORMs and 10 languages | P0 | §33.2 | SA2, RC-G14 |
| NR2 | Implement intraprocedural taint tracking in Rust: for each function, build mini data-flow graph, track taint through assignments and calls | P1 | §33.1 | AN-G12 |
| NR3 | Produce taint summaries per function (which parameters taint which return values) for interprocedural analysis | P1 | §33.1 | CG-G5 |
| NR4 | Implement interprocedural taint analysis via call graph: use taint summaries + call graph to propagate taint across function boundaries | P2 | §33.1, §4.2 | — |
| NR5 | Detect SQL injection via taint: track from HTTP request parameters → ORM raw methods / SQL string construction | P1 | §33.2 | OWASP A04 |
| NR6 | Detect XSS via taint: track from user input → innerHTML / template rendering without encoding | P1 | §33.2 | OWASP A04 |
| NR7 | Detect SSRF via taint: track from user input → HTTP client URL construction | P1 | §33.2 | OWASP A10 |
| NR8 | Detect path traversal via taint: track from user input → file system path construction | P1 | §33.2 | OWASP A04 |

### OWASP 2025 Alignment (§34)

| # | Recommendation | Priority | Evidence | Audit Gap |
|---|---------------|----------|----------|-----------|
| NR9 | Map every security detector to specific CWE ID(s) in detector definition metadata | P1 | §34.1 | SA4, QG-G2 |
| NR10 | Add A03 (Software Supply Chain) detection: dependency file analysis for known vulnerable patterns, lockfile integrity checks | P1 | §34 | OWASP A03 |
| NR11 | Add A02 (Cryptographic Failures) detection: weak algorithm patterns (MD5, SHA1 for security), insecure cipher modes (ECB), hardcoded IVs | P1 | §34 | OWASP A02 |
| NR12 | Build OWASP coverage dashboard showing which categories are covered, which CWEs are mapped, and gap analysis | P2 | §34.1 | — |
| NR13 | Address OWASP Agentic Top 10 for MCP server: input validation on all tool parameters, memory poisoning prevention, tool use authorization | P2 | §9.1 | SA5 |

### Enterprise Secret Detection (§35)

| # | Recommendation | Priority | Evidence | Audit Gap |
|---|---------------|----------|----------|-----------|
| NR14 | Implement Shannon entropy calculation in Rust with per-charset thresholds (base64 > 4.5, hex > 3.0, general > 4.0) | P0 | §35.1 | SA1, RC-G9 |
| NR15 | Add 25+ cloud provider secret patterns (Azure, GCP, GitHub, GitLab, Slack, npm, PyPI, Stripe, Twilio, SendGrid, Databricks, MongoDB, Redis, Elasticsearch, Vault, JWT, PEM) | P0 | §35.2 | SA1 |
| NR16 | Implement contextual scoring: variable name sensitivity check × entropy score × file context (test file penalty, placeholder exclusion) | P1 | §35.1 | — |
| NR17 | Add connection string parsing for embedded credentials (MongoDB, PostgreSQL, MySQL, Redis, MSSQL) | P1 | §35.2 | SA3 |
| NR18 | Add base64-encoded secret detection: decode candidate strings, check decoded content against secret patterns | P2 | §9.3 | SA3 |

### Observability & Structured Logging (§36)

| # | Recommendation | Priority | Evidence | Audit Gap |
|---|---------------|----------|----------|-----------|
| NR19 | Instrument all Rust subsystems with `tracing` crate: `#[instrument]` on key functions, structured fields for timing and counts | P0 | §36.1 | CC3 |
| NR20 | Define key metrics per subsystem: parse_time_per_language, detection_time_per_category, cache_hit_rate, napi_serialization_time, mcp_response_time | P1 | §36.1 | CC3 |
| NR21 | Expose performance counters via NAPI to TypeScript for MCP tool response metadata and CLI progress reporting | P1 | §36.1 | CC6 |
| NR22 | Implement configurable log levels per subsystem (e.g., `DRIFT_LOG=parser=debug,detector=info`) | P1 | §36.1 | — |
| NR23 | Optional OpenTelemetry integration for enterprise distributed tracing (spans exported to Jaeger/Zipkin) | P3 | §36.1 | CC6 |

### Bayesian Convention Learning (§37)

| # | Recommendation | Priority | Evidence | Audit Gap |
|---|---------------|----------|----------|-----------|
| NR24 | Implement Beta distribution posterior calculation: prior Beta(1,1), posterior Beta(1+k, 1+n-k) for each pattern | P0 | §37.1 | DM3 |
| NR25 | Define graduated confidence tiers based on posterior credible interval width: Established (mean>0.7, CI<0.15), Emerging (mean>0.5, CI<0.25), Tentative (mean>0.3, CI<0.40), Uncertain (else) | P0 | §37.1 | — |
| NR26 | Integrate Bayesian posterior with momentum scoring: final_score = posterior_mean × 0.70 + consistency × 0.15 + momentum × 0.15 | P0 | §37.1, §5.2 | — |
| NR27 | Store posterior parameters (α, β) per pattern in SQLite for incremental updates without full recalculation | P1 | §37.1 | — |

### Code Embedding Models (§38)

| # | Recommendation | Priority | Evidence | Audit Gap |
|---|---------------|----------|----------|-----------|
| NR28 | Select Jina Code 0.5B as primary local embedding model (896-dim, Apache 2.0, ONNX-exportable, 78.41% avg on code retrieval benchmarks) | P0 | §38.1 | CX-G1 |
| NR29 | Implement Matryoshka embedding strategy: store full 896-dim, use 256-dim truncation for fast initial search, re-rank top-K with full dimensions | P1 | §38.1 | CX-G12 |
| NR30 | Provide pluggable embedding provider: local (Jina Code 0.5B via ort), API (VoyageCode3 or OpenAI), fallback (CodeRankEmbed 137M for resource-constrained) | P1 | §38.1 | — |

### Declarative Pattern Definitions (§39)

| # | Recommendation | Priority | Evidence | Audit Gap |
|---|---------------|----------|----------|-----------|
| NR31 | Define TOML pattern format with fields: id, name, language, category, subcategory, severity, description, query (tree-sitter), metadata (framework, min_confidence, cwe_ids, tags) | P0 | §39.1 | Non-Negotiable #13 |
| NR32 | Implement graduated complexity levels: (1) Simple node match, (2) Structural parent-child with fields, (3) Predicate content matching, (4) Cross-reference with relationship constraints | P1 | §39.1 | — |

---

## Part 4: Build Phases (Updated)

The build phases have been updated to incorporate new research areas (§33-40) and audit findings. Key changes from v1: taint analysis foundation added to Phase 3, observability added to Phase 1, Bayesian scoring added to Phase 2, secret detection expanded in Phase 2, OWASP alignment added to Phase 8.

```
Phase 0 — Architectural Decisions (before code)
  Duration: 1-2 weeks
  Deliverables:
  • AD1-AD12 documented and agreed upon
  • Rust crate structure defined (with taint analysis module placeholder)
  • TypeScript package structure defined
  • SQLite schema v1 designed (including posterior parameters for Bayesian scoring)
  • CI/CD pipeline configured
  • TOML pattern definition format finalized (NR31)
  • Source/sink/sanitizer registry format defined (NR1)
  • tracing infrastructure scaffolded (NR19)
  • Embedding model selected and ONNX export validated (NR28)

Phase 1 — Core Engine (Rust)
  Duration: 4-6 weeks
  Dependencies: Phase 0
  Deliverables:
  • Scanner with incremental change detection (RC1)
  • Parser layer with rich extraction for 10 languages (RC2, PA1-PA11, PA13, PA15)
  • String interning with lasso (RC3)
  • Unified analyzer with declarative patterns (RC4, NR31, NR32)
  • Content-hash-based parse cache with Moka (PA1)
  • N-API bridge with batch/streaming (RC15)
  • SQLite storage with WAL mode (ST1, ST2, ST9)
  • Structured error handling with thiserror (AD6, PA13)
  • tracing instrumentation on all core functions (NR19, NR20)
  • Dependency graph building in Rust (RC19)

Phase 2 — Pattern Detection (Rust)
  Duration: 3-4 weeks
  Dependencies: Phase 1
  Deliverables:
  • Visitor pattern detection engine (DE1)
  • Bayesian confidence scoring with Beta distribution (NR24, NR25, NR26)
  • Momentum-aware temporal scoring (DE3, AD8)
  • Outlier detection with refined statistics (DE6)
  • Convention learning with graduated confidence tiers (DE9, AD12)
  • Enterprise secret detection (100+ patterns, Shannon entropy) (RC5, NR14, NR15, NR16)
  • Incremental detection with hash skipping (DE2)
  • Feedback loop infrastructure (AD9, DE5)
  • Pattern merging for similar patterns (DE13)
  • Connection string parsing for embedded credentials (NR17)

Phase 3 — Analysis Subsystems (Rust)
  Duration: 4-6 weeks
  Dependencies: Phase 1
  Deliverables:
  • Call graph with full 6-strategy resolution (CG1, CG2, CG9, CG10)
  • Coupling with Tarjan's SCC (RC7)
  • Boundary analysis with ORM extractors (RC8)
  • Environment analyzer (RC9)
  • Error handling analyzer with propagation chains (RC10, SP10-SP14)
  • Test topology with quality scoring (RC11, SP1-SP5)
  • In-memory graph with petgraph (CG8)
  • Taint analysis foundation: source/sink registry + intraprocedural tracking (NR1, NR2, NR3)
  • Scope tree and CFG construction (AN7, AN9)
  • Forward/backward dataflow framework (AN10)
  • Normalized IR per language (AN14)

Phase 4 — Bridge & Orchestration
  Duration: 2-3 weeks
  Dependencies: Phases 1-3
  Deliverables:
  • N-API bridge with all Rust functions exposed (RC15)
  • TypeScript orchestration layer (thin wrapper)
  • Feedback loop infrastructure (AD9)
  • Rules engine with quick fixes (AN2, AN3)
  • Performance counters exposed via NAPI (NR21)
  • Violation system fully populated (RC20)

Phase 5 — MCP Servers (TypeScript)
  Duration: 3-4 weeks
  Dependencies: Phase 4
  Deliverables:
  • drift-analysis server with progressive disclosure (MC1, MC2)
  • drift-memory server with progressive disclosure (MC1, MC2)
  • Tool description optimization (MC3)
  • Response caching and token estimation (MC6, MC7)
  • Cortex facade pattern (MC16)
  • Consistent JSON response schemas (MC9)
  • Workflow tools (MC10)
  • Pagination with cursor support (MC11)

Phase 6 — Cortex Memory (TypeScript + Rust)
  Duration: 3-4 weeks
  Dependencies: Phase 4
  Deliverables:
  • Hybrid search: FTS5 + sqlite-vec with RRF (CX1)
  • Code-specific embeddings: Jina Code 0.5B via ort (CX2, CX3, NR28)
  • Matryoshka embedding strategy (CX14, NR29)
  • Two-phase memory pipeline (CX4)
  • Embedding enrichment (CX6)
  • Accurate token counting via tiktoken-rs (CX8)
  • PII detection expansion to 50+ patterns (CX13)
  • Memory type consolidation (CX15)
  • Air-gapped consolidation fallback (CX16)
  • Re-ranking stage (CX7)

Phase 7 — Presentation Layer (TypeScript)
  Duration: 3-4 weeks
  Dependencies: Phases 5-6
  Deliverables:
  • CLI with incremental scan (CL1, CL2, CL4)
  • Quality gates with transparent rationale (QG1, QG7)
  • SARIF + GitHub/GitLab reporters with CWE IDs (QG2, QG3)
  • VSCode extension with LSP (ID1, ID2, ID3)
  • Setup wizard (CL3)
  • Progress reporting with ETA (CL11)
  • `drift secrets` command (CL14)
  • Pluggable reporters (CL6)
  • Configurable log levels (NR22)

Phase 8 — Enterprise & Ecosystem
  Duration: 4-6 weeks (ongoing)
  Dependencies: Phase 7
  Deliverables:
  • OWASP 2025 alignment with CWE mapping (NR9, NR10, NR11, NR12)
  • Taint-based vulnerability detection: SQLi, XSS, SSRF, path traversal (NR5-NR8)
  • Interprocedural taint analysis via call graph (NR4)
  • Contract expansion: GraphQL, gRPC, OpenAPI (SP15-SP19)
  • Constraint enforcement with AST/call graph/data flow integration (SP6-SP9, SP30-SP33)
  • KPI dashboard (QG5)
  • DNA system migration (AV1, AV5)
  • Simulation engine integration (AV2, AV9, AV10)
  • Advanced memory features (CX9-CX12)
  • Cross-service reachability (CG7, RC18)
  • MCP authentication (MC15)
  • OWASP Agentic Top 10 hardening (NR13)
  • Base64 secret detection (NR18)
  • OpenTelemetry integration (NR23)
```

---

## Part 5: V2 Target Metrics (Updated)

| Metric | V1 Baseline | V2 Target | Evidence | Change from V1 Recs |
|--------|-------------|-----------|----------|---------------------|
| Full scan (10K files) | 5-10s | <2s | §1.1 (incremental) | — |
| Incremental scan (50 changed files) | 5-10s (full rescan) | <200ms | §1.2 (content-hash) | — |
| MCP tool definitions (analysis only) | ~15-25K tokens | <2K tokens | §7.2, §7.3 | — |
| MCP tool definitions (analysis + memory) | ~25-40K tokens | <4K tokens | §7.2, §7.3 | — |
| Secret detection patterns | 21 | 100+ | §9.2, §35 | — |
| Secret detection: cloud providers covered | 3 (AWS, GitHub, generic) | 25+ | §35.2 | NEW |
| Shannon entropy false-positive rate | N/A | <10% | §35.1 | NEW |
| AST patterns (Rust) | ~30 | 350+ (all v1 detectors) | §3.2 | — |
| Call resolution strategies | 3 (Rust) | 6 (full parity) | Recap §7 | — |
| Languages parsed | 10 | 10+ (with scaffold) | §2.2 | — |
| Frameworks detected | 7 | 20+ (with middleware) | Recap §3 | — |
| OWASP Top 10 2025 coverage | ~4/10 | 9/10 | §9.1, §34 | Updated to 2025 |
| CWE IDs mapped per detector | 0 | 100% of security detectors | §34.1 | NEW |
| Effective false-positive rate | Unknown | <5% | §3.1 (Tricorder) | — |
| Embedding dimensions | 384 (general) | 896 (code-specific, Jina Code 0.5B) | §6.3, §38 | Updated model |
| Embedding model | Transformers.js (general) | Jina Code 0.5B (Apache 2.0, ONNX) | §38.1 | NEW |
| Memory retrieval method | Vector-only | Hybrid (FTS5 + vector + RRF) | §6.2 | — |
| Token counting accuracy | ~±30% (string length) | ~±2% (tiktoken) | §6.8 | — |
| Outlier detection min sample | 3 | 10 | §5.3 (NIST) | — |
| Z-score threshold | 2.0 | 2.5 | §5.3 (NIST) | — |
| Convention learning | Binary 60% threshold | Bayesian Beta posterior with graduated tiers | §37 | Updated method |
| Convention learning confidence tiers | 2 (dominant/not) | 4 (Established/Emerging/Tentative/Uncertain) | §37.1 | NEW |
| Contract protocols | REST only | REST + GraphQL + gRPC | §13.1, §13.2 | — |
| CWE ID mapping | None | Per-detector | §9.1, §34 | — |
| SARIF enrichment | Basic | CWE IDs + code flows + fixes | §10.2 | — |
| Taint analysis | None | Intraprocedural (Phase 1), Interprocedural (Phase 2) | §33 | NEW |
| Taint vulnerability classes | 0 | 4 (SQLi, XSS, SSRF, Path Traversal) | §33.2 | NEW |
| Observability | None (no structured logging) | Full tracing instrumentation, per-subsystem metrics | §36 | NEW |
| PII detection patterns | 10 | 50+ | §9.3 | — |
| Memory types | 23 | ~15 (consolidated) | Audit §5 | NEW |
| Error handling | Mixed (String, anyhow, custom) | thiserror everywhere, per-subsystem enums | §40 | NEW |

---

## Part 6: Risk Register (Updated)

### Technical Risks

| Risk | Likelihood | Impact | Mitigation | New? |
|------|-----------|--------|------------|------|
| Rust migration takes longer than estimated | High | High | Phase incrementally; TS fallback for each subsystem | — |
| Tree-sitter query consolidation introduces regressions | Medium | Medium | Golden file test suite per language | — |
| Visitor pattern doesn't handle all detector types | Low | High | Fallback to per-detector traversal for complex detectors | — |
| Code-specific embedding model quality varies by language | Medium | Medium | Benchmark on Drift-specific retrieval tasks before committing | — |
| NAPI bridge becomes bottleneck for large result sets | Medium | Medium | Batch/streaming APIs; JSON serialization fallback | — |
| SQLite WAL mode checkpoint stalls during heavy writes | Low | Medium | Configure auto-checkpoint threshold; manual checkpoint between phases | — |
| Progressive disclosure confuses AI agents | Medium | Medium | Fallback to full tool loading; A/B test with real agents | — |
| Taint analysis produces too many false positives | Medium | High | Start intraprocedural only; conservative source/sink definitions; contextual filtering | NEW |
| Bayesian scoring diverges from v1 behavior unexpectedly | Medium | Medium | Run both systems in parallel during migration; compare outputs on real codebases | NEW |
| Jina Code 0.5B ONNX inference too slow on CPU | Low | Medium | Matryoshka truncation to 256-dim; batch inference; fallback to CodeRankEmbed 137M | NEW |
| Shannon entropy secret detection flags UUIDs/hashes | Medium | Low | Contextual scoring (variable name check); known-format exclusion list | NEW |
| tracing instrumentation adds measurable overhead | Low | Low | Use `#[instrument(level = "debug")]` for hot paths; compile-time filtering | NEW |
| OWASP 2025 categories change before v2 launch | Low | Low | Modular CWE mapping; easy to remap detectors to new categories | NEW |

### Organizational Risks

| Risk | Likelihood | Impact | Mitigation | New? |
|------|-----------|--------|------------|------|
| Scope creep from 350+ detector migration | High | High | Prioritize by usage frequency; migrate top 50 first | — |
| Enterprise customers need features before Phase 8 | Medium | High | Identify top 3 enterprise blockers; fast-track those | — |
| Community adoption requires documentation | High | Medium | Document as you build; TOML pattern format enables community rules | — |
| Taint analysis scope expands beyond intraprocedural | Medium | Medium | Strict phase gates; interprocedural only after intraprocedural is stable | NEW |
| Source/sink registry maintenance burden | Medium | Low | Community-contributed TOML files; automated extraction from framework docs | NEW |

---

## Part 7: Decision Log (Updated)

| Decision | Options Considered | Chosen | Rationale | New? |
|----------|-------------------|--------|-----------|------|
| MCP architecture | Single server, Split servers, Microservices | Split (2 servers) | Token efficiency, single responsibility, spec support (§7.1-7.5) | — |
| Detection architecture | Per-detector traversal, Visitor pattern, Pipeline | Visitor pattern | O(files) vs O(files × detectors) traversals (§3.2) | — |
| Incremental strategy | Full rescan, File-hash skip, Salsa framework | File-hash skip | Simpler than Salsa, covers 90% of benefit (§1.1, §1.2) | — |
| Confidence scoring | Static weights, Momentum-aware, Full Bayesian | Bayesian + Momentum | Beta posterior provides principled uncertainty; momentum captures temporal trends (§37, §5.2) | UPDATED |
| Embedding model | General-purpose, Code-specific, Multi-model | Jina Code 0.5B | 78.41% avg, Apache 2.0, ONNX, Matryoshka truncation, 896-dim (§38) | UPDATED |
| Graph library | Custom, petgraph, neo4rs | petgraph | Standard library, built-in algorithms, 10M+ downloads (§16.3) | — |
| Cache library | Custom LRU, Moka, quick_cache | Moka | TinyLFU, thread-safe, TTL support, most popular (§16.2) | — |
| String interning | Custom, lasso, symbol_table | lasso | ThreadedRodeo for build, RodeoReader for query (§16.1) | — |
| Error handling | anyhow, thiserror, custom | thiserror | Structured variants, zero-cost, ecosystem standard (§40) | — |
| Secret detection | Regex-only, Entropy + regex, ML-based | Entropy + regex | Catches unknown formats without ML complexity (§35) | — |
| Outlier threshold | Z=2.0, Z=2.5, Z=3.0 | Z=2.5 | Reduces false positives while catching meaningful deviations (§5.3) | — |
| Contract protocols | REST-only, REST+GraphQL, REST+GraphQL+gRPC | All three | Enterprise codebases use all three (§13.1, §13.2) | — |
| Memory search | Vector-only, FTS-only, Hybrid RRF | Hybrid RRF | Consistently outperforms either alone (§6.2) | — |
| Taint analysis scope | None, Intraprocedural, Full interprocedural | Phased (intra → inter) | Intraprocedural catches most common vulns; interprocedural adds cost (§33) | NEW |
| Convention learning | Binary threshold, Bayesian posterior, ML classifier | Bayesian posterior | Principled uncertainty quantification; naturally handles small samples (§37) | NEW |
| Observability | println!, log crate, tracing crate | tracing | Spans + events, async-safe, OpenTelemetry compatible, ecosystem standard (§36) | NEW |
| OWASP version | 2021, 2025 | 2025 | Latest standard; adds supply chain (A03) and expanded logging (A10) (§34) | NEW |
| Embedding dimensions | 384, 768, 896, 1536 | 896 (truncatable) | Matryoshka allows 256-dim for speed, 896 for quality; best tradeoff (§38) | NEW |
| Source/sink format | Hardcoded, JSON, TOML | TOML | Consistent with pattern definitions; Rust-native parsing; human-readable (§33.2) | NEW |

---

## Part 8: Recommendation Cross-Reference Matrix (Expanded)

This matrix shows how recommendations connect across categories. A change in one area affects others. New connections from §33-40 research areas are marked with (NEW).

```
AD1 (Incremental) ──→ RC1 (Scanner) ──→ DE2 (Detection skip) ──→ CG5 (Call graph update)
                  ──→ PA1 (Parse cache) ──→ ST7 (Cache invalidation)

AD2 (Canonical model) ──→ PA2 (ParseResult) ──→ RC15 (NAPI bridge) ──→ AN1 (Unified provider)
                      ──→ AN14 (Normalized IR) ──→ AN9 (CFG construction) ──→ AN6 (Dataflow)

AD4 (Visitor pattern) ──→ DE1 (Detection engine) ──→ DE3 (Confidence) ──→ DE5 (Feedback loop)
                      ──→ RC4 (Declarative patterns) ──→ DE12 (Testing framework)
                      ──→ NR31 (TOML format) ──→ NR32 (Graduated complexity) (NEW)

AD5 (MCP split) ──→ MC1-MC16 (All MCP) ──→ CL3 (Setup wizard) ──→ ID1 (LSP server)
               ──→ MC10 (Workflow tools) ──→ MC9 (Consistent schemas)
               ──→ MC16 (Cortex facade) ──→ CX1 (Hybrid search) (NEW)

AD9 (Feedback loop) ──→ DE5 (False positive tracking) ──→ DE3 (Confidence adjustment)
                    ──→ CX11 (Memory observability) ──→ QG5 (KPI dashboard)

AD10 (Observability) ──→ NR19 (tracing instrumentation) ──→ NR20 (Key metrics) (NEW)
                     ──→ NR21 (NAPI counters) ──→ CL11 (Progress reporting) (NEW)
                     ──→ NR22 (Log levels) ──→ NR23 (OpenTelemetry) (NEW)

AD11 (Taint analysis) ──→ NR1 (Source/sink registry) ──→ NR2 (Intraprocedural) (NEW)
                      ──→ NR3 (Taint summaries) ──→ NR4 (Interprocedural) (NEW)
                      ──→ NR5-NR8 (Vulnerability detection: SQLi, XSS, SSRF, PathTraversal) (NEW)
                      ──→ SP24 (Security taint tracking) ──→ QG2 (SARIF + CWE) (NEW)

AD12 (Bayesian learning) ──→ NR24 (Beta distribution) ──→ NR25 (Graduated tiers) (NEW)
                         ──→ NR26 (Momentum integration) ──→ NR27 (SQLite storage) (NEW)
                         ──→ DE9 (Convention learning) ──→ DE3 (Confidence scoring) (NEW)

RC5 (Secrets) ──→ NR14 (Shannon entropy) ──→ NR15 (Cloud provider patterns) (NEW)
             ──→ NR16 (Contextual scoring) ──→ NR17 (Connection strings) (NEW)
             ──→ DE7 (OWASP alignment) ──→ SP23 (Security coverage) ──→ QG2 (SARIF + CWE)

CG1-CG2 (Call graph) ──→ RC12 (Reachability) ──→ SP10-SP14 (Error chains + boundaries)
                     ──→ CG3 (Impact analysis) ──→ QG6 (Pre-merge simulation) ──→ AV9 (Simulation scoring)
                     ──→ SP1-SP4 (Test topology) ──→ CG4 (Dead code)
                     ──→ SP24 (Security taint tracking) ──→ SP21 (ORM unsafe API detection)
                     ──→ NR3 (Taint summaries) ──→ NR4 (Interprocedural taint) (NEW)
                     ──→ CG9 (Polymorphism) ──→ CG10 (DI resolution) (NEW)

CX1-CX2 (Memory search) ──→ CX6 (Enrichment) ──→ CX7 (Re-ranking) ──→ CX11 (Observability)
                        ──→ NR28 (Jina Code 0.5B) ──→ NR29 (Matryoshka strategy) (NEW)
                        ──→ CX3 (ort inference) ──→ NR30 (Pluggable provider) (NEW)

AN7 (Scope tree) ──→ AN11 (Shadowed vars) ──→ AN14 (Normalized IR) ──→ AN9 (CFG) ──→ AN6 (Dataflow)
                ──→ AN12 (Unreachable code) ──→ AN13 (Null dereference)
                ──→ NR2 (Intraprocedural taint) ──→ NR3 (Taint summaries) (NEW)

SP15-SP18 (Contracts) ──→ SP19 (Frontend usage) ──→ MC10 (Workflow tools)

SP6-SP9 (Constraints) ──→ SP30 (AST verification) ──→ SP31 (Call graph integration) (NEW)
                      ──→ SP32 (Data flow integration) ──→ SP33 (Cross-file verification) (NEW)

NR9 (CWE mapping) ──→ QG2 (SARIF enrichment) ──→ NR12 (Coverage dashboard) (NEW)
                  ──→ NR10 (Supply chain) ──→ NR11 (Crypto failures) (NEW)

DI1-DI4 (Pattern repo events) ──→ AV7 (DNA mutation tracking) ──→ AV1 (DNA fingerprinting)

DI6-DI9 (Services pipeline) ──→ CL4 (Rayon parallelism) ──→ RC16 (Thread-local cleanup)

SP25-SP29 (Context gen) ──→ MC7 (Token estimation) ──→ CX8 (tiktoken-rs)

DI17 (Remove JSON storage) ──→ ST1 (SQLite consolidation) ──→ DI18 (Remove duplicates) (NEW)
```

---

## Part 9: Audit Gap → Recommendation Traceability Matrix

Every audit gap has at least one recommendation addressing it. This matrix ensures complete coverage.

### Architecture Audit Findings

| Audit Finding | Recommendations |
|--------------|----------------|
| A1: Circular Dependency Risk | MC16 (Cortex facade), AD2 (Canonical model) |
| A2: Language Split Maintenance | RC2, PA2, AN15, CG1 (all migrate to Rust) |
| A3: Three ParseResult Shapes | AD2, PA2 |
| A4: Storage Fragmentation | ST1, ST2, DI5, DI17 |
| A5: MCP Tool Explosion | AD5, MC1, MC2 |

### Cross-Cutting Concerns

| Concern | Recommendations |
|---------|----------------|
| CC1: Incrementality Missing | AD1, RC1, DE2, CG5, PA1 |
| CC2: No Unified Error Handling | AD6, PA13, §40 architecture |
| CC3: No Observability | AD10, NR19-NR23 |
| CC4: No Configuration Validation | NR31 (TOML schema), AD3 |
| CC5: Testing Strategy Inconsistent | DE12 (golden file tests) |
| CC6: No Telemetry | NR21, NR23 |

### Data Model Inconsistencies

| Inconsistency | Recommendations |
|--------------|----------------|
| DM1: Pattern Multiple Definitions | AD2 |
| DM2: FunctionNode Duplicates | DI18 |
| DM3: Confidence Weights Disagree | AD8, AD12, NR24-NR27 |
| DM4: Violation Underspecified | RC20 |
| DM5: Memory Types Overengineered | CX15 |

### Performance Bottlenecks

| Bottleneck | Recommendations |
|-----------|----------------|
| PB1: Sequential Detection | AD4, DE1 |
| PB2: Full Rescan | AD1, RC1, DE2 |
| PB3: NAPI Per-Call Overhead | RC15, PA8 |
| PB4: JSON Storage I/O | ST1, DI5, DI17 |
| PB5: No Query Caching | MC6, ST7 |
| PB6: Embedding Bottleneck | CX3, NR28 |

### Security Findings

| Finding | Recommendations |
|---------|----------------|
| SA1: Secret Detection Gaps | RC5, NR14, NR15, NR16, NR17 |
| SA2: No Taint Analysis | AD11, NR1-NR8, SP24 |
| SA3: Limited PII Detection | CX13, NR17, NR18 |
| SA4: No OWASP/CWE Alignment | DE7, NR9-NR12, SP23 |
| SA5: No MCP Authentication | MC8, MC15, NR13 |

### V2 Non-Negotiables

| Non-Negotiable | Recommendations |
|---------------|----------------|
| #1: Incremental scanning | AD1, RC1 |
| #2: Single canonical data model | AD2, PA2 |
| #3: 100+ secret patterns | RC5, NR14, NR15 |
| #4: Visitor pattern detection | AD4, DE1 |
| #5: Feedback loop | AD9, DE5 |
| #6: Split MCP servers | AD5, MC1 |
| #7: SQLite-only storage | AD7, ST1, DI5, DI17 |
| #8: Structured error handling | AD6, PA13 |
| #9: OWASP/CWE alignment | DE7, NR9-NR12 |
| #10: Temporal confidence | AD8, AD12, NR24-NR27 |
| #11: Hybrid search in Cortex | CX1 |
| #12: Code-specific embeddings | CX2, NR28 |
| #13: Declarative pattern definitions | AD3, NR31, NR32 |
| #14: GraphQL + gRPC contracts | DE8, SP15-SP19 |
| #15: Taint analysis foundation | AD11, NR1-NR8 |

---

## Updated Quality Checklist

- [x] All 27 categories have specific, deep recommendations
- [x] Every recommendation has priority level (P0-P3)
- [x] Every recommendation cites evidence (research section or recap section)
- [x] Every recommendation traces to audit gap where applicable
- [x] 12 architectural decisions documented with rationale (up from 9)
- [x] 8 build phases defined with dependency ordering and duration estimates (updated)
- [x] 30+ target metrics with V1 baselines and V2 targets (up from 20+)
- [x] Technical and organizational risks identified with mitigations (13 new risks added)
- [x] 20 key decisions logged with options considered and rationale (up from 13)
- [x] Cross-reference matrix shows inter-category dependencies (expanded with NEW connections)
- [x] Full audit gap → recommendation traceability matrix (NEW)

### Category Recommendation Counts

| Category | V1 Count | V2 Count | Change |
|----------|----------|----------|--------|
| Architectural Decisions (AD) | 9 | 12 | +3 (Observability, Taint, Bayesian) |
| Rust Core (RC) | 17 | 20 | +3 (Cross-service, Dependency graph, Violations) |
| Parsers (PA) | 14 | 16 | +2 (Inheritance chains, Incremental parsing) |
| Detectors (DE) | 12 | 16 | +4 (Merging, Call graph, Data flow, Framework coverage) |
| Call Graph (CG) | 8 | 10 | +2 (Polymorphism, DI resolution) |
| Analyzers (AN) | 14 | 16 | +2 (Core migration, Cross-file dataflow) |
| Cortex Memory (CX) | 13 | 16 | +3 (Matryoshka, Type consolidation, Air-gapped) |
| MCP Server (MC) | 14 | 16 | +2 (Authentication, Cortex facade) |
| Storage (ST) | 8 | 10 | +2 (Integrity validation, Retention policies) |
| Quality Gates (QG) | 6 | 8 | +2 (SQLite snapshots, Gate ordering) |
| CLI (CL) | 12 | 14 | +2 (Taint command, Secrets command) |
| IDE (ID) | 13 | 14 | +1 (Taint diagnostics) |
| Infrastructure (IN) | 6 | 8 | +2 (WebAssembly, CI matrix) |
| Advanced Systems (AV) | 13 | 13 | — |
| Specialized Analysis (SP) | 29 | 34 | +5 (AST constraints, Call graph constraints, Data flow constraints, Cross-file constraints, Crypto detection) |
| Data Infrastructure (DI) | 16 | 18 | +2 (Remove JSON, Remove duplicates) |
| New Research Areas (NR) | 0 | 32 | +32 (Taint, OWASP, Secrets, Observability, Bayesian, Embeddings, Patterns) |
| **TOTAL** | **194** | **263** | **+69** |

### New Research Area Coverage

| Research Area | Section | Recommendations | Key Deliverables |
|--------------|---------|----------------|-----------------|
| Taint Analysis | §33 | NR1-NR8 | Source/sink registry, intraprocedural tracking, taint summaries, SQLi/XSS/SSRF/PathTraversal detection |
| OWASP 2025 | §34 | NR9-NR13 | CWE mapping, supply chain detection, crypto failure detection, coverage dashboard, agentic security |
| Secret Detection | §35 | NR14-NR18 | Shannon entropy, 25+ cloud providers, contextual scoring, connection strings, base64 detection |
| Observability | §36 | NR19-NR23 | tracing instrumentation, per-subsystem metrics, NAPI counters, log levels, OpenTelemetry |
| Bayesian Learning | §37 | NR24-NR27 | Beta distribution, graduated tiers, momentum integration, SQLite posterior storage |
| Code Embeddings | §38 | NR28-NR30 | Jina Code 0.5B selection, Matryoshka strategy, pluggable provider |
| Declarative Patterns | §39 | NR31-NR32 | TOML format definition, graduated complexity levels |
| Error Handling | §40 | AD6, PA13 | thiserror per-subsystem, NAPI propagation (covered in AD6) |

### Completeness Verification

- [x] Every audit gap (80+) has at least one recommendation
- [x] Every cross-cutting concern (CC1-CC6) has recommendations
- [x] Every data model inconsistency (DM1-DM5) has recommendations
- [x] Every performance bottleneck (PB1-PB6) has recommendations
- [x] Every security finding (SA1-SA5) has recommendations
- [x] Every v2 non-negotiable (15) has recommendations
- [x] Every new research area (§33-40) has concrete recommendations
- [x] Every recommendation traces to evidence (research section, recap, or audit)
- [x] Build phases incorporate all new recommendations with correct dependency ordering
- [x] Target metrics include baselines for all new capabilities
- [x] Risk register covers new technical and organizational risks
- [x] Decision log captures all new architectural decisions with rationale
- [x] Cross-reference matrix shows all inter-category dependencies including new connections
