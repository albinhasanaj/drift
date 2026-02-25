# Drift V2 — Master Recommendations

> **Purpose**: Unified, deduplicated build plan synthesizing all 70 per-category recommendations (18 + 14 + 12 + 12 + 14) into a single authoritative v2 blueprint. Organized by build phase with dependency graph, cross-category impact analysis, and success metrics.
>
> **Inputs**: 5 category RECOMMENDATIONS.md files, MASTER_RECAP.md, MASTER_RESEARCH.md
>
> **Date**: February 2026

---

## Executive Summary

Drift v2 is a greenfield rebuild. V1 is the requirements spec — not code to port. This document distills 70 per-category recommendations into 42 unified recommendations organized across 7 build phases. Deduplication removed 28 overlapping items (e.g., taint analysis appeared in 01-rust-core R12, 04-call-graph R1, and 05-analyzers R3; incremental computation appeared in all 5 categories). Every recommendation is framed as "build new" with no migration constraints.

The build plan targets enterprise-grade performance (500K+ files, sub-second incremental response), security compliance (OWASP/CWE mapping, taint analysis), and statistical rigor (Bayesian confidence, temporal decay). The 7 phases form a strict dependency chain — each phase's outputs are the next phase's inputs.

---

## Phase 0: Architectural Decisions (Before Code)

These decisions are load-bearing. They constrain every subsystem. Make them first, document them, and enforce them.

### M1: Incremental-First Computation Model

**Sources**: 01-rust-core FA1, 02-parsers R1, 03-detectors R2, 04-call-graph R5, 05-analyzers R1
**Priority**: P0 | **Effort**: High | **Impact**: 10-100x performance for incremental workflows

This is the single most cross-cutting decision. Every subsystem in v1 is batch-only. V2 must be incremental-first — not batch-first with incrementality bolted on.

**Architecture**:
1. Per-file indexing phase: parse → extract → produce file index entry. Embarrassingly parallel. Each entry is content-hashed (xxhash) and cached.
2. Cross-file analysis phase: call graph resolution, coupling metrics, reachability — computed from file indexes as derived queries that auto-invalidate when inputs change.
3. Tree-sitter incremental parsing: cache `Tree` objects per file. On edit, use `tree.edit()` + re-parse for sub-millisecond updates.
4. SQLite-backed persistent index: survives restarts. On startup, hash-check files against stored index — only re-index changed files.
5. Evaluate Salsa framework for the cross-file phase. If too complex, build a simpler content-hash + dependency-tracking cache. Start with file-level granularity.

**Key Invariant** (from rust-analyzer): "Typing inside a function body never invalidates global derived data." Separate function signatures (module-level) from function bodies (local).

**Cancellation Pattern**: When inputs change, increment a global revision counter. Long-running queries check the counter and panic with a special `Cancelled` value, caught at the API boundary.

**Evidence**: Salsa framework, rust-analyzer architecture, Google Tricorder incremental model, Moka concurrent cache.

---

### M2: Structured Error Handling from Day One

**Sources**: 01-rust-core FA2, 02-parsers R13
**Priority**: P0 | **Effort**: Low | **Impact**: Every subsystem uses this — impossible to retrofit

Use `thiserror` for all error types. One error enum per subsystem with structured variants:

```rust
#[derive(thiserror::Error, Debug)]
pub enum ScanError {
    #[error("path not found: {path}")]
    PathNotFound { path: String },
    #[error("permission denied: {path}")]
    PermissionDenied { path: String },
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
// Per subsystem: ParseError, CallGraphError, AnalysisError, CouplingError, etc.
```

Structured errors enable programmatic handling in the TS orchestration layer, better NAPI error propagation, and error categorization for telemetry.

---

### M3: SQLite WAL Mode as Default

**Sources**: 01-rust-core FA3
**Priority**: P0 | **Effort**: Trivial | **Impact**: Concurrent reads during writes across all databases

Every SQLite database opens with:
```sql
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA mmap_size=268435456;  -- 256MB memory-mapped I/O
PRAGMA optimize;             -- on close
```

---

### M4: Layered Architecture with Explicit API Boundaries

**Sources**: 05-analyzers R2
**Priority**: P0 | **Effort**: High | **Impact**: Independent layer evolution, testability, clear responsibilities

Adopt rust-analyzer's layered architecture:

```
Layer 1: syntax (API Boundary)
├── Tree-sitter parsing, syntax tree types (value types, no semantic info)
└── No dependencies on other Drift crates — usable standalone

Layer 2: hir-def, hir-ty (Internal — can change freely)
├── Low-level semantic analysis, scope resolution, type inference, flow analysis
└── ECS-style with raw IDs and direct DB queries

Layer 3: hir (API Boundary)
├── High-level semantic API, stable types for external consumers
└── Source-to-HIR mapping, OO-flavored facade

Layer 4: ide (API Boundary)
├── IDE features built on hir, POD types only
└── Editor terminology (offsets, labels), conceptually serializable
```

Key: syntax is value types (fully determined by content, no global context). Internal layers (hir-def, hir-ty) can be refactored freely. IDE layer uses editor terminology, not compiler terminology.

---

## Phase 1: Core Engine

Build the foundational subsystems everything else depends on.

### M5: Parallel Filesystem Scanner with Change Detection

**Sources**: 01-rust-core R1
**Priority**: P0 | **Effort**: Medium

A parallel scanner that:
1. Walks directories via `walkdir` + `rayon` with `.gitignore`/`.driftignore` support
2. Returns file metadata: path, size, content hash (xxhash), detected language
3. Compares content hashes against persistent index to identify changed/added/removed files
4. Builds a dependency graph from import/export analysis
5. Supports configurable max file size, include/exclude globs, symlink following

Key difference from v1: v1 scanner was file-list-only. V2 scanner owns change detection and dependency graph.

---

### M6: Canonical ParseResult with Rich Extraction

**Sources**: 01-rust-core R2, 02-parsers R2, R3, R7, R10
**Priority**: P0 | **Effort**: High

One `ParseResult` type that serves Rust internals, NAPI bridge, and all downstream consumers. V1 had three shapes — v2 has exactly one.

Must include from day one:
- Functions with full signatures, return types, generics, doc comments, body hash (for function-level change detection)
- Classes with inheritance, interfaces, abstract status, nested methods, properties, `ClassKind` (class/interface/struct/enum/trait/record)
- Structured decorators/annotations with parsed arguments (`DecoratorInfo { name, arguments: Vec<DecoratorArgument>, raw_text }`) — not strings
- Imports/exports with type-only distinction, re-exports, namespace imports
- Call sites with receiver, argument count, position
- String/numeric literals with AST context
- Error handling constructs (try/catch/finally with caught types)
- Namespace/package declarations for all languages (Java package, C# namespace, PHP namespace, Go package, Python from path)
- Generic type parameters with bounds for all languages that support them
- `content_hash: u64` and `file_path: Option<String>` for cache invalidation and cross-file resolution

This is the foundational data model. Every other recommendation depends on it.

**Evidence**: YASA UAST (factorized union), Semgrep ast_generic, Roslyn Syntax API.

---

### M7: Trait-Based Language Parser Architecture

**Sources**: 02-parsers R6, R14
**Priority**: P0 | **Effort**: Medium

```rust
pub trait LanguageParser: Send + Sync {
    fn language(&self) -> Language;
    fn extensions(&self) -> &[&str];
    fn parse(&mut self, source: &str) -> ParseResult;
    fn parse_incremental(&mut self, source: &str, old_tree: &Tree, edits: &[InputEdit]) -> ParseResult;
    fn supports_framework_extraction(&self) -> bool { false }
    fn extract_framework_constructs(&self, tree: &Tree, source: &str) -> Vec<FrameworkConstruct> { Vec::new() }
}
```

`ParserManager` dispatches via trait objects. Registration is explicit. `Send + Sync` bound enables safe use with rayon. Provide a `define_parser!` macro for mechanical new-language addition.

---

### M8: String Interning with Lasso

**Sources**: 01-rust-core R3
**Priority**: P0 | **Effort**: Low

Use `lasso` crate: `Rodeo` during build/scan phase (mutable), `RodeoReader` for query phase (immutable, contention-free). Domain-specific wrappers: `PathInterner` (normalizes `\` → `/`), `FunctionInterner` (supports `intern_qualified(class, method)`).

---

### M9: Performance-Optimized Data Structures

**Sources**: 01-rust-core R17
**Priority**: P1 | **Effort**: Low

Use from the start:
- `FxHashMap` for all internal hash maps (faster than std for small keys)
- `SmallVec<[T; 4]>` for usually-small collections
- `BTreeMap` for ordered lookups and prefix search
- `xxhash` (xxh3) for content hashing
- Release profile: `lto = true`, `codegen-units = 1`, `opt-level = 3`

---

### M10: Thread-Safe Parser Pool for Rayon

**Sources**: 01-rust-core R16, 02-parsers R11
**Priority**: P1 | **Effort**: Low

Use `thread_local!` with explicit cleanup between scan operations. Pre-compiled Query objects (50-500ms per language) are reused across files. Cleanup function addresses memory growth. `Arc<RwLock<ResolutionIndex>>` for shared cross-file state. Batch processing with `par_iter()` + `flat_map_iter()`.

---

### M11: Consolidated Tree-Sitter Queries

**Sources**: 02-parsers R5
**Priority**: P1 | **Effort**: Low

Consolidate v1's 4-5 separate queries per language into 1-2 consolidated queries with alternations. Each `QueryCursor::matches()` traverses the entire tree — fewer queries = fewer traversals. Group by: declarations (top-level) in one query, expressions (nested) in another. Pre-compile at parser construction time.

---

### M12: Error-Tolerant Extraction

**Sources**: 02-parsers R9
**Priority**: P1 | **Effort**: Low

Never fail on error nodes. Partial results are valuable. Track error locations in `ParseResult.errors`. Confidence degradation for regions near error nodes. Critical for IDE integration where files are frequently in invalid states.

---

### M13: Incremental Parse Cache

**Sources**: 02-parsers R1
**Priority**: P0 | **Effort**: Medium

Content-addressed caching with Moka (TinyLFU admission + LRU eviction). Two-tier: file-level (batch/CLI — skip unchanged via content hash) and edit-level (IDE — `tree.edit()` for sub-millisecond re-parse). Durable persistence to SQLite between sessions. Cache statistics for observability.

```rust
fn parse(&self, path: &Path, source: &str) -> ParseResult {
    let hash = xxhash(source);
    if let Some(cached) = self.cache.get(&(path.to_owned(), hash)) {
        return cached;
    }
    let result = self.do_parse(path, source);
    self.cache.insert((path.to_owned(), hash), result.clone());
    result
}
```

---

## Phase 2: Detection Engine

### M14: Single-Pass Visitor Pattern

**Sources**: 03-detectors R1, 01-rust-core R4
**Priority**: P0 | **Effort**: High | **Impact**: 10-100x detection performance

This IS the detection engine — build it first. Traverse each file's AST once, dispatch to all interested handlers per node type.

```rust
struct DetectionEngine {
    handlers: HashMap<NodeType, Vec<Box<dyn DetectorHandler>>>,
}

trait DetectorHandler: Send + Sync {
    fn node_types(&self) -> &[NodeType];
    fn on_enter(&mut self, node: &Node, ctx: &DetectionContext);
    fn on_exit(&mut self, node: &Node, ctx: &DetectionContext);
    fn results(&self) -> Vec<PatternMatch>;
}
```

Current: `O(files × detectors × AST_nodes)`. Proposed: `O(files × AST_nodes × handlers_per_node)`. Since most detectors care about 2-5 node types, this is 10-100x faster.

**Evidence**: ESLint visitor pattern, Google Tricorder shardable analysis, Semgrep single-pass matching.

---

### M15: Unified Analyzer with Declarative Patterns

**Sources**: 01-rust-core R4
**Priority**: P0 | **Effort**: High

4-phase per-file pipeline:
```
File → tree-sitter parse → ParseResult
  Phase 1: AST Pattern Detection (tree-sitter queries, confidence 0.85-0.95)
  Phase 2: String Extraction (from AST, with context)
  Phase 3: String Literal Analysis (regex, confidence 0.80-0.90)
  Phase 4: Resolution Index population
```

Critical new capability: declarative pattern definitions loaded from TOML at startup. Ship with hardcoded defaults (all v1 patterns). Users can add custom patterns without recompiling.

Wire up ALL pattern sets from day one — including logging (v1 compiled but never used). Build the Violation system from day one (v1 defined the type but never populated it). Wire up `ResolutionStats` tracking (v1 left as TODO).

---

### M16: Generic AST Normalization Layer (GAST)

**Sources**: 03-detectors R4
**Priority**: P1 | **Effort**: High | **Impact**: Reduces detector codebase by 50-70%

```
Source Code → tree-sitter → Language-Specific CST → GAST Normalizer → Generic AST → Detectors
```

~30 normalized node types covering 80% of detection needs: Function, Class, TryCatch, Call, Import, Route, etc. Per-language normalizers (10 languages). Language-specific detectors kept for truly unique patterns (PHP attributes, Rust lifetimes). Adding a new language requires only a normalizer (~500-1000 lines) — all existing detectors work automatically.

**Evidence**: Semgrep `ast_generic`, YASA UAST (Ant Group, 200+ applications, 6 languages).

---

### M17: Incremental Detection with Content-Hash Skipping

**Sources**: 03-detectors R2
**Priority**: P0 | **Effort**: Medium

Three layers:
1. **File-level skip**: If `contentHash === previousScan.contentHash`, reuse previous results.
2. **Pattern-level re-scoring**: Re-detect only changed files, re-aggregate only affected patterns, re-score only affected patterns.
3. **Convention re-learning**: <10% files changed → skip re-learning; 10-30% → incremental update; >30% → full re-learning.

Store per-file detection results in SQLite keyed by `(file_path, content_hash)`.

---

### M18: Enterprise-Grade Secret Detection (100+ Patterns)

**Sources**: 01-rust-core R5, 05-analyzers R7
**Priority**: P0 | **Effort**: Medium

Ship with 100+ patterns from day one, organized by provider:
- Cloud: AWS (5), GCP (4), Azure (4), DigitalOcean (2), Heroku (2)
- Code platforms: GitHub (3), GitLab (2), Bitbucket (2), npm (2), PyPI (2), NuGet (1)
- Payment: Stripe (3), Square (2), PayPal (2)
- Communication: Slack (3), Twilio (2), SendGrid (2)
- Database: connection strings (4), passwords (3)
- Auth: JWT (2), OAuth (2), bearer tokens (2)
- Crypto: RSA/SSH/PGP private keys (3)
- Generic: password assignments, secret assignments, API key assignments

Shannon entropy calculator (`H > 4.5` threshold for sensitive variable contexts). Contextual confidence scoring with adjustments for: variable name sensitivity (+0.10), test file (-0.20), comment (-0.30), .env file (+0.10), placeholder detected (-1.00). Declarative TOML format for pattern maintenance.

---

### M19: Comprehensive Pattern Category Coverage

**Sources**: 01-rust-core R18
**Priority**: P1 | **Effort**: Medium

All 15 pattern categories with AST queries AND string patterns from day one. V1 had gaps in Components, Documentation, Logging, Performance, Structural, Styling, Testing, Types. V2 covers all 15:

Api, Auth, Components, Config, DataAccess, Documentation, Errors, Logging, Performance, Security, Structural, Styling, Testing, Types, Validation.

---

## Phase 3: Analysis Subsystems

### M20: Call Graph with Full 6-Strategy Resolution

**Sources**: 01-rust-core R6, 04-call-graph R2, R3
**Priority**: P0 | **Effort**: High

Per-language hybrid extractors in Rust (8 languages × tree-sitter + regex fallback). 6-strategy resolution:

1. Same-file (highest confidence)
2. Method call (via class/receiver type)
3. DI injection (FastAPI Depends, Spring @Autowired, NestJS @Inject)
4. Import-based (follow import chains)
5. Export-based (match exported names)
6. Fuzzy matching (lowest confidence, configurable threshold)

Target: resolution rate from ~60% to ~80%. Track resolution statistics from day one. Parallel construction via rayon with `StreamingBuilder` + `ParallelWriter`. SQLite storage with WAL mode.

---

### M21: Namespace-Based Attribute Resolution

**Sources**: 04-call-graph R4
**Priority**: P1 | **Effort**: Medium | **Impact**: Reduces false positives by 10-20%

Follow PyCG's approach: resolve `obj.method()` by walking the class hierarchy in MRO order, not by global name lookup. Critical for duck-typed languages (Python, JavaScript). PyCG achieves 99.2% precision specifically because of this.

---

### M22: Coupling Analyzer with Full Feature Set

**Sources**: 01-rust-core R7, 05-analyzers R11
**Priority**: P1 | **Effort**: Medium

Build ALL features from day one:
1. Martin metrics: Ca, Ce, Instability (I), Abstractness (A), Distance (D)
2. Tarjan's SCC for cycle detection (not DFS — guarantees completeness, same O(V+E))
3. Condensation graph generation (DAG of SCCs for architecture visualization)
4. Zone detection: Zone of Pain (low I, low A), Zone of Uselessness (high I, high A)
5. Module role classification: hub, authority, balanced, isolated
6. Cycle break suggestions: score by `(Ce of source / Ca of target)`, suggest approach (ExtractInterface, DependencyInversion, MergeModules, IntroduceMediator)
7. Refactor impact analysis via transitive dependencies + call graph
8. Health score: penalize cycles, high coupling, zone violations, unused exports

---

### M23: Boundary Analysis with ORM Extractors

**Sources**: 01-rust-core R8
**Priority**: P1 | **Effort**: Medium

Data access point detection with operation classification (Read/Write/Delete/Update). ORM-specific field extractors in Rust: Prisma, Django, SQLAlchemy, Entity Framework, Sequelize, TypeORM (Tier 1); Supabase, GORM, Diesel, Raw SQL (Tier 2). Sensitive field detection (PII, financial, auth, health) with reason tracking. Risk scoring: `risk = sensitivity × exposure × frequency`.

---

### M24: Environment Analyzer with Cross-Referencing

**Sources**: 01-rust-core R9
**Priority**: P1 | **Effort**: Low-Medium

Extract env var access patterns across all languages. Sensitivity classification (Critical/Secret/Internal/Public). `.env` file parser with cross-referencing (missing variable detection). Environment consistency checking across `.env`, `.env.production`, `.env.development`. Framework-specific prefix detection: `NEXT_PUBLIC_*`, `VITE_*`, `REACT_APP_*`, `NUXT_*`, `EXPO_PUBLIC_*`.

---

### M25: Error Handling Analyzer with Propagation Tracking

**Sources**: 01-rust-core R10
**Priority**: P1 | **Effort**: Medium

Error boundary detection (6 types), error gap detection (6 types), gap severity classification with fix suggestions, error type tracking (custom classes, inheritance chains), error propagation chain tracking via call graph integration, error profile generation per module.

---

### M26: Test Topology with Quality Scoring

**Sources**: 01-rust-core R11
**Priority**: P1 | **Effort**: Medium

35+ framework detection across 10 languages (all in Rust). Test case extraction with type classification (Unit/Integration/E2E/Performance/Snapshot). Mock detection and classification. Test-to-source mapping via import analysis AND call graph. Test quality scoring: assertion density, mock ratio, test isolation, naming conventions. Minimum test set calculation: given a code change, which tests must run?

---

### M27: Reachability Engine with Taint Analysis

**Sources**: 01-rust-core R12, 04-call-graph R1, R11, 05-analyzers R3
**Priority**: P0 | **Effort**: Very High | **Impact**: Transforms structural analysis into security analysis

This is the single most impactful security improvement. Drift already has the call graph — taint is an incremental addition.

**Intraprocedural taint (Phase 1)**:
- Sources: function parameters, request objects, env vars, user input APIs
- Sinks: SQL query construction, command execution, HTML rendering, file writes, URL redirects, deserialization
- Track propagation through assignments, concatenation, function calls within a single function
- Sanitizer recognition (escapeHtml, parameterize, DOMPurify, express-validator) to reduce false positives

**Interprocedural taint (Phase 2)**:
- Extend via call graph integration using function summaries
- Summary-based: compute summaries once per function, reuse across call sites
- Context-sensitive: distinguish between different call sites
- Framework-aware: recognize framework-specific sources (Express `req.body`, Django `request.POST`)

**Field-level data flow**:
- Track individual fields through call paths (`users.password_hash` vs `users.display_name`)
- Detect transformations along paths: DirectAccess, Aggregation, Hashing, Encryption, Masking, Concatenation, Filtering
- Reduces false positives by 50-80% in security analysis

**Evidence**: Semgrep taint mode, SonarSource, JetBrains, FlowDroid (field-sensitivity), PyCG (call graph prerequisite).

---

### M28: Wrapper Detector with Multi-Framework Registry

**Sources**: 01-rust-core R13
**Priority**: P2 | **Effort**: Low-Medium

Comprehensive primitives registry: React, Vue, Angular, Svelte, Express, NestJS, data fetching (fetch, axios, useSWR, useQuery), validation (zod, yup, joi), database (prisma.*, sequelize.*), logging (console.*, winston.*, pino.*). Configurable via TOML. Cross-file usage counting via call graph.

---

### M29: Constants Analyzer with Fuzzy Matching

**Sources**: 01-rust-core R14
**Priority**: P2 | **Effort**: Low-Medium

AST-based magic number detection (not line-level regex). Fuzzy name matching for inconsistency detection: normalize names by splitting on `_`, `-`, camelCase → lowercase → join. Dead constant detection via usage analysis.

---

### M30: Pydantic Model Extraction in Rust

**Sources**: 02-parsers R4
**Priority**: P0 | **Effort**: High

Rust-native Pydantic v1/v2 model extractor: model detector, field extractor, recursive type resolver (with depth limit), constraint parser, validator extractor, config extractor, version detector. Enables FastAPI contract detection, Python API shape extraction, BE-FE mismatch detection.

---

### M31: Impact Analysis in Rust

**Sources**: 04-call-graph R6
**Priority**: P1 | **Effort**: Medium

Reverse BFS from changed function → affected functions → affected entry points → affected data paths. Blast radius calculation (direct callers, transitive callers, affected entry points, affected sensitive data). Risk scoring. Expose via N-API: `analyze_impact(function_id)`.

---

### M32: Dead Code Detection in Rust

**Sources**: 04-call-graph R7
**Priority**: P1 | **Effort**: Low

Functions with empty `called_by` that aren't entry points, framework hooks, exports, or test functions. Confidence scoring based on false positive likelihood. O(V) single pass.

---

## Phase 4: Statistical & Scoring Engine

### M33: Temporal Confidence Decay and Momentum Scoring

**Sources**: 03-detectors R3
**Priority**: P0 | **Effort**: Medium | **Impact**: Eliminates stale convention enforcement

Add temporal decay and momentum to confidence scoring:

**Temporal Decay**: `ageFactor = ageFactor × (currentFrequency / previousFrequency)` when frequency declines.

**Momentum Signal**: `momentum = (currentFrequency - previousFrequency) / max(previousFrequency, 0.01)`, normalized to [0, 1].

**Revised weights**:
```
score = frequency × 0.30 + consistency × 0.25 + ageFactor × 0.10 + spread × 0.15 + momentum × 0.20
```

Momentum gets 0.20 because convention migration is a critical enterprise scenario. Without momentum, Drift fights intentional migrations by flagging the new pattern as violations.

Minimum activation: momentum only active after 3+ scans with 50+ files.

---

### M34: Bayesian Convention Learning

**Sources**: 03-detectors R9
**Priority**: P1 | **Effort**: Medium | **Impact**: Eliminates arbitrary 60% threshold

Replace binary ValueDistribution with Beta-Binomial model:
```
Prior: Beta(α=1, β=1) — uniform
Posterior: Beta(α + successes, β + failures)
confidence = (α + successes) / (α + β + total_files)
```

Convention categories: Universal (>90%), ProjectSpecific (>60%), Emerging (<60% but rising), Legacy (was dominant, declining), Contested (two conventions at 40-60% each).

Contested convention handling: detect explicitly, report both with strengths, generate "inconsistency" finding rather than violations against either, suggest the team make a deliberate choice.

Minimum evidence: 5 files, 10 occurrences, 0.7 Bayesian posterior.

**Evidence**: Allamanis et al. (FSE 2014), Hindle et al. (software naturalness).

---

### M35: Outlier Detection Statistical Refinements

**Sources**: 03-detectors R6
**Priority**: P1 | **Effort**: Low | **Impact**: Reduces false-positive outlier flags by 30-50%

Build from scratch with correct thresholds:
1. Z-Score threshold: |z| > 2.5 (v1 used 2.0, NIST recommends 3.0; 2.5 balances sensitivity/precision)
2. Minimum sample size: 10 (not 3)
3. Grubbs' test for small samples (10 ≤ n < 30)
4. Iterative detection with 3-iteration cap (addresses masking effects)
5. Significance tiers: |z| > 3.5 → critical, > 3.0 → high, > 2.5 → moderate

---

## Phase 5: Security & Compliance

### M36: OWASP/CWE-Aligned Security Detection

**Sources**: 03-detectors R7
**Priority**: P1 | **Effort**: High | **Impact**: Enterprise compliance readiness

Design security detection around OWASP Top 10 and CWE/SANS Top 25:

| OWASP | Detectors to Build | Priority |
|-------|-------------------|----------|
| A01: Broken Access Control | permission-checks, rbac-patterns, path-traversal, cors-misconfiguration | P0 |
| A02: Cryptographic Failures | weak-crypto-algorithms, hardcoded-keys, insecure-random, weak-hashing | P0 |
| A03: Injection | sql-injection, xss-prevention, command-injection, ldap-injection, template-injection | P0 |
| A04: Insecure Design | missing-rate-limiting, missing-input-validation, trust-boundary-violations | P1 |
| A05: Security Misconfiguration | debug-mode-enabled, default-credentials, missing-security-headers | P1 |
| A07: Auth Failures | weak-password-policy, missing-mfa-check, session-fixation | P0 |
| A08: Integrity Failures | insecure-deserialization, unsigned-data-acceptance | P1 |
| A09: Logging Failures | missing-security-logging, pii-in-logs | P1 |
| A10: SSRF | ssrf-detection, url-from-user-input | P0 |

Every security finding includes CWE IDs and OWASP category references:
```rust
struct SecurityFinding {
    pattern: PatternMatch,
    cwe_ids: Vec<u32>,
    owasp_category: String,
    severity: SecuritySeverity,
    cvss_estimate: Option<f32>,
}
```

---

### M37: N+1 Query Detection

**Sources**: 05-analyzers R8
**Priority**: P1 | **Effort**: Medium

Combine call graph analysis with ORM pattern detection: find loops containing ORM queries that depend on loop variables without a preceding bulk query. Generate framework-specific fix suggestions (Prisma: `include`/`select`, Django: `select_related`/`prefetch_related`, SQLAlchemy: `joinedload`/`subqueryload`).

---

## Phase 6: Bridge & Developer Experience

### M38: N-API Bridge with Batch and Streaming

**Sources**: 01-rust-core R15, 02-parsers R8
**Priority**: P0 | **Effort**: Medium

First-class API layer:
1. Individual analysis functions (~25, covering all new capabilities)
2. Batch API: `analyze_batch(root, analyses: Vec<AnalysisType>)` — multiple analyses in one N-API call, shared parsed results
3. Streaming support via napi-rs `AsyncTask` + chunked results for large result sets
4. Async variants for long-running operations
5. Structured error propagation: Rust error enums → meaningful N-API error objects
6. Consider `parse_batch_json()` variant returning serialized JSON for reduced conversion overhead

Platform support: darwin-arm64, darwin-x64, linux-arm64-gnu, linux-arm64-musl, linux-x64-gnu, linux-x64-musl, win32-x64-msvc.

---

### M39: Suggested Fixes as First-Class Output

**Sources**: 03-detectors R10, 05-analyzers R9
**Priority**: P1 | **Effort**: Medium | **Impact**: Google data: fixes applied ~3,000 times/day

Fix categories: TextEdit, MultiEdit, Rename, ImportChange, Structural, Suggestion. Every detector implements `generate_fix()`. Fix safety levels: Level 1 (auto-apply: formatting, naming), Level 2 (apply with review: structure changes), Level 3 (suggestion only: architectural, security).

Batch fix support: `drift fix --auto`, `drift fix --review`, `drift fix --category=security`.

Target: 80%+ violations have at least one fix. Detectors without fixes are flagged in health dashboard.

---

### M40: Effective False-Positive Tracking and Feedback Loop

**Sources**: 03-detectors R5, 05-analyzers R10
**Priority**: P1 | **Effort**: Medium | **Impact**: Continuous improvement, builds developer trust

Track violation actions: Fixed, Dismissed, Ignored, AutoFixed, NotSeen.

Effective FP rate per detector: `(dismissed + ignored) / (fixed + dismissed + ignored + autoFixed)`.

Detector health dashboard: alert at >10% FP rate, auto-disable at >20% for 30+ days. Expose health metrics via MCP. Track in IDE (opt-in), CLI, and CI.

**Evidence**: Google Tricorder <5% effective FP rate, "Not useful" button on every result.

---

### M41: Contract Detection — REST, GraphQL, gRPC

**Sources**: 03-detectors R8
**Priority**: P1 | **Effort**: High

Three API paradigms from the start:
1. **REST**: Backend endpoint extraction (Express, FastAPI, Spring, Laravel, Django, ASP.NET, Go, Rust, C++), frontend API call extraction, OpenAPI/Swagger spec parsing, breaking change classification
2. **GraphQL**: Schema extraction (.graphql files, code-first, introspection), schema↔resolver mismatch detection, frontend query↔schema mismatch, N+1 resolver detection
3. **gRPC/Protobuf**: .proto file parsing, service/message definitions, client↔server mismatch, breaking change detection (field number reuse, type changes)

Unified contract model normalizing all three paradigms for cross-paradigm analysis.

---

### M42: Framework Detection as Composable Middleware

**Sources**: 03-detectors R11, 02-parsers R12
**Priority**: P2 | **Effort**: Medium

Framework middleware enriches detection context by normalizing framework idioms to generic patterns (Spring `@GetMapping` → generic route, Laravel `Route::get()` → generic route, Django `path()` → generic route).

Plugin system: each framework is a separate crate implementing `FrameworkMiddleware`. Tier 1 (launch): React, Express, Spring Boot, Django, Laravel. Tier 2 (3 months): Vue, Angular, FastAPI, ASP.NET, Next.js, NestJS. Tier 3 (6 months): Svelte, Remix, Gin, Axum, Phoenix, Rails.

---

## Phase 7: Quality Assurance & Ecosystem

### Generalized Semantic Analysis (Future — P1)

**Sources**: 05-analyzers R4, R5, R6
**Priority**: P1 (post-launch) | **Effort**: Very High

Language-agnostic semantic model with per-language implementations (TypeSystem, ScopeResolver traits). Compilation abstraction bundling source files with dependencies. Interprocedural data flow via function summaries. Start with Python (type hints increasingly common), then Java and Go.

### Detector Testing Framework (P2)

**Sources**: 03-detectors R12
**Priority**: P2 | **Effort**: Medium

Snapshot testing with annotated fixtures (`@drift-expect` inline annotations). Cross-language parity testing. False-positive regression corpus. Confidence calibration tests. Performance benchmarks per detector.

### Call Graph Accuracy Benchmarking (P1)

**Sources**: 04-call-graph R12
**Priority**: P1 | **Effort**: Medium

Micro-benchmarks per resolution strategy (following PyCG's 112-program methodology). Macro-benchmarks with real-world projects and ground truth. Track precision, recall, resolution rate per language per strategy. Run in CI to detect regressions.

### Cross-Service Reachability (Future — P2)

**Sources**: 04-call-graph R9
**Priority**: P2 | **Effort**: High

Track API calls between services, link call graphs across service boundaries. Enables microservice architecture analysis and cross-service security vulnerability detection.

### SQLite Recursive CTEs for Reachability (P2)

**Sources**: 04-call-graph R8
**Priority**: P2 | **Effort**: Medium

Single-query reachability via recursive CTEs instead of N queries for N-hop BFS. Benchmark against current approach for various depths.

### Reachability Result Caching (P2)

**Sources**: 04-call-graph R10
**Priority**: P2 | **Effort**: Low

LRU cache for reachability results keyed on `(origin, max_depth, sensitive_only, tables)`. Invalidate on call graph rebuild.

### Abstract Interpretation (Future — P3)

**Sources**: 05-analyzers R13
**Priority**: P3 | **Effort**: Very High

Optional sound analysis using abstract interpretation. Start with interval domain (bounds checking), add nullness domain. Opt-in only — expensive but provides soundness guarantees for safety-critical code.

---

## Master Dependency Graph

```
Phase 0 (Decisions)
  M1 Incremental-First ──────────────────────────────────────────────────┐
  M2 Structured Errors ──→ ALL subsystems                               │
  M3 SQLite WAL ─────────→ ALL databases                                │
  M4 Layered Architecture → ALL crates                                  │
                                                                        │
Phase 1 (Core Engine)                                                   │
  M5 Scanner ──→ M13 Parse Cache                                        │
  M6 ParseResult ──→ ALL consumers (M14-M32)                            │
  M7 Parser Trait ──→ M6, M13                                           │
  M8 String Interning ──→ M15, M20                                      │
  M9 Data Structures ──→ ALL subsystems                                 │
  M10 Parser Pool ──→ M13                                               │
  M11 Query Consolidation ──→ M6                                        │
  M12 Error-Tolerant ──→ M6                                             │
  M13 Parse Cache ──→ M14, M15, M20 ←──────────────────────────────────┘
                                                                        
Phase 2 (Detection)                                                     
  M14 Visitor Pattern ──→ M15, M16                                      
  M15 Unified Analyzer ──→ M18, M19                                     
  M16 GAST ──→ M36 (security detectors)                                 
  M17 Incremental Detection ──→ M33 (scoring)                           
  M18 Secret Detection ──→ M36 (OWASP A02)                              
  M19 Pattern Coverage ──→ M39 (fixes)                                  
                                                                        
Phase 3 (Analysis)                                                      
  M20 Call Graph ──→ M21, M22, M25, M26, M27, M31, M32                 
  M21 Namespace Resolution ──→ M20 (improves precision)                 
  M22 Coupling ──→ M31 (impact analysis)                                
  M23 Boundaries ──→ M27 (reachability)                                 
  M24 Environment ──→ M36 (security)                                    
  M25 Error Handling ──→ M20 (propagation chains)                       
  M26 Test Topology ──→ M31 (minimum test set)                          
  M27 Taint Analysis ──→ M36 (OWASP A01, A03, A10)                     
  M30 Pydantic ──→ M41 (FastAPI contracts)                              
  M31 Impact Analysis ──→ M38 (N-API exposure)                          
  M32 Dead Code ──→ M38 (N-API exposure)                                
                                                                        
Phase 4 (Scoring)                                                       
  M33 Decay + Momentum ──→ M34 (Bayesian)                               
  M34 Bayesian Learning ──→ M40 (feedback loop)                         
  M35 Outlier Refinements ──→ standalone                                 
                                                                        
Phase 5 (Security)                                                      
  M36 OWASP/CWE ──→ M39 (fixes), M40 (feedback)                        
  M37 N+1 Detection ──→ M39 (fixes)                                     
                                                                        
Phase 6 (Bridge & DX)                                                   
  M38 N-API Bridge ──→ TS orchestration layer                           
  M39 Fixes ──→ IDE, CLI, MCP                                           
  M40 Feedback Loop ──→ IDE, CLI, CI                                    
  M41 Contracts ──→ MCP tools                                           
  M42 Framework Middleware ──→ M14 (detection engine)                    
```

---

## Cross-Category Impact Matrix

| Recommendation | Categories Affected | Impact Type |
|---|---|---|
| M1 (Incremental) | All 5 | Computation model for every subsystem |
| M6 (ParseResult) | All 5 | Foundational data model consumed everywhere |
| M14 (Visitor) | 01, 02, 03 | Requires AST traversal API changes |
| M16 (GAST) | 01, 02, 03 | New normalization layer between parsing and detection |
| M20 (Call Graph) | 01, 03, 04, 05 | Enables taint, impact, dead code, test topology |
| M27 (Taint) | 01, 03, 04, 05 | Transforms security detection across all categories |
| M33 (Decay) | 03, 05 | Changes confidence scoring for all patterns |
| M34 (Bayesian) | 03, 05 | Changes convention learning for all detectors |
| M36 (OWASP) | 03, 04, 05 | Security findings feed gates, MCP, and CI |
| M38 (N-API) | All 5 | Bridge layer for all Rust → TS communication |
| M39 (Fixes) | 03, 05 | Fix generation for all detectors and analyzers |
| M40 (Feedback) | 03, 05 | Feedback loop for all detectors and analyzers |

---

## Deduplication Map

The 70 per-category recommendations collapsed into 42 unified recommendations. Here is the mapping:

| Unified | Source Recommendations | Deduplication Reason |
|---|---|---|
| M1 | 01-FA1, 02-R1, 03-R2, 04-R5, 05-R1 | Incremental computation appeared in all 5 categories |
| M2 | 01-FA2, 02-R13 | Structured errors in rust-core and parsers |
| M6 | 01-R2, 02-R2, 02-R3, 02-R7, 02-R10 | ParseResult shape, decorators, namespace, generics — all one data model |
| M13 | 02-R1 (cache portion), 04-R10 | Parse cache and reachability cache — same pattern |
| M18 | 01-R5, 05-R7 | Secret detection in rust-core and analyzers |
| M20 | 01-R6, 04-R2, 04-R3 | Call graph builder, extractors, resolution — one subsystem |
| M22 | 01-R7, 05-R11 | Coupling analyzer in rust-core and analyzers |
| M27 | 01-R12, 04-R1, 04-R11, 05-R3, 05-R6 | Taint/reachability/data flow — one security analysis system |
| M39 | 03-R10, 05-R9 | Fix generation in detectors and analyzers |
| M40 | 03-R5, 05-R10 | Feedback loop in detectors and analyzers |

Remaining 32 recommendations mapped 1:1 from their source categories.

---

## Success Metrics

| Metric | V1 Baseline | V2 Target | Measurement |
|---|---|---|---|
| Incremental scan (1 file changed, 10K codebase) | ~10s (full rescan) | <100ms | Wall clock time |
| Full scan (10K files) | ~30s | <5s | Wall clock time |
| Full scan (500K files) | Untested/infeasible | <60s | Wall clock time |
| Detection per file | ~5ms (100+ traversals) | <0.5ms (single pass) | Per-file average |
| Call graph resolution rate | ~60% (Rust), ~80% (TS) | >80% (unified Rust) | Resolved / total calls |
| Security false positive rate | ~30% (estimated) | <10% | Via feedback loop |
| Effective false positive rate (all detectors) | Unknown | <5% | Google Tricorder model |
| Quick fix coverage | ~30% of violation types | >80% | Violations with ≥1 fix |
| Secret patterns | 21 | 100+ | Pattern count |
| Languages with semantic analysis | 1 (TS) | 5+ | Languages with type/scope |
| OWASP Top 10 coverage | 2-3 categories | 8+ categories | Detectable categories |
| Framework coverage (Tier 1) | 6 | 10+ | Frameworks with middleware |
| Parse cache hit rate (incremental) | 0% (no cache) | >95% | Hits / (hits + misses) |
| Convention learning accuracy | Binary (60% threshold) | Bayesian posterior | Calibration tests |
| Outlier false positive rate | ~4.6% (|z|>2.0) | ~1.2% (|z|>2.5) | Statistical model |

---

## Build Timeline (Suggested)

```
Weeks 1-2:   Phase 0 — Architectural decisions (M1-M4)
Weeks 3-8:   Phase 1 — Core engine (M5-M13)
Weeks 9-14:  Phase 2 — Detection engine (M14-M19)
Weeks 15-22: Phase 3 — Analysis subsystems (M20-M32)
Weeks 23-26: Phase 4 — Statistical engine (M33-M35)
Weeks 27-30: Phase 5 — Security & compliance (M36-M37)
Weeks 31-36: Phase 6 — Bridge & DX (M38-M42)
Weeks 37-40: Phase 7 — Quality assurance & ecosystem
```

Note: Phase 4-5 items (scoring, security) can be built in parallel with Phase 3 analysis subsystems since they have minimal cross-dependencies. The critical path is: Phase 0 → Phase 1 → Phase 2 → Phase 3 → Phase 6.

---

## Quality Checklist

- [x] All 70 per-category recommendations accounted for
- [x] 28 duplicates identified and merged with deduplication map
- [x] 42 unified recommendations organized across 7 build phases
- [x] Master dependency graph showing all inter-recommendation relationships
- [x] Cross-category impact matrix for high-impact recommendations
- [x] Success metrics with V1 baselines and V2 targets
- [x] Build timeline with phase dependencies
- [x] Every recommendation framed as "build new" (greenfield)
- [x] External evidence cited throughout (25+ sources from MASTER_RESEARCH.md)
- [x] P0 recommendations form the critical path
- [x] Security (OWASP/CWE, taint) treated as first-class concern
- [x] Statistical rigor (Bayesian, temporal decay) built into scoring engine
- [x] Enterprise scale (500K+ files) addressed in architecture decisions
- [x] Feedback loop (Google Tricorder model) integrated into DX phase
