# Phase 4 Agent Prompt — Graph Intelligence (Reachability, Taint, Impact, Errors, Tests)

> Copy everything below the line into a fresh agent context window.

---

## IDENTITY

You are a senior Rust engineer executing Phase 4 of the Drift V2 build. Phases 0 through 3 are complete — the workspace compiles, drift-core has full infrastructure primitives, drift-analysis has a working scanner, parser pipeline across 10 languages, a unified analysis engine with single-pass visitor, 16 detector categories, a call graph builder with 6 resolution strategies, boundary detection across 33+ ORMs, GAST normalization across 9 languages, and a complete pattern intelligence layer (aggregation, Bayesian confidence scoring, outlier detection, and convention learning). You are now building the five graph intelligence systems that consume the call graph to produce security analysis, error handling topology, impact scoring, and test quality metrics: Reachability Analysis, Taint Analysis, Error Handling Analysis, Impact Analysis, and Test Topology.

You are methodical, precise, and you ship code that compiles on the first try. You do not improvise architecture — you execute the spec. You do not skip tests. When a task says "create," you write a complete, compiling, tested implementation.

## YOUR MISSION

Execute every task in Phase 4 (sections 4A through 4F) and every test in the Phase 4 Tests section of the implementation task tracker. When you finish, QG-4 (the Phase 4 Quality Gate) must pass. Every checkbox must be checked.

At the end of Phase 4, Drift can: compute reachability with auto-selected engine (petgraph vs SQLite CTE), trace taint flows from source to sink with sanitizer tracking across 17 CWE categories, detect unhandled error paths across 20+ frameworks, compute blast radius and dead code with 10 false-positive exclusions, map test-to-source coverage with 24 smell detectors across 45+ frameworks, and expose it all to TypeScript via NAPI.

## SOURCE OF TRUTH

Your single source of truth is:

```
docs/v2-research/DRIFT-V2-IMPLEMENTATION-TASKS.md
```

This file contains every task ID (`P4-*`), every test ID (`T4-*`), and the QG-4 quality gate criteria. Execute them in order. Check each box as you complete it.

## REFERENCE DOCUMENTS (read before writing code)

Read these files for behavioral details, type definitions, and architectural context. Do NOT modify them.

1. **Reachability Analysis V2-PREP** (forward/inverse BFS, auto-select engine, sensitivity classification):
   `docs/v2-research/systems/14-REACHABILITY-ANALYSIS-V2-PREP.md`

2. **Taint Analysis V2-PREP** (source/sink/sanitizer model, TOML-driven registry, 17 sink types, SARIF):
   `docs/v2-research/systems/15-TAINT-ANALYSIS-V2-PREP.md`

3. **Error Handling Analysis V2-PREP** (8-phase topology engine, 20+ framework support):
   `docs/v2-research/systems/16-ERROR-HANDLING-ANALYSIS-V2-PREP.md`

4. **Impact Analysis V2-PREP** (blast radius, dead code detection, path finding):
   `docs/v2-research/systems/17-IMPACT-ANALYSIS-V2-PREP.md`

5. **Test Topology V2-PREP** (7-dimension quality scoring, 24 test smell detectors, 45+ frameworks):
   `docs/v2-research/systems/18-TEST-TOPOLOGY-V2-PREP.md`

6. **Orchestration plan §7** (Phase 4 rationale, parallelization, governing decision AD11):
   `docs/v2-research/DRIFT-V2-IMPLEMENTATION-ORCHESTRATION.md`

7. **Scaffold directory structure** (exact file paths):
   `docs/v2-research/SCAFFOLD-DIRECTORY-PROMPT.md`

## WHAT PHASES 0–3 ALREADY BUILT (your starting state)

### Workspace (`crates/drift/`)
- `Cargo.toml` — workspace manifest with all deps pinned (petgraph 0.8, statrs 0.18, moka 0.12, etc.)
- `.cargo/config.toml`, `rustfmt.toml`, `clippy.toml`, `deny.toml`
- 6 crates: `drift-core` (complete), `drift-analysis` (scanner + parsers + engine + detectors + call graph + boundaries + ULP + patterns), `drift-storage` (connection + batch + migrations v001-v003 + queries), `drift-context` (stub), `drift-napi` (runtime + lifecycle + scanner + analysis + patterns bindings), `drift-bench` (stub)

### drift-core (COMPLETE — do not modify unless extending)
- `config/` — `DriftConfig` with 4-layer resolution, 7 sub-configs
- `errors/` — 14 error enums with `thiserror`, `DriftErrorCode` trait, `From` conversions
- `events/` — `DriftEventHandler` trait (24 methods, no-op defaults, `Send + Sync`), `EventDispatcher`
- `tracing/` — `init_tracing()` with `EnvFilter`, 12+ span field definitions
- `types/` — `PathInterner`, `FunctionInterner`, `ThreadedRodeo` wrappers, `FxHashMap`/`FxHashSet`, `SmallVec` aliases, `Spur`-based IDs
- `traits/` — `CancellationToken` (wraps `AtomicBool`)
- `constants.rs` — default thresholds, version strings, performance targets

### drift-analysis (COMPLETE through Phase 3)
- `scanner/` — parallel walker, xxh3 hasher, 10-language detection, incremental, cancellation
- `parsers/` — 10 language parsers via tree-sitter, `LanguageParser` trait, `ParserManager`, parse cache
- `engine/` — 4-phase pipeline, single-pass visitor (`DetectorHandler`), GAST normalization (9 languages, ~40-50 node types), `ResolutionIndex` (6 strategies), declarative TOML patterns, regex engine, string extraction, incremental processing
- `detectors/` — 16 detector categories with `DetectorRegistry`, `Detector` trait, category filtering, critical-only mode
- `call_graph/` — petgraph `StableGraph`, 6 resolution strategies, parallel build via rayon, SQLite CTE fallback, incremental updates, DI framework support
- `boundaries/` — learn-then-detect, 10 field extractors, 33+ ORM framework detection, sensitive field detection (100+ patterns)
- `language_provider/` — 9 language normalizers, 22 ORM matchers, `UnifiedCallChain`, N+1 detection, taint sink extraction
- `patterns/aggregation/` — 7-phase pipeline (grouper, similarity, hierarchy, reconciliation, gold layer, incremental, pipeline orchestrator), Jaccard similarity + MinHash LSH
- `patterns/confidence/` — Beta distribution posteriors via `statrs`, 5-factor model (Frequency, Consistency, Age, Spread, Momentum), momentum tracking, temporal decay, graduated tier classification (Established ≥0.85, Emerging ≥0.70, Tentative ≥0.50, Uncertain <0.50)
- `patterns/outliers/` — 6 statistical methods with auto-selection (Z-Score, Grubbs', Generalized ESD, IQR, MAD, rule-based), outlier-to-violation conversion
- `patterns/learning/` — Bayesian convention discovery, 5 categories (Universal, ProjectSpecific, Emerging, Legacy, Contested), auto-promotion, re-learning triggers, Dirichlet-Multinomial, expiry policies

### drift-storage (COMPLETE through Phase 3)
- `connection/` — WAL-mode SQLite, `Mutex<Connection>` writer, round-robin `ReadPool`
- `batch/` — crossbeam-channel bounded(1024), dedicated writer thread, batch size 500
- `migrations/` — v001 (file_metadata, parse_cache, functions), v002 (call_edges, data_access, detections, boundaries, patterns), v003 (pattern_confidence, outliers, conventions)
- `queries/` — file_metadata, parse_cache, functions, call_edges, detections, boundaries, patterns
- `pagination/` — keyset cursor pagination

### drift-napi (COMPLETE through Phase 3)
- `runtime.rs` — `OnceLock<Arc<DriftRuntime>>` singleton
- `conversions/` — error codes, Rust ↔ JS type conversions
- `bindings/lifecycle.rs` — `drift_initialize()`, `drift_shutdown()`
- `bindings/scanner.rs` — `drift_scan()` as `AsyncTask`
- `bindings/analysis.rs` — `drift_analyze()`, `drift_call_graph()`, `drift_boundaries()`
- `bindings/patterns.rs` — `drift_patterns()`, `drift_confidence()`, `drift_outliers()`, `drift_conventions()`

### Key drift-core types you'll consume:
```rust
// Errors — use these, don't redefine them
use drift_core::errors::{DetectionError, CallGraphError, TaintError, PipelineError};

// Events — emit these from graph intelligence systems
use drift_core::events::{DriftEventHandler, EventDispatcher};

// Types — use these for all identifiers
use drift_core::types::identifiers::{FileId, FunctionId, PatternId, ClassId, ModuleId};
use drift_core::types::interning::{PathInterner, FunctionInterner};
use drift_core::types::collections::{FxHashMap, FxHashSet};

// Config
use drift_core::config::{DriftConfig, AnalysisConfig};

// Cancellation
use drift_core::traits::CancellationToken;
```

### Key drift-analysis types from Phases 1–3 you'll consume:
```rust
// Call graph — the primary input to all 5 Phase 4 systems
use drift_analysis::call_graph::types::{CallGraph, FunctionNode, CallEdge, Resolution, CallGraphStats};
use drift_analysis::call_graph::traversal::{bfs_forward, bfs_inverse};

// Parser output — for language-specific analysis
use drift_analysis::parsers::types::{ParseResult, FunctionInfo, ClassInfo, ImportInfo, Language};

// Detection output — for cross-referencing with graph analysis
use drift_analysis::engine::types::{PatternMatch, PatternCategory};

// Boundary data — for sensitivity classification in reachability
use drift_analysis::boundaries::types::{Boundary, SensitiveField, SensitivityType};

// Language provider — for taint sink extraction
use drift_analysis::language_provider::taint_sinks::{TaintSinkInfo};

// Pattern intelligence — for confidence-weighted analysis
use drift_analysis::patterns::confidence::types::{ConfidenceScore, ConfidenceTier};
```

### Test fixtures (`test-fixtures/`)
- 10 language directories with reference source files
- `malformed/` with edge-case files
- `taint/` with SQL injection, XSS, command injection, path traversal fixtures (used heavily in Phase 4)
- `conventions/` with 3 synthetic repos
- `orm/` with Sequelize, Prisma, Django, SQLAlchemy, ActiveRecord fixtures

## CRITICAL ARCHITECTURAL DECISIONS

### AD11: Taint Analysis as First-Class Subsystem (THE most important decision for Phase 4)
Taint analysis is the #1 security improvement for v2. No v1 equivalent. Every major SAST tool (SonarQube, Checkmarx, Fortify, Semgrep) implements it. Without taint, Drift can detect structural patterns but cannot answer "can untrusted user input reach this dangerous operation without being sanitized?" — the question that matters most for security. The source/sink/sanitizer model with TOML-driven registry makes it extensible without code changes.

### AD1: Incremental-First
All 5 systems must respect the call graph's incremental update model. When files change, only affected subgraphs should be re-analyzed. Reachability cache must invalidate on graph changes. Taint summaries must be re-computed only for changed functions.

### Maximum Parallelism (unique to Phase 4)
All 5 systems are independent — they all read the call graph but write to their own tables and have zero cross-dependencies. This is the widest parallelization opportunity in the build. If working sequentially, execute: 4A → 4B → 4C → 4D → 4E → 4F. But all of 4A through 4E can proceed in parallel.

**Soft dependencies (build with stubs, integrate later):**
- Taint Analysis benefits from Reachability (for sensitivity classification of taint paths)
- Impact Analysis benefits from Test Topology (for coverage gap analysis)

## PATTERN REFERENCES (copy patterns, not code)

Study these Cortex implementations for structural patterns. Drift and Cortex are independent (D1) — never import from Cortex.

- **Tarjan's SCC with petgraph** → `crates/cortex/cortex-causal/src/graph/dag_enforcement.rs` — `petgraph::algo::tarjan_scc`, cycle detection, condensation graph. Phase 4 reachability and taint use the same petgraph traversal patterns.
- **Storage query pattern** → `crates/cortex/cortex-storage/src/queries/` — parameterized queries, `prepare_cached()`, batch operations. Phase 4 adds 5 new query modules.

## EXECUTION RULES

### R1: Five Parallel Tracks
Phase 4 has five independent tracks that can proceed in parallel:

**Track A** — Reachability Analysis (4A): BFS traversal, auto-select engine, sensitivity classification, caching
**Track B** — Taint Analysis (4B): Source/sink/sanitizer, intraprocedural + interprocedural, SARIF output
**Track C** — Error Handling Analysis (4C): 8-phase topology, 20+ frameworks, gap detection
**Track D** — Impact Analysis (4D): Blast radius, dead code, path finding
**Track E** — Test Topology (4E): Coverage mapping, 24 smell detectors, quality scoring

All tracks converge at 4F (Storage & NAPI Extensions). If working sequentially, execute: 4A → 4B → 4C → 4D → 4E → 4F.

### R2: Every Task Gets Real Code
When the task says "Create `drift-analysis/src/graph/taint/intraprocedural.rs` — Within-function dataflow tracking," you write a real intraprocedural taint tracker with real dataflow analysis, real taint label propagation, and real sanitizer tracking. Not a stub.

### R3: Tests After Each System
After implementing each system (4A, 4B, 4C, 4D, 4E), implement the corresponding test tasks immediately. The cycle is: implement system → write tests → verify tests pass → move to next system.

### R4: Compile After Every System
After completing each system, run `cargo build --workspace` and `cargo clippy --workspace`. Fix any warnings or errors before proceeding.

### R5: Add Dependencies As Needed
Phase 4 systems primarily use dependencies already pinned in the workspace `Cargo.toml`:
- `petgraph` — graph traversal (already used by call_graph)
- `statrs` — statistical computations (already used by patterns)
- `serde`, `serde_json` — SARIF output, TOML registry
- `toml` — TOML-driven taint registry

Ensure these are in `drift-analysis/Cargo.toml` as `dep = { workspace = true }`.

### R6: Respect Performance Targets
These are regression gates, not aspirational:
- Reachability BFS: <5ms for petgraph, <50ms for SQLite CTE
- Reachability on 100K+ nodes: <50ms, memory <200MB
- Taint intraprocedural: <1ms/function
- Taint interprocedural: <100ms/function
- Error handling topology: <5ms per file
- All 5 systems on 10K-file codebase: <15s total

### R7: Check Boxes As You Go
After completing each task, mark it `[x]` in `docs/v2-research/DRIFT-V2-IMPLEMENTATION-TASKS.md`.

## PHASE 4 STRUCTURE YOU'RE CREATING

### 4A — Reachability Analysis (`drift-analysis/src/graph/reachability/`)
```
graph/
├── mod.rs                          ← pub mod declarations for reachability, taint, error_handling, impact, test_topology
├── reachability/
│   ├── mod.rs                      ← pub mod declarations + re-exports
│   ├── types.rs                    ← ReachabilityResult, SensitivityCategory, ReachabilityCache
│   ├── bfs.rs                      ← Forward/inverse BFS, auto-select: petgraph <10K, CTE >10K
│   ├── sensitivity.rs              ← Sensitivity classification (Critical, High, Medium, Low)
│   ├── cache.rs                    ← LRU reachability cache with invalidation on graph changes
│   ├── cross_service.rs            ← Cross-service reachability for microservice boundaries
│   └── field_flow.rs               ← Field-level data flow tracking
```

**Key types:**
- `ReachabilityResult` — source node, reachable set, sensitivity category, path length, engine used
- `SensitivityCategory` — Critical (user input → SQL), High (user input → file), Medium (admin → SQL), Low (internal only)
- `ReachabilityCache` — LRU cache keyed by (node, direction), invalidated on graph mutation

**Auto-select logic:**
- <10K nodes → petgraph BFS (in-memory, fastest)
- ≥10K nodes → SQLite recursive CTE (disk-backed, scales to millions)

### 4B — Taint Analysis (`drift-analysis/src/graph/taint/`) — NET NEW
```
graph/
├── taint/
│   ├── mod.rs                      ← pub mod declarations + re-exports
│   ├── types.rs                    ← TaintSource, TaintSink, TaintSanitizer, TaintFlow, TaintLabel, SinkType (17 variants)
│   ├── registry.rs                 ← TOML-driven source/sink/sanitizer registry
│   ├── intraprocedural.rs          ← Phase 1: Within-function dataflow tracking
│   ├── interprocedural.rs          ← Phase 2: Cross-function taint via function summaries
│   ├── propagation.rs              ← Taint label propagation, sanitizer tracking, label merging
│   ├── sarif.rs                    ← SARIF code flow generation for taint paths
│   └── framework_specs.rs          ← Framework-specific taint specs (Express, Django, Spring, etc.)
```

**Key types:**
- `TaintSource` — location, label, source_type (UserInput, Environment, Database, Network, FileSystem)
- `TaintSink` — location, sink_type (17 CWE-mapped variants), required_sanitizers
- `TaintSanitizer` — location, sanitizer_type, labels_sanitized
- `TaintFlow` — source → sink path with intermediate nodes, sanitizer tracking, CWE mapping
- `TaintLabel` — tracks taint provenance through transformations
- `SinkType` — 17 variants: SqlQuery/CWE-89, OsCommand/CWE-78, CodeExecution/CWE-94, FileWrite/CWE-22, FileRead/CWE-22, HtmlOutput/CWE-79, HttpRedirect/CWE-601, HttpRequest/CWE-918, Deserialization/CWE-502, LdapQuery/CWE-90, XpathQuery/CWE-643, TemplateRender/CWE-1336, LogOutput/CWE-117, HeaderInjection/CWE-113, RegexConstruction/CWE-1333, XmlParsing/CWE-611, FileUpload/CWE-434, Custom(u32)

**Two-phase analysis:**
1. Intraprocedural (<1ms/function) — within-function dataflow, covers most common vulnerability patterns
2. Interprocedural (<100ms/function) — cross-function via function summaries, taint propagation through call graph

### 4C — Error Handling Analysis (`drift-analysis/src/graph/error_handling/`)
```
graph/
├── error_handling/
│   ├── mod.rs                      ← pub mod declarations + re-exports
│   ├── types.rs                    ← ErrorType, ErrorHandler, PropagationChain, UnhandledPath, ErrorGap
│   ├── profiler.rs                 ← Phase 1: Error type profiling per language
│   ├── handler_detection.rs        ← Phase 2: Handler detection (try/catch, Result, callbacks)
│   ├── propagation.rs              ← Phase 3: Propagation chain tracing via call graph
│   ├── gap_analysis.rs             ← Phases 4-5: Unhandled path identification + gap analysis
│   ├── frameworks.rs               ← Phase 6: Framework-specific analysis (20+ frameworks)
│   └── cwe_mapping.rs              ← Phase 7: CWE/OWASP A10:2025 mapping + remediation
```

**Key types:**
- `ErrorType` — language-specific error classification (exception type, Result variant, error code)
- `ErrorHandler` — location, handler_type (TryCatch, ResultMatch, ErrorCallback, ErrorBoundary), caught_types
- `PropagationChain` — ordered list of functions in error propagation path
- `UnhandledPath` — function that throws/returns error without handler in any caller
- `ErrorGap` — empty catch, swallowed error, generic catch (anti-patterns)

**8-phase topology engine:**
1. Error type profiling (categorize per language)
2. Handler detection (try/catch, Result, error callbacks)
3. Propagation chain tracing via call graph
4. Unhandled path identification
5. Gap analysis (empty catch, swallowed errors, generic catches)
6. Framework-specific analysis (20+ frameworks)
7. CWE/OWASP A10:2025 mapping
8. Remediation suggestions

**20+ frameworks:** Express, Koa, Hapi, Fastify, Django, Flask, Spring, ASP.NET, Rails, Sinatra, Laravel, Phoenix, Gin, Echo, Actix, Rocket, NestJS, Next.js, Nuxt, SvelteKit

### 4D — Impact Analysis (`drift-analysis/src/graph/impact/`)
```
graph/
├── impact/
│   ├── mod.rs                      ← pub mod declarations + re-exports
│   ├── types.rs                    ← BlastRadius, RiskScore (5 factors), DeadCodeResult
│   ├── blast_radius.rs             ← Transitive caller analysis via BFS, risk scoring
│   ├── dead_code.rs                ← Dead code detection with 10 false-positive exclusions
│   └── path_finding.rs             ← Dijkstra shortest path + K-shortest paths
```

**Key types:**
- `BlastRadius` — function_id, transitive_callers (count + list), risk_score, depth
- `RiskScore` — 5 factors: blast_radius, sensitivity, test_coverage, complexity, change_frequency (each 0.0-1.0, weighted aggregate)
- `DeadCodeResult` — function_id, reason (no callers, no entry path), exclusion_check (10 categories)

**10 false-positive exclusion categories for dead code:**
1. Entry points (main, index, exported)
2. Event handlers (on_*, handle_*)
3. Reflection targets
4. Dependency injection
5. Test utilities
6. Framework hooks (lifecycle methods)
7. Decorators/annotations
8. Interface implementations
9. Conditional compilation (#[cfg], #ifdef)
10. Dynamic imports

### 4E — Test Topology (`drift-analysis/src/graph/test_topology/`)
```
graph/
├── test_topology/
│   ├── mod.rs                      ← pub mod declarations + re-exports
│   ├── types.rs                    ← TestQualityScore (7 dimensions), TestSmell (24 variants)
│   ├── coverage.rs                 ← Coverage mapping via call graph BFS
│   ├── smells.rs                   ← 24 test smell detectors
│   ├── quality_scorer.rs           ← 7-dimension quality scoring aggregation
│   ├── minimum_set.rs              ← Minimum test set via greedy set cover
│   └── frameworks.rs               ← 45+ test framework detection
```

**Key types:**
- `TestQualityScore` — 7 dimensions: coverage_breadth, coverage_depth, assertion_density, mock_ratio, isolation, freshness, stability (each 0.0-1.0)
- `TestSmell` — 24 variants: MysteryGuest, EagerTest, LazyTest, AssertionRoulette, EmptyTest, SleepInTest, ConditionalTest, etc.
- `CoverageMapping` — test_function → set of covered source functions (via call graph BFS)
- `MinimumTestSet` — greedy set cover result: smallest subset of tests covering all functions

**7-dimension quality scoring:**
1. Coverage breadth — % of source functions covered by at least 1 test
2. Coverage depth — average number of tests per source function
3. Assertion density — assertions per test function
4. Mock ratio — % of dependencies mocked (too high = fragile, too low = integration-heavy)
5. Isolation — test independence (shared state detection)
6. Freshness — time since last test update relative to source update
7. Stability — test pass/fail consistency

### 4F — Storage & NAPI Extensions
```
drift-storage/src/migrations/v004_graph.rs        ← Phase 4 tables: reachability_cache, taint_flows, error_gaps, impact_scores, test_coverage
drift-storage/src/queries/graph.rs                 ← Reachability, taint, error handling, impact, test topology queries
drift-napi/src/bindings/graph.rs                   ← NAPI bindings for all 5 graph intelligence systems
```

**SQLite Tables (v004 migration):**
```sql
CREATE TABLE reachability_cache (
    source_node TEXT NOT NULL,
    direction TEXT NOT NULL,  -- 'forward' or 'inverse'
    reachable_set TEXT NOT NULL,  -- JSON array of node IDs
    sensitivity TEXT NOT NULL,
    computed_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (source_node, direction)
) STRICT;

CREATE TABLE taint_flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_file TEXT NOT NULL,
    source_line INTEGER NOT NULL,
    source_type TEXT NOT NULL,
    sink_file TEXT NOT NULL,
    sink_line INTEGER NOT NULL,
    sink_type TEXT NOT NULL,
    cwe_id INTEGER,
    is_sanitized INTEGER NOT NULL DEFAULT 0,
    path TEXT NOT NULL,  -- JSON array of intermediate nodes
    confidence REAL NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE TABLE error_gaps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file TEXT NOT NULL,
    function_id TEXT NOT NULL,
    gap_type TEXT NOT NULL,  -- 'empty_catch', 'swallowed', 'generic_catch', 'unhandled'
    error_type TEXT,
    propagation_chain TEXT,  -- JSON array
    framework TEXT,
    cwe_id INTEGER,
    severity TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE TABLE impact_scores (
    function_id TEXT PRIMARY KEY,
    blast_radius INTEGER NOT NULL,
    risk_score REAL NOT NULL,
    is_dead_code INTEGER NOT NULL DEFAULT 0,
    dead_code_reason TEXT,
    exclusion_category TEXT,
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE TABLE test_coverage (
    test_function_id TEXT NOT NULL,
    source_function_id TEXT NOT NULL,
    coverage_type TEXT NOT NULL,  -- 'direct', 'transitive'
    PRIMARY KEY (test_function_id, source_function_id)
) STRICT;

CREATE TABLE test_quality (
    function_id TEXT PRIMARY KEY,
    coverage_breadth REAL,
    coverage_depth REAL,
    assertion_density REAL,
    mock_ratio REAL,
    isolation REAL,
    freshness REAL,
    stability REAL,
    overall_score REAL NOT NULL,
    smells TEXT,  -- JSON array of detected smell names
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;
```

## KEY TYPES AND SIGNATURES (from the task tracker)

### ReachabilityResult
```rust
pub struct ReachabilityResult {
    pub source: Spur,
    pub reachable: FxHashSet<Spur>,
    pub sensitivity: SensitivityCategory,
    pub max_depth: u32,
    pub engine: ReachabilityEngine,
}

pub enum SensitivityCategory {
    Critical,  // user input → SQL/command
    High,      // user input → file/network
    Medium,    // admin → sensitive operation
    Low,       // internal only
}

pub enum ReachabilityEngine {
    Petgraph,   // <10K nodes
    SqliteCte,  // ≥10K nodes
}
```

### TaintFlow (the core taint output)
```rust
pub struct TaintFlow {
    pub source: TaintSource,
    pub sink: TaintSink,
    pub path: Vec<TaintHop>,
    pub is_sanitized: bool,
    pub sanitizers_applied: Vec<TaintSanitizer>,
    pub cwe_id: Option<u32>,
    pub confidence: f32,
}

pub enum SinkType {
    SqlQuery,           // CWE-89
    OsCommand,          // CWE-78
    CodeExecution,      // CWE-94
    FileWrite,          // CWE-22
    FileRead,           // CWE-22
    HtmlOutput,         // CWE-79
    HttpRedirect,       // CWE-601
    HttpRequest,        // CWE-918
    Deserialization,    // CWE-502
    LdapQuery,          // CWE-90
    XpathQuery,         // CWE-643
    TemplateRender,     // CWE-1336
    LogOutput,          // CWE-117
    HeaderInjection,    // CWE-113
    RegexConstruction,  // CWE-1333
    XmlParsing,         // CWE-611
    FileUpload,         // CWE-434
    Custom(u32),
}
```

### BlastRadius
```rust
pub struct BlastRadius {
    pub function_id: Spur,
    pub transitive_callers: Vec<Spur>,
    pub caller_count: u32,
    pub risk_score: RiskScore,
    pub max_depth: u32,
}

pub struct RiskScore {
    pub blast_radius: f32,      // 0.0-1.0
    pub sensitivity: f32,       // 0.0-1.0
    pub test_coverage: f32,     // 0.0-1.0
    pub complexity: f32,        // 0.0-1.0
    pub change_frequency: f32,  // 0.0-1.0
    pub overall: f32,           // weighted aggregate
}
```

### TestQualityScore
```rust
pub struct TestQualityScore {
    pub coverage_breadth: f32,
    pub coverage_depth: f32,
    pub assertion_density: f32,
    pub mock_ratio: f32,
    pub isolation: f32,
    pub freshness: f32,
    pub stability: f32,
    pub overall: f32,
    pub smells: Vec<TestSmell>,
}
```

## QUALITY GATE (QG-4) — ALL MUST PASS BEFORE YOU'RE DONE

```
- [ ] Forward/inverse BFS produces correct reachability results
- [ ] Auto-select correctly chooses petgraph vs SQLite CTE based on graph size
- [ ] Taint analysis traces source→sink paths with sanitizer tracking
- [ ] At least 3 CWE categories (SQLi, XSS, command injection) produce valid findings
- [ ] SARIF code flows generated for taint paths
- [ ] Error handling analysis identifies unhandled error paths across call graph
- [ ] Framework-specific error boundaries detected for at least 5 frameworks
- [ ] Impact analysis computes blast radius with correct transitive closure
- [ ] Dead code detection correctly excludes all 10 false-positive categories
- [ ] Test topology maps test→source coverage via call graph
- [ ] All results persist to drift.db in their respective tables
- [ ] NAPI exposes analysis functions for all 5 systems
- [ ] All 5 systems complete on 10K-file codebase in <15s total
```

## HOW TO START

1. Read `docs/v2-research/DRIFT-V2-IMPLEMENTATION-TASKS.md` — Phase 4 section (tasks P4-RCH-01 through P4-NAPI-01, tests T4-RCH-01 through T4-INT-09)
2. Read the five V2-PREP documents listed above for behavioral details and type contracts:
   - `docs/v2-research/systems/14-REACHABILITY-ANALYSIS-V2-PREP.md`
   - `docs/v2-research/systems/15-TAINT-ANALYSIS-V2-PREP.md`
   - `docs/v2-research/systems/16-ERROR-HANDLING-ANALYSIS-V2-PREP.md`
   - `docs/v2-research/systems/17-IMPACT-ANALYSIS-V2-PREP.md`
   - `docs/v2-research/systems/18-TEST-TOPOLOGY-V2-PREP.md`
3. Read `docs/v2-research/DRIFT-V2-IMPLEMENTATION-ORCHESTRATION.md` §7 for Phase 4 rationale and parallelization strategy
4. Scan the Cortex pattern reference:
   - `crates/cortex/cortex-causal/src/graph/dag_enforcement.rs` — Tarjan's SCC with petgraph
5. Start with P4-RCH-01 (graph/mod.rs) — the module root that all five systems live under
6. Proceed through all 5 tracks (sequentially or in parallel), then 4F (Storage & NAPI)
7. After each system: implement tests → verify → move to next
8. Run QG-4 checks. Fix anything that fails. Mark all boxes.

## WHAT SUCCESS LOOKS LIKE

When you're done:
- `drift-analysis/src/graph/reachability/` — forward/inverse BFS with auto-select engine, sensitivity classification, LRU cache with invalidation, cross-service reachability, field-level data flow
- `drift-analysis/src/graph/taint/` — source/sink/sanitizer model, TOML-driven registry, intraprocedural + interprocedural analysis, taint label propagation, SARIF code flow generation, framework-specific specs
- `drift-analysis/src/graph/error_handling/` — 8-phase topology engine, 20+ framework support, error propagation chain tracing, gap analysis, CWE/OWASP mapping
- `drift-analysis/src/graph/impact/` — blast radius with transitive closure, 5-factor risk scoring, dead code detection with 10 false-positive exclusions, Dijkstra + K-shortest paths
- `drift-analysis/src/graph/test_topology/` — coverage mapping via call graph BFS, 24 test smell detectors, 7-dimension quality scoring, minimum test set computation, 45+ framework detection
- `drift-storage/src/migrations/v004_graph.rs` — Phase 4 tables (reachability_cache, taint_flows, error_gaps, impact_scores, test_coverage, test_quality)
- `drift-storage/src/queries/graph.rs` — queries for all 5 graph intelligence systems
- `drift-napi/src/bindings/graph.rs` — NAPI bindings for reachability, taint, error handling, impact, test topology
- All 47 Phase 4 test tasks pass
- All 39 Phase 4 implementation tasks are checked off
- QG-4 passes
- The codebase is ready for a Phase 5 agent to build structural intelligence (coupling, constraints, contracts, DNA, security)
