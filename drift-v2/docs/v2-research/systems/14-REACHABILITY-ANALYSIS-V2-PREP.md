# Reachability Analysis (BFS Engines, Sensitivity Classification) — V2 Implementation Prep

> Comprehensive build specification for Drift v2's Reachability Analysis subsystem (System 14).
> Synthesized from: 04-call-graph/reachability.md (v1 ReachabilityEngine, SqliteReachabilityEngine),
> 04-call-graph/analysis.md (BFS engines, impact analyzer, dead code, path finder, coverage),
> 04-call-graph/enrichment.md (sensitivity classifier, impact scorer, remediation generator),
> 04-call-graph/overview.md (architecture, capabilities matrix, consumer list),
> 04-call-graph/types.md (ReachabilityResult, InverseReachabilityResult, type parity),
> 04-call-graph/rust-core.md (CallGraphDb queries, ParallelWriter),
> 04-call-graph/storage.md (SQLite schema, UnifiedCallGraphProvider, LRU cache),
> 21-security/overview.md (security analysis pipeline, sensitivity categories),
> 21-security/types.md (DataAccessPoint, SensitiveField, ORMModel, BoundaryViolation),
> 05-CALL-GRAPH-V2-PREP.md (petgraph StableGraph, Resolution, CallEdge, SQLite CTEs),
> 07-BOUNDARY-DETECTION-V2-PREP.md (learn-then-detect, 33 ORM frameworks, field-level flow),
> DRIFT-V2-FULL-SYSTEM-AUDIT.md (AD1 incremental, AD11 taint first-class, AD12 data structures),
> DRIFT-V2-STACK-HIERARCHY.md (Level 2B — Graph Intelligence),
> DRIFT-V2-SYSTEMS-REFERENCE.md (reachability capabilities, sensitivity categories),
> PLANNING-DRIFT.md (D1-D7),
> .research/04-call-graph/RECOMMENDATIONS.md (R1 taint, R5 incremental, R6 impact in Rust,
> R7 dead code in Rust, R8 recursive CTEs, R9 cross-service, R10 caching, R11 field-level,
> R12 accuracy benchmarking),
> .research/04-call-graph/RECAP.md (capabilities matrix, limitations, type parity),
> .research/16-gap-analysis/RECOMMENDATIONS.md (GE4 security roadmap, GAP-4.3 taint,
> GAP-4.5 field-level flow),
> .research/16-gap-analysis/RESEARCH.md (§2.3 taint analysis industry consensus,
> §2.4 SAST landscape, FlowDroid, Semgrep taint mode, SemTaint),
> 03-NAPI-BRIDGE-V2-PREP.md (command/query pattern, async tasks),
> 02-STORAGE-V2-PREP.md (batch writer, keyset pagination),
> 04-INFRASTRUCTURE-V2-PREP.md (thiserror, tracing, FxHashMap, petgraph),
> FlowDroid (Arzt et al., PLDI 2014 — context/flow/field/object-sensitive taint),
> Semgrep taint mode (source/sink/sanitizer, intraprocedural default),
> SemTaint (arxiv 2025 — multi-agent LLM taint specification extraction),
> PyCG (Salis et al., ICSE 2021 — namespace-based call graph, 99.2% precision),
> Oligo reachability analysis (5 techniques, internet-facing prioritization),
> Qt/Axivion dead code analysis (reachability on call relation),
> petgraph StableGraph (Rust graph library, BFS/DFS algorithms).
>
> Purpose: Everything needed to build the Reachability Analysis subsystem from scratch.
> This is the DEDICATED deep-dive — the 05-CALL-GRAPH-V2-PREP doc covers the call graph
> builder (extraction, resolution, persistence); this document covers everything that
> CONSUMES the call graph: forward/inverse reachability, sensitivity classification,
> taint analysis integration, impact analysis, dead code detection, coverage analysis,
> path finding, and the enrichment pipeline. Every v1 feature accounted for. Zero
> feature loss. Every algorithm specified. Every type defined. Every integration point
> documented. Every architectural decision resolved.
> Generated: 2026-02-07

---

## Table of Contents

1. Architectural Position
2. V1 Complete Feature Inventory
3. V2 Architecture — Unified Reachability Engine
4. Core Data Model
5. Forward Reachability Engine (BFS)
6. Inverse Reachability Engine (Reverse BFS)
7. SQLite CTE Reachability (Large Codebase Fallback)
8. Sensitivity Classification Engine
9. Taint Analysis Integration (AD11)
10. Impact Analysis Engine
11. Dead Code Detection Engine
12. Coverage Analysis Engine (Call Graph × Test Topology)
13. Path Finding Engine
14. Enrichment Pipeline (Sensitivity → Impact → Remediation)
15. Reachability Caching (LRU + Invalidation)
16. Incremental Reachability (Content-Hash Aware)
17. Cross-Service Reachability (Microservice Boundaries)
18. Field-Level Data Flow Tracking
19. Storage Schema
20. NAPI Interface
21. MCP Tool Interface
22. CLI Interface
23. Event Interface
24. Tracing & Observability
25. Performance Targets & Benchmarks
26. Build Order & Dependencies
27. V1 → V2 Feature Cross-Reference
28. Inconsistencies & Decisions
29. Risk Register

---

## 1. Architectural Position

Reachability Analysis is **Level 2B — Graph Intelligence** in the Drift v2 stack hierarchy.
It is the primary consumer of the call graph and the primary producer of security intelligence.
Without it, Drift can map function relationships but cannot answer the questions that matter:
"Can user input reach this SQL query?", "What breaks if I change this function?",
"Which functions are dead code?", "Do tests cover this sensitive data path?"

Per DRIFT-V2-STACK-HIERARCHY.md:

> Reachability Analysis: Forward/inverse BFS, sensitivity classification, taint tracking.
> Powers security ("can user input reach this SQL query?"), impact, taint.
> High leverage — one engine, many consumers.

This is the system that transforms Drift's structural call graph into actionable security
and engineering intelligence. It sits at the intersection of the call graph (Level 1) and
every downstream consumer that needs to understand data flow, change impact, or code liveness.

### Architectural Decision: AD11 (Taint Analysis as First-Class Subsystem)

From DRIFT-V2-FULL-SYSTEM-AUDIT.md:

> AD11: Taint Analysis as First-Class Subsystem — Not an afterthought.
> Source/sink/sanitizer registry (TOML-configurable, per-framework defaults).
> Phase 1: intraprocedural taint tracking in Rust.
> Phase 2: interprocedural via call graph taint summaries.

The Reachability Analysis subsystem is where taint analysis lives. Taint tracking is an
extension of reachability — instead of asking "can function A reach function B?", taint
asks "can untrusted data from source A reach dangerous sink B without sanitization?"
Same BFS engine, enriched with taint labels.

### What Lives Here

- Forward reachability engine (BFS from function → reachable data access points)
- Inverse reachability engine (reverse BFS from data → entry points that can reach it)
- SQLite CTE reachability (large codebase fallback, O(1) memory)
- Sensitivity classification (4 categories: PII, Credentials, Financial, Health)
- Sensitivity level scoring (Critical, High, Medium, Low)
- False positive filtering for sensitivity (6 filter types)
- Taint analysis integration (source/sink/sanitizer tracking along BFS paths)
- Impact analysis (transitive caller analysis, blast radius, risk scoring)
- Dead code detection (unreachable functions with false positive filtering)
- Coverage analysis (call graph × test topology for data path coverage)
- Path finding (BFS with path tracking between any two functions)
- Enrichment pipeline (sensitivity → impact scoring → remediation generation)
- Reachability result caching (LRU with call graph invalidation)
- Field-level data flow tracking (7 transformation types)
- Cross-service reachability (API call tracking between microservices)
- Reachability query API (NAPI, MCP, CLI consumers)

### What Does NOT Live Here

- Call graph construction → Call Graph Builder (Level 1, produces the graph we traverse)
- Call resolution → Call Graph Builder (Level 1, resolves call targets)
- Data access detection → Boundary Detection (Level 1, produces DataAccessPoint[])
- ORM framework detection → Boundary Detection (Level 1, learns frameworks)
- Pattern detection → Detector System (Level 1, produces raw matches)
- Quality gate evaluation → Quality Gates (Level 3, consumes our results)
- MCP tool routing → MCP Server (Level 5, presentation layer)
- Cortex memory linking → Bridge crate (optional, separate)

### Critical Path Position

```
Scanner (Level 0)
  → Parsers (Level 0) — produce ParseResult with FunctionInfo, CallSite
    → Call Graph Builder (Level 1) — builds petgraph + drift.db edges
      → Boundary Detection (Level 1) — produces DataAccessPoint[], SensitiveField[]
        → Reachability Analysis (Level 2B) ← YOU ARE HERE
          → Quality Gates (Level 3) — security gate uses reachability results
            → MCP Tools (Level 5) — drift_reachability, drift_impact, drift_security
              → CLI (Level 5) — drift callgraph reachability, drift security reachability
```

### Dependency Direction

```
                    ┌─────────────────────────────────────────────────┐
                    │         Downstream Consumers                    │
                    │  Quality Gates (security gate, impact gate),    │
                    │  MCP Tools (drift_reachability, drift_impact,   │
                    │    drift_dead_code, drift_security_reachability,│
                    │    drift_taint_analysis),                       │
                    │  CLI (callgraph reachability, security, taint), │
                    │  Context Generation (security context budget),  │
                    │  Simulation Engine (blast radius calculation),  │
                    │  DNA System (security health metrics),          │
                    │  Cortex Grounding (D7 — security validation)   │
                    └──────────────────┬──────────────────────────────┘
                                       │ reads reachability results
                    ┌──────────────────▼──────────────────────────────┐
                    │   Reachability Analysis (this system)           │
                    │   Level 2B — Graph Intelligence                 │
                    └──────────────────┬──────────────────────────────┘
                                       │ reads call graph + boundaries
                    ┌──────────────────▼──────────────────────────────┐
                    │         Upstream Producers                      │
                    │  Call Graph Builder (petgraph + drift.db edges),│
                    │  Boundary Detection (DataAccessPoint[],         │
                    │    SensitiveField[], ORMModel[]),               │
                    │  Scanner (file metadata, content hashes),       │
                    │  Storage (drift.db persistence)                 │
                    └─────────────────────────────────────────────────┘
```

### Consumer Count: 10+ Downstream Systems

The reachability engine is the highest-leverage Level 2B system. Every security query,
every impact analysis, every dead code report, every test coverage gap, every taint flow
passes through this engine. Building it well pays compound dividends across the entire
Drift analysis stack.

---

## 2. V1 Complete Feature Inventory

Every v1 feature documented here must be accounted for in v2 — either preserved, upgraded,
or explicitly replaced with rationale. This is the zero-feature-loss guarantee.

### 2.1 V1 ReachabilityEngine (In-Memory BFS)

**Location**: `crates/drift-core/src/reachability/engine.rs`

```rust
pub struct ReachabilityEngine {
    graph: CallGraph,  // HashMap<String, FunctionNode>
}

impl ReachabilityEngine {
    // Forward: function → what data can it reach?
    pub fn get_reachable_data(
        &self, file: &str, line: u32, options: &ReachabilityOptions
    ) -> ReachabilityResult;

    // Inverse: data → who can reach it?
    pub fn get_code_paths_to_data(
        &self, options: &InverseReachabilityOptions
    ) -> InverseReachabilityResult;

    // Path finding: any two functions
    pub fn get_call_path(
        &self, from_id: &str, to_id: &str, max_depth: u32
    ) -> Vec<Vec<CallPathNode>>;
}
```

**Forward BFS algorithm**:
1. Find containing function at file:line
2. BFS through `calls` edges, tracking visited set
3. At each function, collect `data_access` points
4. Classify sensitive fields (PII, credentials, financial, health)
5. Build call path for each reachable data access
6. Return with depth tracking and function traversal count

**Inverse BFS algorithm**:
1. Find all functions that access the target table/field
2. For each accessor, find all paths from entry points via reverse BFS
3. Return entry points and access paths

### 2.2 V1 SqliteReachabilityEngine

**Location**: `crates/drift-core/src/reachability/sqlite_engine.rs`

Same API as in-memory engine, but queries SQLite directly:
- `get_function_info()` → SQL query on functions table
- `get_resolved_calls()` → SQL query on call_edges table
- `get_data_access()` → SQL query on data_access table
- `get_table_accessors()` → SQL query filtering by table name
- `get_entry_points()` → SQL query for is_entry_point = 1
- `find_containing_function()` → SQL range query on start_line/end_line

Trade-off: Latency per lookup for memory efficiency.

### 2.3 V1 TypeScript Reachability (TS Layer)

**Location**: `packages/core/src/call-graph/analysis/reachability.ts`

```typescript
// Forward reachability
function getReachableData(
    graph: CallGraph, file: string, line: number, options: ReachabilityOptions
): ReachabilityResult;

// Inverse reachability
function getCodePathsToData(
    graph: CallGraph, options: InverseReachabilityOptions
): InverseReachabilityResult;
```

### 2.4 V1 Sensitivity Classification

**Rust** (`crates/drift-core/src/boundaries/sensitive.rs`):
- Pattern-based detection with specificity scoring
- 4 categories: PII, Credentials, Financial, Health
- False positive filtering (function names, imports, comments, test/mock prefixes)

**TypeScript** (`packages/core/src/call-graph/enrichment/sensitivity-classifier.ts`):
- 4 sensitivity levels: Critical, High, Medium, Low
- Pattern matching on field names and table names
- Context-aware scoring

### 2.5 V1 Impact Analyzer (TS Only)

**Location**: `packages/core/src/call-graph/analysis/impact-analyzer.ts`

```typescript
function analyzeImpact(graph: CallGraph, functionId: string): {
    affectedFunctions: string[];
    affectedDataPaths: DataPath[];
    risk: 'low' | 'medium' | 'high' | 'critical';
}
```

Risk factors: affected function count, entry point impact, sensitive data paths, depth.

### 2.6 V1 Dead Code Detector (TS Only)

**Location**: `packages/core/src/call-graph/analysis/dead-code-detector.ts`

```typescript
function detectDeadCode(graph: CallGraph): {
    candidates: DeadCodeCandidate[];
    confidence: 'high' | 'medium' | 'low';
    falsePositiveReasons: string[];
}
```

False positive handling: entry points, framework hooks, dynamic dispatch, event handlers,
exported functions.

### 2.7 V1 Coverage Analyzer (TS Only)

**Location**: `packages/core/src/call-graph/analysis/coverage-analyzer.ts`

```typescript
function analyzeCoverage(graph: CallGraph, testTopology: TestTopology): {
    fieldCoverage: FieldCoverage[];
    uncoveredPaths: DataPath[];
}
```

### 2.8 V1 Path Finder

**Location**: `packages/core/src/call-graph/analysis/path-finder.ts` + Rust

BFS with path tracking between any two functions. Returns multiple paths.

### 2.9 V1 Enrichment Pipeline (TS Only)

**Location**: `packages/core/src/call-graph/enrichment/`

3 components:
1. Sensitivity Classifier — classifies data access by sensitivity level
2. Impact Scorer — scores function impact (centrality, entry point, sensitive data)
3. Remediation Generator — generates actionable fix suggestions

### 2.10 V1 NAPI Functions (12)

```
build_call_graph(config) → JsBuildResult
is_call_graph_available(root_dir) → bool
get_call_graph_stats(root_dir) → JsCallGraphStats
get_call_graph_entry_points(root_dir) → Vec<JsEntryPointInfo>
get_call_graph_data_accessors(root_dir) → Vec<JsDataAccessorInfo>
get_call_graph_callers(root_dir, target) → Vec<JsCallerInfo>
get_call_graph_file_callers(root_dir, file_path) → Vec<JsCallerInfo>
analyze_reachability(options) → JsReachabilityResult
analyze_inverse_reachability(options) → JsInverseReachabilityResult
analyze_reachability_sqlite(options) → JsReachabilityResult
analyze_inverse_reachability_sqlite(options) → JsInverseReachabilityResult
```

### 2.11 V1 MCP Tools

- `drift_reachability` — Forward/inverse data reachability via UnifiedCallGraphProvider
- `drift_callers` — Who calls this function (uses native SQLite when available)
- `drift_signature` — Function signature lookup
- `drift_impact_analysis` — Change blast radius

### 2.12 V1 UnifiedCallGraphProvider

**Location**: `packages/core/src/call-graph/unified-provider.ts`

Auto-detects storage format (sqlite/sharded/legacy/none), LRU cache (500 entries),
delegates to Rust N-API when available. Unified query API across all storage backends.


### 2.13 V1 Feature Inventory (Exhaustive)

| # | Feature | V1 Behavior | V2 Status |
|---|---------|-------------|-----------|
| R1 | Forward reachability (in-memory BFS) | HashMap-based BFS, file:line → reachable data | Upgraded → petgraph BFS with taint labels (§5) |
| R2 | Inverse reachability (in-memory) | Reverse BFS from data accessor → entry points | Upgraded → petgraph reverse BFS with path ranking (§6) |
| R3 | SQLite reachability (forward) | Per-hop SQL queries, BFS in Rust | Upgraded → recursive CTEs, single query (§7) |
| R4 | SQLite reachability (inverse) | Per-hop SQL queries, reverse BFS | Upgraded → recursive CTEs, single query (§7) |
| R5 | Path finding | BFS with path tracking, multiple paths | Preserved → petgraph all_simple_paths (§13) |
| R6 | Sensitivity classification (Rust) | Pattern-based, 4 categories, specificity scoring | Upgraded → 6 categories + composite scoring (§8) |
| R7 | Sensitivity classification (TS) | 4 levels (Critical/High/Medium/Low) | Merged → unified Rust engine (§8) |
| R8 | False positive filtering | Function names, imports, comments, test/mock | Upgraded → 8 filter types + context scoring (§8) |
| R9 | Impact analysis (TS only) | Reverse BFS, risk scoring (4 levels) | Ported → Rust with blast radius metrics (§10) |
| R10 | Dead code detection (TS only) | calledBy.length == 0, false positive handling | Ported → Rust with 8 false positive categories (§11) |
| R11 | Coverage analysis (TS only) | Call graph × test topology | Ported → Rust with field-level coverage (§12) |
| R12 | Enrichment: sensitivity classifier | TS pattern matching on field/table names | Replaced → Rust unified sensitivity engine (§14) |
| R13 | Enrichment: impact scorer | TS centrality + entry point + sensitive data | Replaced → Rust PageRank-inspired scoring (§14) |
| R14 | Enrichment: remediation generator | TS heuristic suggestions | Preserved → Rust heuristics + AI-assisted (§14) |
| R15 | NAPI: analyze_reachability | In-memory forward reachability | Preserved → unified engine auto-selects (§20) |
| R16 | NAPI: analyze_inverse_reachability | In-memory inverse reachability | Preserved → unified engine auto-selects (§20) |
| R17 | NAPI: analyze_reachability_sqlite | SQLite-backed forward reachability | Merged → single API, engine auto-selects (§20) |
| R18 | NAPI: analyze_inverse_reachability_sqlite | SQLite-backed inverse reachability | Merged → single API, engine auto-selects (§20) |
| R19 | MCP: drift_reachability | Forward/inverse via UnifiedCallGraphProvider | Preserved + taint mode added (§21) |
| R20 | MCP: drift_impact_analysis | Change blast radius | Preserved + blast radius metrics (§21) |
| R21 | MCP: drift_callers | Reverse caller lookup | Preserved (call graph builder scope) |
| R22 | UnifiedCallGraphProvider | Auto-detect storage, LRU cache, unified API | Replaced → Rust-native unified engine (§3) |
| R23 | Reachability result caching | TS CallGraphStore.cacheReachability() | Upgraded → Rust LRU with invalidation (§15) |
| R24 | Depth tracking | max_depth in results | Preserved (§5, §6) |
| R25 | Functions traversed count | functions_traversed in results | Preserved (§5, §6) |
| R26 | Call path construction | Vec<CallPathNode> per reachable access | Preserved + taint labels added (§5) |
| R27 | Sensitive field access aggregation | SensitiveFieldAccess with paths + count | Upgraded → field-level with transformations (§18) |
| R28 | Table list in results | tables: Vec<String> | Preserved (§5) |
| R29 | No taint analysis | Cannot track data transformations | Added → full taint engine (§9) |
| R30 | No field-level flow | Table-level granularity only | Added → field-level tracking (§18) |
| R31 | No cross-service reachability | Single-service only | Added → API call tracking (§17) |
| R32 | No reachability caching in Rust | TS-only caching | Added → Rust LRU cache (§15) |
| R33 | No incremental reachability | Full recompute on graph change | Added → incremental invalidation (§16) |
| R34 | No dead code in Rust | TS-only dead code detection | Added → Rust dead code engine (§11) |
| R35 | No impact analysis in Rust | TS-only impact analysis | Added → Rust impact engine (§10) |
| R36 | No coverage analysis in Rust | TS-only coverage analysis | Added → Rust coverage engine (§12) |
| R37 | Dual engine (in-memory + SQLite) | Separate APIs, manual selection | Unified → auto-select based on graph size (§3) |
| R38 | Credential field warning | Warns on credential field access | Preserved + enhanced (§8) |

**Coverage**: 38/38 v1 features accounted for. 0 features lost.

---

## 3. V2 Architecture — Unified Reachability Engine

### 3.1 Design Philosophy

V1's reachability is split across two Rust engines (in-memory, SQLite), one TS engine,
and a TS enrichment pipeline. The consumer must choose which engine to use, and the
enrichment pipeline runs separately. This creates 4 problems:

1. **Engine selection burden**: Consumers must know whether to call `analyze_reachability`
   or `analyze_reachability_sqlite`. The UnifiedCallGraphProvider partially solves this
   in TS, but Rust callers have no unified API.
2. **No taint tracking**: BFS traverses call edges but doesn't track data labels.
   Cannot distinguish sanitized from unsanitized paths.
3. **No field-level precision**: Reachability reports table-level access. Cannot
   distinguish `users.password_hash` from `users.display_name`.
4. **Enrichment is disconnected**: Sensitivity classification, impact scoring, and
   remediation run as separate TS passes after reachability. Should be integrated.

V2 solves all four with a unified Rust engine that:
- Auto-selects in-memory (petgraph) or SQLite (CTE) based on graph size
- Tracks taint labels along BFS paths (source → sanitizer → sink)
- Supports field-level data flow tracking
- Integrates sensitivity classification into the traversal itself

### 3.2 Engine Auto-Selection

```rust
/// Unified reachability engine. Auto-selects the optimal backend.
pub struct ReachabilityEngine {
    /// In-memory graph for fast BFS (loaded from drift.db on startup).
    graph: Option<Arc<CallGraph>>,

    /// SQLite connection for CTE-based reachability (large codebases).
    db: Arc<DatabaseManager>,

    /// Sensitivity classifier (shared across all queries).
    sensitivity: SensitivityClassifier,

    /// Taint registry (source/sink/sanitizer definitions).
    taint_registry: TaintRegistry,

    /// LRU cache for reachability results.
    cache: Mutex<LruCache<ReachabilityKey, CachedResult>>,

    /// Configuration.
    config: ReachabilityConfig,
}

impl ReachabilityEngine {
    /// Create engine with auto-selection.
    /// If graph fits in memory (< config.memory_threshold), use petgraph.
    /// Otherwise, fall back to SQLite CTEs.
    pub fn new(
        db: Arc<DatabaseManager>,
        config: ReachabilityConfig,
    ) -> Result<Self, ReachabilityError> {
        let stats = db.reader()?.query_row(
            "SELECT COUNT(*) FROM functions", [], |r| r.get::<_, usize>(0)
        )?;

        let graph = if stats <= config.memory_threshold {
            Some(Arc::new(CallGraph::load_from_db(&db)?))
        } else {
            tracing::info!(
                functions = stats,
                threshold = config.memory_threshold,
                "Graph exceeds memory threshold, using SQLite CTE fallback"
            );
            None
        };

        Ok(Self {
            graph,
            db,
            sensitivity: SensitivityClassifier::new(),
            taint_registry: TaintRegistry::load_or_default()?,
            cache: Mutex::new(LruCache::new(
                NonZeroUsize::new(config.cache_size).unwrap()
            )),
            config,
        })
    }

    /// Forward reachability — auto-selects engine.
    pub fn forward(
        &self,
        origin: &CodeLocation,
        options: &ReachabilityOptions,
    ) -> Result<ReachabilityResult, ReachabilityError> {
        // Check cache first
        let key = ReachabilityKey::forward(origin, options);
        if let Some(cached) = self.cache.lock().unwrap().get(&key) {
            return Ok(cached.result.clone());
        }

        let result = match &self.graph {
            Some(graph) => self.forward_petgraph(graph, origin, options)?,
            None => self.forward_sqlite(origin, options)?,
        };

        // Cache result
        self.cache.lock().unwrap().put(key, CachedResult {
            result: result.clone(),
            computed_at: Instant::now(),
        });

        Ok(result)
    }

    /// Inverse reachability — auto-selects engine.
    pub fn inverse(
        &self,
        target: &InverseTarget,
        options: &InverseReachabilityOptions,
    ) -> Result<InverseReachabilityResult, ReachabilityError> {
        let key = ReachabilityKey::inverse(target, options);
        if let Some(cached) = self.cache.lock().unwrap().get(&key) {
            return Ok(cached.inverse_result.clone());
        }

        let result = match &self.graph {
            Some(graph) => self.inverse_petgraph(graph, target, options)?,
            None => self.inverse_sqlite(target, options)?,
        };

        self.cache.lock().unwrap().put(key, CachedResult {
            inverse_result: result.clone(),
            computed_at: Instant::now(),
        });

        Ok(result)
    }

    /// Invalidate cache (called after call graph rebuild).
    pub fn invalidate_cache(&self) {
        self.cache.lock().unwrap().clear();
    }

    /// Reload in-memory graph from drift.db (called after incremental update).
    pub fn reload_graph(&mut self) -> Result<(), ReachabilityError> {
        let stats = self.db.reader()?.query_row(
            "SELECT COUNT(*) FROM functions", [], |r| r.get::<_, usize>(0)
        )?;

        if stats <= self.config.memory_threshold {
            self.graph = Some(Arc::new(CallGraph::load_from_db(&self.db)?));
        } else {
            self.graph = None;
        }

        self.invalidate_cache();
        Ok(())
    }
}
```

### 3.3 Configuration

```rust
/// Reachability engine configuration.
pub struct ReachabilityConfig {
    /// Maximum number of functions before falling back to SQLite CTEs.
    /// Default: 500_000 (500K functions ≈ 200MB in-memory graph).
    pub memory_threshold: usize,

    /// Default maximum BFS depth for forward reachability.
    /// Default: 50 (most real call chains are <20 deep).
    pub default_max_depth: u32,

    /// Maximum BFS depth for inverse reachability.
    /// Default: 50.
    pub default_inverse_max_depth: u32,

    /// LRU cache size for reachability results.
    /// Default: 256.
    pub cache_size: usize,

    /// Whether to include taint labels in BFS traversal.
    /// Default: true.
    pub enable_taint: bool,

    /// Whether to track field-level data flow.
    /// Default: true.
    pub enable_field_level: bool,

    /// Minimum confidence for call edges to be traversed.
    /// Default: 0.40 (includes fuzzy resolution).
    pub min_edge_confidence: f64,

    /// Whether to include unresolved calls in traversal.
    /// Default: false (only traverse resolved edges).
    pub include_unresolved: bool,
}

impl Default for ReachabilityConfig {
    fn default() -> Self {
        Self {
            memory_threshold: 500_000,
            default_max_depth: 50,
            default_inverse_max_depth: 50,
            cache_size: 256,
            enable_taint: true,
            enable_field_level: true,
            min_edge_confidence: 0.40,
            include_unresolved: false,
        }
    }
}
```

### 3.4 Relationship to Call Graph Builder

The Reachability Engine is a **pure consumer** of the call graph. It never modifies the
graph — it only traverses it. The call graph builder (05-CALL-GRAPH-V2-PREP) owns:
- petgraph StableGraph construction
- SQLite persistence (functions, call_edges, data_access tables)
- Resolution (6 strategies)
- Incremental updates (file-level invalidation)

The Reachability Engine owns:
- BFS/DFS traversal algorithms
- Sensitivity classification during traversal
- Taint label propagation during traversal
- Impact/dead code/coverage analysis
- Result caching and invalidation
- NAPI/MCP/CLI query interfaces

This separation means the call graph builder can be rebuilt independently, and the
reachability engine simply reloads from drift.db.


---

## 4. Core Data Model

### 4.1 ReachabilityResult (Primary Output Type)

Replaces v1's `ReachabilityResult` with taint labels, field-level tracking, and
sensitivity classification integrated into the result.

```rust
use serde::{Deserialize, Serialize};

/// Result of a forward reachability query.
/// Answers: "From this code location, what data can it ultimately access?"
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReachabilityResult {
    /// The starting point of the reachability query.
    pub origin: CodeLocation,

    /// All data access points reachable from the origin, with call paths.
    pub reachable_access: Vec<ReachableDataAccess>,

    /// Sensitive fields reachable, aggregated across all paths.
    pub sensitive_fields: Vec<SensitiveFieldAccess>,

    /// Taint flows detected (source → sink, with sanitizer tracking).
    /// Empty if taint analysis is disabled.
    pub taint_flows: Vec<TaintFlow>,

    /// Unique table names reachable from the origin.
    pub tables: Vec<String>,

    /// Number of functions traversed during BFS.
    pub functions_traversed: u32,

    /// Maximum depth reached during BFS.
    pub max_depth_reached: u32,

    /// Maximum depth configured for this query.
    pub max_depth_configured: u32,

    /// Which engine was used (petgraph or sqlite_cte).
    pub engine: EngineType,

    /// Whether the result was served from cache.
    pub from_cache: bool,

    /// Time taken for the query (microseconds).
    pub query_time_us: u64,

    /// Security summary: highest sensitivity level found, risk tier.
    pub security_summary: SecuritySummary,
}

/// A single reachable data access point with the call path to reach it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReachableDataAccess {
    /// The data access point (table, fields, operation, framework).
    pub access: DataAccessPoint,

    /// The call path from origin to this access point.
    pub path: Vec<CallPathNode>,

    /// BFS depth at which this access was found.
    pub depth: u32,

    /// Sensitivity level of this access (computed from fields + table).
    pub sensitivity: SensitivityLevel,

    /// Taint status: is the data reaching this access sanitized?
    pub taint_status: TaintStatus,

    /// Field-level access details (if field-level tracking enabled).
    pub field_access: Vec<FieldLevelAccess>,
}

/// A node in a call path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallPathNode {
    /// Function ID (interned in petgraph, string in SQLite).
    pub function_id: String,

    /// Human-readable function name.
    pub function_name: String,

    /// File containing this function.
    pub file: String,

    /// Line number of the function definition.
    pub line: u32,

    /// Resolution strategy that connected this edge.
    pub resolution: Option<String>,

    /// Confidence of the edge resolution.
    pub confidence: Option<f64>,

    /// Taint labels active at this point in the path.
    pub taint_labels: Vec<TaintLabel>,
}

/// Aggregated sensitive field access across all reachable paths.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensitiveFieldAccess {
    /// The sensitive field.
    pub field: SensitiveField,

    /// All paths that reach this field.
    pub paths: Vec<Vec<CallPathNode>>,

    /// Number of distinct access points for this field.
    pub access_count: u32,

    /// Whether any path to this field is unsanitized (taint analysis).
    pub has_unsanitized_path: bool,
}
```

### 4.2 InverseReachabilityResult

```rust
/// Result of an inverse reachability query.
/// Answers: "Who can reach this sensitive data?"
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InverseReachabilityResult {
    /// The target data being queried.
    pub target: InverseTarget,

    /// All access paths from entry points to the target data.
    pub access_paths: Vec<InverseAccessPath>,

    /// Entry points that can reach the target.
    pub entry_points: Vec<EntryPointInfo>,

    /// Total number of data accessors for the target.
    pub total_accessors: u32,

    /// Security summary for the target.
    pub security_summary: SecuritySummary,

    /// Engine used and timing.
    pub engine: EngineType,
    pub query_time_us: u64,
}

/// Target for inverse reachability.
#[derive(Debug, Clone, Serialize, Deserialize, Hash, Eq, PartialEq)]
pub struct InverseTarget {
    /// Table name (required).
    pub table: String,

    /// Optional field name for field-level inverse reachability.
    pub field: Option<String>,

    /// Optional operation filter (e.g., only write operations).
    pub operation: Option<DataOperation>,
}

/// A path from an entry point to a data accessor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InverseAccessPath {
    /// The entry point (HTTP handler, CLI command, etc.).
    pub entry_point: EntryPointInfo,

    /// The data accessor function.
    pub accessor: DataAccessorInfo,

    /// The call path from entry point to accessor.
    pub path: Vec<CallPathNode>,

    /// BFS depth of this path.
    pub depth: u32,

    /// Whether this path has authentication checks.
    pub has_auth_check: bool,

    /// Whether this path has input validation.
    pub has_input_validation: bool,

    /// Taint status along this path.
    pub taint_status: TaintStatus,
}

/// Information about an entry point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryPointInfo {
    pub function_id: String,
    pub function_name: String,
    pub file: String,
    pub line: u32,
    pub entry_type: EntryPointType,
    pub http_method: Option<String>,
    pub route_path: Option<String>,
}

/// Types of entry points.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EntryPointType {
    HttpHandler,
    CliCommand,
    MainFunction,
    ExportedFunction,
    EventHandler,
    ScheduledTask,
    WebSocketHandler,
    GraphQLResolver,
    GrpcHandler,
}
```

### 4.3 Supporting Enums

```rust
/// Which engine was used for the query.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum EngineType {
    /// In-memory petgraph BFS.
    Petgraph,
    /// SQLite recursive CTE.
    SqliteCte,
}

/// Sensitivity level of a data access point.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SensitivityLevel {
    /// Credentials, financial data with high specificity.
    Critical,
    /// PII (SSN, date_of_birth), health data.
    High,
    /// Contact info (email, phone, address).
    Medium,
    /// General data, non-sensitive fields.
    Low,
    /// Sensitivity could not be determined.
    Unknown,
}

/// Sensitivity category (what kind of sensitive data).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum SensitivityCategory {
    /// Personally Identifiable Information.
    Pii,
    /// Authentication credentials, API keys, tokens.
    Credentials,
    /// Financial data (credit cards, bank accounts, salary).
    Financial,
    /// Health/medical data (HIPAA-relevant).
    Health,
    /// Geolocation data.
    Geolocation,
    /// Biometric data.
    Biometric,
    /// Not sensitive or unknown.
    None,
}

/// Taint status of a data flow path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TaintStatus {
    /// No taint analysis performed (disabled or not applicable).
    NotAnalyzed,
    /// Data is sanitized before reaching the access point.
    Sanitized { sanitizer: String, sanitizer_type: SanitizerType },
    /// Data reaches the access point without sanitization.
    Unsanitized,
    /// Data is partially sanitized (some fields sanitized, others not).
    PartiallySanitized { sanitized_fields: Vec<String>, unsanitized_fields: Vec<String> },
}

/// Code location for reachability queries.
#[derive(Debug, Clone, Serialize, Deserialize, Hash, Eq, PartialEq)]
pub struct CodeLocation {
    /// File path (relative to project root).
    pub file: String,
    /// Line number (1-indexed).
    pub line: u32,
    /// Optional column number.
    pub column: Option<u32>,
    /// Optional function ID (if known, avoids file:line lookup).
    pub function_id: Option<String>,
}

/// Security summary for a reachability result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritySummary {
    /// Highest sensitivity level found across all reachable access points.
    pub highest_sensitivity: SensitivityLevel,
    /// Risk tier (1-4, where 1 is critical).
    pub risk_tier: u8,
    /// Count of reachable access points by sensitivity level.
    pub by_sensitivity: FxHashMap<SensitivityLevel, usize>,
    /// Count of unsanitized taint flows.
    pub unsanitized_flows: usize,
    /// Whether credential fields are reachable.
    pub credential_access: bool,
    /// Actionable summary message.
    pub summary: String,
}
```

### 4.4 Query Options

```rust
/// Options for forward reachability queries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReachabilityOptions {
    /// Maximum BFS depth. None = use config default.
    pub max_depth: Option<u32>,

    /// Only return sensitive data access points.
    pub sensitive_only: bool,

    /// Filter by specific table names.
    pub tables: Vec<String>,

    /// Filter by sensitivity level (minimum).
    pub min_sensitivity: Option<SensitivityLevel>,

    /// Filter by sensitivity category.
    pub categories: Vec<SensitivityCategory>,

    /// Include unresolved call edges in traversal.
    pub include_unresolved: bool,

    /// Minimum edge confidence for traversal.
    pub min_confidence: Option<f64>,

    /// Enable taint tracking along paths.
    pub enable_taint: Option<bool>,

    /// Enable field-level data flow tracking.
    pub enable_field_level: Option<bool>,

    /// Maximum number of paths to return per access point.
    pub max_paths_per_access: Option<usize>,
}

/// Options for inverse reachability queries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InverseReachabilityOptions {
    /// Target table name (required).
    pub table: String,

    /// Optional target field name.
    pub field: Option<String>,

    /// Optional operation filter.
    pub operation: Option<DataOperation>,

    /// Maximum reverse BFS depth.
    pub max_depth: Option<u32>,

    /// Only return paths from entry points (skip internal callers).
    pub entry_points_only: bool,

    /// Enable taint tracking along paths.
    pub enable_taint: Option<bool>,
}
```


---

## 5. Forward Reachability Engine (BFS)

### 5.1 petgraph BFS Implementation

The core forward reachability algorithm. Uses petgraph's `Bfs` iterator with custom
traversal logic for sensitivity classification, taint tracking, and path construction.

```rust
use petgraph::visit::Bfs;
use petgraph::Direction;
use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::VecDeque;

impl ReachabilityEngine {
    /// Forward reachability via petgraph BFS.
    /// Complexity: O(V + E) where V = reachable functions, E = traversed edges.
    fn forward_petgraph(
        &self,
        graph: &CallGraph,
        origin: &CodeLocation,
        options: &ReachabilityOptions,
    ) -> Result<ReachabilityResult, ReachabilityError> {
        let start = std::time::Instant::now();
        let max_depth = options.max_depth
            .unwrap_or(self.config.default_max_depth);
        let min_confidence = options.min_confidence
            .unwrap_or(self.config.min_edge_confidence);
        let enable_taint = options.enable_taint
            .unwrap_or(self.config.enable_taint);

        // Step 1: Find the containing function at origin location
        let start_node = graph.find_function_at(origin)?;

        // Step 2: BFS with depth tracking and path construction
        let mut visited: FxHashSet<NodeIndex> = FxHashSet::default();
        let mut queue: VecDeque<BfsEntry> = VecDeque::new();
        let mut reachable_access: Vec<ReachableDataAccess> = Vec::new();
        let mut sensitive_fields: FxHashMap<String, SensitiveFieldAccess> = FxHashMap::default();
        let mut tables: FxHashSet<String> = FxHashSet::default();
        let mut taint_flows: Vec<TaintFlow> = Vec::new();
        let mut max_depth_reached: u32 = 0;

        // Initialize BFS with the starting function
        queue.push_back(BfsEntry {
            node: start_node,
            depth: 0,
            path: vec![graph.node_to_path_node(start_node)],
            taint_labels: if enable_taint {
                self.taint_registry.get_source_labels(graph, start_node)
            } else {
                Vec::new()
            },
        });
        visited.insert(start_node);

        // Step 3: BFS traversal
        while let Some(entry) = queue.pop_front() {
            if entry.depth > max_depth {
                continue;
            }
            max_depth_reached = max_depth_reached.max(entry.depth);

            let func = &graph.graph[entry.node];

            // Step 3a: Collect data access points at this function
            let data_accesses = graph.get_data_access(entry.node);
            for access in data_accesses {
                // Apply table filter
                if !options.tables.is_empty()
                    && !options.tables.contains(&access.table)
                {
                    continue;
                }

                // Classify sensitivity
                let sensitivity = self.sensitivity.classify_access(&access);

                // Apply sensitivity filter
                if options.sensitive_only && sensitivity == SensitivityLevel::Low {
                    continue;
                }
                if let Some(min_sens) = &options.min_sensitivity {
                    if sensitivity < *min_sens {
                        continue;
                    }
                }

                // Track tables
                tables.insert(access.table.clone());

                // Compute taint status
                let taint_status = if enable_taint {
                    self.compute_taint_status(&entry.taint_labels, &access)
                } else {
                    TaintStatus::NotAnalyzed
                };

                // Build field-level access
                let field_access = if self.config.enable_field_level {
                    self.extract_field_level_access(&access)
                } else {
                    Vec::new()
                };

                // Aggregate sensitive fields
                for field in &access.fields {
                    if let Some(sf) = self.sensitivity.classify_field(field, &access.table) {
                        sensitive_fields
                            .entry(format!("{}.{}", access.table, field))
                            .or_insert_with(|| SensitiveFieldAccess {
                                field: sf.clone(),
                                paths: Vec::new(),
                                access_count: 0,
                                has_unsanitized_path: false,
                            })
                            .paths.push(entry.path.clone());
                        if matches!(taint_status, TaintStatus::Unsanitized) {
                            sensitive_fields
                                .get_mut(&format!("{}.{}", access.table, field))
                                .unwrap()
                                .has_unsanitized_path = true;
                        }
                    }
                }

                reachable_access.push(ReachableDataAccess {
                    access,
                    path: entry.path.clone(),
                    depth: entry.depth,
                    sensitivity,
                    taint_status,
                    field_access,
                });
            }

            // Step 3b: Check for taint sinks at this function
            if enable_taint && !entry.taint_labels.is_empty() {
                if let Some(sink) = self.taint_registry.get_sink(graph, entry.node) {
                    let sanitizers = self.find_sanitizers_on_path(&entry.path);
                    taint_flows.push(TaintFlow {
                        source: entry.taint_labels[0].source.clone(),
                        sink,
                        path: entry.path.clone(),
                        sanitizers: sanitizers.clone(),
                        is_sanitized: !sanitizers.is_empty(),
                        risk_level: self.compute_taint_risk(
                            &entry.taint_labels, &sanitizers
                        ),
                    });
                }
            }

            // Step 3c: Enqueue neighbors (callees)
            for edge in graph.graph.edges_directed(entry.node, Direction::Outgoing) {
                let callee = edge.target();
                let edge_data = edge.weight();

                // Skip low-confidence edges
                if edge_data.confidence < min_confidence {
                    continue;
                }

                // Skip unresolved unless explicitly requested
                if !options.include_unresolved
                    && edge_data.resolution == Resolution::Fuzzy
                    && edge_data.confidence < 0.50
                {
                    continue;
                }

                if visited.insert(callee) {
                    let mut new_path = entry.path.clone();
                    new_path.push(graph.node_to_path_node_with_edge(callee, edge_data));

                    // Propagate taint labels (apply sanitizers)
                    let new_labels = if enable_taint {
                        self.propagate_taint_labels(
                            &entry.taint_labels, graph, callee
                        )
                    } else {
                        Vec::new()
                    };

                    queue.push_back(BfsEntry {
                        node: callee,
                        depth: entry.depth + 1,
                        path: new_path,
                        taint_labels: new_labels,
                    });
                }
            }
        }

        // Step 4: Build security summary
        let security_summary = self.build_security_summary(
            &reachable_access, &sensitive_fields, &taint_flows
        );

        Ok(ReachabilityResult {
            origin: origin.clone(),
            reachable_access,
            sensitive_fields: sensitive_fields.into_values().collect(),
            taint_flows,
            tables: tables.into_iter().collect(),
            functions_traversed: visited.len() as u32,
            max_depth_reached,
            max_depth_configured: max_depth,
            engine: EngineType::Petgraph,
            from_cache: false,
            query_time_us: start.elapsed().as_micros() as u64,
            security_summary,
        })
    }
}

/// Internal BFS queue entry.
struct BfsEntry {
    node: NodeIndex,
    depth: u32,
    path: Vec<CallPathNode>,
    taint_labels: Vec<TaintLabel>,
}
```

### 5.2 Performance Characteristics

| Metric | Target | Rationale |
|--------|--------|-----------|
| BFS 10K functions, depth 20 | < 5ms | In-memory petgraph, O(V+E) |
| BFS 100K functions, depth 20 | < 50ms | In-memory petgraph, O(V+E) |
| BFS 500K functions, depth 20 | < 200ms | In-memory petgraph, O(V+E) |
| BFS with taint tracking | < 2x base | Taint label propagation adds constant factor |
| BFS with field-level tracking | < 1.5x base | Field extraction adds per-access overhead |
| Cache hit | < 100μs | LRU lookup + clone |

### 5.3 Depth Limiting Strategy

V1 used `Infinity` as default max_depth. This is dangerous for large graphs with cycles
(petgraph StableGraph allows cycles via self-edges or mutual recursion). V2 defaults to
50, which covers all realistic call chains while preventing runaway traversal.

The visited set prevents infinite loops, but unbounded depth still causes excessive
path construction. Depth 50 is the sweet spot: deep enough for real-world call chains
(most are <20), shallow enough to bound memory usage.

---

## 6. Inverse Reachability Engine (Reverse BFS)

### 6.1 petgraph Reverse BFS Implementation

Inverse reachability answers: "Who can reach this sensitive data?" It starts from data
accessor functions and traverses the call graph in reverse (following `calledBy` edges)
to find all entry points that can ultimately reach the target data.

```rust
impl ReachabilityEngine {
    /// Inverse reachability via petgraph reverse BFS.
    /// Complexity: O(A × (V + E)) where A = accessors for target table.
    fn inverse_petgraph(
        &self,
        graph: &CallGraph,
        target: &InverseTarget,
        options: &InverseReachabilityOptions,
    ) -> Result<InverseReachabilityResult, ReachabilityError> {
        let start = std::time::Instant::now();
        let max_depth = options.max_depth
            .unwrap_or(self.config.default_inverse_max_depth);

        // Step 1: Find all functions that access the target table/field
        let accessors = graph.find_data_accessors(
            &target.table,
            target.field.as_deref(),
            target.operation.as_ref(),
        );

        if accessors.is_empty() {
            return Ok(InverseReachabilityResult {
                target: target.clone(),
                access_paths: Vec::new(),
                entry_points: Vec::new(),
                total_accessors: 0,
                security_summary: SecuritySummary::default(),
                engine: EngineType::Petgraph,
                query_time_us: start.elapsed().as_micros() as u64,
            });
        }

        // Step 2: For each accessor, reverse BFS to find entry points
        let mut all_paths: Vec<InverseAccessPath> = Vec::new();
        let mut all_entry_points: FxHashSet<String> = FxHashSet::default();

        for accessor_node in &accessors {
            let mut visited: FxHashSet<NodeIndex> = FxHashSet::default();
            let mut queue: VecDeque<ReverseBfsEntry> = VecDeque::new();

            queue.push_back(ReverseBfsEntry {
                node: *accessor_node,
                depth: 0,
                path: vec![graph.node_to_path_node(*accessor_node)],
            });
            visited.insert(*accessor_node);

            while let Some(entry) = queue.pop_front() {
                if entry.depth > max_depth {
                    continue;
                }

                let func = &graph.graph[entry.node];

                // Check if this is an entry point
                if func.is_entry_point {
                    let entry_info = graph.build_entry_point_info(entry.node);
                    all_entry_points.insert(entry_info.function_id.clone());

                    // Build the path (reverse it so it reads entry → accessor)
                    let mut forward_path = entry.path.clone();
                    forward_path.reverse();

                    let accessor_info = graph.build_data_accessor_info(*accessor_node);

                    all_paths.push(InverseAccessPath {
                        entry_point: entry_info,
                        accessor: accessor_info,
                        path: forward_path,
                        depth: entry.depth,
                        has_auth_check: self.detect_auth_check_on_path(&entry.path, graph),
                        has_input_validation: self.detect_validation_on_path(
                            &entry.path, graph
                        ),
                        taint_status: if options.enable_taint.unwrap_or(false) {
                            self.compute_inverse_taint_status(&entry.path, graph)
                        } else {
                            TaintStatus::NotAnalyzed
                        },
                    });

                    // Don't stop — continue BFS to find other entry points
                    // that also reach this accessor through different paths
                }

                // If entry_points_only, only continue BFS if we haven't found
                // an entry point yet on this path
                if options.entry_points_only && func.is_entry_point {
                    continue; // Don't traverse past entry points
                }

                // Enqueue callers (reverse edges)
                for edge in graph.graph.edges_directed(entry.node, Direction::Incoming) {
                    let caller = edge.source();
                    if visited.insert(caller) {
                        let mut new_path = entry.path.clone();
                        new_path.push(graph.node_to_path_node(caller));
                        queue.push_back(ReverseBfsEntry {
                            node: caller,
                            depth: entry.depth + 1,
                            path: new_path,
                        });
                    }
                }
            }
        }

        // Step 3: Build entry point info list
        let entry_points: Vec<EntryPointInfo> = all_entry_points
            .iter()
            .filter_map(|id| graph.get_entry_point_info(id))
            .collect();

        // Step 4: Build security summary
        let security_summary = self.build_inverse_security_summary(
            target, &all_paths, &entry_points
        );

        Ok(InverseReachabilityResult {
            target: target.clone(),
            access_paths: all_paths,
            entry_points,
            total_accessors: accessors.len() as u32,
            security_summary,
            engine: EngineType::Petgraph,
            query_time_us: start.elapsed().as_micros() as u64,
        })
    }
}

struct ReverseBfsEntry {
    node: NodeIndex,
    depth: u32,
    path: Vec<CallPathNode>,
}
```

### 6.2 Auth Check Detection on Paths

A key v2 enhancement: inverse reachability reports whether paths from entry points to
data accessors include authentication checks. This is critical for security analysis —
an unauthenticated path to sensitive data is a vulnerability.

```rust
impl ReachabilityEngine {
    /// Detect if any function on the path performs authentication.
    /// Uses heuristic pattern matching on function names and decorators.
    fn detect_auth_check_on_path(
        &self,
        path: &[CallPathNode],
        graph: &CallGraph,
    ) -> bool {
        for node in path {
            if let Some(func) = graph.get_function(&node.function_id) {
                // Check function name patterns
                let name_lower = func.name.to_lowercase();
                if AUTH_FUNCTION_PATTERNS.iter().any(|p| name_lower.contains(p)) {
                    return true;
                }

                // Check decorator patterns (e.g., @login_required, @Authorize)
                if let Some(decorators) = graph.get_decorators(&node.function_id) {
                    if decorators.iter().any(|d| AUTH_DECORATOR_PATTERNS.iter()
                        .any(|p| d.to_lowercase().contains(p)))
                    {
                        return true;
                    }
                }
            }
        }
        false
    }
}

/// Auth function name patterns (case-insensitive).
const AUTH_FUNCTION_PATTERNS: &[&str] = &[
    "authenticate", "authorize", "check_auth", "verify_token",
    "require_auth", "is_authenticated", "validate_session",
    "check_permission", "require_login", "verify_jwt",
    "check_role", "has_permission", "ensure_auth",
];

/// Auth decorator patterns (case-insensitive).
const AUTH_DECORATOR_PATTERNS: &[&str] = &[
    "login_required", "authorize", "authenticated", "requires_auth",
    "auth_required", "permission_required", "role_required",
    "jwt_required", "token_required", "guard",
];
```


---

## 7. SQLite CTE Reachability (Large Codebase Fallback)

### 7.1 When SQLite CTEs Are Used

The SQLite CTE engine activates when the call graph exceeds the memory threshold
(default 500K functions). This is the fallback for very large codebases where loading
the full graph into petgraph would consume excessive memory.

Trade-off: ~10x slower per query than petgraph BFS, but O(1) memory usage.

### 7.2 Forward Reachability CTE

```sql
-- Forward reachability: from a starting function, find all reachable data access points.
-- Single query replaces v1's per-hop BFS loop.
WITH RECURSIVE reachable(id, name, file, line, depth, path) AS (
    -- Base case: the starting function
    SELECT f.id, f.name, f.file, f.line, 0, f.id
    FROM functions f
    WHERE f.id = :start_function_id

    UNION ALL

    -- Recursive case: follow call edges to callees
    SELECT f.id, f.name, f.file, f.line, r.depth + 1,
           r.path || ' -> ' || f.id
    FROM functions f
    INNER JOIN call_edges e ON e.callee_id = f.id
    INNER JOIN reachable r ON e.caller_id = r.id
    WHERE r.depth < :max_depth
      -- Cycle detection: ensure we don't revisit nodes
      AND r.path NOT LIKE '%' || f.id || '%'
      -- Confidence filter
      AND e.confidence >= :min_confidence
)
SELECT DISTINCT
    r.id AS function_id,
    r.name AS function_name,
    r.file,
    r.line,
    r.depth,
    r.path,
    da.table_name,
    da.operation,
    da.fields_json,
    da.framework,
    da.line AS access_line
FROM reachable r
LEFT JOIN data_access da ON da.function_id = r.id
WHERE da.table_name IS NOT NULL
  -- Optional table filter
  AND (:table_filter IS NULL OR da.table_name IN (SELECT value FROM json_each(:table_filter)))
ORDER BY r.depth, da.table_name;
```

### 7.3 Inverse Reachability CTE

```sql
-- Inverse reachability: from a target table, find all entry points that can reach it.
-- Step 1: Find all functions that access the target table
WITH accessors AS (
    SELECT DISTINCT function_id
    FROM data_access
    WHERE table_name = :target_table
      AND (:target_field IS NULL OR fields_json LIKE '%' || :target_field || '%')
      AND (:target_operation IS NULL OR operation = :target_operation)
),
-- Step 2: Reverse BFS from each accessor to find callers
RECURSIVE callers(id, name, file, line, depth, path, accessor_id) AS (
    -- Base case: the data accessor functions
    SELECT f.id, f.name, f.file, f.line, 0, f.id, f.id
    FROM functions f
    INNER JOIN accessors a ON a.function_id = f.id

    UNION ALL

    -- Recursive case: follow call edges in reverse (callee → caller)
    SELECT f.id, f.name, f.file, f.line, c.depth + 1,
           f.id || ' -> ' || c.path, c.accessor_id
    FROM functions f
    INNER JOIN call_edges e ON e.caller_id = f.id
    INNER JOIN callers c ON e.callee_id = c.id
    WHERE c.depth < :max_depth
      AND c.path NOT LIKE '%' || f.id || '%'
      AND e.confidence >= :min_confidence
)
SELECT DISTINCT
    c.id AS function_id,
    c.name AS function_name,
    c.file,
    c.line,
    c.depth,
    c.path,
    c.accessor_id,
    f.is_entry_point
FROM callers c
INNER JOIN functions f ON f.id = c.id
WHERE (:entry_points_only = 0 OR f.is_entry_point = 1)
ORDER BY c.depth;
```

### 7.4 CTE Performance Optimization

SQLite recursive CTEs can be slow for deep graphs. Optimizations:

1. **Cycle detection via path string**: `path NOT LIKE '%' || f.id || '%'` prevents
   revisiting nodes. This is O(path_length) per check but avoids maintaining a separate
   visited set in SQL.

2. **Confidence filter in CTE**: Filtering low-confidence edges inside the CTE reduces
   the search space significantly. Most fuzzy-resolved edges (confidence < 0.50) are
   pruned early.

3. **Indexed joins**: The `idx_call_edges_caller` and `idx_call_edges_callee` indexes
   make the JOIN operations O(log n) instead of O(n).

4. **DISTINCT elimination**: Using DISTINCT in the final SELECT deduplicates paths
   that reach the same function through different routes.

5. **Depth limit**: The `depth < :max_depth` condition bounds the recursion. SQLite's
   default recursion limit is 1000; we set it to 50 for safety.

### 7.5 CTE vs petgraph Performance Comparison

| Scenario | petgraph BFS | SQLite CTE | Ratio |
|----------|-------------|------------|-------|
| 10K functions, depth 10 | 1ms | 15ms | 15x |
| 100K functions, depth 20 | 10ms | 120ms | 12x |
| 500K functions, depth 20 | 50ms | 400ms | 8x |
| 1M functions, depth 20 | N/A (OOM) | 800ms | ∞ |

The CTE approach is always slower but scales to arbitrary graph sizes. The auto-selection
in §3.2 ensures the optimal engine is used for each codebase.

---

## 8. Sensitivity Classification Engine

### 8.1 Architecture

V2 unifies the Rust `SensitiveFieldDetector` and TS `SensitivityClassifier` into a single
Rust engine. This eliminates the dual-classification problem where Rust and TS could
disagree on sensitivity levels.

```rust
/// Unified sensitivity classification engine.
/// Classifies data access points and individual fields by sensitivity.
pub struct SensitivityClassifier {
    /// Pattern registry: field name patterns → sensitivity category + specificity.
    field_patterns: Vec<SensitivityPattern>,

    /// Table name patterns → sensitivity category.
    table_patterns: Vec<SensitivityPattern>,

    /// False positive filter patterns.
    fp_filters: Vec<FalsePositiveFilter>,

    /// Custom patterns loaded from drift.toml.
    custom_patterns: Vec<SensitivityPattern>,
}

/// A sensitivity pattern with specificity scoring.
#[derive(Debug, Clone)]
pub struct SensitivityPattern {
    /// Regex pattern to match against field/table names.
    pub pattern: regex::Regex,

    /// Sensitivity category this pattern indicates.
    pub category: SensitivityCategory,

    /// Specificity score (0.0-1.0). Higher = more specific = fewer false positives.
    /// "ssn" (0.95) is more specific than "name" (0.50).
    pub specificity: f64,

    /// Human-readable description.
    pub description: String,
}

/// False positive filter.
#[derive(Debug, Clone)]
pub struct FalsePositiveFilter {
    /// Context pattern that reduces confidence.
    pub pattern: regex::Regex,

    /// Confidence reduction factor (0.0-1.0).
    pub reduction: f64,

    /// Filter type.
    pub filter_type: FpFilterType,
}

#[derive(Debug, Clone, Copy)]
pub enum FpFilterType {
    FunctionName,       // validatePassword → not a password field
    ImportStatement,    // import { password } → not sensitive
    Comment,            // // password field → not sensitive
    TestMockPrefix,     // mockPassword, testEmail → not sensitive
    HealthCheck,        // health_check, health_endpoint → not health data
    ConfigKey,          // password_min_length → not a password
    EnumVariant,        // PasswordStrength.Strong → not a password
    TypeAnnotation,     // type: Password → not a password value
}
```

### 8.2 Sensitivity Pattern Registry

V2 expands from v1's 4 categories to 6, and significantly expands the pattern set.

```rust
impl SensitivityClassifier {
    /// Build the default pattern registry.
    pub fn new() -> Self {
        let field_patterns = vec![
            // === PII (Personally Identifiable Information) ===
            sp(r"\bssn\b|social_security", Pii, 0.95, "Social Security Number"),
            sp(r"\bdate_of_birth\b|\bdob\b", Pii, 0.90, "Date of birth"),
            sp(r"\bfull_name\b|\blegal_name\b", Pii, 0.85, "Full legal name"),
            sp(r"\bnational_id\b|\bpassport\b", Pii, 0.90, "National ID/passport"),
            sp(r"\bdriver_license\b", Pii, 0.90, "Driver's license"),
            sp(r"\btax_id\b|\btin\b", Pii, 0.85, "Tax identification"),
            sp(r"\bphone\b|\bmobile\b|\bcell\b", Pii, 0.65, "Phone number"),
            sp(r"\bemail\b|\be_mail\b", Pii, 0.65, "Email address"),
            sp(r"\baddress\b|\bstreet\b|\bzip\b|\bpostal\b", Pii, 0.60, "Physical address"),
            sp(r"\bfirst_name\b|\blast_name\b|\bsurname\b", Pii, 0.55, "Name component"),
            sp(r"\bname\b", Pii, 0.50, "Generic name field"),

            // === Credentials ===
            sp(r"\bpassword_hash\b|\bpasswd_hash\b", Credentials, 0.95, "Password hash"),
            sp(r"\bapi_key\b|\bapikey\b", Credentials, 0.90, "API key"),
            sp(r"\baccess_token\b|\brefresh_token\b", Credentials, 0.90, "Auth token"),
            sp(r"\bsecret_key\b|\bsigning_key\b", Credentials, 0.90, "Secret key"),
            sp(r"\bprivate_key\b|\bpubkey\b", Credentials, 0.90, "Cryptographic key"),
            sp(r"\bpassword\b|\bpasswd\b", Credentials, 0.75, "Password"),
            sp(r"\btoken\b", Credentials, 0.60, "Generic token"),
            sp(r"\bsalt\b", Credentials, 0.70, "Cryptographic salt"),
            sp(r"\bclient_secret\b", Credentials, 0.90, "OAuth client secret"),
            sp(r"\bauth_code\b|\bverification_code\b", Credentials, 0.80, "Auth code"),

            // === Financial ===
            sp(r"\bcredit_card\b|\bcard_number\b|\bcc_num\b", Financial, 0.95, "Credit card"),
            sp(r"\bcvv\b|\bcvc\b|\bsecurity_code\b", Financial, 0.95, "Card security code"),
            sp(r"\bbank_account\b|\baccount_number\b|\biban\b", Financial, 0.90, "Bank account"),
            sp(r"\brouting_number\b|\bswift\b|\bbic\b", Financial, 0.90, "Bank routing"),
            sp(r"\bsalary\b|\bwage\b|\bcompensation\b", Financial, 0.85, "Salary/wage"),
            sp(r"\bbalance\b|\btransaction\b", Financial, 0.60, "Financial transaction"),

            // === Health (HIPAA-relevant) ===
            sp(r"\bmedical_record\b|\bhealth_record\b", Health, 0.95, "Medical record"),
            sp(r"\bdiagnosis\b|\bdiagnoses\b", Health, 0.90, "Medical diagnosis"),
            sp(r"\bprescription\b|\bmedication\b", Health, 0.90, "Prescription"),
            sp(r"\binsurance_id\b|\bpolicy_number\b", Health, 0.85, "Insurance ID"),
            sp(r"\bblood_type\b|\ballergy\b|\ballergies\b", Health, 0.85, "Health data"),

            // === Geolocation (new in v2) ===
            sp(r"\blatitude\b|\blongitude\b|\bgeo_?loc", Geolocation, 0.80, "Geolocation"),
            sp(r"\bip_address\b|\bip_addr\b|\bclient_ip\b", Geolocation, 0.70, "IP address"),

            // === Biometric (new in v2) ===
            sp(r"\bfingerprint\b|\bface_id\b|\bbiometric", Biometric, 0.90, "Biometric data"),
            sp(r"\bretina\b|\bvoice_print\b", Biometric, 0.90, "Biometric identifier"),
        ];

        let fp_filters = vec![
            fpf(r"\bvalidate\b|\bcheck\b|\bverify\b|\bassert\b", 0.40, FpFilterType::FunctionName),
            fpf(r"^import\b|^from\b|^require\b", 0.80, FpFilterType::ImportStatement),
            fpf(r"^//|^#|^\*|^/\*", 0.90, FpFilterType::Comment),
            fpf(r"\bmock\b|\btest\b|\bfake\b|\bdummy\b|\bstub\b", 0.60, FpFilterType::TestMockPrefix),
            fpf(r"\bhealth_check\b|\bhealth_endpoint\b|\bhealthz\b", 0.90, FpFilterType::HealthCheck),
            fpf(r"\b_min_length\b|\b_max_length\b|\b_policy\b|\b_strength\b", 0.70, FpFilterType::ConfigKey),
            fpf(r"\bEnum\b|\bVariant\b|\bCase\b", 0.50, FpFilterType::EnumVariant),
            fpf(r"\btype\b|\binterface\b|\btypedef\b", 0.30, FpFilterType::TypeAnnotation),
        ];

        Self {
            field_patterns,
            table_patterns: Vec::new(), // Populated from learned conventions
            fp_filters,
            custom_patterns: Vec::new(), // Loaded from drift.toml
        }
    }

    /// Classify a data access point's overall sensitivity level.
    pub fn classify_access(&self, access: &DataAccessPoint) -> SensitivityLevel {
        let mut max_level = SensitivityLevel::Low;

        // Check each field in the access point
        for field in &access.fields {
            if let Some(sf) = self.classify_field(field, &access.table) {
                let level = self.category_to_level(&sf.category, sf.specificity);
                if level > max_level {
                    max_level = level;
                }
            }
        }

        // Check table name itself
        for pattern in &self.table_patterns {
            if pattern.pattern.is_match(&access.table) {
                let level = self.category_to_level(&pattern.category, pattern.specificity);
                if level > max_level {
                    max_level = level;
                }
            }
        }

        max_level
    }

    /// Classify a single field by sensitivity.
    pub fn classify_field(
        &self,
        field: &str,
        table: &str,
    ) -> Option<SensitiveField> {
        let field_lower = field.to_lowercase();
        let mut best_match: Option<(SensitivityCategory, f64)> = None;

        for pattern in self.field_patterns.iter().chain(self.custom_patterns.iter()) {
            if pattern.pattern.is_match(&field_lower) {
                // Apply false positive filters
                let mut adjusted_specificity = pattern.specificity;
                for filter in &self.fp_filters {
                    if filter.pattern.is_match(&field_lower) {
                        adjusted_specificity *= 1.0 - filter.reduction;
                    }
                }

                if adjusted_specificity > best_match.map_or(0.0, |m| m.1) {
                    best_match = Some((pattern.category, adjusted_specificity));
                }
            }
        }

        best_match.map(|(category, specificity)| SensitiveField {
            field: field.to_string(),
            table: Some(table.to_string()),
            category,
            specificity,
            level: self.category_to_level(&category, specificity),
        })
    }

    /// Map category + specificity to sensitivity level.
    fn category_to_level(
        &self,
        category: &SensitivityCategory,
        specificity: f64,
    ) -> SensitivityLevel {
        match (category, specificity) {
            (Credentials, s) if s >= 0.70 => SensitivityLevel::Critical,
            (Financial, s) if s >= 0.80 => SensitivityLevel::Critical,
            (Pii, s) if s >= 0.85 => SensitivityLevel::High,
            (Health, _) => SensitivityLevel::High,
            (Biometric, _) => SensitivityLevel::High,
            (Pii, s) if s >= 0.60 => SensitivityLevel::Medium,
            (Geolocation, _) => SensitivityLevel::Medium,
            (Financial, s) if s < 0.80 => SensitivityLevel::Medium,
            (Credentials, s) if s < 0.70 => SensitivityLevel::Medium,
            _ => SensitivityLevel::Low,
        }
    }
}

// Helper constructors
fn sp(pattern: &str, cat: SensitivityCategory, spec: f64, desc: &str) -> SensitivityPattern {
    SensitivityPattern {
        pattern: regex::Regex::new(pattern).unwrap(),
        category: cat,
        specificity: spec,
        description: desc.to_string(),
    }
}

fn fpf(pattern: &str, reduction: f64, ft: FpFilterType) -> FalsePositiveFilter {
    FalsePositiveFilter {
        pattern: regex::Regex::new(pattern).unwrap(),
        reduction,
        filter_type: ft,
    }
}
```


---

## 9. Taint Analysis Integration (AD11)

### 9.1 Design: Source/Sink/Sanitizer Model

Per AD11, taint analysis is a first-class subsystem. The implementation follows the
industry-standard source/sink/sanitizer model used by FlowDroid, Semgrep, SonarQube,
and CodeQL. Taint tracking is integrated directly into the BFS traversal — not a
separate pass.

**Key insight from Semgrep's pragmatic approach**: Start intraprocedural (within a single
function), then extend to interprocedural via function summaries. Don't aim for soundness —
aim for practical detection with low false positives.

**Key insight from FlowDroid**: Context-sensitive, field-sensitive taint analysis achieves
93% recall and 86% precision on DroidBench. Function summaries enable interprocedural
analysis without re-analyzing callees.

**Key insight from SemTaint (2025)**: Multi-agent LLM can extract taint specifications
for undocumented APIs, detecting vulnerabilities previously undetectable by CodeQL alone.
This is a future enhancement for Drift's AI-assisted mode.

### 9.2 Taint Registry (TOML-Configurable)

```rust
/// Registry of taint sources, sinks, and sanitizers.
/// Loaded from drift.toml with per-framework defaults.
pub struct TaintRegistry {
    /// Taint sources: functions that introduce untrusted data.
    pub sources: Vec<TaintSource>,

    /// Taint sinks: functions where untrusted data is dangerous.
    pub sinks: Vec<TaintSink>,

    /// Taint sanitizers: functions that make data safe.
    pub sanitizers: Vec<TaintSanitizer>,
}

/// A taint source: function that introduces untrusted data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSource {
    /// Function name pattern (regex).
    pub function_pattern: String,

    /// Which parameter is tainted (-1 = return value, 0+ = parameter index).
    pub tainted_output: i32,

    /// Source type classification.
    pub source_type: TaintSourceType,

    /// Framework this source belongs to (e.g., "express", "fastapi").
    pub framework: Option<String>,

    /// Language this source applies to.
    pub language: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum TaintSourceType {
    UserInput,          // req.body, request.form, stdin
    ApiResponse,        // fetch(), axios.get(), http.get()
    FileRead,           // fs.readFile, open(), File::open
    EnvironmentVar,     // process.env, os.environ, std::env
    DatabaseRead,       // SELECT results
    CommandLineArg,     // process.argv, sys.argv
    WebSocketMessage,   // ws.on('message')
    DeserializedData,   // JSON.parse, pickle.loads, serde_json::from_str
}

/// A taint sink: function where untrusted data is dangerous.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSink {
    /// Function name pattern (regex).
    pub function_pattern: String,

    /// Which parameter must not be tainted (0+ = parameter index).
    pub sensitive_input: i32,

    /// Sink type classification.
    pub sink_type: TaintSinkType,

    /// Framework this sink belongs to.
    pub framework: Option<String>,

    /// Language this sink applies to.
    pub language: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum TaintSinkType {
    SqlQuery,           // db.query(), cursor.execute(), raw SQL
    CommandExecution,   // exec(), subprocess.run(), Command::new
    HtmlRendering,      // res.send(), render(), innerHTML
    FileWrite,          // fs.writeFile, open('w'), File::create
    UrlRedirect,        // res.redirect(), HttpResponseRedirect
    Deserialization,    // eval(), pickle.loads (when input is tainted)
    LogOutput,          // console.log(sensitive), logger.info(pii)
    HeaderInjection,    // res.setHeader with tainted value
    PathTraversal,      // fs.readFile(tainted_path)
    LdapQuery,          // ldap.search with tainted filter
}

/// A taint sanitizer: function that makes data safe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSanitizer {
    /// Function name pattern (regex).
    pub function_pattern: String,

    /// Which parameter is sanitized (input).
    pub input_param: i32,

    /// Which output carries the sanitized data (-1 = return value).
    pub output_param: i32,

    /// What kind of sanitization this performs.
    pub sanitizer_type: SanitizerType,

    /// Framework this sanitizer belongs to.
    pub framework: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum SanitizerType {
    Escape,             // escapeHtml, escape_string
    Validate,           // parseInt, Number(), type checking
    Encode,             // encodeURIComponent, base64_encode
    Hash,               // bcrypt.hash, sha256
    Parameterize,       // prepared statements, parameterized queries
    Sanitize,           // DOMPurify.sanitize, bleach.clean
    TypeCast,           // parseInt, Number(), as i32
    LengthCheck,        // if (input.length > MAX)
    RegexValidation,    // if (/^[a-z]+$/.test(input))
    AllowlistCheck,     // if (ALLOWED_VALUES.includes(input))
}
```

### 9.3 Default Taint Specifications (Per Framework)

```toml
# drift.toml — taint configuration (defaults, user can override)

[taint]
enabled = true

# === Express.js Sources ===
[[taint.sources]]
function_pattern = "req\\.(body|params|query|headers|cookies)"
tainted_output = -1
source_type = "UserInput"
framework = "express"
language = "typescript"

# === Express.js Sinks ===
[[taint.sinks]]
function_pattern = "\\.(query|exec|raw)\\("
sensitive_input = 0
sink_type = "SqlQuery"
framework = "express"

# === Express.js Sanitizers ===
[[taint.sanitizers]]
function_pattern = "escape|sanitize|DOMPurify|validator\\."
input_param = 0
output_param = -1
sanitizer_type = "Sanitize"
framework = "express"

# === FastAPI Sources ===
[[taint.sources]]
function_pattern = "request\\.(body|form|json|query_params)"
tainted_output = -1
source_type = "UserInput"
framework = "fastapi"
language = "python"

# === Django Sources ===
[[taint.sources]]
function_pattern = "request\\.(POST|GET|FILES|body|META)"
tainted_output = -1
source_type = "UserInput"
framework = "django"
language = "python"

# === Spring Boot Sources ===
[[taint.sources]]
function_pattern = "@RequestBody|@RequestParam|@PathVariable"
tainted_output = -1
source_type = "UserInput"
framework = "spring"
language = "java"
```

### 9.4 Taint Label Propagation During BFS

Taint labels are propagated along BFS paths. When a function is a sanitizer, the
taint label is removed (or marked as sanitized). When a function is a sink and
taint labels are still active, a taint flow is recorded.

```rust
/// A taint label carried along a BFS path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintLabel {
    /// The source that introduced this taint.
    pub source: TaintSource,

    /// The source type.
    pub source_type: TaintSourceType,

    /// Whether this label has been sanitized.
    pub sanitized: bool,

    /// Sanitizer that cleaned this label (if any).
    pub sanitizer: Option<TaintSanitizer>,
}

/// A detected taint flow from source to sink.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintFlow {
    /// The taint source.
    pub source: TaintSource,

    /// The taint sink.
    pub sink: TaintSink,

    /// The call path from source to sink.
    pub path: Vec<CallPathNode>,

    /// Sanitizers encountered along the path.
    pub sanitizers: Vec<TaintSanitizer>,

    /// Whether the flow is sanitized (sanitizers.len() > 0).
    pub is_sanitized: bool,

    /// Risk level based on source type, sink type, and sanitization.
    pub risk_level: TaintRiskLevel,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum TaintRiskLevel {
    /// Unsanitized flow to critical sink (SQL injection, command execution).
    Critical,
    /// Unsanitized flow to high-risk sink (XSS, file write).
    High,
    /// Partially sanitized or medium-risk sink.
    Medium,
    /// Sanitized flow or low-risk sink.
    Low,
}

impl ReachabilityEngine {
    /// Propagate taint labels through a function.
    /// If the function is a sanitizer, mark labels as sanitized.
    /// If the function introduces new taint, add new labels.
    fn propagate_taint_labels(
        &self,
        current_labels: &[TaintLabel],
        graph: &CallGraph,
        function_node: NodeIndex,
    ) -> Vec<TaintLabel> {
        let func = &graph.graph[function_node];
        let func_name = graph.interner.resolve(&func.id);
        let mut labels = current_labels.to_vec();

        // Check if this function is a sanitizer
        for sanitizer in &self.taint_registry.sanitizers {
            if regex::Regex::new(&sanitizer.function_pattern)
                .map(|r| r.is_match(func_name))
                .unwrap_or(false)
            {
                // Mark all matching labels as sanitized
                for label in &mut labels {
                    if !label.sanitized {
                        label.sanitized = true;
                        label.sanitizer = Some(sanitizer.clone());
                    }
                }
            }
        }

        // Check if this function introduces new taint
        for source in &self.taint_registry.sources {
            if regex::Regex::new(&source.function_pattern)
                .map(|r| r.is_match(func_name))
                .unwrap_or(false)
            {
                labels.push(TaintLabel {
                    source: source.clone(),
                    source_type: source.source_type,
                    sanitized: false,
                    sanitizer: None,
                });
            }
        }

        labels
    }

    /// Compute taint risk level based on source, sink, and sanitization.
    fn compute_taint_risk(
        &self,
        labels: &[TaintLabel],
        sanitizers: &[TaintSanitizer],
    ) -> TaintRiskLevel {
        if sanitizers.is_empty() {
            // No sanitization — risk depends on source type
            if labels.iter().any(|l| matches!(l.source_type,
                TaintSourceType::UserInput | TaintSourceType::DeserializedData))
            {
                TaintRiskLevel::Critical
            } else {
                TaintRiskLevel::High
            }
        } else if labels.iter().all(|l| l.sanitized) {
            TaintRiskLevel::Low
        } else {
            TaintRiskLevel::Medium
        }
    }
}
```

### 9.5 Phased Implementation

Per AD11 and the gap analysis:

**Phase 1 — Intraprocedural (v2.0 launch)**:
- Source/sink/sanitizer registry loaded from TOML
- Taint labels propagated during BFS traversal
- Detection of unsanitized flows from user input to SQL/command/HTML sinks
- Per-framework default specifications for top 10 frameworks
- OWASP A03 (Injection) coverage

**Phase 2 — Interprocedural (+3 months)**:
- Function taint summaries: "parameter 0 taints return value"
- Summaries computed once per function, cached in drift.db
- Cross-function taint propagation via summaries (no re-analysis)
- Field-level taint tracking (users.password_hash vs users.display_name)

**Phase 3 — AI-Assisted (+6 months)**:
- LLM-based taint specification extraction (SemTaint approach)
- Auto-discovery of undocumented sources/sinks in custom frameworks
- Cross-service taint tracking via API call graph


---

## 10. Impact Analysis Engine

### 10.1 Architecture

V1 impact analysis exists only in TypeScript. V2 ports it to Rust with enhanced metrics.
Impact analysis answers: "What breaks if I change this function?"

```rust
/// Impact analysis engine. Computes blast radius for function changes.
pub struct ImpactAnalyzer {
    /// Reference to the reachability engine (shares the call graph).
    engine: Arc<ReachabilityEngine>,
}

/// Result of an impact analysis query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactResult {
    /// The function being analyzed for change impact.
    pub changed_function: FunctionInfo,

    /// All functions transitively affected by the change.
    pub affected_functions: Vec<AffectedFunction>,

    /// Entry points affected (API surface impact).
    pub affected_entry_points: Vec<EntryPointInfo>,

    /// Data paths affected (security impact).
    pub affected_data_paths: Vec<AffectedDataPath>,

    /// Blast radius metrics.
    pub blast_radius: BlastRadius,

    /// Overall risk level.
    pub risk: RiskLevel,

    /// Timing.
    pub query_time_us: u64,
}

/// Blast radius metrics for a function change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlastRadius {
    /// Direct callers of the changed function.
    pub direct_callers: usize,

    /// Transitive callers (all functions that eventually call the changed function).
    pub transitive_callers: usize,

    /// Entry points that can reach the changed function.
    pub affected_entry_points: usize,

    /// Sensitive data paths through the changed function.
    pub affected_sensitive_paths: usize,

    /// Test functions that cover the changed function.
    pub covering_tests: usize,

    /// Percentage of codebase affected (transitive_callers / total_functions).
    pub codebase_percentage: f64,

    /// Maximum depth of impact propagation.
    pub max_propagation_depth: u32,
}

/// Risk level for a function change.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    /// Low risk: few callers, no entry points, no sensitive data.
    Low,
    /// Medium risk: moderate callers or some entry points.
    Medium,
    /// High risk: many callers, entry points affected, or sensitive data paths.
    High,
    /// Critical risk: widespread impact, sensitive data, entry points, low test coverage.
    Critical,
}

impl ImpactAnalyzer {
    /// Analyze the impact of changing a function.
    /// Algorithm: Reverse BFS from changed function, collecting all callers transitively.
    pub fn analyze(
        &self,
        function_id: &str,
    ) -> Result<ImpactResult, ReachabilityError> {
        let start = std::time::Instant::now();
        let graph = self.engine.graph.as_ref()
            .ok_or(ReachabilityError::GraphNotLoaded)?;

        let start_node = graph.find_function_by_id(function_id)?;

        // Step 1: Reverse BFS to find all affected functions
        let mut visited: FxHashSet<NodeIndex> = FxHashSet::default();
        let mut queue: VecDeque<(NodeIndex, u32)> = VecDeque::new();
        let mut affected: Vec<AffectedFunction> = Vec::new();
        let mut entry_points: Vec<EntryPointInfo> = Vec::new();
        let mut max_depth: u32 = 0;

        queue.push_back((start_node, 0));
        visited.insert(start_node);

        while let Some((node, depth)) = queue.pop_front() {
            max_depth = max_depth.max(depth);
            let func = &graph.graph[node];

            // Record affected function
            if node != start_node {
                affected.push(AffectedFunction {
                    function_id: graph.interner.resolve(&func.id).to_string(),
                    function_name: graph.get_function_name(node),
                    file: graph.interner.resolve(&func.file).to_string(),
                    line: func.line,
                    depth,
                    is_entry_point: func.is_entry_point,
                    is_exported: func.is_exported,
                });
            }

            // Track entry points
            if func.is_entry_point {
                entry_points.push(graph.build_entry_point_info(node));
            }

            // Enqueue callers (reverse edges)
            for edge in graph.graph.edges_directed(node, Direction::Incoming) {
                let caller = edge.source();
                if visited.insert(caller) {
                    queue.push_back((caller, depth + 1));
                }
            }
        }

        // Step 2: Find affected data paths
        let affected_data_paths = self.find_affected_data_paths(
            graph, &visited
        );

        // Step 3: Compute blast radius
        let total_functions = graph.graph.node_count();
        let blast_radius = BlastRadius {
            direct_callers: graph.graph
                .edges_directed(start_node, Direction::Incoming).count(),
            transitive_callers: affected.len(),
            affected_entry_points: entry_points.len(),
            affected_sensitive_paths: affected_data_paths.iter()
                .filter(|p| p.sensitivity >= SensitivityLevel::Medium).count(),
            covering_tests: 0, // Populated by coverage analysis integration
            codebase_percentage: affected.len() as f64 / total_functions as f64,
            max_propagation_depth: max_depth,
        };

        // Step 4: Compute risk level
        let risk = self.compute_risk(&blast_radius, &affected_data_paths);

        Ok(ImpactResult {
            changed_function: graph.get_function_info(start_node),
            affected_functions: affected,
            affected_entry_points: entry_points,
            affected_data_paths,
            blast_radius,
            risk,
            query_time_us: start.elapsed().as_micros() as u64,
        })
    }

    /// Risk computation based on blast radius metrics.
    /// Weighted scoring: entry_points(30) + sensitive_paths(30) + callers(25) + coverage(15)
    fn compute_risk(
        &self,
        radius: &BlastRadius,
        data_paths: &[AffectedDataPath],
    ) -> RiskLevel {
        let mut score: f64 = 0.0;

        // Entry point impact (30% weight)
        score += match radius.affected_entry_points {
            0 => 0.0,
            1..=2 => 15.0,
            3..=5 => 22.0,
            _ => 30.0,
        };

        // Sensitive data path impact (30% weight)
        let sensitive_count = data_paths.iter()
            .filter(|p| p.sensitivity >= SensitivityLevel::High).count();
        score += match sensitive_count {
            0 => 0.0,
            1..=2 => 15.0,
            3..=5 => 22.0,
            _ => 30.0,
        };

        // Transitive caller impact (25% weight)
        score += match radius.transitive_callers {
            0..=5 => 0.0,
            6..=20 => 10.0,
            21..=50 => 18.0,
            _ => 25.0,
        };

        // Test coverage gap (15% weight)
        if radius.covering_tests == 0 && radius.transitive_callers > 0 {
            score += 15.0; // No tests covering this function = higher risk
        }

        match score as u32 {
            0..=20 => RiskLevel::Low,
            21..=45 => RiskLevel::Medium,
            46..=70 => RiskLevel::High,
            _ => RiskLevel::Critical,
        }
    }
}
```

---

## 11. Dead Code Detection Engine

### 11.1 Architecture

V1 dead code detection exists only in TypeScript. V2 ports it to Rust with enhanced
false positive handling (8 categories vs v1's 5).

```rust
/// Dead code detection engine.
pub struct DeadCodeDetector {
    engine: Arc<ReachabilityEngine>,
}

/// A dead code candidate with confidence and false positive analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadCodeCandidate {
    /// The function identified as potentially dead.
    pub function_id: String,
    pub function_name: String,
    pub file: String,
    pub line: u32,
    pub end_line: u32,
    pub language: String,

    /// Confidence that this is truly dead code (0.0-1.0).
    pub confidence: f64,

    /// Reasons this might be a false positive.
    pub false_positive_reasons: Vec<FalsePositiveReason>,

    /// Lines of code in this function (impact of removal).
    pub lines_of_code: u32,

    /// Whether this function accesses sensitive data (removal risk).
    pub accesses_sensitive_data: bool,
}

/// Reasons a dead code candidate might be a false positive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FalsePositiveReason {
    /// Function is an entry point (HTTP handler, CLI command, main).
    EntryPoint { entry_type: EntryPointType },

    /// Function is a framework lifecycle hook (componentDidMount, setUp, etc.).
    FrameworkHook { framework: String, hook_name: String },

    /// Function may be called via dynamic dispatch (reflection, eval, getattr).
    DynamicDispatch { evidence: String },

    /// Function is an event handler (called via event system, signals).
    EventHandler { event_pattern: String },

    /// Function is exported (may be used by external packages).
    Exported,

    /// Function is a test function or test utility.
    TestFunction,

    /// Function is a decorator/annotation handler.
    DecoratorHandler { decorator: String },

    /// Function matches a known interface/trait implementation pattern.
    InterfaceImplementation { interface_name: String },
}

impl DeadCodeDetector {
    /// Detect dead code in the call graph.
    /// Algorithm: Find all functions with no incoming edges that are not entry points
    /// or known false positive categories.
    pub fn detect(&self) -> Result<Vec<DeadCodeCandidate>, ReachabilityError> {
        let graph = self.engine.graph.as_ref()
            .ok_or(ReachabilityError::GraphNotLoaded)?;

        let mut candidates: Vec<DeadCodeCandidate> = Vec::new();

        for node_idx in graph.graph.node_indices() {
            let func = &graph.graph[node_idx];

            // Skip if function has callers
            let caller_count = graph.graph
                .edges_directed(node_idx, Direction::Incoming).count();
            if caller_count > 0 {
                continue;
            }

            // Collect false positive reasons
            let mut fp_reasons: Vec<FalsePositiveReason> = Vec::new();

            if func.is_entry_point {
                fp_reasons.push(FalsePositiveReason::EntryPoint {
                    entry_type: graph.get_entry_type(node_idx),
                });
            }

            if func.is_exported {
                fp_reasons.push(FalsePositiveReason::Exported);
            }

            if let Some(hook) = self.detect_framework_hook(graph, node_idx) {
                fp_reasons.push(hook);
            }

            if let Some(event) = self.detect_event_handler(graph, node_idx) {
                fp_reasons.push(event);
            }

            if self.is_test_function(graph, node_idx) {
                fp_reasons.push(FalsePositiveReason::TestFunction);
            }

            if let Some(iface) = self.detect_interface_impl(graph, node_idx) {
                fp_reasons.push(iface);
            }

            // Compute confidence (inverse of false positive likelihood)
            let confidence = match fp_reasons.len() {
                0 => 0.95,  // No FP reasons → high confidence it's dead
                1 => 0.50,  // One FP reason → moderate confidence
                2 => 0.25,  // Two FP reasons → low confidence
                _ => 0.10,  // Many FP reasons → very low confidence
            };

            // Only report candidates above minimum confidence
            if confidence >= 0.25 {
                let func_name = graph.interner.resolve(&func.id);
                candidates.push(DeadCodeCandidate {
                    function_id: func_name.to_string(),
                    function_name: graph.get_function_name(node_idx),
                    file: graph.interner.resolve(&func.file).to_string(),
                    line: func.line,
                    end_line: func.end_line,
                    language: func.language.to_string(),
                    confidence,
                    false_positive_reasons: fp_reasons,
                    lines_of_code: func.end_line.saturating_sub(func.line),
                    accesses_sensitive_data: self.engine.has_sensitive_access(
                        graph, node_idx
                    ),
                });
            }
        }

        // Sort by confidence (highest first), then by lines of code (largest first)
        candidates.sort_by(|a, b| {
            b.confidence.partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(b.lines_of_code.cmp(&a.lines_of_code))
        });

        Ok(candidates)
    }

    /// Framework hook detection patterns.
    fn detect_framework_hook(
        &self,
        graph: &CallGraph,
        node: NodeIndex,
    ) -> Option<FalsePositiveReason> {
        let name = graph.get_function_name(node).to_lowercase();
        let hooks = [
            ("react", &["componentdidmount", "componentwillunmount", "render",
                        "getderivedstatefromprops", "shouldcomponentupdate"][..]),
            ("vue", &["mounted", "created", "beforedestroy", "computed", "watch"]),
            ("angular", &["ngoninit", "ngondestroy", "ngonchanges", "ngafterviewinit"]),
            ("django", &["setup", "teardown", "setuptestdata", "get_queryset"]),
            ("spring", &["init", "destroy", "afterpropertiesset", "postconstruct"]),
            ("pytest", &["setup_method", "teardown_method", "setup_class"]),
            ("junit", &["setup", "teardown", "beforeeach", "aftereach"]),
        ];

        for (framework, patterns) in &hooks {
            if patterns.iter().any(|p| name.contains(p)) {
                return Some(FalsePositiveReason::FrameworkHook {
                    framework: framework.to_string(),
                    hook_name: name,
                });
            }
        }
        None
    }

    fn detect_event_handler(
        &self,
        graph: &CallGraph,
        node: NodeIndex,
    ) -> Option<FalsePositiveReason> {
        let name = graph.get_function_name(node).to_lowercase();
        let patterns = ["on_", "handle_", "listener", "_handler", "_callback",
                        "on_message", "on_event", "on_error", "on_close"];
        if patterns.iter().any(|p| name.contains(p)) {
            return Some(FalsePositiveReason::EventHandler {
                event_pattern: name,
            });
        }
        None
    }

    fn is_test_function(&self, graph: &CallGraph, node: NodeIndex) -> bool {
        let name = graph.get_function_name(node).to_lowercase();
        let file = graph.get_function_file(node).to_lowercase();
        name.starts_with("test_") || name.starts_with("it_")
            || name.contains("_test") || name.contains("_spec")
            || file.contains("/test") || file.contains("/spec")
            || file.contains("__tests__") || file.ends_with("_test.rs")
            || file.ends_with(".test.ts") || file.ends_with(".spec.ts")
    }

    fn detect_interface_impl(
        &self,
        graph: &CallGraph,
        node: NodeIndex,
    ) -> Option<FalsePositiveReason> {
        // Check if function name matches common interface/trait patterns
        let name = graph.get_function_name(node);
        let interface_patterns = [
            "to_string", "fmt", "clone", "eq", "hash", "serialize",
            "deserialize", "from", "into", "default", "drop",
            "toString", "equals", "hashCode", "compareTo",
            "__str__", "__repr__", "__eq__", "__hash__",
        ];
        if interface_patterns.iter().any(|p| name == *p) {
            return Some(FalsePositiveReason::InterfaceImplementation {
                interface_name: name.to_string(),
            });
        }
        None
    }
}
```


---

## 12. Coverage Analysis Engine (Call Graph × Test Topology)

### 12.1 Architecture

Coverage analysis integrates the call graph with test topology to answer: "Which sensitive
data paths have test coverage?" and "Which data paths are untested?"

```rust
/// Coverage analysis engine.
pub struct CoverageAnalyzer {
    engine: Arc<ReachabilityEngine>,
}

/// Coverage analysis result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageResult {
    /// Field-level coverage: which sensitive fields have test coverage.
    pub field_coverage: Vec<FieldCoverage>,

    /// Data paths without test coverage.
    pub uncovered_paths: Vec<UncoveredPath>,

    /// Overall coverage metrics.
    pub metrics: CoverageMetrics,
}

/// Coverage status for a sensitive field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldCoverage {
    pub table: String,
    pub field: String,
    pub sensitivity: SensitivityLevel,
    pub total_access_paths: usize,
    pub covered_access_paths: usize,
    pub coverage_percentage: f64,
    pub covering_tests: Vec<String>,
}

/// A data path without test coverage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UncoveredPath {
    pub entry_point: EntryPointInfo,
    pub data_access: DataAccessPoint,
    pub path: Vec<CallPathNode>,
    pub sensitivity: SensitivityLevel,
    pub risk: RiskLevel,
}

/// Aggregate coverage metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageMetrics {
    pub total_sensitive_paths: usize,
    pub covered_sensitive_paths: usize,
    pub coverage_percentage: f64,
    pub critical_uncovered: usize,
    pub high_uncovered: usize,
}

impl CoverageAnalyzer {
    /// Analyze test coverage of sensitive data paths.
    /// Requires test topology data in drift.db (from test topology analyzer).
    pub fn analyze(
        &self,
        test_functions: &FxHashSet<String>,
    ) -> Result<CoverageResult, ReachabilityError> {
        let graph = self.engine.graph.as_ref()
            .ok_or(ReachabilityError::GraphNotLoaded)?;

        let mut field_coverage: FxHashMap<String, FieldCoverage> = FxHashMap::default();
        let mut uncovered_paths: Vec<UncoveredPath> = Vec::new();

        // For each entry point, trace forward to data access points
        let entry_points = graph.get_entry_points();

        for ep_node in &entry_points {
            let reachable = self.engine.forward_petgraph(
                graph,
                &CodeLocation {
                    file: graph.interner.resolve(&graph.graph[*ep_node].file).to_string(),
                    line: graph.graph[*ep_node].line,
                    column: None,
                    function_id: Some(
                        graph.interner.resolve(&graph.graph[*ep_node].id).to_string()
                    ),
                },
                &ReachabilityOptions {
                    sensitive_only: true,
                    ..Default::default()
                },
            )?;

            for access in &reachable.reachable_access {
                // Check if any function on the path is covered by a test
                let is_covered = access.path.iter().any(|node| {
                    // Check if this function is directly tested
                    test_functions.contains(&node.function_id)
                    // Or if any test function calls this function
                    || graph.has_test_caller(&node.function_id, test_functions)
                });

                let key = format!("{}.{}", access.access.table,
                    access.access.fields.join(","));

                let coverage = field_coverage.entry(key).or_insert_with(|| {
                    FieldCoverage {
                        table: access.access.table.clone(),
                        field: access.access.fields.join(", "),
                        sensitivity: access.sensitivity,
                        total_access_paths: 0,
                        covered_access_paths: 0,
                        coverage_percentage: 0.0,
                        covering_tests: Vec::new(),
                    }
                });

                coverage.total_access_paths += 1;
                if is_covered {
                    coverage.covered_access_paths += 1;
                } else {
                    uncovered_paths.push(UncoveredPath {
                        entry_point: graph.build_entry_point_info(*ep_node),
                        data_access: access.access.clone(),
                        path: access.path.clone(),
                        sensitivity: access.sensitivity,
                        risk: if access.sensitivity >= SensitivityLevel::High {
                            RiskLevel::High
                        } else {
                            RiskLevel::Medium
                        },
                    });
                }
            }
        }

        // Compute coverage percentages
        for coverage in field_coverage.values_mut() {
            coverage.coverage_percentage = if coverage.total_access_paths > 0 {
                coverage.covered_access_paths as f64 / coverage.total_access_paths as f64
            } else {
                0.0
            };
        }

        let metrics = CoverageMetrics {
            total_sensitive_paths: field_coverage.values()
                .map(|c| c.total_access_paths).sum(),
            covered_sensitive_paths: field_coverage.values()
                .map(|c| c.covered_access_paths).sum(),
            coverage_percentage: {
                let total: usize = field_coverage.values()
                    .map(|c| c.total_access_paths).sum();
                let covered: usize = field_coverage.values()
                    .map(|c| c.covered_access_paths).sum();
                if total > 0 { covered as f64 / total as f64 } else { 0.0 }
            },
            critical_uncovered: uncovered_paths.iter()
                .filter(|p| p.sensitivity == SensitivityLevel::Critical).count(),
            high_uncovered: uncovered_paths.iter()
                .filter(|p| p.sensitivity == SensitivityLevel::High).count(),
        };

        Ok(CoverageResult {
            field_coverage: field_coverage.into_values().collect(),
            uncovered_paths,
            metrics,
        })
    }
}
```

---

## 13. Path Finding Engine

### 13.1 Architecture

Path finding answers: "What are the call paths between function A and function B?"
Uses BFS with path tracking. Returns multiple paths (up to a configurable limit).

```rust
impl ReachabilityEngine {
    /// Find all call paths between two functions.
    /// Algorithm: BFS with path tracking, returns up to max_paths paths.
    /// Complexity: O(V + E) per path, bounded by max_paths × max_depth.
    pub fn find_paths(
        &self,
        from: &CodeLocation,
        to: &CodeLocation,
        max_paths: usize,
        max_depth: u32,
    ) -> Result<Vec<Vec<CallPathNode>>, ReachabilityError> {
        let graph = self.graph.as_ref()
            .ok_or(ReachabilityError::GraphNotLoaded)?;

        let from_node = graph.find_function_at(from)?;
        let to_node = graph.find_function_at(to)?;

        let mut paths: Vec<Vec<CallPathNode>> = Vec::new();
        let mut queue: VecDeque<(NodeIndex, Vec<CallPathNode>, FxHashSet<NodeIndex>)> =
            VecDeque::new();

        let initial_path = vec![graph.node_to_path_node(from_node)];
        let mut initial_visited = FxHashSet::default();
        initial_visited.insert(from_node);

        queue.push_back((from_node, initial_path, initial_visited));

        while let Some((current, path, visited)) = queue.pop_front() {
            if paths.len() >= max_paths {
                break;
            }

            if path.len() as u32 > max_depth {
                continue;
            }

            // Check if we've reached the target
            if current == to_node && path.len() > 1 {
                paths.push(path);
                continue;
            }

            // Explore callees
            for edge in graph.graph.edges_directed(current, Direction::Outgoing) {
                let callee = edge.target();
                if !visited.contains(&callee) {
                    let mut new_path = path.clone();
                    new_path.push(graph.node_to_path_node_with_edge(
                        callee, edge.weight()
                    ));
                    let mut new_visited = visited.clone();
                    new_visited.insert(callee);
                    queue.push_back((callee, new_path, new_visited));
                }
            }
        }

        // Sort paths by length (shortest first)
        paths.sort_by_key(|p| p.len());

        Ok(paths)
    }
}
```

---

## 14. Enrichment Pipeline (Sensitivity → Impact → Remediation)

### 14.1 Architecture

V1's enrichment pipeline runs as 3 separate TS passes after graph construction.
V2 integrates sensitivity classification into the BFS traversal (§5, §8) and runs
impact scoring and remediation generation as post-processing.

```rust
/// Enrichment pipeline. Runs after reachability analysis to add
/// impact scores and remediation suggestions.
pub struct EnrichmentPipeline {
    sensitivity: Arc<SensitivityClassifier>,
}

/// Enriched reachability result with impact scores and remediation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichedResult {
    /// Base reachability result.
    pub reachability: ReachabilityResult,

    /// Impact scores per function (centrality-based).
    pub function_impact_scores: Vec<FunctionImpactScore>,

    /// Remediation suggestions for identified issues.
    pub remediations: Vec<RemediationSuggestion>,
}

/// Impact score for a function based on graph centrality and data sensitivity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionImpactScore {
    pub function_id: String,
    pub score: f64,           // 0.0-100.0
    pub factors: ImpactFactors,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactFactors {
    /// Number of callers (in-degree centrality).
    pub caller_count: usize,
    /// Whether this is an entry point.
    pub is_entry_point: bool,
    /// Whether this accesses sensitive data.
    pub accesses_sensitive_data: bool,
    /// Depth from nearest entry point.
    pub depth_from_entry: u32,
    /// Number of reachable data access points.
    pub reachable_data_points: usize,
}

/// Remediation suggestion for a security finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationSuggestion {
    /// What the issue is.
    pub issue: RemediationIssue,
    /// Where the issue is.
    pub location: CodeLocation,
    /// Suggested fix.
    pub suggestion: String,
    /// Priority (1 = highest).
    pub priority: u8,
    /// Effort estimate.
    pub effort: RemediationEffort,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum RemediationIssue {
    MissingAuthentication,
    MissingInputValidation,
    MissingErrorHandling,
    MissingSensitiveDataLogging,
    MissingRateLimiting,
    UnsanitizedTaintFlow,
    DirectCredentialAccess,
    MissingEncryption,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum RemediationEffort {
    Low,      // < 1 hour
    Medium,   // 1-4 hours
    High,     // 4-16 hours
    VeryHigh, // > 16 hours
}

impl EnrichmentPipeline {
    /// Enrich a reachability result with impact scores and remediation.
    pub fn enrich(
        &self,
        result: &ReachabilityResult,
        graph: &CallGraph,
    ) -> EnrichedResult {
        let impact_scores = self.compute_impact_scores(result, graph);
        let remediations = self.generate_remediations(result, graph);

        EnrichedResult {
            reachability: result.clone(),
            function_impact_scores: impact_scores,
            remediations,
        }
    }

    fn generate_remediations(
        &self,
        result: &ReachabilityResult,
        graph: &CallGraph,
    ) -> Vec<RemediationSuggestion> {
        let mut suggestions: Vec<RemediationSuggestion> = Vec::new();

        // Check for unsanitized taint flows
        for flow in &result.taint_flows {
            if !flow.is_sanitized {
                suggestions.push(RemediationSuggestion {
                    issue: RemediationIssue::UnsanitizedTaintFlow,
                    location: CodeLocation {
                        file: flow.path.last().map(|n| n.file.clone())
                            .unwrap_or_default(),
                        line: flow.path.last().map(|n| n.line).unwrap_or(0),
                        column: None,
                        function_id: flow.path.last().map(|n| n.function_id.clone()),
                    },
                    suggestion: format!(
                        "Add input sanitization before {} sink. Consider using {} for {} data.",
                        flow.sink.sink_type.description(),
                        flow.sink.sink_type.suggested_sanitizer(),
                        flow.source.source_type.description(),
                    ),
                    priority: 1,
                    effort: RemediationEffort::Medium,
                });
            }
        }

        // Check for credential access without auth
        for access in &result.reachable_access {
            if access.sensitivity == SensitivityLevel::Critical {
                // Check if path has auth check
                let has_auth = access.path.iter().any(|node| {
                    AUTH_FUNCTION_PATTERNS.iter()
                        .any(|p| node.function_name.to_lowercase().contains(p))
                });

                if !has_auth {
                    suggestions.push(RemediationSuggestion {
                        issue: RemediationIssue::MissingAuthentication,
                        location: CodeLocation {
                            file: access.path.first().map(|n| n.file.clone())
                                .unwrap_or_default(),
                            line: access.path.first().map(|n| n.line).unwrap_or(0),
                            column: None,
                            function_id: access.path.first()
                                .map(|n| n.function_id.clone()),
                        },
                        suggestion: format!(
                            "Add authentication check before accessing {} (sensitivity: Critical). \
                             This path reaches {} without any auth middleware.",
                            access.access.table,
                            access.access.fields.join(", "),
                        ),
                        priority: 1,
                        effort: RemediationEffort::Medium,
                    });
                }
            }
        }

        suggestions.sort_by_key(|s| s.priority);
        suggestions
    }
}
```


---

## 15. Reachability Caching (LRU + Invalidation)

### 15.1 Cache Architecture

V1 has TS-side caching via `CallGraphStore.cacheReachability()`. V2 moves caching to
Rust with proper invalidation on call graph changes.

```rust
use lru::LruCache;
use std::num::NonZeroUsize;
use std::time::Instant;

/// Cache key for reachability queries.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum ReachabilityKey {
    Forward {
        origin_file: String,
        origin_line: u32,
        max_depth: u32,
        sensitive_only: bool,
        tables: Vec<String>,
    },
    Inverse {
        table: String,
        field: Option<String>,
        max_depth: u32,
        entry_points_only: bool,
    },
    Impact {
        function_id: String,
    },
    Path {
        from_file: String,
        from_line: u32,
        to_file: String,
        to_line: u32,
    },
}

/// Cached result with timestamp for TTL-based eviction.
pub struct CachedResult {
    pub result: ReachabilityResult,
    pub inverse_result: InverseReachabilityResult,
    pub computed_at: Instant,
}

/// Cache invalidation strategy.
pub enum InvalidationStrategy {
    /// Clear entire cache (after full call graph rebuild).
    Full,
    /// Invalidate entries affected by changed files.
    Incremental { changed_files: Vec<String> },
}
```

### 15.2 Invalidation Rules

1. **Full rebuild**: Clear entire cache. Called after `build_call_graph()`.
2. **Incremental update**: Invalidate entries whose origin or path includes a changed file.
   This is conservative — it may invalidate more than necessary, but never misses.
3. **TTL**: Optional TTL (default: none). For long-running processes, set TTL to prevent
   stale results if the call graph is updated externally.

### 15.3 Cache Hit Rate Expectations

| Scenario | Expected Hit Rate | Rationale |
|----------|------------------|-----------|
| MCP interactive queries | 60-80% | Users often query related functions |
| CI scan | 0% | Full rebuild, cache cold |
| IDE hover/completion | 80-95% | Same file, repeated queries |
| Security audit | 30-50% | Systematic but varied queries |

---

## 16. Incremental Reachability (Content-Hash Aware)

### 16.1 Strategy

When the call graph is incrementally updated (files changed, edges re-resolved), the
reachability engine doesn't need to recompute everything. Only queries whose results
could be affected by the changed edges need invalidation.

```rust
impl ReachabilityEngine {
    /// Handle incremental call graph update.
    /// Called after the call graph builder processes changed files.
    pub fn on_incremental_update(
        &mut self,
        changed_files: &[String],
        added_functions: &[String],
        removed_functions: &[String],
    ) -> Result<(), ReachabilityError> {
        // Step 1: Reload graph from drift.db
        self.reload_graph()?;

        // Step 2: Invalidate affected cache entries
        let mut cache = self.cache.lock().unwrap();
        let keys_to_remove: Vec<ReachabilityKey> = cache.iter()
            .filter(|(key, _)| self.is_affected_by_changes(key, changed_files))
            .map(|(key, _)| key.clone())
            .collect();

        for key in keys_to_remove {
            cache.pop(&key);
        }

        tracing::info!(
            changed_files = changed_files.len(),
            invalidated_cache_entries = keys_to_remove.len(),
            "Incremental reachability update complete"
        );

        Ok(())
    }

    fn is_affected_by_changes(
        &self,
        key: &ReachabilityKey,
        changed_files: &[String],
    ) -> bool {
        match key {
            ReachabilityKey::Forward { origin_file, .. } => {
                changed_files.contains(origin_file)
            }
            ReachabilityKey::Inverse { table, .. } => {
                // Conservative: invalidate all inverse queries for changed tables
                // A more precise approach would track which files access which tables
                true
            }
            ReachabilityKey::Impact { function_id } => {
                // Invalidate if the function's file changed
                changed_files.iter().any(|f| function_id.starts_with(f))
            }
            ReachabilityKey::Path { from_file, to_file, .. } => {
                changed_files.contains(from_file) || changed_files.contains(to_file)
            }
        }
    }
}
```

---

## 17. Cross-Service Reachability (Microservice Boundaries)

### 17.1 Architecture

Cross-service reachability extends the call graph across microservice boundaries by
tracking API calls between services. This is a P2 feature (post-launch).

```rust
/// Cross-service reachability types.

/// An API endpoint exposed by a service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceEndpoint {
    pub service_id: String,
    pub method: HttpMethod,
    pub path: String,
    pub handler_function_id: String,
    pub parameters: Vec<EndpointParameter>,
}

/// An API call from one service to another.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossServiceCall {
    pub caller_service_id: String,
    pub caller_function_id: String,
    pub target_service_id: String,
    pub target_endpoint: ServiceEndpoint,
    pub confidence: f64,
    pub line: u32,
}

/// Cross-service reachability result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossServiceReachabilityResult {
    pub origin: CodeLocation,
    pub service_hops: Vec<ServiceHop>,
    pub final_data_access: Vec<ReachableDataAccess>,
    pub total_services_traversed: usize,
}

/// A hop between services in a cross-service reachability path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceHop {
    pub from_service: String,
    pub to_service: String,
    pub api_call: CrossServiceCall,
    pub within_service_path: Vec<CallPathNode>,
}
```

### 17.2 Implementation Strategy

1. Detect API client calls (fetch, axios, http.get, requests.get) during extraction
2. Match calls to known service endpoints (from contract detection or configuration)
3. Link call graphs across services at API boundaries
4. Extend BFS to cross service boundaries (with configurable max service hops)
5. Track taint across service boundaries (tainted request → tainted response)

This requires the contract detection system to provide endpoint registries.

---

## 18. Field-Level Data Flow Tracking

### 18.1 Architecture

V1 tracks data access at the table level. V2 adds field-level tracking with 7
transformation types, enabling precise sensitivity analysis.

```rust
/// Field-level data access with transformation tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldLevelAccess {
    pub table: String,
    pub field: String,
    pub operation: DataOperation,
    pub sensitivity: SensitivityLevel,
    pub category: SensitivityCategory,
    pub transformations: Vec<FieldTransformation>,
}

/// How a field was transformed along the data flow path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FieldTransformation {
    /// Field read directly (no transformation).
    DirectAccess,
    /// Field used in aggregation (COUNT, SUM, AVG, etc.).
    Aggregation { function: String },
    /// Field passed through a hash function.
    Hashing { algorithm: String },
    /// Field encrypted.
    Encryption { algorithm: String },
    /// Field partially masked (e.g., last 4 digits of SSN).
    Masking { mask_type: String },
    /// Field combined with other data.
    Concatenation { with_fields: Vec<String> },
    /// Field used in a filter/WHERE clause (not returned).
    Filtering,
}
```

### 18.2 Why Field-Level Matters

`users.password_hash` reaching an API response is critical.
`users.display_name` reaching an API response is expected.

Without field-level tracking, both are flagged equally. With field-level tracking,
only the password hash triggers a critical alert. This reduces false positives by
50-80% in security analysis (per FlowDroid research).

---

## 19. Storage Schema

### 19.1 Reachability Cache Table (Optional Persistence)

For long-running processes (LSP server, dashboard), reachability results can be
persisted to drift.db for fast startup.

```sql
-- Migration: 005_reachability_cache.sql

CREATE TABLE reachability_cache (
    key_hash BLOB PRIMARY KEY,          -- xxh3 hash of ReachabilityKey
    key_json TEXT NOT NULL,             -- Serialized ReachabilityKey
    result_json TEXT NOT NULL,          -- Serialized result (compressed)
    computed_at INTEGER NOT NULL,       -- Unix timestamp
    call_graph_version TEXT NOT NULL,   -- Call graph build ID for invalidation
    query_time_us INTEGER NOT NULL      -- Original query time
) STRICT;

CREATE INDEX idx_reachability_cache_version
    ON reachability_cache(call_graph_version);

-- Taint flow results (separate for efficient querying)
CREATE TABLE taint_flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_function TEXT NOT NULL,
    sink_function TEXT NOT NULL,
    source_type TEXT NOT NULL,
    sink_type TEXT NOT NULL,
    is_sanitized INTEGER NOT NULL DEFAULT 0,
    risk_level TEXT NOT NULL,
    path_json TEXT NOT NULL,
    sanitizers_json TEXT,
    scan_id TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE INDEX idx_taint_flows_scan ON taint_flows(scan_id);
CREATE INDEX idx_taint_flows_risk ON taint_flows(risk_level);
CREATE INDEX idx_taint_flows_sink ON taint_flows(sink_type);

-- Dead code results
CREATE TABLE dead_code (
    function_id TEXT PRIMARY KEY,
    function_name TEXT NOT NULL,
    file TEXT NOT NULL,
    line INTEGER NOT NULL,
    end_line INTEGER NOT NULL,
    confidence REAL NOT NULL,
    false_positive_reasons_json TEXT,
    lines_of_code INTEGER NOT NULL,
    accesses_sensitive_data INTEGER NOT NULL DEFAULT 0,
    scan_id TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE INDEX idx_dead_code_scan ON dead_code(scan_id);
CREATE INDEX idx_dead_code_confidence ON dead_code(confidence);
CREATE INDEX idx_dead_code_file ON dead_code(file);
```

---

## 20. NAPI Interface

### 20.1 Unified Reachability API

V2 merges the 4 separate v1 NAPI functions into 2 unified functions that auto-select
the optimal engine. The v1 functions are preserved as aliases for backward compatibility.

```rust
use napi_derive::napi;

// === Unified API (v2) ===

/// Forward reachability — auto-selects engine.
/// Replaces: analyze_reachability + analyze_reachability_sqlite
#[napi]
pub fn analyze_reachability(
    options: ReachabilityQueryOptions,
) -> napi::Result<JsReachabilityResult> {
    let rt = crate::runtime::get()?;
    let result = rt.reachability_engine.forward(
        &options.origin.into(),
        &options.into(),
    ).map_err(to_napi_error)?;
    Ok(JsReachabilityResult::from(result))
}

/// Inverse reachability — auto-selects engine.
/// Replaces: analyze_inverse_reachability + analyze_inverse_reachability_sqlite
#[napi]
pub fn analyze_inverse_reachability(
    options: InverseReachabilityQueryOptions,
) -> napi::Result<JsInverseReachabilityResult> {
    let rt = crate::runtime::get()?;
    let result = rt.reachability_engine.inverse(
        &options.target.into(),
        &options.into(),
    ).map_err(to_napi_error)?;
    Ok(JsInverseReachabilityResult::from(result))
}

/// Impact analysis — new in v2.
#[napi]
pub fn analyze_impact(
    function_id: String,
) -> napi::Result<JsImpactResult> {
    let rt = crate::runtime::get()?;
    let result = rt.impact_analyzer.analyze(&function_id)
        .map_err(to_napi_error)?;
    Ok(JsImpactResult::from(result))
}

/// Dead code detection — new in v2.
#[napi]
pub fn detect_dead_code() -> napi::Result<Vec<JsDeadCodeCandidate>> {
    let rt = crate::runtime::get()?;
    let candidates = rt.dead_code_detector.detect()
        .map_err(to_napi_error)?;
    Ok(candidates.into_iter().map(JsDeadCodeCandidate::from).collect())
}

/// Taint analysis — new in v2.
#[napi]
pub fn analyze_taint(
    function_id: String,
    options: Option<TaintQueryOptions>,
) -> napi::Result<Vec<JsTaintFlow>> {
    let rt = crate::runtime::get()?;
    let result = rt.reachability_engine.forward(
        &CodeLocation { function_id: Some(function_id), ..Default::default() },
        &ReachabilityOptions {
            enable_taint: Some(true),
            ..options.map(Into::into).unwrap_or_default()
        },
    ).map_err(to_napi_error)?;
    Ok(result.taint_flows.into_iter().map(JsTaintFlow::from).collect())
}

/// Path finding between two functions.
#[napi]
pub fn find_call_paths(
    from_file: String,
    from_line: u32,
    to_file: String,
    to_line: u32,
    max_paths: Option<u32>,
    max_depth: Option<u32>,
) -> napi::Result<Vec<Vec<JsCallPathNode>>> {
    let rt = crate::runtime::get()?;
    let paths = rt.reachability_engine.find_paths(
        &CodeLocation { file: from_file, line: from_line, ..Default::default() },
        &CodeLocation { file: to_file, line: to_line, ..Default::default() },
        max_paths.unwrap_or(5) as usize,
        max_depth.unwrap_or(30),
    ).map_err(to_napi_error)?;
    Ok(paths.into_iter()
        .map(|p| p.into_iter().map(JsCallPathNode::from).collect())
        .collect())
}

/// Coverage analysis — new in v2.
#[napi]
pub fn analyze_data_path_coverage() -> napi::Result<JsCoverageResult> {
    let rt = crate::runtime::get()?;
    let test_functions = rt.get_test_functions()?;
    let result = rt.coverage_analyzer.analyze(&test_functions)
        .map_err(to_napi_error)?;
    Ok(JsCoverageResult::from(result))
}

/// Invalidate reachability cache (called after call graph rebuild).
#[napi]
pub fn invalidate_reachability_cache() -> napi::Result<()> {
    let rt = crate::runtime::get()?;
    rt.reachability_engine.invalidate_cache();
    Ok(())
}
```

### 20.2 NAPI Function Registry

| Function | Sync/Async | Returns | V1 Equivalent |
|----------|-----------|---------|---------------|
| `analyze_reachability(options)` | Sync | `JsReachabilityResult` | analyze_reachability + analyze_reachability_sqlite |
| `analyze_inverse_reachability(options)` | Sync | `JsInverseReachabilityResult` | analyze_inverse_reachability + analyze_inverse_reachability_sqlite |
| `analyze_impact(function_id)` | Sync | `JsImpactResult` | NEW |
| `detect_dead_code()` | Sync | `Vec<JsDeadCodeCandidate>` | NEW |
| `analyze_taint(function_id, options?)` | Sync | `Vec<JsTaintFlow>` | NEW |
| `find_call_paths(from, to, max_paths?, max_depth?)` | Sync | `Vec<Vec<JsCallPathNode>>` | get_call_path (Rust) |
| `analyze_data_path_coverage()` | Sync | `JsCoverageResult` | NEW |
| `invalidate_reachability_cache()` | Sync | `void` | NEW |

Total: 8 NAPI functions (vs 4 in v1). 4 preserved (unified), 4 new.


---

## 21. MCP Tool Interface

### 21.1 MCP Tools

```typescript
// drift_reachability — Forward/inverse data reachability (preserved + enhanced)
{
  name: "drift_reachability",
  description: "Trace data flow from code to sensitive data, or find who can reach specific data",
  parameters: {
    location: "file:line or function name",
    direction: "forward | inverse",
    table: "target table (required for inverse)",
    field: "target field (optional, for field-level)",
    sensitive_only: "boolean (default: false)",
    enable_taint: "boolean (default: true)",
    max_depth: "number (default: 50)",
  }
}

// drift_taint_analysis — Taint flow analysis (NEW)
{
  name: "drift_taint_analysis",
  description: "Find unsanitized data flows from untrusted sources to dangerous sinks",
  parameters: {
    function: "function name or file:line",
    source_types: "UserInput,ApiResponse,... (optional filter)",
    sink_types: "SqlQuery,CommandExecution,... (optional filter)",
    include_sanitized: "boolean (default: false)",
  }
}

// drift_impact — Change impact analysis (preserved + enhanced)
{
  name: "drift_impact",
  description: "Analyze blast radius of changing a function",
  parameters: {
    function: "function name or file:line",
    include_tests: "boolean (default: true)",
  }
}

// drift_dead_code — Dead code detection (NEW)
{
  name: "drift_dead_code",
  description: "Find functions that are never called",
  parameters: {
    min_confidence: "number (default: 0.50)",
    file: "optional file filter",
    include_false_positives: "boolean (default: false)",
  }
}

// drift_security_reachability — Security-focused reachability (NEW)
{
  name: "drift_security_reachability",
  description: "Security audit: find all paths from entry points to sensitive data",
  parameters: {
    sensitivity: "Critical | High | Medium | Low",
    category: "Pii | Credentials | Financial | Health",
    entry_point_type: "HttpHandler | CliCommand | ... (optional)",
    require_auth_check: "boolean (default: false)",
  }
}
```

---

## 22. CLI Interface

```bash
# Forward reachability
drift callgraph reachability --file src/api/users.ts --line 42
drift callgraph reachability --function getUserById --sensitive-only
drift callgraph reachability --function getUserById --enable-taint

# Inverse reachability
drift callgraph reachability --inverse --table users --field password_hash
drift callgraph reachability --inverse --table payments --entry-points-only

# Impact analysis
drift callgraph impact --function updateUser
drift callgraph impact --file src/services/payment.ts --line 100

# Dead code detection
drift callgraph dead-code
drift callgraph dead-code --min-confidence 0.80 --file src/

# Taint analysis
drift taint --function processPayment
drift taint --source-type UserInput --sink-type SqlQuery
drift taint --all --risk-level Critical

# Security reachability
drift security reachability --sensitivity Critical
drift security reachability --category Credentials --no-auth-check
drift security reachability --table users --field ssn

# Path finding
drift callgraph path --from src/api/users.ts:42 --to src/db/queries.ts:15
```

---

## 23. Event Interface

```rust
/// Events emitted by the reachability engine.
pub trait ReachabilityEventHandler: Send + Sync {
    /// Forward reachability query completed.
    fn on_forward_reachability(
        &self,
        origin: &CodeLocation,
        result: &ReachabilityResult,
    ) {}

    /// Inverse reachability query completed.
    fn on_inverse_reachability(
        &self,
        target: &InverseTarget,
        result: &InverseReachabilityResult,
    ) {}

    /// Taint flow detected.
    fn on_taint_flow_detected(
        &self,
        flow: &TaintFlow,
    ) {}

    /// Impact analysis completed.
    fn on_impact_analysis(
        &self,
        function_id: &str,
        result: &ImpactResult,
    ) {}

    /// Dead code detected.
    fn on_dead_code_detected(
        &self,
        candidates: &[DeadCodeCandidate],
    ) {}

    /// Cache hit.
    fn on_cache_hit(&self, key: &ReachabilityKey) {}

    /// Cache miss.
    fn on_cache_miss(&self, key: &ReachabilityKey) {}
}
```

---

## 24. Tracing & Observability

```rust
// All reachability operations are instrumented with tracing spans.

#[tracing::instrument(
    skip(self, graph, origin, options),
    fields(
        origin.file = %origin.file,
        origin.line = origin.line,
        max_depth = options.max_depth.unwrap_or(50),
        sensitive_only = options.sensitive_only,
        engine = ?self.engine_type(),
    )
)]
fn forward_petgraph(
    &self,
    graph: &CallGraph,
    origin: &CodeLocation,
    options: &ReachabilityOptions,
) -> Result<ReachabilityResult, ReachabilityError> {
    // ... implementation
    tracing::info!(
        functions_traversed = result.functions_traversed,
        reachable_access = result.reachable_access.len(),
        sensitive_fields = result.sensitive_fields.len(),
        taint_flows = result.taint_flows.len(),
        max_depth_reached = result.max_depth_reached,
        query_time_us = result.query_time_us,
        "Forward reachability complete"
    );
    Ok(result)
}

// Key metrics to track:
// - reachability.forward.query_time_us (histogram)
// - reachability.inverse.query_time_us (histogram)
// - reachability.cache.hit_rate (gauge)
// - reachability.taint.flows_detected (counter)
// - reachability.taint.unsanitized_flows (counter)
// - reachability.dead_code.candidates (gauge)
// - reachability.impact.max_blast_radius (gauge)
// - reachability.engine.petgraph_queries (counter)
// - reachability.engine.sqlite_cte_queries (counter)
```

---

## 25. Performance Targets & Benchmarks

| Operation | Target | Measurement |
|-----------|--------|-------------|
| Forward reachability (10K functions) | < 5ms | p99 latency |
| Forward reachability (100K functions) | < 50ms | p99 latency |
| Forward reachability (500K functions, petgraph) | < 200ms | p99 latency |
| Forward reachability (1M functions, SQLite CTE) | < 1s | p99 latency |
| Inverse reachability (10K functions) | < 10ms | p99 latency |
| Inverse reachability (100K functions) | < 100ms | p99 latency |
| Impact analysis (10K functions) | < 5ms | p99 latency |
| Dead code detection (100K functions) | < 500ms | single pass |
| Taint analysis (single function, depth 20) | < 10ms | p99 latency |
| Cache hit | < 100μs | p99 latency |
| Sensitivity classification (single field) | < 1μs | per-field |
| Graph load from drift.db (100K functions) | < 2s | startup |
| Graph load from drift.db (500K functions) | < 10s | startup |
| Memory: petgraph (100K functions) | < 100MB | RSS |
| Memory: petgraph (500K functions) | < 500MB | RSS |

### Benchmark Suite

```rust
#[cfg(test)]
mod benchmarks {
    use criterion::{criterion_group, criterion_main, Criterion};

    fn bench_forward_reachability(c: &mut Criterion) {
        let engine = setup_engine_with_graph(100_000);
        c.bench_function("forward_10k_depth20", |b| {
            b.iter(|| engine.forward(&random_origin(), &default_options()))
        });
    }

    fn bench_inverse_reachability(c: &mut Criterion) {
        let engine = setup_engine_with_graph(100_000);
        c.bench_function("inverse_10k_depth20", |b| {
            b.iter(|| engine.inverse(&random_target(), &default_inverse_options()))
        });
    }

    fn bench_sensitivity_classification(c: &mut Criterion) {
        let classifier = SensitivityClassifier::new();
        c.bench_function("classify_field", |b| {
            b.iter(|| classifier.classify_field("password_hash", "users"))
        });
    }

    fn bench_dead_code_detection(c: &mut Criterion) {
        let detector = setup_dead_code_detector(100_000);
        c.bench_function("dead_code_100k", |b| {
            b.iter(|| detector.detect())
        });
    }

    criterion_group!(
        benches,
        bench_forward_reachability,
        bench_inverse_reachability,
        bench_sensitivity_classification,
        bench_dead_code_detection,
    );
    criterion_main!(benches);
}
```

---

## 26. Build Order & Dependencies

### 26.1 Dependency Graph

```
drift-core/src/reachability/
├── mod.rs                    # Module exports
├── engine.rs                 # ReachabilityEngine (unified, auto-select)
├── forward.rs                # Forward BFS (petgraph + SQLite CTE)
├── inverse.rs                # Inverse BFS (petgraph + SQLite CTE)
├── sensitivity.rs            # SensitivityClassifier
├── taint.rs                  # TaintRegistry, taint label propagation
├── impact.rs                 # ImpactAnalyzer
├── dead_code.rs              # DeadCodeDetector
├── coverage.rs               # CoverageAnalyzer
├── path_finder.rs            # Path finding between functions
├── enrichment.rs             # EnrichmentPipeline
├── cache.rs                  # LRU cache with invalidation
├── cross_service.rs          # Cross-service reachability (P2)
├── field_level.rs            # Field-level data flow tracking
├── types.rs                  # All types (results, options, enums)
└── error.rs                  # ReachabilityError enum
```

### 26.2 Build Order

```
Phase 1: Types & Infrastructure (Week 1)
  1. types.rs — all result types, option types, enums
  2. error.rs — ReachabilityError with thiserror
  3. sensitivity.rs — SensitivityClassifier with pattern registry

Phase 2: Core Engines (Weeks 2-3)
  4. forward.rs — petgraph BFS (without taint)
  5. inverse.rs — petgraph reverse BFS
  6. engine.rs — unified engine with auto-selection
  7. cache.rs — LRU cache with invalidation

Phase 3: Analysis Engines (Weeks 3-4)
  8. impact.rs — ImpactAnalyzer
  9. dead_code.rs — DeadCodeDetector
  10. path_finder.rs — Path finding
  11. coverage.rs — CoverageAnalyzer

Phase 4: Taint Integration (Weeks 5-6)
  12. taint.rs — TaintRegistry, TOML loading, label propagation
  13. Update forward.rs — add taint tracking to BFS
  14. enrichment.rs — EnrichmentPipeline

Phase 5: Advanced Features (Weeks 7-8)
  15. field_level.rs — Field-level data flow tracking
  16. SQLite CTE implementations in forward.rs and inverse.rs
  17. cross_service.rs — Cross-service reachability (stub)

Phase 6: NAPI + Integration (Week 9)
  18. NAPI bindings for all 8 functions
  19. MCP tool implementations
  20. CLI command implementations
```

### 26.3 Crate Dependencies

```toml
[dependencies]
# Core
petgraph = "0.6"              # Graph data structure + algorithms
lru = "0.12"                  # LRU cache
regex = "1"                   # Sensitivity pattern matching
chrono = { version = "0.4", features = ["serde"] }

# From drift-core
rusqlite = { version = "0.31", features = ["bundled"] }
rustc-hash = "1"              # FxHashMap
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "1"
tracing = "0.1"
toml = "0.8"                  # Taint registry loading

# Optional
statrs = "0.17"               # Statistical functions (if needed)
```

---

## 27. V1 → V2 Feature Cross-Reference

| V1 Feature | V1 Location | V2 Location | Status |
|-----------|-------------|-------------|--------|
| Forward BFS (in-memory) | `reachability/engine.rs` | `reachability/forward.rs` | Upgraded (petgraph + taint) |
| Forward BFS (SQLite) | `reachability/sqlite_engine.rs` | `reachability/forward.rs` | Upgraded (recursive CTEs) |
| Inverse BFS (in-memory) | `reachability/engine.rs` | `reachability/inverse.rs` | Upgraded (petgraph + auth check) |
| Inverse BFS (SQLite) | `reachability/sqlite_engine.rs` | `reachability/inverse.rs` | Upgraded (recursive CTEs) |
| Path finding | `reachability/engine.rs` | `reachability/path_finder.rs` | Preserved |
| Sensitivity (Rust) | `boundaries/sensitive.rs` | `reachability/sensitivity.rs` | Upgraded (6 categories) |
| Sensitivity (TS) | `enrichment/sensitivity-classifier.ts` | `reachability/sensitivity.rs` | Merged into Rust |
| Impact analysis | `analysis/impact-analyzer.ts` | `reachability/impact.rs` | Ported to Rust |
| Dead code detection | `analysis/dead-code-detector.ts` | `reachability/dead_code.rs` | Ported to Rust |
| Coverage analysis | `analysis/coverage-analyzer.ts` | `reachability/coverage.rs` | Ported to Rust |
| Impact scoring | `enrichment/impact-scorer.ts` | `reachability/enrichment.rs` | Ported to Rust |
| Remediation gen | `enrichment/remediation-generator.ts` | `reachability/enrichment.rs` | Ported to Rust |
| UnifiedProvider | `unified-provider.ts` | `reachability/engine.rs` | Replaced (Rust-native) |
| LRU cache | `unified-provider.ts` (500 entries) | `reachability/cache.rs` (256 entries) | Upgraded (Rust LRU) |
| NAPI: 4 functions | `drift-napi` | `drift-napi` | Unified to 2 + 6 new |
| MCP: drift_reachability | `packages/mcp` | `packages/mcp` | Preserved + enhanced |
| MCP: drift_impact | `packages/mcp` | `packages/mcp` | Preserved + enhanced |
| Taint analysis | N/A | `reachability/taint.rs` | NEW |
| Field-level flow | N/A | `reachability/field_level.rs` | NEW |
| Cross-service | N/A | `reachability/cross_service.rs` | NEW (P2) |

---

## 28. Inconsistencies & Decisions

### I1: Duplicate Reachability Types (Resolved)

**Issue**: V1 has separate `CallGraph`/`FunctionNode` types in `reachability/` and
`call_graph/` modules. The reachability module re-defines types optimized for traversal.

**Decision**: V2 uses a single `CallGraph` type (petgraph StableGraph from
05-CALL-GRAPH-V2-PREP) shared between the call graph builder and reachability engine.
No duplicate types. The reachability engine reads the graph via `Arc<CallGraph>`.

### I2: In-Memory vs SQLite Engine Selection (Resolved)

**Issue**: V1 exposes separate NAPI functions for in-memory and SQLite engines.
Consumers must choose.

**Decision**: V2 auto-selects based on graph size (§3.2). Single API, engine is
an implementation detail. The `engine` field in results reports which was used.

### I3: Sensitivity Classification Split (Resolved)

**Issue**: V1 has sensitivity classification in both Rust (`boundaries/sensitive.rs`)
and TypeScript (`enrichment/sensitivity-classifier.ts`). They can disagree.

**Decision**: V2 has a single Rust `SensitivityClassifier` (§8). TS layer is
presentation only. No dual classification.

### I4: Taint Analysis Scope (Resolved)

**Issue**: AD11 says "Phase 1: intraprocedural, Phase 2: interprocedural." But
reachability BFS is inherently interprocedural.

**Decision**: Phase 1 taint tracking during BFS is interprocedural at the function
level (taint labels propagate across function boundaries via call edges). Phase 2
adds intraprocedural precision (tracking taint through assignments within a function
via function summaries). Phase 1 is sufficient for launch.

### I5: Cache Size (Resolved)

**Issue**: V1 TS UnifiedCallGraphProvider uses 500-entry LRU. V2 Rust engine uses 256.

**Decision**: 256 is sufficient. Reachability results are larger than function lookups
(the v1 500-entry cache was for function lookups, not reachability results). 256 entries
at ~10KB each = ~2.5MB cache, which is reasonable.

### I6: Dead Code Confidence Threshold (Resolved)

**Issue**: What minimum confidence should dead code candidates have?

**Decision**: Report candidates with confidence ≥ 0.25. MCP/CLI default filter is 0.50.
This allows users to see low-confidence candidates if they want, while defaulting to
higher confidence for actionable results.

---

## 29. Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Taint false positives from imprecise sanitizer detection | High | Medium | Conservative sanitizer matching, user-configurable registry |
| petgraph memory pressure for large codebases | Medium | High | Auto-fallback to SQLite CTEs at 500K functions |
| Sensitivity pattern false positives | Medium | Medium | 8 false positive filter types, user-configurable patterns |
| Dead code false positives from dynamic dispatch | High | Low | 8 false positive categories, confidence scoring |
| Cross-service reachability requires service discovery | High | Medium | Defer to P2, require explicit configuration |
| Field-level tracking performance overhead | Medium | Medium | Optional (config flag), ~1.5x overhead |
| Taint registry maintenance burden | Medium | Medium | Per-framework defaults, community contributions |
| SQLite CTE cycle detection via string LIKE | Low | Medium | Bounded depth (50), visited set in application layer |
| Cache invalidation misses (stale results) | Low | High | Conservative invalidation, version-based cache keys |
| Regression in sensitivity classification during migration | Medium | High | Comprehensive test suite, golden file tests |
