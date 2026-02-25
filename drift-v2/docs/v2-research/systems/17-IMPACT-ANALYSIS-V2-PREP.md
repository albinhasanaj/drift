# Impact Analysis (Blast Radius, Dead Code, Path Finding) — V2 Implementation Prep

> Comprehensive build specification for Drift v2's Impact Analysis subsystem (System 17).
> Synthesized from: 04-call-graph/analysis.md (ImpactAnalyzer, DeadCodeDetector, PathFinder, CoverageAnalyzer),
> 04-call-graph/enrichment.md (sensitivity classifier, impact scorer, remediation generator),
> 04-call-graph/reachability.md (v1 ReachabilityEngine path finding, BFS algorithms),
> 04-call-graph/types.md (FunctionNode, CallSite, CallGraph, ReachabilityResult),
> 04-call-graph/overview.md (capabilities matrix, consumer list),
> 14-REACHABILITY-ANALYSIS-V2-PREP.md (§10 Impact, §11 Dead Code, §12 Coverage, §13 Path Finding, §14 Enrichment),
> 05-CALL-GRAPH-V2-PREP.md (petgraph StableGraph, Resolution, CallEdge, SQLite CTEs),
> 07-BOUNDARY-DETECTION-V2-PREP.md (learn-then-detect, 33 ORM frameworks, field-level flow),
> 03-NAPI-BRIDGE-V2-PREP.md (command/query pattern, async tasks, napi-rs v3),
> 02-STORAGE-V2-PREP.md (drift.db schema, batch writer, medallion architecture),
> 04-INFRASTRUCTURE-V2-PREP.md (thiserror, tracing, FxHashMap, petgraph, lasso),
> 15-TAINT-ANALYSIS-V2-PREP.md (taint flow integration with impact scoring),
> 16-ERROR-HANDLING-ANALYSIS-V2-PREP.md (error propagation chain analysis),
> DRIFT-V2-FULL-SYSTEM-AUDIT.md (AD1 incremental, AD8 Bayesian confidence, AD9 feedback loop,
>   AD10 observability, AD11 taint first-class, AD12 performance data structures),
> DRIFT-V2-STACK-HIERARCHY.md (Level 2B — Graph Intelligence, consumer count),
> DRIFT-V2-SYSTEMS-REFERENCE.md (impact capabilities, dead code, path finding),
> PLANNING-DRIFT.md (D1 standalone, D5 event trait, D6 separate databases, D7 grounding),
> .research/04-call-graph/RECOMMENDATIONS.md (R6 impact in Rust, R7 dead code in Rust,
>   R8 recursive CTEs, R9 cross-service, R10 caching, R12 accuracy benchmarking),
> .research/04-call-graph/RECAP.md (capabilities matrix, limitations, type parity),
> .research/16-gap-analysis/RECOMMENDATIONS.md (GE4 security roadmap),
> Change Impact Analysis (Bohnner & Arnold — "identifying potential consequences of a change"),
> Enhancing Code Understanding for Impact Analysis by Combining Transformers and PDGs
>   (ACM 2024 — program dependence graphs + transformer models for IA),
> Overmind blast radius analysis (dependency graph traversal, risk categorization),
> Apiiro Deep Code Analysis (call flow + data flow + reachability for exploitability),
> Reducing False Positives in Static Bug Detection with LLMs (arxiv 2025 — hybrid
>   LLM + static analysis eliminates 94-98% false positives),
> Qt/Axivion dead code analysis (reachability on call relation, entry point enumeration),
> PyCG (Salis et al., ICSE 2021 — namespace-based call graph, 99.2% precision),
> petgraph StableGraph (Rust graph library, BFS/DFS/Dijkstra/PageRank algorithms),
> SonarQube dead code detection (unused declarations, unreachable code, redundant assignments),
> Facebook Infer (compositional per-function summaries, latent/manifest issues),
> Demanded Abstract Interpretation (PLDI — 95% queries <1.2s, on-demand summarization).
>
> Purpose: Everything needed to build the Impact Analysis subsystem from scratch.
> This is the DEDICATED deep-dive for impact analysis — the 14-REACHABILITY-ANALYSIS-V2-PREP
> doc covers the BFS engines that impact analysis extends; this document covers the
> impact-specific machinery: blast radius computation, multi-dimensional risk scoring,
> dead code detection with 10 false positive categories, path finding with weighted
> shortest paths, coverage gap analysis, enrichment pipeline, change simulation
> integration, and the full integration with the call graph, reachability engine,
> taint analysis, quality gates, and CI agent.
> Every v1 feature accounted for. Every algorithm specified. Every type defined.
> Every integration point documented. Every architectural decision resolved.
> Generated: 2026-02-07

---

## Table of Contents

1. Architectural Position
2. V1 Complete Feature Inventory
3. V2 Architecture — Unified Impact Intelligence Engine
4. Core Data Model
5. Blast Radius Engine (Reverse BFS + Metrics)
6. Multi-Dimensional Risk Scoring
7. Dead Code Detection Engine (10 False Positive Categories)
8. Dead Code Confidence Scoring (Bayesian)
9. Path Finding Engine (BFS, Dijkstra, K-Shortest)
10. Weighted Path Scoring (Resolution Confidence × Depth)
11. Coverage Gap Analysis (Call Graph × Test Topology)
12. Enrichment Pipeline (Impact Scoring + Remediation)
13. Change Simulation Integration
14. Incremental Impact Analysis (Content-Hash Aware)
15. Cross-Service Impact Propagation
16. Git Integration (Diff-Based Impact)
17. LLM-Assisted False Positive Reduction (P2)
18. Storage Schema
19. NAPI Interface
20. MCP Tool Interface
21. CLI Interface
22. Event Interface
23. Tracing & Observability
24. Performance Targets & Benchmarks
25. Build Order & Dependencies
26. V1 → V2 Feature Cross-Reference
27. Inconsistencies & Decisions
28. Risk Register

---

## 1. Architectural Position

Impact Analysis is **Level 2B — Graph Intelligence** in the Drift v2 stack hierarchy.
It is the system that transforms Drift's call graph into actionable change intelligence —
answering questions like "what breaks if I change this function?", "which functions are
never called?", "what's the shortest call path between these two functions?", and
"which sensitive data paths lack test coverage?"

Per DRIFT-V2-STACK-HIERARCHY.md:

> Impact Analysis: Transitive caller analysis, risk scoring, dead code, path finding.
> "What breaks if I change this?" — critical for simulation, CI agent, `drift_impact`.

Per DRIFT-V2-FULL-SYSTEM-AUDIT.md Category 01:

> Reachability (Rust): Forward/inverse BFS, sensitivity classification, taint tracking.
> Impact analysis, dead code detection, coverage analysis, path finding — all Rust.

### Core Thesis

Impact analysis is a **topology problem with risk semantics**. A function's blast radius
is not just the count of transitive callers — it's the weighted combination of how many
entry points are affected, whether sensitive data paths are disrupted, how deep the
propagation goes, and whether test coverage exists for the affected paths. A function
with 100 transitive callers but full test coverage and no sensitive data access is
lower risk than a function with 5 callers that includes an unauthenticated path to
credential data.

This is why impact analysis requires the full graph intelligence stack: call graph for
topology, reachability for data flow, sensitivity classification for risk weighting,
taint analysis for security impact, and test topology for coverage gaps.

### What Lives Here

- Blast radius computation (reverse BFS with transitive caller collection)
- Multi-dimensional risk scoring (6 factors: callers, entry points, sensitive data,
  test coverage, taint flows, propagation depth)
- Dead code detection (unreachable functions with 10 false positive categories)
- Dead code confidence scoring (Bayesian posterior with evidence accumulation)
- Path finding between any two functions (BFS, Dijkstra weighted, K-shortest)
- Weighted path scoring (resolution confidence × depth × edge type)
- Coverage gap analysis (call graph × test topology for data path coverage)
- Enrichment pipeline (impact scoring + remediation generation)
- Change simulation integration (blast radius feeds simulation engine)
- Incremental impact analysis (content-hash aware, cache invalidation)
- Cross-service impact propagation (microservice boundary tracking)
- Git integration (diff-based impact for PR analysis)
- Impact result persistence (drift.db impact tables)

### What Does NOT Live Here

- Call graph construction → Call Graph Builder (Level 1, produces the graph we traverse)
- Forward/inverse reachability BFS → Reachability Engine (Level 2B, provides traversal)
- Sensitivity classification → Reachability Engine (Level 2B, classifies during BFS)
- Taint analysis → Taint Analysis Engine (Level 2B, provides taint flow data)
- Error propagation chains → Error Handling Analysis (Level 2B, separate domain)
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
        → Reachability Engine (Level 2B) — provides BFS primitives, sensitivity
          → Taint Analysis (Level 2B) — provides taint flow data
            → Impact Analysis (Level 2B) ← YOU ARE HERE
              → Quality Gates (Level 3) — impact gate, coverage gate
                → Simulation Engine (Level 4) — blast radius scoring
                  → CI Agent (Level 5) — PR impact analysis
                    → MCP Tools (Level 5) — drift_impact, drift_dead_code
```

### Dependency Direction

```
                    ┌─────────────────────────────────────────────────┐
                    │         Downstream Consumers                    │
                    │  Quality Gates (impact gate, coverage gate),    │
                    │  Simulation Engine (blast radius calculation),  │
                    │  CI Agent (PR impact analysis, risk scoring),   │
                    │  DNA System (impact health metrics),            │
                    │  MCP Tools (drift_impact, drift_dead_code,      │
                    │    drift_path_finder, drift_coverage_gaps),     │
                    │  CLI (drift impact, drift dead-code, drift path)│
                    │  Cortex Grounding (D7 — impact validation)     │
                    └──────────────────┬──────────────────────────────┘
                                       │ reads impact results
                    ┌──────────────────▼──────────────────────────────┐
                    │   Impact Analysis (this system)                 │
                    │   Level 2B — Graph Intelligence                 │
                    └──────────────────┬──────────────────────────────┘
                                       │ reads call graph + reachability + taint
                    ┌──────────────────▼──────────────────────────────┐
                    │         Upstream Producers                      │
                    │  Call Graph Builder (petgraph + drift.db edges),│
                    │  Reachability Engine (BFS, sensitivity),        │
                    │  Taint Analysis (taint flows, sanitizer data),  │
                    │  Boundary Detection (DataAccessPoint[]),        │
                    │  Test Topology (test function registry),        │
                    │  Scanner (file metadata, content hashes)        │
                    └─────────────────────────────────────────────────┘
```

### Consumer Count: 8+ Downstream Systems

Impact analysis is the highest-leverage "change intelligence" system. Every PR review,
every simulation, every quality gate check, every CI pipeline decision about risk
passes through this engine. Building it well means every downstream consumer gets
accurate risk assessment for free.



---

## 2. V1 Complete Feature Inventory

Every v1 feature documented here must be accounted for in v2 — either preserved, upgraded,
or explicitly replaced with rationale. This is the zero-feature-loss guarantee.

### 2.1 V1 Impact Analyzer (TS Only)

**Location**: `packages/core/src/call-graph/analysis/impact-analyzer.ts`

```typescript
function analyzeImpact(graph: CallGraph, functionId: string): {
    affectedFunctions: string[];
    affectedDataPaths: DataPath[];
    risk: 'low' | 'medium' | 'high' | 'critical';
}
```

**Algorithm**:
1. Find the target function in the call graph
2. Reverse BFS: collect all transitive callers (functions that call the target, directly or transitively)
3. Collect affected data paths: data access points reachable through the affected functions
4. Compute risk level based on 4 factors:
   - Number of affected functions (more = higher risk)
   - Whether affected functions are entry points (API surface impact)
   - Whether data paths include sensitive data (security impact)
   - Depth of impact propagation (how far the change ripples)
5. Return affected functions, data paths, and risk level

**Limitations**:
- No blast radius metrics (just counts)
- No test coverage integration
- No taint flow awareness
- Risk scoring is heuristic (4 string levels, no numeric score)
- No caching
- No incremental analysis
- TS-only (no Rust implementation)

### 2.2 V1 Dead Code Detector (TS Only)

**Location**: `packages/core/src/call-graph/analysis/dead-code-detector.ts`

```typescript
function detectDeadCode(graph: CallGraph): {
    candidates: DeadCodeCandidate[];
    confidence: 'high' | 'medium' | 'low';
    falsePositiveReasons: string[];
}
```

**Algorithm**:
1. Iterate all functions in the call graph
2. Find functions with `calledBy.length === 0` (no incoming edges)
3. For each candidate, check false positive categories:
   - Entry point (HTTP handler, CLI command, main function)
   - Framework hook (lifecycle method: componentDidMount, setUp, etc.)
   - Dynamic dispatch (called via reflection, eval, getattr)
   - Event handler (called via event system, signals)
   - Exported function (may be used by external packages)
4. Assign confidence based on false positive reason count
5. Return sorted candidates

**Limitations**:
- Only 5 false positive categories (v2 has 10)
- No confidence scoring (just 'high'/'medium'/'low' strings)
- No lines-of-code impact metric
- No sensitive data access awareness
- No Bayesian confidence
- TS-only (no Rust implementation)

### 2.3 V1 Path Finder

**Location**: `packages/core/src/call-graph/analysis/path-finder.ts` + Rust `engine.rs`

```typescript
// TS
function findPaths(graph: CallGraph, from: string, to: string, maxPaths: number): CallPath[];

// Rust
pub fn get_call_path(&self, from_id: &str, to_id: &str, max_depth: u32) -> Vec<Vec<CallPathNode>>;
```

**Algorithm**: BFS with path tracking between any two functions. Returns multiple paths
up to a configurable limit. Paths sorted by length (shortest first).

**Limitations**:
- No weighted paths (all edges treated equally)
- No confidence-weighted scoring
- No path ranking beyond length
- No Dijkstra or K-shortest algorithms
- No cross-service path finding

### 2.4 V1 Coverage Analyzer (TS Only)

**Location**: `packages/core/src/call-graph/analysis/coverage-analyzer.ts`

```typescript
function analyzeCoverage(graph: CallGraph, testTopology: TestTopology): {
    fieldCoverage: FieldCoverage[];
    uncoveredPaths: DataPath[];
}
```

**Algorithm**:
1. For each entry point, trace forward to data access points
2. For each data path, check if any function on the path is covered by a test
3. Aggregate coverage by field (table.field → coverage percentage)
4. Report uncovered paths with sensitivity and risk

**Limitations**:
- TS-only (no Rust implementation)
- No field-level granularity (table-level only)
- No risk-weighted coverage (all paths weighted equally)
- No minimum test set computation

### 2.5 V1 Enrichment Pipeline (TS Only)

**Location**: `packages/core/src/call-graph/enrichment/`

3 components:
1. **Sensitivity Classifier** (`sensitivity-classifier.ts`) — classifies data access by
   sensitivity level (Critical/High/Medium/Low) using pattern matching on field/table names
2. **Impact Scorer** (`impact-scorer.ts`) — scores function impact based on centrality,
   entry point status, sensitive data access, depth from entry, reachable data points
3. **Remediation Generator** (`remediation-generator.ts`) — generates actionable fix
   suggestions for missing auth, missing validation, missing error handling, missing
   logging, missing rate limiting

**Limitations**:
- TS-only (should be Rust for performance)
- Sensitivity classification duplicated between Rust and TS
- Impact scoring is simple heuristic (no PageRank or graph centrality)
- Remediation is template-based (no AI assistance)

### 2.6 V1 NAPI Functions (Impact-Related)

```
analyze_reachability(options) → JsReachabilityResult        // includes path data
analyze_inverse_reachability(options) → JsInverseReachabilityResult
get_call_graph_callers(root_dir, target) → Vec<JsCallerInfo>  // direct callers
```

No dedicated NAPI functions for impact analysis, dead code, or coverage in v1.
These are TS-only operations.

### 2.7 V1 MCP Tools (Impact-Related)

- `drift_impact_analysis` — Change blast radius (TS implementation)
- `drift_callers` — Who calls this function (uses native SQLite when available)
- `drift_reachability` — Forward/inverse data reachability (includes path data)

### 2.8 V1 Feature Inventory (Exhaustive)

| # | Feature | V1 Behavior | V2 Status |
|---|---------|-------------|-----------|
| IA1 | Impact analysis (TS) | Reverse BFS, 4 risk levels, affected functions list | Ported → Rust with blast radius metrics (§5) |
| IA2 | Risk scoring | Heuristic: callers + entry points + sensitive + depth | Upgraded → 6-factor weighted scoring (§6) |
| IA3 | Affected functions list | Transitive callers as string[] | Upgraded → AffectedFunction with depth, type, metadata (§5) |
| IA4 | Affected data paths | DataPath[] through changed function | Upgraded → with taint status and sensitivity (§5) |
| IA5 | Dead code detection (TS) | calledBy.length == 0, 5 FP categories | Ported → Rust with 10 FP categories (§7) |
| IA6 | Dead code confidence | 'high'/'medium'/'low' strings | Upgraded → Bayesian posterior (§8) |
| IA7 | Dead code FP: entry points | HTTP handlers, CLI, main | Preserved + expanded (§7) |
| IA8 | Dead code FP: framework hooks | componentDidMount, setUp, etc. | Preserved + expanded to 12 frameworks (§7) |
| IA9 | Dead code FP: dynamic dispatch | reflection, eval, getattr | Preserved + evidence tracking (§7) |
| IA10 | Dead code FP: event handlers | on_, handle_, listener patterns | Preserved + expanded patterns (§7) |
| IA11 | Dead code FP: exported functions | May be used externally | Preserved (§7) |
| IA12 | Path finding (Rust + TS) | BFS with path tracking, multiple paths | Upgraded → BFS + Dijkstra + K-shortest (§9) |
| IA13 | Path sorting | By length (shortest first) | Upgraded → weighted scoring (§10) |
| IA14 | Coverage analysis (TS) | Call graph × test topology | Ported → Rust with field-level (§11) |
| IA15 | Field coverage | Table-level granularity | Upgraded → field-level (§11) |
| IA16 | Uncovered paths | DataPath[] without tests | Preserved + risk-weighted (§11) |
| IA17 | Sensitivity classifier (TS) | Pattern matching, 4 levels | Merged → Rust unified engine (§12) |
| IA18 | Impact scorer (TS) | Centrality + entry + sensitive | Upgraded → PageRank-inspired (§12) |
| IA19 | Remediation generator (TS) | Template-based suggestions | Preserved + AI-assisted (§12) |
| IA20 | NAPI: get_call_graph_callers | Direct callers only | Preserved + transitive option (§19) |
| IA21 | MCP: drift_impact_analysis | Change blast radius | Preserved + blast radius metrics (§20) |
| IA22 | MCP: drift_callers | Reverse caller lookup | Preserved (call graph scope) |
| IA23 | No blast radius metrics | Just affected function count | Added → BlastRadius struct (§5) |
| IA24 | No test coverage in impact | Impact doesn't consider test coverage | Added → covering_tests in blast radius (§5) |
| IA25 | No taint-aware impact | Impact doesn't consider taint flows | Added → affected_taint_flows (§5) |
| IA26 | No dead code in Rust | TS-only dead code detection | Added → Rust dead code engine (§7) |
| IA27 | No impact analysis in Rust | TS-only impact analysis | Added → Rust impact engine (§5) |
| IA28 | No coverage analysis in Rust | TS-only coverage analysis | Added → Rust coverage engine (§11) |
| IA29 | No weighted path scoring | All edges treated equally | Added → confidence × depth scoring (§10) |
| IA30 | No Dijkstra paths | BFS only (unweighted) | Added → Dijkstra weighted paths (§9) |
| IA31 | No K-shortest paths | Single BFS, multiple paths by chance | Added → Yen's K-shortest (§9) |
| IA32 | No cross-service impact | Single-service only | Added → API boundary tracking (§15) |
| IA33 | No git-based impact | No diff awareness | Added → git diff integration (§16) |
| IA34 | No incremental impact | Full recompute on graph change | Added → incremental invalidation (§14) |
| IA35 | No dead code FP: decorator handlers | Not detected | Added (§7) |
| IA36 | No dead code FP: interface impls | Not detected | Added (§7) |
| IA37 | No dead code FP: serialization hooks | Not detected | Added (§7) |
| IA38 | No dead code FP: plugin/extension points | Not detected | Added (§7) |
| IA39 | No dead code FP: conditional compilation | Not detected | Added (§7) |
| IA40 | No impact caching | Full recompute per query | Added → LRU cache (§14) |

**Coverage**: 40/40 v1 features accounted for. 0 features lost.



---

## 3. V2 Architecture — Unified Impact Intelligence Engine

### 3.1 Design Philosophy

V1's impact analysis is scattered across 5 TS files with no Rust implementation.
The dead code detector, path finder, coverage analyzer, and enrichment pipeline are
all separate TS modules that independently query the call graph. This creates 5 problems:

1. **No Rust performance**: Impact analysis, dead code detection, and path finding are
   all graph traversal algorithms that benefit enormously from Rust's zero-cost abstractions.
   TS adds GC pauses, object allocation overhead, and Map lookup costs.
2. **No unified risk model**: Impact scoring, dead code confidence, and coverage gaps
   each use different risk models. A unified engine can cross-reference: "this dead code
   candidate accesses sensitive data" or "this high-impact function has no test coverage."
3. **No taint awareness**: V1 impact analysis doesn't know about taint flows. A function
   change that breaks a sanitizer on a critical taint path is higher risk than one that
   affects only non-sensitive code.
4. **No incremental analysis**: Every impact query recomputes from scratch. With caching
   and incremental invalidation, repeated queries (common in IDE and CI) are near-instant.
5. **No git integration**: V1 can't answer "what's the blast radius of this PR?" without
   manual function identification. Git diff integration automates this.

V2 solves all five with a unified Rust engine that:
- Shares the call graph (petgraph StableGraph) with the reachability engine
- Integrates taint flow data into risk scoring
- Cross-references test topology for coverage-aware impact
- Caches results with call-graph-version-based invalidation
- Integrates with git2 for diff-based impact analysis

### 3.2 Engine Architecture

```rust
use std::sync::Arc;
use parking_lot::Mutex;
use lru::LruCache;
use rustc_hash::FxHashMap;

/// Unified impact intelligence engine.
/// Owns blast radius, dead code, path finding, coverage, and enrichment.
pub struct ImpactEngine {
    /// Shared reference to the reachability engine (owns the call graph).
    reachability: Arc<ReachabilityEngine>,

    /// Dead code detector (stateless, uses call graph from reachability).
    dead_code: DeadCodeDetector,

    /// Path finder (stateless, uses call graph from reachability).
    path_finder: PathFinder,

    /// Coverage analyzer (stateless, uses call graph + test topology).
    coverage: CoverageAnalyzer,

    /// Enrichment pipeline (impact scoring + remediation).
    enrichment: EnrichmentPipeline,

    /// LRU cache for impact results.
    cache: Mutex<LruCache<ImpactCacheKey, CachedImpactResult>>,

    /// Configuration.
    config: ImpactConfig,

    /// Event handler for downstream notifications.
    event_handler: Arc<dyn ImpactEventHandler>,
}

impl ImpactEngine {
    pub fn new(
        reachability: Arc<ReachabilityEngine>,
        config: ImpactConfig,
        event_handler: Arc<dyn ImpactEventHandler>,
    ) -> Self {
        let dead_code = DeadCodeDetector::new(Arc::clone(&reachability));
        let path_finder = PathFinder::new(Arc::clone(&reachability));
        let coverage = CoverageAnalyzer::new(Arc::clone(&reachability));
        let enrichment = EnrichmentPipeline::new(Arc::clone(&reachability));

        Self {
            reachability,
            dead_code,
            path_finder,
            coverage,
            enrichment,
            cache: Mutex::new(LruCache::new(
                std::num::NonZeroUsize::new(config.cache_size).unwrap()
            )),
            config,
            event_handler,
        }
    }

    /// Invalidate cache (called after call graph rebuild).
    pub fn invalidate_cache(&self) {
        self.cache.lock().clear();
        tracing::debug!("Impact cache invalidated");
    }
}
```

### 3.3 Configuration

```rust
/// Impact engine configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactConfig {
    /// LRU cache size for impact results. Default: 128.
    pub cache_size: usize,

    /// Default maximum reverse BFS depth for blast radius. Default: 50.
    pub default_max_depth: u32,

    /// Minimum dead code confidence to report. Default: 0.25.
    pub dead_code_min_confidence: f64,

    /// Maximum paths to return from path finder. Default: 10.
    pub default_max_paths: usize,

    /// Maximum path finding depth. Default: 30.
    pub path_max_depth: u32,

    /// Risk scoring weights (must sum to 1.0).
    pub risk_weights: RiskWeights,

    /// Whether to include taint flow data in impact results. Default: true.
    pub include_taint: bool,

    /// Whether to include test coverage data in impact results. Default: true.
    pub include_coverage: bool,

    /// Whether to generate remediation suggestions. Default: true.
    pub generate_remediations: bool,

    /// Git integration: path to .git directory. Default: auto-detect.
    pub git_dir: Option<String>,
}

/// Risk scoring weight configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskWeights {
    /// Weight for affected entry points. Default: 0.25.
    pub entry_points: f64,
    /// Weight for sensitive data paths. Default: 0.25.
    pub sensitive_paths: f64,
    /// Weight for transitive caller count. Default: 0.20.
    pub caller_count: f64,
    /// Weight for test coverage gaps. Default: 0.15.
    pub coverage_gaps: f64,
    /// Weight for unsanitized taint flows. Default: 0.10.
    pub taint_flows: f64,
    /// Weight for propagation depth. Default: 0.05.
    pub propagation_depth: f64,
}

impl Default for ImpactConfig {
    fn default() -> Self {
        Self {
            cache_size: 128,
            default_max_depth: 50,
            dead_code_min_confidence: 0.25,
            default_max_paths: 10,
            path_max_depth: 30,
            risk_weights: RiskWeights::default(),
            include_taint: true,
            include_coverage: true,
            generate_remediations: true,
            git_dir: None,
        }
    }
}

impl Default for RiskWeights {
    fn default() -> Self {
        Self {
            entry_points: 0.25,
            sensitive_paths: 0.25,
            caller_count: 0.20,
            coverage_gaps: 0.15,
            taint_flows: 0.10,
            propagation_depth: 0.05,
        }
    }
}
```

### 3.4 Relationship to Reachability Engine

The Impact Engine is a **pure consumer** of the reachability engine. It shares the
call graph via `Arc<ReachabilityEngine>` and delegates BFS traversal to the reachability
engine's forward/inverse methods. The impact engine adds:
- Reverse BFS with blast radius metric collection
- Multi-dimensional risk scoring
- Dead code detection (no-incoming-edge analysis)
- Path finding (BFS/Dijkstra/K-shortest)
- Coverage gap analysis (cross-referencing test topology)
- Enrichment (impact scoring + remediation)

This separation means the reachability engine can be used independently for security
queries, while the impact engine adds change-intelligence semantics on top.



---

## 4. Core Data Model

### 4.1 ImpactResult (Primary Output Type)

```rust
use serde::{Deserialize, Serialize};
use rustc_hash::FxHashMap;

/// Result of an impact analysis query.
/// Answers: "What breaks if I change this function?"
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

    /// Taint flows affected (security impact).
    /// Empty if taint analysis is disabled.
    pub affected_taint_flows: Vec<AffectedTaintFlow>,

    /// Blast radius metrics.
    pub blast_radius: BlastRadius,

    /// Multi-dimensional risk assessment.
    pub risk: RiskAssessment,

    /// Remediation suggestions (if enabled).
    pub remediations: Vec<RemediationSuggestion>,

    /// Timing and engine metadata.
    pub query_time_us: u64,
    pub from_cache: bool,
}

/// A function affected by the change, with impact metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AffectedFunction {
    /// Function identifier.
    pub function_id: String,
    /// Human-readable function name.
    pub function_name: String,
    /// File containing this function.
    pub file: String,
    /// Line number.
    pub line: u32,
    /// BFS depth from the changed function (1 = direct caller).
    pub depth: u32,
    /// Whether this function is an entry point.
    pub is_entry_point: bool,
    /// Whether this function is exported.
    pub is_exported: bool,
    /// Whether this function accesses sensitive data.
    pub accesses_sensitive_data: bool,
    /// Whether this function is covered by tests.
    pub is_tested: bool,
    /// Impact type: how this function is affected.
    pub impact_type: ImpactType,
}

/// How a function is affected by the change.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ImpactType {
    /// Direct caller of the changed function.
    DirectCaller,
    /// Transitive caller (calls a caller of the changed function).
    TransitiveCaller,
    /// Shares data access with the changed function.
    SharedDataAccess,
    /// On a taint flow path through the changed function.
    TaintFlowParticipant,
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
    /// Taint flows through the changed function.
    pub affected_taint_flows: usize,
    /// Test functions that cover the changed function.
    pub covering_tests: usize,
    /// Percentage of codebase affected (transitive_callers / total_functions).
    pub codebase_percentage: f64,
    /// Maximum depth of impact propagation.
    pub max_propagation_depth: u32,
    /// Affected functions by language.
    pub by_language: FxHashMap<String, usize>,
    /// Affected functions by file.
    pub by_file: FxHashMap<String, usize>,
}

/// A data path affected by the change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AffectedDataPath {
    /// The data access point.
    pub access: DataAccessPoint,
    /// Sensitivity level of this access.
    pub sensitivity: SensitivityLevel,
    /// The call path from entry point through changed function to data access.
    pub path: Vec<CallPathNode>,
    /// Whether this path has test coverage.
    pub is_tested: bool,
    /// Taint status of this path.
    pub taint_status: TaintStatus,
}

/// A taint flow affected by the change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AffectedTaintFlow {
    /// The taint flow.
    pub flow: TaintFlow,
    /// How the changed function participates in this flow.
    pub role: TaintFlowRole,
}

/// Role of the changed function in a taint flow.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TaintFlowRole {
    /// The changed function is a taint source.
    Source,
    /// The changed function is a taint sink.
    Sink,
    /// The changed function is a sanitizer.
    Sanitizer,
    /// The changed function is on the propagation path.
    Propagator,
}
```

### 4.2 RiskAssessment (Multi-Dimensional)

```rust
/// Multi-dimensional risk assessment for a function change.
/// Replaces v1's simple 'low'/'medium'/'high'/'critical' string.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    /// Overall risk level (derived from score).
    pub level: RiskLevel,

    /// Numeric risk score (0.0-100.0).
    pub score: f64,

    /// Individual factor scores.
    pub factors: RiskFactors,

    /// Human-readable risk summary.
    pub summary: String,

    /// Specific risk concerns (actionable).
    pub concerns: Vec<RiskConcern>,
}

/// Risk level for a function change.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    /// Low risk: few callers, no entry points, no sensitive data, good test coverage.
    Low,
    /// Medium risk: moderate callers or some entry points.
    Medium,
    /// High risk: many callers, entry points affected, or sensitive data paths.
    High,
    /// Critical risk: widespread impact, sensitive data, entry points, low test coverage.
    Critical,
}

/// Individual risk factor scores (each 0.0-1.0).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactors {
    /// Entry point impact (0.0 = no entry points, 1.0 = all entry points affected).
    pub entry_point_impact: f64,
    /// Sensitive data impact (0.0 = no sensitive data, 1.0 = critical data affected).
    pub sensitive_data_impact: f64,
    /// Caller breadth (0.0 = no callers, 1.0 = >5% of codebase affected).
    pub caller_breadth: f64,
    /// Coverage gap (0.0 = fully tested, 1.0 = no test coverage).
    pub coverage_gap: f64,
    /// Taint flow impact (0.0 = no taint flows, 1.0 = unsanitized critical flows).
    pub taint_flow_impact: f64,
    /// Propagation depth (0.0 = shallow, 1.0 = deep propagation chain).
    pub propagation_depth: f64,
}

/// A specific risk concern with actionable context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskConcern {
    /// Concern category.
    pub category: RiskConcernCategory,
    /// Human-readable description.
    pub description: String,
    /// Severity (1 = highest).
    pub severity: u8,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RiskConcernCategory {
    /// Entry point affected without test coverage.
    UntestedEntryPoint,
    /// Sensitive data path affected.
    SensitiveDataExposure,
    /// Taint sanitizer on affected path.
    SanitizerDisruption,
    /// High codebase percentage affected.
    WideBlastRadius,
    /// Deep propagation chain.
    DeepPropagation,
    /// No test coverage for affected paths.
    NoCoverage,
    /// Auth boundary on affected path.
    AuthBoundaryImpact,
    /// Cross-service impact.
    CrossServiceImpact,
}
```



---

## 5. Blast Radius Engine (Reverse BFS + Metrics)

### 5.1 Architecture

The blast radius engine is the core of impact analysis. It performs reverse BFS from
the changed function, collecting all transitive callers while simultaneously computing
blast radius metrics, test coverage, taint flow participation, and sensitive data access.

This is a significant upgrade from v1's simple `affectedFunctions: string[]` — v2
produces a full `BlastRadius` struct with 10 metrics and per-function impact metadata.

### 5.2 Implementation

```rust
impl ImpactEngine {
    /// Analyze the impact of changing a function.
    /// Algorithm: Reverse BFS from changed function, collecting all callers transitively.
    /// Simultaneously computes blast radius metrics, test coverage, taint participation.
    ///
    /// Complexity: O(V + E) where V = reachable callers, E = traversed reverse edges.
    /// Bounded by max_depth (default 50).
    #[tracing::instrument(
        skip(self),
        fields(function_id = %function_id, max_depth = self.config.default_max_depth)
    )]
    pub fn analyze_impact(
        &self,
        function_id: &str,
        options: Option<&ImpactOptions>,
    ) -> Result<ImpactResult, ImpactError> {
        let start = std::time::Instant::now();

        // Check cache
        let cache_key = ImpactCacheKey::Impact {
            function_id: function_id.to_string(),
        };
        if let Some(cached) = self.cache.lock().get(&cache_key) {
            self.event_handler.on_cache_hit(&cache_key);
            return Ok(cached.impact.clone());
        }
        self.event_handler.on_cache_miss(&cache_key);

        let graph = self.reachability.graph()
            .ok_or(ImpactError::GraphNotLoaded)?;

        let max_depth = options
            .and_then(|o| o.max_depth)
            .unwrap_or(self.config.default_max_depth);

        let start_node = graph.find_function_by_id(function_id)
            .map_err(|_| ImpactError::FunctionNotFound(function_id.to_string()))?;

        // Step 1: Reverse BFS to find all affected functions
        let mut visited: FxHashSet<NodeIndex> = FxHashSet::default();
        let mut queue: VecDeque<(NodeIndex, u32)> = VecDeque::new();
        let mut affected: Vec<AffectedFunction> = Vec::new();
        let mut entry_points: Vec<EntryPointInfo> = Vec::new();
        let mut max_depth_reached: u32 = 0;
        let mut by_language: FxHashMap<String, usize> = FxHashMap::default();
        let mut by_file: FxHashMap<String, usize> = FxHashMap::default();

        queue.push_back((start_node, 0));
        visited.insert(start_node);

        while let Some((node, depth)) = queue.pop_front() {
            if depth > max_depth {
                continue;
            }
            max_depth_reached = max_depth_reached.max(depth);
            let func = &graph.graph[node];

            // Record affected function (skip the changed function itself)
            if node != start_node {
                let func_id = graph.interner.resolve(&func.id).to_string();
                let func_file = graph.interner.resolve(&func.file).to_string();
                let func_lang = func.language.to_string();

                let is_tested = self.is_function_tested(graph, node);
                let accesses_sensitive = self.reachability
                    .has_sensitive_access(graph, node);

                affected.push(AffectedFunction {
                    function_id: func_id.clone(),
                    function_name: graph.get_function_name(node),
                    file: func_file.clone(),
                    line: func.line,
                    depth,
                    is_entry_point: func.is_entry_point,
                    is_exported: func.is_exported,
                    accesses_sensitive_data: accesses_sensitive,
                    is_tested,
                    impact_type: if depth == 1 {
                        ImpactType::DirectCaller
                    } else {
                        ImpactType::TransitiveCaller
                    },
                });

                *by_language.entry(func_lang).or_insert(0) += 1;
                *by_file.entry(func_file).or_insert(0) += 1;
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
            graph, &visited, start_node
        );

        // Step 3: Find affected taint flows (if enabled)
        let affected_taint_flows = if self.config.include_taint {
            self.find_affected_taint_flows(graph, &visited, start_node)
        } else {
            Vec::new()
        };

        // Step 4: Compute blast radius
        let total_functions = graph.graph.node_count();
        let direct_callers = graph.graph
            .edges_directed(start_node, Direction::Incoming).count();
        let covering_tests = self.count_covering_tests(graph, start_node);

        let blast_radius = BlastRadius {
            direct_callers,
            transitive_callers: affected.len(),
            affected_entry_points: entry_points.len(),
            affected_sensitive_paths: affected_data_paths.iter()
                .filter(|p| p.sensitivity >= SensitivityLevel::Medium).count(),
            affected_taint_flows: affected_taint_flows.len(),
            covering_tests,
            codebase_percentage: if total_functions > 0 {
                affected.len() as f64 / total_functions as f64
            } else {
                0.0
            },
            max_propagation_depth: max_depth_reached,
            by_language,
            by_file,
        };

        // Step 5: Compute risk assessment
        let risk = self.compute_risk_assessment(&blast_radius, &affected_data_paths,
            &affected_taint_flows, &affected);

        // Step 6: Generate remediations (if enabled)
        let remediations = if self.config.generate_remediations {
            self.enrichment.generate_impact_remediations(
                &blast_radius, &risk, &affected_data_paths, &affected_taint_flows
            )
        } else {
            Vec::new()
        };

        let result = ImpactResult {
            changed_function: graph.get_function_info(start_node),
            affected_functions: affected,
            affected_entry_points: entry_points,
            affected_data_paths,
            affected_taint_flows,
            blast_radius,
            risk,
            remediations,
            query_time_us: start.elapsed().as_micros() as u64,
            from_cache: false,
        };

        // Cache result
        self.cache.lock().put(cache_key, CachedImpactResult {
            impact: result.clone(),
            computed_at: std::time::Instant::now(),
        });

        // Emit event
        self.event_handler.on_impact_analysis(function_id, &result);

        tracing::info!(
            direct_callers = result.blast_radius.direct_callers,
            transitive_callers = result.blast_radius.transitive_callers,
            entry_points = result.blast_radius.affected_entry_points,
            sensitive_paths = result.blast_radius.affected_sensitive_paths,
            risk_level = ?result.risk.level,
            risk_score = result.risk.score,
            query_time_us = result.query_time_us,
            "Impact analysis complete"
        );

        Ok(result)
    }

    /// Find data paths affected by the change.
    /// A data path is affected if any function on the path is in the visited set.
    fn find_affected_data_paths(
        &self,
        graph: &CallGraph,
        affected_nodes: &FxHashSet<NodeIndex>,
        changed_node: NodeIndex,
    ) -> Vec<AffectedDataPath> {
        let mut paths: Vec<AffectedDataPath> = Vec::new();

        // Check data access at the changed function itself
        let direct_access = graph.get_data_access(changed_node);
        for access in direct_access {
            let sensitivity = self.reachability.sensitivity().classify_access(&access);
            paths.push(AffectedDataPath {
                access,
                sensitivity,
                path: vec![graph.node_to_path_node(changed_node)],
                is_tested: self.is_function_tested(graph, changed_node),
                taint_status: TaintStatus::NotAnalyzed,
            });
        }

        // Check data access at affected functions
        for &node in affected_nodes {
            let accesses = graph.get_data_access(node);
            for access in accesses {
                let sensitivity = self.reachability.sensitivity().classify_access(&access);
                if sensitivity >= SensitivityLevel::Medium {
                    paths.push(AffectedDataPath {
                        access,
                        sensitivity,
                        path: vec![
                            graph.node_to_path_node(node),
                            graph.node_to_path_node(changed_node),
                        ],
                        is_tested: self.is_function_tested(graph, node),
                        taint_status: TaintStatus::NotAnalyzed,
                    });
                }
            }
        }

        paths.sort_by(|a, b| b.sensitivity.cmp(&a.sensitivity));
        paths
    }

    /// Find taint flows that pass through the changed function or affected functions.
    fn find_affected_taint_flows(
        &self,
        graph: &CallGraph,
        affected_nodes: &FxHashSet<NodeIndex>,
        changed_node: NodeIndex,
    ) -> Vec<AffectedTaintFlow> {
        let mut flows: Vec<AffectedTaintFlow> = Vec::new();

        // Query taint flows from the reachability engine's taint registry
        if let Some(taint_registry) = self.reachability.taint_registry() {
            let changed_id = graph.interner.resolve(
                &graph.graph[changed_node].id
            ).to_string();

            // Check if changed function is a source, sink, or sanitizer
            if taint_registry.is_source(&changed_id) {
                // All flows originating from this source are affected
                for flow in taint_registry.flows_from_source(&changed_id) {
                    flows.push(AffectedTaintFlow {
                        flow,
                        role: TaintFlowRole::Source,
                    });
                }
            }

            if taint_registry.is_sink(&changed_id) {
                for flow in taint_registry.flows_to_sink(&changed_id) {
                    flows.push(AffectedTaintFlow {
                        flow,
                        role: TaintFlowRole::Sink,
                    });
                }
            }

            if taint_registry.is_sanitizer(&changed_id) {
                // CRITICAL: changing a sanitizer can break security guarantees
                for flow in taint_registry.flows_through_sanitizer(&changed_id) {
                    flows.push(AffectedTaintFlow {
                        flow,
                        role: TaintFlowRole::Sanitizer,
                    });
                }
            }
        }

        flows
    }
}
```

### 5.3 ImpactOptions

```rust
/// Options for impact analysis queries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactOptions {
    /// Maximum reverse BFS depth. None = use config default.
    pub max_depth: Option<u32>,
    /// Include test coverage data. Default: true.
    pub include_tests: Option<bool>,
    /// Include taint flow data. Default: true.
    pub include_taint: Option<bool>,
    /// Generate remediation suggestions. Default: true.
    pub generate_remediations: Option<bool>,
    /// Filter affected functions by file pattern.
    pub file_filter: Option<String>,
    /// Minimum risk level to include in results.
    pub min_risk: Option<RiskLevel>,
}
```



---

## 6. Multi-Dimensional Risk Scoring

### 6.1 Architecture

V1 uses a simple heuristic: count affected functions, check for entry points, check for
sensitive data, check depth. This produces a string ('low'/'medium'/'high'/'critical')
with no numeric score and no factor breakdown.

V2 replaces this with a 6-factor weighted scoring model inspired by PageRank centrality
and Bayesian risk assessment. Each factor produces a normalized score (0.0-1.0), and the
final score is a weighted sum. The weights are configurable per-project.

### 6.2 Scoring Algorithm

```rust
impl ImpactEngine {
    /// Compute multi-dimensional risk assessment.
    /// Each factor is normalized to 0.0-1.0, then weighted and summed.
    /// Final score is 0.0-100.0.
    fn compute_risk_assessment(
        &self,
        blast_radius: &BlastRadius,
        data_paths: &[AffectedDataPath],
        taint_flows: &[AffectedTaintFlow],
        affected: &[AffectedFunction],
    ) -> RiskAssessment {
        let w = &self.config.risk_weights;

        // Factor 1: Entry point impact (0.0-1.0)
        // Sigmoid normalization: 1 entry point = 0.3, 5 = 0.7, 10+ = 0.95
        let entry_point_impact = sigmoid_normalize(
            blast_radius.affected_entry_points as f64, 5.0, 2.0
        );

        // Factor 2: Sensitive data impact (0.0-1.0)
        // Based on highest sensitivity level found
        let sensitive_data_impact = if data_paths.iter()
            .any(|p| p.sensitivity == SensitivityLevel::Critical)
        {
            1.0
        } else if data_paths.iter()
            .any(|p| p.sensitivity == SensitivityLevel::High)
        {
            0.75
        } else if data_paths.iter()
            .any(|p| p.sensitivity == SensitivityLevel::Medium)
        {
            0.40
        } else {
            0.0
        };

        // Factor 3: Caller breadth (0.0-1.0)
        // Sigmoid: 1% codebase = 0.3, 5% = 0.7, 10%+ = 0.95
        let caller_breadth = sigmoid_normalize(
            blast_radius.codebase_percentage * 100.0, 5.0, 2.0
        );

        // Factor 4: Coverage gap (0.0-1.0)
        // Percentage of affected functions without test coverage
        let untested_count = affected.iter()
            .filter(|f| !f.is_tested).count();
        let coverage_gap = if affected.is_empty() {
            0.0
        } else {
            untested_count as f64 / affected.len() as f64
        };

        // Factor 5: Taint flow impact (0.0-1.0)
        // Sanitizer disruption is the highest risk
        let taint_flow_impact = if taint_flows.iter()
            .any(|f| f.role == TaintFlowRole::Sanitizer)
        {
            1.0  // Changing a sanitizer can break security guarantees
        } else if taint_flows.iter()
            .any(|f| !f.flow.is_sanitized)
        {
            0.80  // Unsanitized flows through changed function
        } else if !taint_flows.is_empty() {
            0.30  // Sanitized flows (lower risk)
        } else {
            0.0
        };

        // Factor 6: Propagation depth (0.0-1.0)
        // Sigmoid: depth 5 = 0.3, depth 15 = 0.7, depth 30+ = 0.95
        let propagation_depth = sigmoid_normalize(
            blast_radius.max_propagation_depth as f64, 15.0, 5.0
        );

        // Weighted sum → 0.0-100.0
        let score = (
            entry_point_impact * w.entry_points
            + sensitive_data_impact * w.sensitive_paths
            + caller_breadth * w.caller_count
            + coverage_gap * w.coverage_gaps
            + taint_flow_impact * w.taint_flows
            + propagation_depth * w.propagation_depth
        ) * 100.0;

        // Map score to risk level
        let level = match score {
            s if s >= 75.0 => RiskLevel::Critical,
            s if s >= 50.0 => RiskLevel::High,
            s if s >= 25.0 => RiskLevel::Medium,
            _ => RiskLevel::Low,
        };

        // Generate concerns
        let concerns = self.generate_risk_concerns(
            &RiskFactors {
                entry_point_impact,
                sensitive_data_impact,
                caller_breadth,
                coverage_gap,
                taint_flow_impact,
                propagation_depth,
            },
            blast_radius,
            taint_flows,
        );

        // Generate summary
        let summary = self.generate_risk_summary(level, blast_radius, &concerns);

        RiskAssessment {
            level,
            score,
            factors: RiskFactors {
                entry_point_impact,
                sensitive_data_impact,
                caller_breadth,
                coverage_gap,
                taint_flow_impact,
                propagation_depth,
            },
            summary,
            concerns,
        }
    }

    /// Generate specific risk concerns based on factor scores.
    fn generate_risk_concerns(
        &self,
        factors: &RiskFactors,
        blast_radius: &BlastRadius,
        taint_flows: &[AffectedTaintFlow],
    ) -> Vec<RiskConcern> {
        let mut concerns: Vec<RiskConcern> = Vec::new();

        if factors.taint_flow_impact >= 0.80 {
            let sanitizer_count = taint_flows.iter()
                .filter(|f| f.role == TaintFlowRole::Sanitizer).count();
            if sanitizer_count > 0 {
                concerns.push(RiskConcern {
                    category: RiskConcernCategory::SanitizerDisruption,
                    description: format!(
                        "This function is a sanitizer on {} taint flow(s). \
                         Changing it could break security guarantees and allow \
                         unsanitized data to reach dangerous sinks.",
                        sanitizer_count
                    ),
                    severity: 1,
                });
            }
        }

        if factors.sensitive_data_impact >= 0.75 {
            concerns.push(RiskConcern {
                category: RiskConcernCategory::SensitiveDataExposure,
                description: format!(
                    "{} sensitive data path(s) pass through this function. \
                     Changes could affect data handling for credentials, PII, \
                     or financial data.",
                    blast_radius.affected_sensitive_paths
                ),
                severity: 1,
            });
        }

        if factors.coverage_gap >= 0.70 {
            concerns.push(RiskConcern {
                category: RiskConcernCategory::NoCoverage,
                description: format!(
                    "{:.0}% of affected functions lack test coverage. \
                     Changes may introduce regressions without detection.",
                    factors.coverage_gap * 100.0
                ),
                severity: 2,
            });
        }

        if factors.entry_point_impact >= 0.50 {
            concerns.push(RiskConcern {
                category: RiskConcernCategory::UntestedEntryPoint,
                description: format!(
                    "{} API entry point(s) affected. Changes may alter \
                     external-facing behavior.",
                    blast_radius.affected_entry_points
                ),
                severity: 2,
            });
        }

        if factors.caller_breadth >= 0.70 {
            concerns.push(RiskConcern {
                category: RiskConcernCategory::WideBlastRadius,
                description: format!(
                    "{:.1}% of the codebase is transitively affected ({} functions). \
                     This is a high-leverage change point.",
                    blast_radius.codebase_percentage * 100.0,
                    blast_radius.transitive_callers
                ),
                severity: 2,
            });
        }

        if factors.propagation_depth >= 0.70 {
            concerns.push(RiskConcern {
                category: RiskConcernCategory::DeepPropagation,
                description: format!(
                    "Impact propagates {} levels deep through the call graph. \
                     Deep changes are harder to reason about.",
                    blast_radius.max_propagation_depth
                ),
                severity: 3,
            });
        }

        concerns.sort_by_key(|c| c.severity);
        concerns
    }
}

/// Sigmoid normalization: maps a value to 0.0-1.0 with configurable midpoint and steepness.
/// sigmoid(x) = 1 / (1 + e^(-(x - midpoint) / steepness))
fn sigmoid_normalize(value: f64, midpoint: f64, steepness: f64) -> f64 {
    1.0 / (1.0 + (-((value - midpoint) / steepness)).exp())
}
```

### 6.3 Risk Level Thresholds

| Score Range | Risk Level | Interpretation |
|-------------|-----------|----------------|
| 75-100 | Critical | Widespread impact, sensitive data, low coverage, taint disruption |
| 50-74 | High | Significant impact, entry points affected, or sensitive data |
| 25-49 | Medium | Moderate impact, some callers, partial coverage |
| 0-24 | Low | Minimal impact, few callers, good coverage |

### 6.4 Why Sigmoid Normalization

Linear normalization (value / max) is brittle — it depends on knowing the maximum.
Sigmoid normalization is self-scaling: it maps any positive value to 0.0-1.0 with a
configurable midpoint (where the score is 0.5) and steepness (how quickly it approaches
1.0). This means:
- 1 entry point → ~0.15 (low concern)
- 5 entry points → ~0.50 (moderate concern)
- 20 entry points → ~0.98 (high concern)

The midpoint and steepness are tuned per-factor based on empirical analysis of real
codebases. They can be overridden in `drift.toml` for project-specific calibration.



---

## 7. Dead Code Detection Engine (10 False Positive Categories)

### 7.1 Architecture

Dead code detection identifies functions that are never called. The core algorithm is
simple: find functions with no incoming edges in the call graph. The hard part is
false positive reduction — many functions with no callers are intentionally uncalled
(entry points, framework hooks, exported APIs, etc.).

V1 handles 5 false positive categories. V2 expands to 10, adds evidence tracking for
each category, and introduces Bayesian confidence scoring (§8).

### 7.2 Implementation

```rust
/// Dead code detection engine.
pub struct DeadCodeDetector {
    reachability: Arc<ReachabilityEngine>,
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

    /// Reasons this might be a false positive, with evidence.
    pub false_positive_reasons: Vec<FalsePositiveReason>,

    /// Lines of code in this function (impact of removal).
    pub lines_of_code: u32,

    /// Whether this function accesses sensitive data (removal risk).
    pub accesses_sensitive_data: bool,

    /// Whether this function is on a taint flow path.
    pub on_taint_path: bool,

    /// Estimated effort to safely remove (based on LOC + complexity).
    pub removal_effort: RemovalEffort,

    /// Suggested action.
    pub suggested_action: DeadCodeAction,
}

/// Reasons a dead code candidate might be a false positive.
/// V2 expands from v1's 5 categories to 10.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FalsePositiveReason {
    /// Function is an entry point (HTTP handler, CLI command, main).
    /// V1: ✓ (preserved)
    EntryPoint {
        entry_type: EntryPointType,
        evidence: String,
    },

    /// Function is a framework lifecycle hook.
    /// V1: ✓ (preserved, expanded to 12 frameworks)
    FrameworkHook {
        framework: String,
        hook_name: String,
        confidence: f64,
    },

    /// Function may be called via dynamic dispatch (reflection, eval, getattr).
    /// V1: ✓ (preserved, evidence tracking added)
    DynamicDispatch {
        dispatch_type: DynamicDispatchType,
        evidence: String,
    },

    /// Function is an event handler (called via event system, signals).
    /// V1: ✓ (preserved, expanded patterns)
    EventHandler {
        event_pattern: String,
        framework: Option<String>,
    },

    /// Function is exported (may be used by external packages).
    /// V1: ✓ (preserved)
    Exported {
        export_type: ExportType,
    },

    /// Function is a test function or test utility.
    /// V1: ✓ (preserved, expanded patterns)
    TestFunction {
        test_framework: Option<String>,
    },

    /// Function is a decorator/annotation handler.
    /// V2: NEW — decorators are invoked by the framework, not by user code.
    DecoratorHandler {
        decorator: String,
        framework: String,
    },

    /// Function matches a known interface/trait implementation pattern.
    /// V2: NEW — trait impls are called via vtable dispatch, not direct calls.
    InterfaceImplementation {
        interface_name: String,
        language_pattern: String,
    },

    /// Function is a serialization/deserialization hook.
    /// V2: NEW — serde, Jackson, Gson hooks are called by the framework.
    SerializationHook {
        framework: String,
        hook_type: String,
    },

    /// Function is a plugin/extension point.
    /// V2: NEW — plugin systems load functions dynamically.
    PluginExtensionPoint {
        plugin_system: String,
        evidence: String,
    },

    /// Function is conditionally compiled (cfg, #ifdef, platform-specific).
    /// V2: NEW — may be dead on current platform but alive on others.
    ConditionalCompilation {
        condition: String,
        platforms: Vec<String>,
    },
}

/// Types of dynamic dispatch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DynamicDispatchType {
    Reflection,       // Java getMethod, C# GetType
    Eval,             // JavaScript eval, Python exec
    Getattr,          // Python getattr, Ruby send
    FunctionPointer,  // C/C++ function pointers, Rust fn()
    StringDispatch,   // dispatch[name](), handlers[event]()
    DependencyInjection, // Spring @Autowired, NestJS @Inject
}

/// Types of exports.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ExportType {
    NamedExport,      // export function foo()
    DefaultExport,    // export default class
    ModuleExport,     // module.exports
    PublicApi,        // pub fn (Rust), public (Java/C#)
    PackageExport,    // Listed in package.json exports
}

/// Suggested action for dead code.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum DeadCodeAction {
    /// Safe to remove — high confidence dead code.
    Remove,
    /// Review before removing — moderate confidence.
    Review,
    /// Likely false positive — keep but verify.
    Keep,
    /// Deprecate — mark as deprecated, remove in next major version.
    Deprecate,
}

/// Estimated effort to remove dead code.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum RemovalEffort {
    Trivial,    // < 10 LOC, no dependencies
    Low,        // 10-50 LOC, few dependencies
    Medium,     // 50-200 LOC, some dependencies
    High,       // > 200 LOC or complex dependencies
}

impl DeadCodeDetector {
    pub fn new(reachability: Arc<ReachabilityEngine>) -> Self {
        Self { reachability }
    }

    /// Detect dead code in the call graph.
    /// Algorithm: Find all functions with no incoming edges that are not
    /// entry points or known false positive categories.
    #[tracing::instrument(skip(self))]
    pub fn detect(
        &self,
        options: Option<&DeadCodeOptions>,
    ) -> Result<Vec<DeadCodeCandidate>, ImpactError> {
        let start = std::time::Instant::now();
        let graph = self.reachability.graph()
            .ok_or(ImpactError::GraphNotLoaded)?;

        let min_confidence = options
            .and_then(|o| o.min_confidence)
            .unwrap_or(0.25);

        let mut candidates: Vec<DeadCodeCandidate> = Vec::new();

        for node_idx in graph.graph.node_indices() {
            let func = &graph.graph[node_idx];

            // Skip if function has callers
            let caller_count = graph.graph
                .edges_directed(node_idx, Direction::Incoming).count();
            if caller_count > 0 {
                continue;
            }

            // Collect false positive reasons with evidence
            let fp_reasons = self.collect_false_positive_reasons(graph, node_idx);

            // Compute confidence using Bayesian model (§8)
            let confidence = self.compute_dead_code_confidence(&fp_reasons, graph, node_idx);

            // Skip below minimum confidence
            if confidence < min_confidence {
                continue;
            }

            // Apply file filter if specified
            let func_file = graph.interner.resolve(&func.file).to_string();
            if let Some(opts) = options {
                if let Some(ref filter) = opts.file_filter {
                    if !func_file.contains(filter.as_str()) {
                        continue;
                    }
                }
            }

            let func_name = graph.interner.resolve(&func.id).to_string();
            let loc = func.end_line.saturating_sub(func.line);
            let accesses_sensitive = self.reachability.has_sensitive_access(graph, node_idx);
            let on_taint = self.is_on_taint_path(graph, node_idx);

            let removal_effort = match loc {
                0..=10 => RemovalEffort::Trivial,
                11..=50 => RemovalEffort::Low,
                51..=200 => RemovalEffort::Medium,
                _ => RemovalEffort::High,
            };

            let suggested_action = if confidence >= 0.80 && !accesses_sensitive {
                DeadCodeAction::Remove
            } else if confidence >= 0.50 {
                DeadCodeAction::Review
            } else if confidence >= 0.25 {
                DeadCodeAction::Deprecate
            } else {
                DeadCodeAction::Keep
            };

            candidates.push(DeadCodeCandidate {
                function_id: func_name,
                function_name: graph.get_function_name(node_idx),
                file: func_file,
                line: func.line,
                end_line: func.end_line,
                language: func.language.to_string(),
                confidence,
                false_positive_reasons: fp_reasons,
                lines_of_code: loc,
                accesses_sensitive_data: accesses_sensitive,
                on_taint_path: on_taint,
                removal_effort,
                suggested_action,
            });
        }

        // Sort by confidence (highest first), then by LOC (largest first)
        candidates.sort_by(|a, b| {
            b.confidence.partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(b.lines_of_code.cmp(&a.lines_of_code))
        });

        tracing::info!(
            total_functions = graph.graph.node_count(),
            candidates = candidates.len(),
            high_confidence = candidates.iter().filter(|c| c.confidence >= 0.80).count(),
            query_time_us = start.elapsed().as_micros(),
            "Dead code detection complete"
        );

        Ok(candidates)
    }

    /// Collect all false positive reasons for a function with evidence.
    fn collect_false_positive_reasons(
        &self,
        graph: &CallGraph,
        node: NodeIndex,
    ) -> Vec<FalsePositiveReason> {
        let mut reasons: Vec<FalsePositiveReason> = Vec::new();
        let func = &graph.graph[node];
        let name = graph.get_function_name(node);
        let name_lower = name.to_lowercase();

        // FP1: Entry point
        if func.is_entry_point {
            reasons.push(FalsePositiveReason::EntryPoint {
                entry_type: graph.get_entry_type(node),
                evidence: format!("Detected as {:?} entry point", graph.get_entry_type(node)),
            });
        }

        // FP2: Exported
        if func.is_exported {
            reasons.push(FalsePositiveReason::Exported {
                export_type: graph.get_export_type(node),
            });
        }

        // FP3: Framework hook (12 frameworks)
        if let Some(hook) = self.detect_framework_hook(graph, node) {
            reasons.push(hook);
        }

        // FP4: Event handler
        if let Some(event) = self.detect_event_handler(graph, node) {
            reasons.push(event);
        }

        // FP5: Test function
        if self.is_test_function(graph, node) {
            reasons.push(FalsePositiveReason::TestFunction {
                test_framework: self.detect_test_framework(graph, node),
            });
        }

        // FP6: Dynamic dispatch
        if let Some(dispatch) = self.detect_dynamic_dispatch(graph, node) {
            reasons.push(dispatch);
        }

        // FP7: Decorator handler (NEW in v2)
        if let Some(decorator) = self.detect_decorator_handler(graph, node) {
            reasons.push(decorator);
        }

        // FP8: Interface implementation (NEW in v2)
        if let Some(iface) = self.detect_interface_impl(graph, node) {
            reasons.push(iface);
        }

        // FP9: Serialization hook (NEW in v2)
        if let Some(ser) = self.detect_serialization_hook(graph, node) {
            reasons.push(ser);
        }

        // FP10: Plugin/extension point (NEW in v2)
        if let Some(plugin) = self.detect_plugin_extension(graph, node) {
            reasons.push(plugin);
        }

        // FP11: Conditional compilation (NEW in v2)
        if let Some(cond) = self.detect_conditional_compilation(graph, node) {
            reasons.push(cond);
        }

        reasons
    }
}
```

### 7.3 Framework Hook Detection (12 Frameworks)

```rust
impl DeadCodeDetector {
    /// Framework hook detection patterns.
    /// Expanded from v1's 7 frameworks to 12.
    fn detect_framework_hook(
        &self,
        graph: &CallGraph,
        node: NodeIndex,
    ) -> Option<FalsePositiveReason> {
        let name = graph.get_function_name(node).to_lowercase();
        let hooks: &[(&str, &[&str])] = &[
            // Frontend frameworks
            ("react", &["componentdidmount", "componentwillunmount", "render",
                        "getderivedstatefromprops", "shouldcomponentupdate",
                        "componentdidupdate", "getsnapshotbeforeupdate",
                        "componentdidcatch", "getderivedstatefromerror"]),
            ("vue", &["mounted", "created", "beforedestroy", "computed", "watch",
                      "beforecreate", "beforemount", "updated", "beforeupdate",
                      "activated", "deactivated", "errorcaptured"]),
            ("angular", &["ngoninit", "ngondestroy", "ngonchanges", "ngafterviewinit",
                         "ngdocheck", "ngaftercontentinit", "ngaftercontentchecked",
                         "ngafterviewchecked"]),
            ("svelte", &["onmount", "ondestroy", "beforeupdate", "afterupdate"]),

            // Backend frameworks
            ("django", &["setup", "teardown", "setuptestdata", "get_queryset",
                        "get_context_data", "get_object", "form_valid",
                        "get_serializer_class", "perform_create"]),
            ("spring", &["init", "destroy", "afterpropertiesset", "postconstruct",
                        "predestroy", "onstart", "onstop", "onapplicationevent"]),
            ("express", &["use", "listen", "configure"]),
            ("fastapi", &["startup", "shutdown", "on_event"]),
            ("nestjs", &["onmoduleinit", "onmoduledestroy", "onapplicationbootstrap",
                        "onapplicationshutdown"]),

            // Testing frameworks
            ("pytest", &["setup_method", "teardown_method", "setup_class",
                        "teardown_class", "setup_module", "teardown_module",
                        "conftest", "fixture"]),
            ("junit", &["setup", "teardown", "beforeeach", "aftereach",
                       "beforeall", "afterall", "beforeclass", "afterclass"]),
            ("jest", &["beforeeach", "aftereach", "beforeall", "afterall",
                      "describe", "it", "test"]),
        ];

        for (framework, patterns) in hooks {
            if patterns.iter().any(|p| name.contains(p)) {
                return Some(FalsePositiveReason::FrameworkHook {
                    framework: framework.to_string(),
                    hook_name: name,
                    confidence: 0.85,
                });
            }
        }

        // Check decorators for framework hooks
        if let Some(decorators) = graph.get_decorators_for_node(node) {
            let hook_decorators = [
                ("spring", &["postconstruct", "predestroy", "eventlistener",
                            "scheduled", "async"][..]),
                ("django", &["receiver", "register"][..]),
                ("fastapi", &["on_event"][..]),
                ("nestjs", &["onmoduleinit", "cron", "interval"][..]),
            ];

            for (framework, patterns) in &hook_decorators {
                for dec in &decorators {
                    let dec_lower = dec.to_lowercase();
                    if patterns.iter().any(|p| dec_lower.contains(p)) {
                        return Some(FalsePositiveReason::FrameworkHook {
                            framework: framework.to_string(),
                            hook_name: dec.clone(),
                            confidence: 0.90,
                        });
                    }
                }
            }
        }

        None
    }

    /// Interface/trait implementation detection.
    /// These functions are called via vtable dispatch, not direct calls.
    fn detect_interface_impl(
        &self,
        graph: &CallGraph,
        node: NodeIndex,
    ) -> Option<FalsePositiveReason> {
        let name = graph.get_function_name(node);
        let lang = graph.graph[node].language;

        // Rust trait implementations
        let rust_traits = [
            ("Display", &["fmt"][..]),
            ("Debug", &["fmt"]),
            ("Clone", &["clone"]),
            ("Default", &["default"]),
            ("Drop", &["drop"]),
            ("Iterator", &["next"]),
            ("From", &["from"]),
            ("Into", &["into"]),
            ("Serialize", &["serialize"]),
            ("Deserialize", &["deserialize"]),
            ("Hash", &["hash"]),
            ("PartialEq", &["eq"]),
            ("Ord", &["cmp"]),
        ];

        // Java/C# interface implementations
        let java_interfaces = [
            ("Object", &["toString", "equals", "hashCode", "clone"][..]),
            ("Comparable", &["compareTo"]),
            ("Serializable", &["readObject", "writeObject", "readResolve"]),
            ("Iterable", &["iterator"]),
            ("AutoCloseable", &["close"]),
            ("Runnable", &["run"]),
            ("Callable", &["call"]),
        ];

        // Python dunder methods
        let python_dunders = [
            "__str__", "__repr__", "__eq__", "__hash__", "__lt__", "__le__",
            "__gt__", "__ge__", "__len__", "__iter__", "__next__", "__enter__",
            "__exit__", "__call__", "__getattr__", "__setattr__", "__delattr__",
            "__getitem__", "__setitem__", "__contains__", "__add__", "__sub__",
            "__mul__", "__truediv__", "__init__", "__del__", "__new__",
        ];

        let patterns: &[(&str, &[&str])] = match lang {
            Language::Rust => &rust_traits.map(|(iface, methods)| (iface, methods)),
            Language::Java | Language::CSharp => &java_interfaces,
            _ => &[],
        };

        for (iface, methods) in patterns {
            if methods.iter().any(|m| name == *m) {
                return Some(FalsePositiveReason::InterfaceImplementation {
                    interface_name: iface.to_string(),
                    language_pattern: format!("{}::{}", iface, name),
                });
            }
        }

        // Python dunder methods
        if matches!(lang, Language::Python) && python_dunders.contains(&name.as_str()) {
            return Some(FalsePositiveReason::InterfaceImplementation {
                interface_name: "Python dunder".to_string(),
                language_pattern: name.to_string(),
            });
        }

        None
    }

    /// Serialization hook detection.
    fn detect_serialization_hook(
        &self,
        graph: &CallGraph,
        node: NodeIndex,
    ) -> Option<FalsePositiveReason> {
        let name = graph.get_function_name(node).to_lowercase();
        let ser_hooks = [
            ("serde", &["serialize", "deserialize", "visit_", "expecting"][..]),
            ("jackson", &["serialize", "deserialize", "getserializer"]),
            ("gson", &["tojson", "fromjson", "typeadapter"]),
            ("pydantic", &["validator", "root_validator", "model_validator",
                          "field_validator", "model_serializer"]),
            ("marshmallow", &["pre_load", "post_load", "pre_dump", "post_dump"]),
            ("json.net", &["readjson", "writejson", "canconvert"]),
        ];

        for (framework, patterns) in &ser_hooks {
            if patterns.iter().any(|p| name.contains(p)) {
                return Some(FalsePositiveReason::SerializationHook {
                    framework: framework.to_string(),
                    hook_type: name,
                });
            }
        }
        None
    }

    /// Plugin/extension point detection.
    fn detect_plugin_extension(
        &self,
        graph: &CallGraph,
        node: NodeIndex,
    ) -> Option<FalsePositiveReason> {
        let name = graph.get_function_name(node).to_lowercase();
        let plugin_patterns = [
            ("webpack", &["apply", "plugin"][..]),
            ("babel", &["visitor", "pre", "post"]),
            ("eslint", &["create", "meta"]),
            ("pytest", &["pytest_", "conftest"]),
            ("gradle", &["apply", "configure"]),
            ("vscode", &["activate", "deactivate"]),
        ];

        for (system, patterns) in &plugin_patterns {
            if patterns.iter().any(|p| name.starts_with(p) || name.contains(p)) {
                return Some(FalsePositiveReason::PluginExtensionPoint {
                    plugin_system: system.to_string(),
                    evidence: format!("Function name '{}' matches {} plugin pattern", name, system),
                });
            }
        }
        None
    }

    /// Conditional compilation detection.
    fn detect_conditional_compilation(
        &self,
        graph: &CallGraph,
        node: NodeIndex,
    ) -> Option<FalsePositiveReason> {
        // Check for cfg attributes (Rust), #ifdef (C/C++), platform checks
        if let Some(attrs) = graph.get_attributes(node) {
            for attr in &attrs {
                let attr_lower = attr.to_lowercase();
                if attr_lower.contains("cfg(") || attr_lower.contains("#ifdef")
                    || attr_lower.contains("#if ") || attr_lower.contains("platform")
                    || attr_lower.contains("target_os") || attr_lower.contains("feature")
                {
                    return Some(FalsePositiveReason::ConditionalCompilation {
                        condition: attr.clone(),
                        platforms: self.extract_platforms(attr),
                    });
                }
            }
        }
        None
    }
}
```

### 7.4 DeadCodeOptions

```rust
/// Options for dead code detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadCodeOptions {
    /// Minimum confidence to report. Default: 0.25.
    pub min_confidence: Option<f64>,
    /// Filter by file path pattern.
    pub file_filter: Option<String>,
    /// Include false positive analysis in results. Default: true.
    pub include_false_positives: Option<bool>,
    /// Filter by language.
    pub language: Option<String>,
    /// Maximum candidates to return. Default: 1000.
    pub max_candidates: Option<usize>,
    /// Sort order.
    pub sort_by: Option<DeadCodeSortOrder>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum DeadCodeSortOrder {
    /// Highest confidence first (default).
    Confidence,
    /// Largest functions first (most LOC savings).
    LinesOfCode,
    /// By file path (for systematic review).
    File,
}
```



---

## 8. Dead Code Confidence Scoring (Bayesian)

### 8.1 Architecture

V1 uses a simple inverse mapping: 0 FP reasons → 'high', 1 → 'medium', 2+ → 'low'.
This is crude — it doesn't account for the strength of each FP reason or accumulate
evidence over time.

V2 uses a Bayesian confidence model aligned with AD8 (Bayesian Confidence with Momentum).
Each false positive reason has a prior probability of being a true false positive, and
the confidence is the posterior probability that the function is truly dead.

### 8.2 Scoring Algorithm

```rust
impl DeadCodeDetector {
    /// Compute dead code confidence using Bayesian model.
    ///
    /// Base prior: 0.95 (most functions with no callers are truly dead).
    /// Each FP reason reduces confidence by its weight.
    /// Weights are calibrated per-category based on empirical false positive rates.
    fn compute_dead_code_confidence(
        &self,
        fp_reasons: &[FalsePositiveReason],
        graph: &CallGraph,
        node: NodeIndex,
    ) -> f64 {
        let base_confidence = 0.95;

        if fp_reasons.is_empty() {
            return base_confidence;
        }

        // Each FP reason has a weight representing how likely it is to be
        // a true false positive (i.e., the function is NOT dead).
        let mut total_fp_weight: f64 = 0.0;

        for reason in fp_reasons {
            let weight = match reason {
                // Entry points are almost certainly not dead code
                FalsePositiveReason::EntryPoint { .. } => 0.95,

                // Framework hooks are very likely not dead code
                FalsePositiveReason::FrameworkHook { confidence, .. } => *confidence,

                // Exported functions might be used externally
                FalsePositiveReason::Exported { export_type } => match export_type {
                    ExportType::PackageExport => 0.90,  // Listed in package.json
                    ExportType::DefaultExport => 0.70,
                    ExportType::NamedExport => 0.60,
                    ExportType::PublicApi => 0.50,
                    ExportType::ModuleExport => 0.50,
                },

                // Test functions are not dead code
                FalsePositiveReason::TestFunction { .. } => 0.95,

                // Dynamic dispatch is uncertain
                FalsePositiveReason::DynamicDispatch { dispatch_type, .. } => match dispatch_type {
                    DynamicDispatchType::DependencyInjection => 0.90,
                    DynamicDispatchType::Reflection => 0.80,
                    DynamicDispatchType::StringDispatch => 0.70,
                    DynamicDispatchType::Eval => 0.60,
                    DynamicDispatchType::Getattr => 0.60,
                    DynamicDispatchType::FunctionPointer => 0.50,
                },

                // Event handlers are likely called by the event system
                FalsePositiveReason::EventHandler { .. } => 0.75,

                // Decorator handlers are called by the framework
                FalsePositiveReason::DecoratorHandler { .. } => 0.85,

                // Interface implementations are called via vtable
                FalsePositiveReason::InterfaceImplementation { .. } => 0.90,

                // Serialization hooks are called by the framework
                FalsePositiveReason::SerializationHook { .. } => 0.85,

                // Plugin extension points are loaded dynamically
                FalsePositiveReason::PluginExtensionPoint { .. } => 0.70,

                // Conditional compilation: may be alive on other platforms
                FalsePositiveReason::ConditionalCompilation { .. } => 0.80,
            };

            // Combine using noisy-OR: P(dead) = P(dead) × (1 - P(fp_reason))
            total_fp_weight = 1.0 - (1.0 - total_fp_weight) * (1.0 - weight);
        }

        // Final confidence: base × (1 - combined FP weight)
        let confidence = base_confidence * (1.0 - total_fp_weight);

        // Clamp to [0.0, 1.0]
        confidence.clamp(0.0, 1.0)
    }
}
```

### 8.3 Noisy-OR Combination

The noisy-OR model is used to combine multiple independent false positive reasons.
If a function has 3 FP reasons with weights 0.80, 0.70, and 0.60:

```
P(not_dead) = 1 - (1-0.80) × (1-0.70) × (1-0.60)
            = 1 - 0.20 × 0.30 × 0.40
            = 1 - 0.024
            = 0.976

confidence = 0.95 × (1 - 0.976) = 0.95 × 0.024 = 0.023
```

This means a function with 3 strong FP reasons has only 2.3% confidence of being dead —
correctly reflecting that multiple independent reasons compound the evidence against
dead code classification.

### 8.4 Confidence Calibration

| FP Reasons | Example | Expected Confidence | Action |
|-----------|---------|-------------------|--------|
| 0 | Truly orphaned function | 0.95 | Remove |
| 1 (weak) | Has `on_` prefix | 0.24 | Review |
| 1 (strong) | Is entry point | 0.05 | Keep |
| 2 (mixed) | Exported + event handler | 0.05 | Keep |
| 3+ | Entry + exported + hook | < 0.01 | Keep |

---

## 9. Path Finding Engine (BFS, Dijkstra, K-Shortest)

### 9.1 Architecture

V1 path finding uses BFS with path tracking — it finds paths but treats all edges
equally. V2 adds three algorithms:

1. **BFS (unweighted)**: Fastest, finds shortest paths by hop count. Preserved from v1.
2. **Dijkstra (weighted)**: Finds shortest paths by edge weight (resolution confidence).
   Higher-confidence edges are "shorter" (preferred).
3. **Yen's K-Shortest**: Finds the K shortest paths, useful for understanding alternative
   routes through the call graph.

### 9.2 Implementation

```rust
/// Path finding engine.
pub struct PathFinder {
    reachability: Arc<ReachabilityEngine>,
}

/// A found path between two functions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FoundPath {
    /// The call path nodes.
    pub nodes: Vec<CallPathNode>,
    /// Total path weight (sum of edge weights). Lower = better.
    pub weight: f64,
    /// Path length (number of hops).
    pub hops: usize,
    /// Average edge confidence along the path.
    pub avg_confidence: f64,
    /// Minimum edge confidence along the path (weakest link).
    pub min_confidence: f64,
    /// Algorithm used to find this path.
    pub algorithm: PathAlgorithm,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum PathAlgorithm {
    Bfs,
    Dijkstra,
    YenKShortest,
}

/// Path finding options.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathOptions {
    /// Maximum number of paths to return. Default: 10.
    pub max_paths: Option<usize>,
    /// Maximum path depth. Default: 30.
    pub max_depth: Option<u32>,
    /// Algorithm to use. Default: Bfs.
    pub algorithm: Option<PathAlgorithm>,
    /// Minimum edge confidence to traverse. Default: 0.40.
    pub min_confidence: Option<f64>,
    /// Whether to include edge metadata in path nodes. Default: true.
    pub include_edge_metadata: Option<bool>,
}

impl PathFinder {
    pub fn new(reachability: Arc<ReachabilityEngine>) -> Self {
        Self { reachability }
    }

    /// Find paths between two functions.
    /// Dispatches to the appropriate algorithm based on options.
    pub fn find_paths(
        &self,
        from: &CodeLocation,
        to: &CodeLocation,
        options: Option<&PathOptions>,
    ) -> Result<Vec<FoundPath>, ImpactError> {
        let graph = self.reachability.graph()
            .ok_or(ImpactError::GraphNotLoaded)?;

        let max_paths = options.and_then(|o| o.max_paths).unwrap_or(10);
        let max_depth = options.and_then(|o| o.max_depth).unwrap_or(30);
        let algorithm = options.and_then(|o| o.algorithm).unwrap_or(PathAlgorithm::Bfs);
        let min_confidence = options.and_then(|o| o.min_confidence).unwrap_or(0.40);

        match algorithm {
            PathAlgorithm::Bfs => self.find_paths_bfs(
                graph, from, to, max_paths, max_depth, min_confidence
            ),
            PathAlgorithm::Dijkstra => self.find_paths_dijkstra(
                graph, from, to, max_paths, max_depth, min_confidence
            ),
            PathAlgorithm::YenKShortest => self.find_paths_yen(
                graph, from, to, max_paths, max_depth, min_confidence
            ),
        }
    }

    /// BFS path finding (preserved from v1, enhanced with metadata).
    fn find_paths_bfs(
        &self,
        graph: &CallGraph,
        from: &CodeLocation,
        to: &CodeLocation,
        max_paths: usize,
        max_depth: u32,
        min_confidence: f64,
    ) -> Result<Vec<FoundPath>, ImpactError> {
        let from_node = graph.find_function_at(from)
            .map_err(|_| ImpactError::FunctionNotFound(format!("{:?}", from)))?;
        let to_node = graph.find_function_at(to)
            .map_err(|_| ImpactError::FunctionNotFound(format!("{:?}", to)))?;

        let mut paths: Vec<FoundPath> = Vec::new();
        let mut queue: VecDeque<(NodeIndex, Vec<(CallPathNode, f64)>, FxHashSet<NodeIndex>)> =
            VecDeque::new();

        let initial_node = graph.node_to_path_node(from_node);
        let mut initial_visited = FxHashSet::default();
        initial_visited.insert(from_node);
        queue.push_back((from_node, vec![(initial_node, 1.0)], initial_visited));

        while let Some((current, path, visited)) = queue.pop_front() {
            if paths.len() >= max_paths {
                break;
            }
            if path.len() as u32 > max_depth {
                continue;
            }

            if current == to_node && path.len() > 1 {
                let (nodes, confidences): (Vec<_>, Vec<_>) = path.into_iter().unzip();
                let avg_conf = confidences.iter().sum::<f64>() / confidences.len() as f64;
                let min_conf = confidences.iter().cloned().fold(f64::INFINITY, f64::min);
                paths.push(FoundPath {
                    hops: nodes.len() - 1,
                    weight: nodes.len() as f64,  // BFS: weight = hop count
                    avg_confidence: avg_conf,
                    min_confidence: min_conf,
                    nodes,
                    algorithm: PathAlgorithm::Bfs,
                });
                continue;
            }

            for edge in graph.graph.edges_directed(current, Direction::Outgoing) {
                let callee = edge.target();
                let edge_conf = edge.weight().confidence;
                if edge_conf < min_confidence {
                    continue;
                }
                if !visited.contains(&callee) {
                    let mut new_path = path.clone();
                    new_path.push((
                        graph.node_to_path_node_with_edge(callee, edge.weight()),
                        edge_conf,
                    ));
                    let mut new_visited = visited.clone();
                    new_visited.insert(callee);
                    queue.push_back((callee, new_path, new_visited));
                }
            }
        }

        paths.sort_by_key(|p| p.hops);
        Ok(paths)
    }

    /// Dijkstra weighted path finding.
    /// Edge weight = 1.0 / confidence (higher confidence = lower cost = preferred).
    fn find_paths_dijkstra(
        &self,
        graph: &CallGraph,
        from: &CodeLocation,
        to: &CodeLocation,
        max_paths: usize,
        max_depth: u32,
        min_confidence: f64,
    ) -> Result<Vec<FoundPath>, ImpactError> {
        let from_node = graph.find_function_at(from)
            .map_err(|_| ImpactError::FunctionNotFound(format!("{:?}", from)))?;
        let to_node = graph.find_function_at(to)
            .map_err(|_| ImpactError::FunctionNotFound(format!("{:?}", to)))?;

        // Use petgraph's Dijkstra with custom edge cost
        use petgraph::algo::dijkstra;
        use std::collections::BinaryHeap;
        use std::cmp::Reverse;

        // Custom Dijkstra with path tracking
        let mut dist: FxHashMap<NodeIndex, f64> = FxHashMap::default();
        let mut prev: FxHashMap<NodeIndex, (NodeIndex, f64)> = FxHashMap::default();
        let mut heap: BinaryHeap<Reverse<(ordered_float::OrderedFloat<f64>, NodeIndex)>> =
            BinaryHeap::new();

        dist.insert(from_node, 0.0);
        heap.push(Reverse((ordered_float::OrderedFloat(0.0), from_node)));

        while let Some(Reverse((cost, node))) = heap.pop() {
            let cost = cost.0;
            if cost > dist.get(&node).copied().unwrap_or(f64::INFINITY) {
                continue;
            }
            if node == to_node {
                break;
            }

            for edge in graph.graph.edges_directed(node, Direction::Outgoing) {
                let callee = edge.target();
                let edge_conf = edge.weight().confidence;
                if edge_conf < min_confidence {
                    continue;
                }

                // Edge cost: inverse of confidence (prefer high-confidence edges)
                let edge_cost = 1.0 / edge_conf.max(0.01);
                let new_cost = cost + edge_cost;

                if new_cost < dist.get(&callee).copied().unwrap_or(f64::INFINITY) {
                    dist.insert(callee, new_cost);
                    prev.insert(callee, (node, edge_conf));
                    heap.push(Reverse((ordered_float::OrderedFloat(new_cost), callee)));
                }
            }
        }

        // Reconstruct path
        if !dist.contains_key(&to_node) {
            return Ok(Vec::new());  // No path found
        }

        let mut path_nodes: Vec<CallPathNode> = Vec::new();
        let mut confidences: Vec<f64> = Vec::new();
        let mut current = to_node;

        while current != from_node {
            path_nodes.push(graph.node_to_path_node(current));
            if let Some(&(prev_node, conf)) = prev.get(&current) {
                confidences.push(conf);
                current = prev_node;
            } else {
                break;
            }
        }
        path_nodes.push(graph.node_to_path_node(from_node));
        path_nodes.reverse();
        confidences.reverse();

        let total_weight = dist[&to_node];
        let avg_conf = if confidences.is_empty() {
            1.0
        } else {
            confidences.iter().sum::<f64>() / confidences.len() as f64
        };
        let min_conf = confidences.iter().cloned().fold(f64::INFINITY, f64::min);

        Ok(vec![FoundPath {
            hops: path_nodes.len() - 1,
            weight: total_weight,
            avg_confidence: avg_conf,
            min_confidence: if min_conf.is_infinite() { 1.0 } else { min_conf },
            nodes: path_nodes,
            algorithm: PathAlgorithm::Dijkstra,
        }])
    }

    /// Yen's K-Shortest Paths algorithm.
    /// Finds the K shortest loopless paths between two nodes.
    /// Uses Dijkstra as the subroutine for each iteration.
    fn find_paths_yen(
        &self,
        graph: &CallGraph,
        from: &CodeLocation,
        to: &CodeLocation,
        k: usize,
        max_depth: u32,
        min_confidence: f64,
    ) -> Result<Vec<FoundPath>, ImpactError> {
        // Yen's algorithm:
        // 1. Find shortest path using Dijkstra
        // 2. For each node in the shortest path, create a "spur" path
        //    by removing edges used by previously found paths
        // 3. Combine spur path with root path to get candidate
        // 4. Add best candidate to result set
        // 5. Repeat until K paths found or no more candidates

        let mut result: Vec<FoundPath> = Vec::new();
        let mut candidates: BinaryHeap<Reverse<(ordered_float::OrderedFloat<f64>, FoundPath)>> =
            BinaryHeap::new();

        // Step 1: Find first shortest path
        let first = self.find_paths_dijkstra(
            graph, from, to, 1, max_depth, min_confidence
        )?;
        if first.is_empty() {
            return Ok(Vec::new());
        }
        result.push(first.into_iter().next().unwrap());

        // Steps 2-5: Find K-1 more paths
        for _k_idx in 1..k {
            let prev_path = &result.last().unwrap().nodes;

            for i in 0..prev_path.len().saturating_sub(1) {
                // Spur node is the i-th node in the previous path
                let spur_node_id = &prev_path[i].function_id;

                // Root path is the sub-path from source to spur node
                let root_path: Vec<CallPathNode> = prev_path[..=i].to_vec();

                // Find spur path from spur node to target
                // (excluding edges used by previous paths at this spur point)
                let spur_from = CodeLocation {
                    function_id: Some(spur_node_id.clone()),
                    ..Default::default()
                };

                if let Ok(spur_paths) = self.find_paths_dijkstra(
                    graph, &spur_from, to, 1, max_depth, min_confidence
                ) {
                    for spur_path in spur_paths {
                        // Combine root + spur (skip duplicate spur node)
                        let mut combined = root_path.clone();
                        if spur_path.nodes.len() > 1 {
                            combined.extend(spur_path.nodes[1..].iter().cloned());
                        }

                        // Check for loops
                        let mut seen = FxHashSet::default();
                        let has_loop = combined.iter()
                            .any(|n| !seen.insert(n.function_id.clone()));
                        if has_loop {
                            continue;
                        }

                        let total_weight = combined.len() as f64; // Simplified
                        let found = FoundPath {
                            hops: combined.len() - 1,
                            weight: total_weight,
                            avg_confidence: spur_path.avg_confidence,
                            min_confidence: spur_path.min_confidence,
                            nodes: combined,
                            algorithm: PathAlgorithm::YenKShortest,
                        };

                        // Check if this path is already in results
                        let is_duplicate = result.iter().any(|r| {
                            r.nodes.len() == found.nodes.len()
                            && r.nodes.iter().zip(found.nodes.iter())
                                .all(|(a, b)| a.function_id == b.function_id)
                        });

                        if !is_duplicate {
                            candidates.push(Reverse((
                                ordered_float::OrderedFloat(found.weight),
                                found,
                            )));
                        }
                    }
                }
            }

            // Add best candidate to results
            if let Some(Reverse((_, best))) = candidates.pop() {
                result.push(best);
            } else {
                break;  // No more candidates
            }
        }

        Ok(result)
    }
}
```



---

## 10. Weighted Path Scoring (Resolution Confidence × Depth)

### 10.1 Architecture

V1 sorts paths by length only. V2 introduces a composite path score that considers
edge resolution confidence, path depth, and edge type. This allows ranking paths by
"reliability" — a 5-hop path through high-confidence edges is better than a 3-hop
path through fuzzy-resolved edges.

### 10.2 Scoring Formula

```rust
/// Compute a composite score for a found path.
/// Lower score = better path.
///
/// score = Σ(edge_cost_i) where edge_cost = (1/confidence) × depth_penalty × type_penalty
///
/// - confidence: 0.0-1.0 (higher = lower cost)
/// - depth_penalty: 1.0 + (depth × 0.05) (deeper = slightly more expensive)
/// - type_penalty: 1.0 for same-file, 1.2 for import-based, 1.5 for fuzzy
fn compute_path_score(path: &FoundPath) -> f64 {
    let mut score = 0.0;
    for (i, node) in path.nodes.iter().enumerate() {
        let confidence = node.confidence.unwrap_or(1.0).max(0.01);
        let depth_penalty = 1.0 + (i as f64 * 0.05);
        let type_penalty = match node.resolution.as_deref() {
            Some("same_file") => 1.0,
            Some("method_call") => 1.0,
            Some("di_injection") => 1.1,
            Some("import_based") => 1.2,
            Some("export_based") => 1.3,
            Some("fuzzy") => 1.5,
            _ => 1.2,
        };
        score += (1.0 / confidence) * depth_penalty * type_penalty;
    }
    score
}
```

### 10.3 Path Ranking

When multiple paths are found, they are ranked by composite score (lowest first).
The MCP tool and CLI display the top-ranked paths with score breakdown.

---

## 11. Coverage Gap Analysis (Call Graph × Test Topology)

### 11.1 Architecture

Coverage gap analysis integrates the call graph with test topology to answer:
"Which sensitive data paths have test coverage?" and "Which data paths are untested?"

This is ported from v1 TS to Rust with field-level granularity and risk-weighted
coverage metrics.

### 11.2 Implementation

```rust
/// Coverage gap analysis engine.
pub struct CoverageAnalyzer {
    reachability: Arc<ReachabilityEngine>,
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
    /// Risk-weighted coverage score (0.0-100.0).
    pub risk_weighted_score: f64,
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
    /// Risk weight: Critical fields weigh more than Low fields.
    pub risk_weight: f64,
}

/// A data path without test coverage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UncoveredPath {
    pub entry_point: EntryPointInfo,
    pub data_access: DataAccessPoint,
    pub path: Vec<CallPathNode>,
    pub sensitivity: SensitivityLevel,
    pub risk: RiskLevel,
    /// Suggested test: which function to test to cover this path.
    pub suggested_test_target: Option<String>,
}

/// Aggregate coverage metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageMetrics {
    pub total_sensitive_paths: usize,
    pub covered_sensitive_paths: usize,
    pub coverage_percentage: f64,
    pub critical_uncovered: usize,
    pub high_uncovered: usize,
    pub medium_uncovered: usize,
    /// Minimum test set: smallest set of functions to test to maximize coverage.
    pub minimum_test_set: Vec<MinimumTestTarget>,
}

/// A function in the minimum test set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinimumTestTarget {
    pub function_id: String,
    pub function_name: String,
    pub file: String,
    /// Number of uncovered paths this function would cover.
    pub paths_covered: usize,
    /// Sensitivity levels of paths covered.
    pub sensitivities: Vec<SensitivityLevel>,
}

impl CoverageAnalyzer {
    pub fn new(reachability: Arc<ReachabilityEngine>) -> Self {
        Self { reachability }
    }

    /// Analyze test coverage of sensitive data paths.
    #[tracing::instrument(skip(self, test_functions))]
    pub fn analyze(
        &self,
        test_functions: &FxHashSet<String>,
    ) -> Result<CoverageResult, ImpactError> {
        let graph = self.reachability.graph()
            .ok_or(ImpactError::GraphNotLoaded)?;

        let mut field_coverage: FxHashMap<String, FieldCoverage> = FxHashMap::default();
        let mut uncovered_paths: Vec<UncoveredPath> = Vec::new();

        let entry_points = graph.get_entry_points();

        for ep_node in &entry_points {
            let reachable = self.reachability.forward_petgraph(
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
            ).map_err(|e| ImpactError::ReachabilityError(e.to_string()))?;

            for access in &reachable.reachable_access {
                let is_covered = access.path.iter().any(|node| {
                    test_functions.contains(&node.function_id)
                    || graph.has_test_caller(&node.function_id, test_functions)
                });

                let key = format!("{}.{}", access.access.table,
                    access.access.fields.join(","));

                let risk_weight = match access.sensitivity {
                    SensitivityLevel::Critical => 4.0,
                    SensitivityLevel::High => 3.0,
                    SensitivityLevel::Medium => 2.0,
                    SensitivityLevel::Low => 1.0,
                    SensitivityLevel::Unknown => 0.5,
                };

                let coverage = field_coverage.entry(key).or_insert_with(|| {
                    FieldCoverage {
                        table: access.access.table.clone(),
                        field: access.access.fields.join(", "),
                        sensitivity: access.sensitivity,
                        total_access_paths: 0,
                        covered_access_paths: 0,
                        coverage_percentage: 0.0,
                        covering_tests: Vec::new(),
                        risk_weight,
                    }
                });

                coverage.total_access_paths += 1;
                if is_covered {
                    coverage.covered_access_paths += 1;
                } else {
                    // Find the best function to test to cover this path
                    let suggested_target = self.find_best_test_target(
                        &access.path, graph
                    );

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
                        suggested_test_target: suggested_target,
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

        // Compute risk-weighted coverage score
        let risk_weighted_score = self.compute_risk_weighted_score(&field_coverage);

        // Compute minimum test set (greedy set cover)
        let minimum_test_set = self.compute_minimum_test_set(&uncovered_paths, graph);

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
            medium_uncovered: uncovered_paths.iter()
                .filter(|p| p.sensitivity == SensitivityLevel::Medium).count(),
            minimum_test_set,
        };

        Ok(CoverageResult {
            field_coverage: field_coverage.into_values().collect(),
            uncovered_paths,
            metrics,
            risk_weighted_score,
        })
    }

    /// Compute risk-weighted coverage score.
    /// Critical paths weigh 4x, High 3x, Medium 2x, Low 1x.
    fn compute_risk_weighted_score(
        &self,
        field_coverage: &FxHashMap<String, FieldCoverage>,
    ) -> f64 {
        let mut weighted_covered = 0.0;
        let mut weighted_total = 0.0;

        for coverage in field_coverage.values() {
            weighted_total += coverage.total_access_paths as f64 * coverage.risk_weight;
            weighted_covered += coverage.covered_access_paths as f64 * coverage.risk_weight;
        }

        if weighted_total > 0.0 {
            (weighted_covered / weighted_total) * 100.0
        } else {
            100.0
        }
    }

    /// Compute minimum test set using greedy set cover.
    /// Finds the smallest set of functions to test to maximize coverage.
    fn compute_minimum_test_set(
        &self,
        uncovered_paths: &[UncoveredPath],
        graph: &CallGraph,
    ) -> Vec<MinimumTestTarget> {
        // Build a map: function_id → set of uncovered path indices it covers
        let mut function_coverage: FxHashMap<String, Vec<usize>> = FxHashMap::default();

        for (idx, path) in uncovered_paths.iter().enumerate() {
            for node in &path.path {
                function_coverage
                    .entry(node.function_id.clone())
                    .or_default()
                    .push(idx);
            }
        }

        // Greedy set cover: repeatedly pick the function that covers the most paths
        let mut covered: FxHashSet<usize> = FxHashSet::default();
        let mut test_set: Vec<MinimumTestTarget> = Vec::new();

        while covered.len() < uncovered_paths.len() {
            let best = function_coverage.iter()
                .max_by_key(|(_, paths)| {
                    paths.iter().filter(|idx| !covered.contains(idx)).count()
                });

            if let Some((func_id, paths)) = best {
                let new_covered: Vec<usize> = paths.iter()
                    .filter(|idx| !covered.contains(idx))
                    .copied()
                    .collect();

                if new_covered.is_empty() {
                    break;
                }

                let sensitivities: Vec<SensitivityLevel> = new_covered.iter()
                    .map(|&idx| uncovered_paths[idx].sensitivity)
                    .collect();

                test_set.push(MinimumTestTarget {
                    function_id: func_id.clone(),
                    function_name: graph.get_function_name_by_id(func_id)
                        .unwrap_or_default(),
                    file: graph.get_function_file_by_id(func_id)
                        .unwrap_or_default(),
                    paths_covered: new_covered.len(),
                    sensitivities,
                });

                for idx in new_covered {
                    covered.insert(idx);
                }
            } else {
                break;
            }
        }

        test_set.sort_by(|a, b| b.paths_covered.cmp(&a.paths_covered));
        test_set
    }
}
```



---

## 12. Enrichment Pipeline (Impact Scoring + Remediation)

### 12.1 Architecture

V1's enrichment pipeline runs as 3 separate TS passes. V2 integrates sensitivity
classification into the BFS traversal (handled by the reachability engine) and runs
impact scoring and remediation generation as post-processing within the impact engine.

### 12.2 Impact Scoring (PageRank-Inspired)

```rust
/// Enrichment pipeline for impact analysis.
pub struct EnrichmentPipeline {
    reachability: Arc<ReachabilityEngine>,
}

/// Impact score for a function based on graph centrality and data sensitivity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionImpactScore {
    pub function_id: String,
    pub score: f64,           // 0.0-100.0
    pub factors: ImpactScoreFactors,
    pub rank: usize,          // 1 = highest impact
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactScoreFactors {
    /// In-degree centrality (number of callers, normalized).
    pub caller_centrality: f64,
    /// Out-degree centrality (number of callees, normalized).
    pub callee_centrality: f64,
    /// Whether this is an entry point.
    pub is_entry_point: bool,
    /// Whether this accesses sensitive data.
    pub accesses_sensitive_data: bool,
    /// Depth from nearest entry point (shorter = higher impact).
    pub depth_from_entry: u32,
    /// Number of reachable data access points.
    pub reachable_data_points: usize,
    /// PageRank-inspired score (iterative importance propagation).
    pub pagerank: f64,
}

impl EnrichmentPipeline {
    pub fn new(reachability: Arc<ReachabilityEngine>) -> Self {
        Self { reachability }
    }

    /// Compute impact scores for all functions in the call graph.
    /// Uses a simplified PageRank algorithm: importance flows from callees to callers.
    pub fn compute_all_impact_scores(
        &self,
        graph: &CallGraph,
    ) -> Vec<FunctionImpactScore> {
        let node_count = graph.graph.node_count();
        if node_count == 0 {
            return Vec::new();
        }

        // Step 1: Compute PageRank (10 iterations, damping = 0.85)
        let damping = 0.85;
        let iterations = 10;
        let initial_rank = 1.0 / node_count as f64;

        let mut ranks: FxHashMap<NodeIndex, f64> = graph.graph.node_indices()
            .map(|n| (n, initial_rank))
            .collect();

        for _ in 0..iterations {
            let mut new_ranks: FxHashMap<NodeIndex, f64> = FxHashMap::default();

            for node in graph.graph.node_indices() {
                let mut rank_sum = 0.0;

                // Sum rank contributions from callers
                for edge in graph.graph.edges_directed(node, Direction::Incoming) {
                    let caller = edge.source();
                    let caller_out_degree = graph.graph
                        .edges_directed(caller, Direction::Outgoing).count();
                    if caller_out_degree > 0 {
                        rank_sum += ranks[&caller] / caller_out_degree as f64;
                    }
                }

                new_ranks.insert(node, (1.0 - damping) / node_count as f64 + damping * rank_sum);
            }

            ranks = new_ranks;
        }

        // Step 2: Compute composite impact scores
        let max_in_degree = graph.graph.node_indices()
            .map(|n| graph.graph.edges_directed(n, Direction::Incoming).count())
            .max()
            .unwrap_or(1) as f64;
        let max_out_degree = graph.graph.node_indices()
            .map(|n| graph.graph.edges_directed(n, Direction::Outgoing).count())
            .max()
            .unwrap_or(1) as f64;
        let max_pagerank = ranks.values().cloned().fold(0.0_f64, f64::max);

        let mut scores: Vec<FunctionImpactScore> = graph.graph.node_indices()
            .map(|node| {
                let func = &graph.graph[node];
                let in_degree = graph.graph
                    .edges_directed(node, Direction::Incoming).count() as f64;
                let out_degree = graph.graph
                    .edges_directed(node, Direction::Outgoing).count() as f64;
                let pagerank = ranks[&node];

                let caller_centrality = in_degree / max_in_degree.max(1.0);
                let callee_centrality = out_degree / max_out_degree.max(1.0);
                let normalized_pagerank = pagerank / max_pagerank.max(f64::EPSILON);

                let accesses_sensitive = self.reachability.has_sensitive_access(graph, node);

                // Composite score: weighted combination
                let score = (
                    normalized_pagerank * 0.35
                    + caller_centrality * 0.25
                    + callee_centrality * 0.10
                    + if func.is_entry_point { 0.20 } else { 0.0 }
                    + if accesses_sensitive { 0.10 } else { 0.0 }
                ) * 100.0;

                FunctionImpactScore {
                    function_id: graph.interner.resolve(&func.id).to_string(),
                    score,
                    factors: ImpactScoreFactors {
                        caller_centrality,
                        callee_centrality,
                        is_entry_point: func.is_entry_point,
                        accesses_sensitive_data: accesses_sensitive,
                        depth_from_entry: 0, // Computed separately if needed
                        reachable_data_points: 0, // Computed separately if needed
                        pagerank: normalized_pagerank,
                    },
                    rank: 0, // Set after sorting
                }
            })
            .collect();

        // Sort by score (highest first) and assign ranks
        scores.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        for (i, score) in scores.iter_mut().enumerate() {
            score.rank = i + 1;
        }

        scores
    }

    /// Generate remediation suggestions for impact analysis results.
    pub fn generate_impact_remediations(
        &self,
        blast_radius: &BlastRadius,
        risk: &RiskAssessment,
        data_paths: &[AffectedDataPath],
        taint_flows: &[AffectedTaintFlow],
    ) -> Vec<RemediationSuggestion> {
        let mut suggestions: Vec<RemediationSuggestion> = Vec::new();

        // Remediation 1: Add tests for untested affected paths
        let untested_sensitive = data_paths.iter()
            .filter(|p| !p.is_tested && p.sensitivity >= SensitivityLevel::High)
            .count();
        if untested_sensitive > 0 {
            suggestions.push(RemediationSuggestion {
                issue: RemediationIssue::MissingTestCoverage,
                location: data_paths.iter()
                    .find(|p| !p.is_tested && p.sensitivity >= SensitivityLevel::High)
                    .and_then(|p| p.path.first())
                    .map(|n| CodeLocation {
                        file: n.file.clone(),
                        line: n.line,
                        column: None,
                        function_id: Some(n.function_id.clone()),
                    })
                    .unwrap_or_default(),
                suggestion: format!(
                    "Add test coverage for {} sensitive data path(s) affected by this change. \
                     Focus on Critical and High sensitivity paths first.",
                    untested_sensitive
                ),
                priority: 1,
                effort: RemediationEffort::Medium,
            });
        }

        // Remediation 2: Sanitizer disruption warning
        let sanitizer_flows = taint_flows.iter()
            .filter(|f| f.role == TaintFlowRole::Sanitizer)
            .count();
        if sanitizer_flows > 0 {
            suggestions.push(RemediationSuggestion {
                issue: RemediationIssue::SanitizerDisruption,
                location: CodeLocation::default(),
                suggestion: format!(
                    "This function is a sanitizer on {} taint flow(s). \
                     Verify that the change preserves sanitization guarantees. \
                     Consider adding regression tests for each taint flow.",
                    sanitizer_flows
                ),
                priority: 1,
                effort: RemediationEffort::High,
            });
        }

        // Remediation 3: Wide blast radius warning
        if blast_radius.codebase_percentage > 0.05 {
            suggestions.push(RemediationSuggestion {
                issue: RemediationIssue::WideBlastRadius,
                location: CodeLocation::default(),
                suggestion: format!(
                    "This change affects {:.1}% of the codebase ({} functions). \
                     Consider breaking the change into smaller, incremental steps \
                     with intermediate testing.",
                    blast_radius.codebase_percentage * 100.0,
                    blast_radius.transitive_callers
                ),
                priority: 2,
                effort: RemediationEffort::Low,
            });
        }

        suggestions.sort_by_key(|s| s.priority);
        suggestions
    }
}

/// Remediation issue types (expanded from v1).
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
    /// NEW in v2: missing test coverage for affected paths.
    MissingTestCoverage,
    /// NEW in v2: sanitizer disruption warning.
    SanitizerDisruption,
    /// NEW in v2: wide blast radius warning.
    WideBlastRadius,
}
```

---

## 13. Change Simulation Integration

### 13.1 Architecture

The impact engine feeds the simulation engine (Level 4) with blast radius data.
When a developer asks "what if I refactor this module?", the simulation engine
uses impact analysis to score the approach.

```rust
/// Interface for simulation engine integration.
/// The simulation engine calls these methods to get impact data for scoring.
pub trait ImpactProvider: Send + Sync {
    /// Get blast radius for a function change.
    fn get_blast_radius(&self, function_id: &str) -> Result<BlastRadius, ImpactError>;

    /// Get blast radius for a set of function changes (batch).
    fn get_batch_blast_radius(
        &self,
        function_ids: &[String],
    ) -> Result<BatchBlastRadius, ImpactError>;

    /// Get dead code candidates in a file (for removal simulation).
    fn get_dead_code_in_file(&self, file: &str) -> Result<Vec<DeadCodeCandidate>, ImpactError>;

    /// Get coverage gaps for a module (for test planning simulation).
    fn get_coverage_gaps(
        &self,
        module_path: &str,
    ) -> Result<CoverageResult, ImpactError>;
}

/// Batch blast radius for multiple function changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchBlastRadius {
    /// Individual blast radii per function.
    pub per_function: Vec<(String, BlastRadius)>,
    /// Combined blast radius (union of all affected functions).
    pub combined: BlastRadius,
    /// Overlap: functions affected by multiple changes.
    pub overlap_count: usize,
}

impl ImpactProvider for ImpactEngine {
    fn get_blast_radius(&self, function_id: &str) -> Result<BlastRadius, ImpactError> {
        let result = self.analyze_impact(function_id, None)?;
        Ok(result.blast_radius)
    }

    fn get_batch_blast_radius(
        &self,
        function_ids: &[String],
    ) -> Result<BatchBlastRadius, ImpactError> {
        let mut per_function: Vec<(String, BlastRadius)> = Vec::new();
        let mut all_affected: FxHashSet<String> = FxHashSet::default();
        let mut all_entry_points: FxHashSet<String> = FxHashSet::default();

        for func_id in function_ids {
            let result = self.analyze_impact(func_id, None)?;
            for af in &result.affected_functions {
                all_affected.insert(af.function_id.clone());
            }
            for ep in &result.affected_entry_points {
                all_entry_points.insert(ep.function_id.clone());
            }
            per_function.push((func_id.clone(), result.blast_radius));
        }

        let graph = self.reachability.graph()
            .ok_or(ImpactError::GraphNotLoaded)?;
        let total_functions = graph.graph.node_count();

        let combined = BlastRadius {
            direct_callers: per_function.iter().map(|(_, b)| b.direct_callers).sum(),
            transitive_callers: all_affected.len(),
            affected_entry_points: all_entry_points.len(),
            affected_sensitive_paths: per_function.iter()
                .map(|(_, b)| b.affected_sensitive_paths).sum(),
            affected_taint_flows: per_function.iter()
                .map(|(_, b)| b.affected_taint_flows).sum(),
            covering_tests: per_function.iter()
                .map(|(_, b)| b.covering_tests).sum(),
            codebase_percentage: all_affected.len() as f64 / total_functions as f64,
            max_propagation_depth: per_function.iter()
                .map(|(_, b)| b.max_propagation_depth).max().unwrap_or(0),
            by_language: FxHashMap::default(),
            by_file: FxHashMap::default(),
        };

        // Count overlap
        let mut function_hit_count: FxHashMap<String, usize> = FxHashMap::default();
        for (_, blast) in &per_function {
            // Simplified: count unique affected across all analyses
        }
        let overlap_count = function_hit_count.values()
            .filter(|&&count| count > 1).count();

        Ok(BatchBlastRadius {
            per_function,
            combined,
            overlap_count,
        })
    }

    fn get_dead_code_in_file(&self, file: &str) -> Result<Vec<DeadCodeCandidate>, ImpactError> {
        let all = self.dead_code.detect(Some(&DeadCodeOptions {
            file_filter: Some(file.to_string()),
            ..Default::default()
        }))?;
        Ok(all)
    }

    fn get_coverage_gaps(
        &self,
        _module_path: &str,
    ) -> Result<CoverageResult, ImpactError> {
        let graph = self.reachability.graph()
            .ok_or(ImpactError::GraphNotLoaded)?;
        let test_functions = self.get_test_functions(graph)?;
        self.coverage.analyze(&test_functions)
    }
}
```



---

## 14. Incremental Impact Analysis (Content-Hash Aware)

### 14.1 Strategy

When the call graph is incrementally updated, impact analysis results may become stale.
The cache invalidation strategy is conservative: any change to the call graph invalidates
all impact results whose changed function or affected functions include a changed file.

```rust
impl ImpactEngine {
    /// Handle incremental call graph update.
    pub fn on_incremental_update(
        &self,
        changed_files: &[String],
    ) {
        let mut cache = self.cache.lock();
        let keys_to_remove: Vec<ImpactCacheKey> = cache.iter()
            .filter(|(key, _)| self.is_affected_by_changes(key, changed_files))
            .map(|(key, _)| key.clone())
            .collect();

        for key in &keys_to_remove {
            cache.pop(key);
        }

        tracing::info!(
            changed_files = changed_files.len(),
            invalidated = keys_to_remove.len(),
            "Impact cache incrementally invalidated"
        );
    }

    fn is_affected_by_changes(
        &self,
        key: &ImpactCacheKey,
        changed_files: &[String],
    ) -> bool {
        match key {
            ImpactCacheKey::Impact { function_id } => {
                // Invalidate if the function's file changed
                changed_files.iter().any(|f| function_id.starts_with(f))
            }
            ImpactCacheKey::DeadCode => true, // Always invalidate dead code
            ImpactCacheKey::Coverage => true,  // Always invalidate coverage
            ImpactCacheKey::Path { from_file, to_file } => {
                changed_files.contains(from_file) || changed_files.contains(to_file)
            }
        }
    }
}

/// Cache key for impact results.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum ImpactCacheKey {
    Impact { function_id: String },
    DeadCode,
    Coverage,
    Path { from_file: String, to_file: String },
}
```

---

## 15. Cross-Service Impact Propagation

### 15.1 Architecture (P2 Feature)

Cross-service impact extends blast radius analysis across microservice boundaries.
When a function change affects an API endpoint, the impact propagates to all services
that call that endpoint.

```rust
/// Cross-service impact result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossServiceImpact {
    /// The changed function's service.
    pub origin_service: String,
    /// Services affected by the change.
    pub affected_services: Vec<AffectedService>,
    /// Total cross-service blast radius.
    pub cross_service_blast_radius: usize,
}

/// A service affected by a cross-service change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AffectedService {
    pub service_id: String,
    /// API endpoints in this service that call the changed endpoint.
    pub calling_endpoints: Vec<String>,
    /// Functions in this service affected.
    pub affected_functions: usize,
    /// Risk level for this service.
    pub risk: RiskLevel,
}
```

### 15.2 Implementation Strategy

1. Detect API endpoints affected by the change (from entry point analysis)
2. Query contract detection for services that consume those endpoints
3. For each consuming service, compute local blast radius
4. Aggregate into cross-service impact result

This requires the contract detection system (Level 2C) to provide endpoint registries.
Deferred to P2 (post-launch).

---

## 16. Git Integration (Diff-Based Impact)

### 16.1 Architecture

Git integration enables "what's the blast radius of this PR?" by parsing git diffs
to identify changed functions, then running impact analysis on each.

```rust
use git2::Repository;

/// Git-based impact analysis.
pub struct GitImpactAnalyzer {
    impact: Arc<ImpactEngine>,
}

/// Result of a git diff impact analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitImpactResult {
    /// The git ref being analyzed (branch, commit, PR).
    pub git_ref: String,
    /// Base ref for comparison.
    pub base_ref: String,
    /// Changed files.
    pub changed_files: Vec<String>,
    /// Changed functions (identified from diff hunks).
    pub changed_functions: Vec<ChangedFunction>,
    /// Combined impact across all changed functions.
    pub combined_impact: BatchBlastRadius,
    /// Overall risk assessment.
    pub risk: RiskAssessment,
    /// Per-file impact summary.
    pub per_file: Vec<FileImpactSummary>,
}

/// A function identified as changed from a git diff.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangedFunction {
    pub function_id: String,
    pub function_name: String,
    pub file: String,
    pub change_type: ChangeType,
    pub lines_changed: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ChangeType {
    Modified,
    Added,
    Deleted,
    Renamed,
}

/// Per-file impact summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileImpactSummary {
    pub file: String,
    pub functions_changed: usize,
    pub total_blast_radius: usize,
    pub risk: RiskLevel,
}

impl GitImpactAnalyzer {
    /// Analyze impact of changes between two git refs.
    pub fn analyze_diff(
        &self,
        repo_path: &str,
        base_ref: &str,
        head_ref: &str,
    ) -> Result<GitImpactResult, ImpactError> {
        let repo = Repository::open(repo_path)
            .map_err(|e| ImpactError::GitError(e.to_string()))?;

        // Step 1: Get diff between refs
        let base = repo.revparse_single(base_ref)
            .map_err(|e| ImpactError::GitError(e.to_string()))?;
        let head = repo.revparse_single(head_ref)
            .map_err(|e| ImpactError::GitError(e.to_string()))?;

        let base_tree = base.peel_to_tree()
            .map_err(|e| ImpactError::GitError(e.to_string()))?;
        let head_tree = head.peel_to_tree()
            .map_err(|e| ImpactError::GitError(e.to_string()))?;

        let diff = repo.diff_tree_to_tree(Some(&base_tree), Some(&head_tree), None)
            .map_err(|e| ImpactError::GitError(e.to_string()))?;

        // Step 2: Extract changed files and line ranges
        let mut changed_files: Vec<String> = Vec::new();
        let mut changed_hunks: Vec<(String, u32, u32)> = Vec::new(); // (file, start, end)

        diff.foreach(
            &mut |delta, _| {
                if let Some(path) = delta.new_file().path() {
                    changed_files.push(path.to_string_lossy().to_string());
                }
                true
            },
            None,
            Some(&mut |delta, hunk| {
                if let Some(path) = delta.new_file().path() {
                    changed_hunks.push((
                        path.to_string_lossy().to_string(),
                        hunk.new_start(),
                        hunk.new_start() + hunk.new_lines(),
                    ));
                }
                true
            }),
            None,
        ).map_err(|e| ImpactError::GitError(e.to_string()))?;

        // Step 3: Map changed hunks to functions
        let graph = self.impact.reachability.graph()
            .ok_or(ImpactError::GraphNotLoaded)?;

        let mut changed_functions: Vec<ChangedFunction> = Vec::new();
        for (file, start_line, end_line) in &changed_hunks {
            // Find functions that overlap with the changed hunk
            let functions = graph.find_functions_in_range(file, *start_line, *end_line);
            for func_node in functions {
                let func = &graph.graph[func_node];
                let func_id = graph.interner.resolve(&func.id).to_string();

                // Avoid duplicates
                if !changed_functions.iter().any(|f| f.function_id == func_id) {
                    changed_functions.push(ChangedFunction {
                        function_id: func_id,
                        function_name: graph.get_function_name(func_node),
                        file: file.clone(),
                        change_type: ChangeType::Modified,
                        lines_changed: end_line - start_line,
                    });
                }
            }
        }

        // Step 4: Run batch impact analysis
        let function_ids: Vec<String> = changed_functions.iter()
            .map(|f| f.function_id.clone())
            .collect();

        let combined_impact = self.impact.get_batch_blast_radius(&function_ids)?;

        // Step 5: Compute overall risk
        let risk = self.compute_git_risk(&combined_impact, &changed_functions);

        // Step 6: Per-file summary
        let per_file = self.compute_per_file_summary(&changed_functions, &combined_impact);

        Ok(GitImpactResult {
            git_ref: head_ref.to_string(),
            base_ref: base_ref.to_string(),
            changed_files,
            changed_functions,
            combined_impact,
            risk,
            per_file,
        })
    }
}
```

---

## 17. LLM-Assisted False Positive Reduction (P2)

### 17.1 Architecture

Per the arxiv 2025 research on reducing false positives with LLMs, hybrid techniques
combining static analysis with LLM reasoning can eliminate 94-98% of false positives.
This is a P2 feature that uses the AI provider abstraction (packages/ai) to validate
dead code candidates and impact assessments.

### 17.2 Strategy

1. For dead code candidates with confidence 0.25-0.75 (uncertain zone), send the
   function source + call graph context to an LLM
2. Ask: "Is this function truly dead code, or is it called via a mechanism the
   static analysis cannot detect?"
3. LLM provides a verdict with reasoning
4. Adjust confidence based on LLM verdict
5. Track LLM accuracy over time (feedback loop per AD9)

### 17.3 Interface

```rust
/// LLM-assisted false positive reduction (P2).
pub trait LlmFalsePositiveReducer: Send + Sync {
    /// Validate a dead code candidate using LLM reasoning.
    fn validate_dead_code(
        &self,
        candidate: &DeadCodeCandidate,
        context: &FunctionContext,
    ) -> Result<LlmVerdict, ImpactError>;

    /// Validate an impact assessment using LLM reasoning.
    fn validate_impact(
        &self,
        result: &ImpactResult,
        change_description: &str,
    ) -> Result<LlmVerdict, ImpactError>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmVerdict {
    pub is_false_positive: bool,
    pub confidence_adjustment: f64,  // -0.5 to +0.5
    pub reasoning: String,
    pub model: String,
    pub tokens_used: u32,
}
```



---

## 18. Storage Schema

### 18.1 Impact Analysis Tables

```sql
-- Migration: 006_impact_analysis.sql

-- Impact analysis results (cached for fast retrieval)
CREATE TABLE impact_results (
    function_id TEXT PRIMARY KEY,
    blast_radius_json TEXT NOT NULL,       -- Serialized BlastRadius
    risk_level TEXT NOT NULL,              -- Low/Medium/High/Critical
    risk_score REAL NOT NULL,              -- 0.0-100.0
    risk_factors_json TEXT NOT NULL,       -- Serialized RiskFactors
    affected_count INTEGER NOT NULL,       -- Transitive caller count
    entry_points_affected INTEGER NOT NULL,
    sensitive_paths_affected INTEGER NOT NULL,
    taint_flows_affected INTEGER NOT NULL,
    covering_tests INTEGER NOT NULL,
    codebase_percentage REAL NOT NULL,
    max_depth INTEGER NOT NULL,
    scan_id TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE INDEX idx_impact_risk ON impact_results(risk_level);
CREATE INDEX idx_impact_scan ON impact_results(scan_id);
CREATE INDEX idx_impact_score ON impact_results(risk_score);

-- Dead code results
CREATE TABLE dead_code (
    function_id TEXT PRIMARY KEY,
    function_name TEXT NOT NULL,
    file TEXT NOT NULL,
    line INTEGER NOT NULL,
    end_line INTEGER NOT NULL,
    language TEXT NOT NULL,
    confidence REAL NOT NULL,
    false_positive_reasons_json TEXT,      -- Serialized Vec<FalsePositiveReason>
    lines_of_code INTEGER NOT NULL,
    accesses_sensitive_data INTEGER NOT NULL DEFAULT 0,
    on_taint_path INTEGER NOT NULL DEFAULT 0,
    removal_effort TEXT NOT NULL,          -- Trivial/Low/Medium/High
    suggested_action TEXT NOT NULL,        -- Remove/Review/Keep/Deprecate
    scan_id TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE INDEX idx_dead_code_scan ON dead_code(scan_id);
CREATE INDEX idx_dead_code_confidence ON dead_code(confidence);
CREATE INDEX idx_dead_code_file ON dead_code(file);
CREATE INDEX idx_dead_code_action ON dead_code(suggested_action);

-- Coverage gap results
CREATE TABLE coverage_gaps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    table_name TEXT NOT NULL,
    field_name TEXT NOT NULL,
    sensitivity TEXT NOT NULL,             -- Critical/High/Medium/Low
    total_paths INTEGER NOT NULL,
    covered_paths INTEGER NOT NULL,
    coverage_percentage REAL NOT NULL,
    risk_weight REAL NOT NULL,
    scan_id TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE INDEX idx_coverage_scan ON coverage_gaps(scan_id);
CREATE INDEX idx_coverage_sensitivity ON coverage_gaps(sensitivity);

-- Uncovered paths (detail table for coverage gaps)
CREATE TABLE uncovered_paths (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_point_id TEXT NOT NULL,
    data_access_table TEXT NOT NULL,
    data_access_fields TEXT NOT NULL,
    sensitivity TEXT NOT NULL,
    risk TEXT NOT NULL,
    path_json TEXT NOT NULL,              -- Serialized Vec<CallPathNode>
    suggested_test_target TEXT,
    scan_id TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE INDEX idx_uncovered_scan ON uncovered_paths(scan_id);
CREATE INDEX idx_uncovered_sensitivity ON uncovered_paths(sensitivity);

-- Function impact scores (PageRank-based)
CREATE TABLE function_impact_scores (
    function_id TEXT PRIMARY KEY,
    score REAL NOT NULL,
    rank INTEGER NOT NULL,
    pagerank REAL NOT NULL,
    caller_centrality REAL NOT NULL,
    callee_centrality REAL NOT NULL,
    is_entry_point INTEGER NOT NULL DEFAULT 0,
    accesses_sensitive INTEGER NOT NULL DEFAULT 0,
    scan_id TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE INDEX idx_impact_scores_scan ON function_impact_scores(scan_id);
CREATE INDEX idx_impact_scores_rank ON function_impact_scores(rank);
CREATE INDEX idx_impact_scores_score ON function_impact_scores(score);

-- Git impact analysis results
CREATE TABLE git_impact (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    git_ref TEXT NOT NULL,
    base_ref TEXT NOT NULL,
    changed_files_count INTEGER NOT NULL,
    changed_functions_count INTEGER NOT NULL,
    combined_blast_radius INTEGER NOT NULL,
    risk_level TEXT NOT NULL,
    risk_score REAL NOT NULL,
    result_json TEXT NOT NULL,             -- Full serialized GitImpactResult
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE INDEX idx_git_impact_ref ON git_impact(git_ref);
CREATE INDEX idx_git_impact_risk ON git_impact(risk_level);
```

---

## 19. NAPI Interface

### 19.1 NAPI Functions

```rust
use napi_derive::napi;

/// Impact analysis — blast radius for a function change.
#[napi]
pub fn analyze_impact(
    function_id: String,
    options: Option<JsImpactOptions>,
) -> napi::Result<JsImpactResult> {
    let rt = crate::runtime::get()?;
    let result = rt.impact_engine.analyze_impact(
        &function_id,
        options.as_ref().map(|o| o.into()).as_ref(),
    ).map_err(to_napi_error)?;
    Ok(JsImpactResult::from(result))
}

/// Dead code detection.
#[napi]
pub fn detect_dead_code(
    options: Option<JsDeadCodeOptions>,
) -> napi::Result<Vec<JsDeadCodeCandidate>> {
    let rt = crate::runtime::get()?;
    let candidates = rt.impact_engine.dead_code.detect(
        options.as_ref().map(|o| o.into()).as_ref(),
    ).map_err(to_napi_error)?;
    Ok(candidates.into_iter().map(JsDeadCodeCandidate::from).collect())
}

/// Path finding between two functions.
#[napi]
pub fn find_call_paths(
    from_file: String,
    from_line: u32,
    to_file: String,
    to_line: u32,
    options: Option<JsPathOptions>,
) -> napi::Result<Vec<JsFoundPath>> {
    let rt = crate::runtime::get()?;
    let from = CodeLocation { file: from_file, line: from_line, ..Default::default() };
    let to = CodeLocation { file: to_file, line: to_line, ..Default::default() };
    let paths = rt.impact_engine.path_finder.find_paths(
        &from, &to, options.as_ref().map(|o| o.into()).as_ref(),
    ).map_err(to_napi_error)?;
    Ok(paths.into_iter().map(JsFoundPath::from).collect())
}

/// Coverage gap analysis.
#[napi]
pub fn analyze_coverage_gaps() -> napi::Result<JsCoverageResult> {
    let rt = crate::runtime::get()?;
    let graph = rt.impact_engine.reachability.graph()
        .ok_or_else(|| napi::Error::from_reason("Graph not loaded"))?;
    let test_functions = rt.impact_engine.get_test_functions(graph)
        .map_err(to_napi_error)?;
    let result = rt.impact_engine.coverage.analyze(&test_functions)
        .map_err(to_napi_error)?;
    Ok(JsCoverageResult::from(result))
}

/// Function impact scores (PageRank-based).
#[napi]
pub fn get_function_impact_scores(
    top_n: Option<u32>,
) -> napi::Result<Vec<JsFunctionImpactScore>> {
    let rt = crate::runtime::get()?;
    let graph = rt.impact_engine.reachability.graph()
        .ok_or_else(|| napi::Error::from_reason("Graph not loaded"))?;
    let mut scores = rt.impact_engine.enrichment.compute_all_impact_scores(graph);
    if let Some(n) = top_n {
        scores.truncate(n as usize);
    }
    Ok(scores.into_iter().map(JsFunctionImpactScore::from).collect())
}

/// Git diff impact analysis.
#[napi]
pub fn analyze_git_impact(
    repo_path: String,
    base_ref: String,
    head_ref: String,
) -> napi::Result<JsGitImpactResult> {
    let rt = crate::runtime::get()?;
    let git_analyzer = GitImpactAnalyzer {
        impact: Arc::clone(&rt.impact_engine_arc),
    };
    let result = git_analyzer.analyze_diff(&repo_path, &base_ref, &head_ref)
        .map_err(to_napi_error)?;
    Ok(JsGitImpactResult::from(result))
}

/// Batch impact analysis for multiple functions.
#[napi]
pub fn analyze_batch_impact(
    function_ids: Vec<String>,
) -> napi::Result<JsBatchBlastRadius> {
    let rt = crate::runtime::get()?;
    let result = rt.impact_engine.get_batch_blast_radius(&function_ids)
        .map_err(to_napi_error)?;
    Ok(JsBatchBlastRadius::from(result))
}

/// Invalidate impact cache.
#[napi]
pub fn invalidate_impact_cache() -> napi::Result<()> {
    let rt = crate::runtime::get()?;
    rt.impact_engine.invalidate_cache();
    Ok(())
}
```

### 19.2 NAPI Function Registry

| Function | Sync/Async | Returns | V1 Equivalent |
|----------|-----------|---------|---------------|
| `analyze_impact(id, options?)` | Sync | `JsImpactResult` | NEW (was TS-only) |
| `detect_dead_code(options?)` | Sync | `Vec<JsDeadCodeCandidate>` | NEW (was TS-only) |
| `find_call_paths(from, to, options?)` | Sync | `Vec<JsFoundPath>` | get_call_path (Rust, enhanced) |
| `analyze_coverage_gaps()` | Sync | `JsCoverageResult` | NEW (was TS-only) |
| `get_function_impact_scores(top_n?)` | Sync | `Vec<JsFunctionImpactScore>` | NEW |
| `analyze_git_impact(repo, base, head)` | Sync | `JsGitImpactResult` | NEW |
| `analyze_batch_impact(ids)` | Sync | `JsBatchBlastRadius` | NEW |
| `invalidate_impact_cache()` | Sync | `void` | NEW |

Total: 8 NAPI functions (vs 0 dedicated impact functions in v1). All new.



---

## 20. MCP Tool Interface

### 20.1 MCP Tools

```typescript
// drift_impact — Change impact analysis (preserved + massively enhanced)
{
  name: "drift_impact",
  description: "Analyze blast radius of changing a function. Shows affected functions, " +
    "entry points, sensitive data paths, taint flows, test coverage, and risk assessment.",
  parameters: {
    function: "function name or file:line (required)",
    include_tests: "boolean — include test coverage data (default: true)",
    include_taint: "boolean — include taint flow data (default: true)",
    max_depth: "number — max reverse BFS depth (default: 50)",
    format: "summary | detailed | json (default: summary)",
  },
  token_cost: "~800-2000 depending on blast radius size"
}

// drift_dead_code — Dead code detection (NEW)
{
  name: "drift_dead_code",
  description: "Find functions that are never called. Reports confidence, false positive " +
    "analysis, lines of code, sensitive data access, and suggested action.",
  parameters: {
    min_confidence: "number — minimum confidence to report (default: 0.50)",
    file: "optional file path filter",
    language: "optional language filter",
    sort_by: "confidence | lines_of_code | file (default: confidence)",
    max_results: "number (default: 50)",
    include_false_positives: "boolean — show FP analysis (default: true)",
  },
  token_cost: "~500-1500 depending on candidate count"
}

// drift_path_finder — Path finding between functions (NEW)
{
  name: "drift_path_finder",
  description: "Find call paths between any two functions. Supports BFS (shortest by hops), " +
    "Dijkstra (shortest by confidence), and K-shortest paths.",
  parameters: {
    from: "source function (file:line or function name)",
    to: "target function (file:line or function name)",
    algorithm: "bfs | dijkstra | yen (default: bfs)",
    max_paths: "number (default: 5)",
    max_depth: "number (default: 30)",
    min_confidence: "number — minimum edge confidence (default: 0.40)",
  },
  token_cost: "~300-800 depending on path count"
}

// drift_coverage_gaps — Coverage gap analysis (NEW)
{
  name: "drift_coverage_gaps",
  description: "Find sensitive data paths without test coverage. Reports field-level " +
    "coverage, risk-weighted score, and minimum test set for maximum coverage.",
  parameters: {
    sensitivity: "Critical | High | Medium | all (default: all)",
    include_minimum_test_set: "boolean (default: true)",
    format: "summary | detailed | json (default: summary)",
  },
  token_cost: "~600-1200 depending on path count"
}

// drift_function_ranking — Function impact ranking (NEW)
{
  name: "drift_function_ranking",
  description: "Rank functions by impact score (PageRank-inspired). Shows the most " +
    "critical functions in the codebase — changing these has the widest blast radius.",
  parameters: {
    top_n: "number — how many to return (default: 20)",
    file: "optional file filter",
    entry_points_only: "boolean (default: false)",
  },
  token_cost: "~400-800"
}

// drift_git_impact — Git diff impact analysis (NEW)
{
  name: "drift_git_impact",
  description: "Analyze the blast radius of a git diff (branch, commit, or PR). " +
    "Maps changed lines to functions, computes combined impact, and assesses risk.",
  parameters: {
    base: "base git ref (default: main)",
    head: "head git ref (default: HEAD)",
    format: "summary | detailed | json (default: summary)",
  },
  token_cost: "~1000-3000 depending on diff size"
}
```

---

## 21. CLI Interface

```bash
# Impact analysis
drift impact --function updateUser
drift impact --file src/services/payment.ts --line 100
drift impact --function processOrder --include-taint --format detailed

# Dead code detection
drift dead-code
drift dead-code --min-confidence 0.80
drift dead-code --file src/ --sort-by lines_of_code
drift dead-code --language python --max-results 100

# Path finding
drift path --from src/api/users.ts:42 --to src/db/queries.ts:15
drift path --from getUserById --to executeQuery --algorithm dijkstra
drift path --from handleRequest --to writeToDb --algorithm yen --max-paths 5

# Coverage gaps
drift coverage-gaps
drift coverage-gaps --sensitivity Critical
drift coverage-gaps --include-minimum-test-set

# Function ranking
drift ranking --top 20
drift ranking --file src/services/ --entry-points-only

# Git impact
drift git-impact
drift git-impact --base main --head feature/payment-refactor
drift git-impact --format json > impact-report.json

# Batch impact
drift impact --batch src/services/user.ts:updateUser,src/services/payment.ts:processPayment
```

---

## 22. Event Interface

```rust
/// Events emitted by the impact analysis engine.
/// Per D5: DriftEventHandler trait with no-op defaults.
pub trait ImpactEventHandler: Send + Sync {
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

    /// Coverage gap analysis completed.
    fn on_coverage_analysis(
        &self,
        result: &CoverageResult,
    ) {}

    /// High-risk change detected (risk >= High).
    fn on_high_risk_change(
        &self,
        function_id: &str,
        risk: &RiskAssessment,
    ) {}

    /// Sanitizer disruption detected (critical security event).
    fn on_sanitizer_disruption(
        &self,
        function_id: &str,
        affected_flows: &[AffectedTaintFlow],
    ) {}

    /// Cache hit.
    fn on_cache_hit(&self, key: &ImpactCacheKey) {}

    /// Cache miss.
    fn on_cache_miss(&self, key: &ImpactCacheKey) {}

    /// Git impact analysis completed.
    fn on_git_impact(
        &self,
        result: &GitImpactResult,
    ) {}
}

/// No-op implementation for standalone mode (per D5).
pub struct NoOpImpactEventHandler;
impl ImpactEventHandler for NoOpImpactEventHandler {}
```

---

## 23. Tracing & Observability

```rust
// All impact operations are instrumented with tracing spans.
// Key metrics to track:

// Impact analysis
// - impact.analyze.query_time_us (histogram)
// - impact.analyze.blast_radius (histogram)
// - impact.analyze.risk_level (counter per level)
// - impact.analyze.risk_score (histogram)
// - impact.cache.hit_rate (gauge)

// Dead code
// - dead_code.detect.query_time_us (histogram)
// - dead_code.detect.candidates (gauge)
// - dead_code.detect.high_confidence (gauge)
// - dead_code.detect.false_positive_rate (gauge)

// Path finding
// - path_finder.find.query_time_us (histogram)
// - path_finder.find.paths_found (histogram)
// - path_finder.find.algorithm (counter per algorithm)

// Coverage
// - coverage.analyze.query_time_us (histogram)
// - coverage.analyze.coverage_percentage (gauge)
// - coverage.analyze.critical_uncovered (gauge)
// - coverage.analyze.risk_weighted_score (gauge)

// Git impact
// - git_impact.analyze.query_time_us (histogram)
// - git_impact.analyze.changed_functions (histogram)
// - git_impact.analyze.combined_blast_radius (histogram)
// - git_impact.analyze.risk_level (counter per level)
```

---

## 24. Performance Targets & Benchmarks

| Operation | Target | Measurement |
|-----------|--------|-------------|
| Impact analysis (10K functions) | < 5ms | p99 latency |
| Impact analysis (100K functions) | < 50ms | p99 latency |
| Impact analysis (500K functions) | < 200ms | p99 latency |
| Dead code detection (10K functions) | < 100ms | single pass |
| Dead code detection (100K functions) | < 500ms | single pass |
| Dead code detection (500K functions) | < 2s | single pass |
| Path finding BFS (10K functions) | < 5ms | p99 latency |
| Path finding Dijkstra (100K functions) | < 50ms | p99 latency |
| Path finding Yen K=5 (100K functions) | < 250ms | p99 latency |
| Coverage analysis (10K functions) | < 200ms | single pass |
| Coverage analysis (100K functions) | < 2s | single pass |
| PageRank scoring (100K functions, 10 iter) | < 5s | single pass |
| Git impact (100 changed functions) | < 1s | single analysis |
| Batch impact (10 functions) | < 100ms | single batch |
| Cache hit | < 100μs | p99 latency |
| Memory: impact engine overhead | < 10MB | RSS above call graph |

### Benchmark Suite

```rust
#[cfg(test)]
mod benchmarks {
    use criterion::{criterion_group, criterion_main, Criterion};

    fn bench_impact_analysis(c: &mut Criterion) {
        let engine = setup_impact_engine(100_000);
        c.bench_function("impact_100k", |b| {
            b.iter(|| engine.analyze_impact(&random_function_id(), None))
        });
    }

    fn bench_dead_code_detection(c: &mut Criterion) {
        let engine = setup_impact_engine(100_000);
        c.bench_function("dead_code_100k", |b| {
            b.iter(|| engine.dead_code.detect(None))
        });
    }

    fn bench_path_finding_bfs(c: &mut Criterion) {
        let engine = setup_impact_engine(100_000);
        c.bench_function("path_bfs_100k", |b| {
            b.iter(|| engine.path_finder.find_paths(
                &random_location(), &random_location(), None
            ))
        });
    }

    fn bench_path_finding_dijkstra(c: &mut Criterion) {
        let engine = setup_impact_engine(100_000);
        let opts = PathOptions {
            algorithm: Some(PathAlgorithm::Dijkstra),
            ..Default::default()
        };
        c.bench_function("path_dijkstra_100k", |b| {
            b.iter(|| engine.path_finder.find_paths(
                &random_location(), &random_location(), Some(&opts)
            ))
        });
    }

    fn bench_pagerank(c: &mut Criterion) {
        let engine = setup_impact_engine(100_000);
        let graph = engine.reachability.graph().unwrap();
        c.bench_function("pagerank_100k", |b| {
            b.iter(|| engine.enrichment.compute_all_impact_scores(graph))
        });
    }

    criterion_group!(
        benches,
        bench_impact_analysis,
        bench_dead_code_detection,
        bench_path_finding_bfs,
        bench_path_finding_dijkstra,
        bench_pagerank,
    );
    criterion_main!(benches);
}
```



---

## 25. Build Order & Dependencies

### 25.1 Module Structure

```
drift-core/src/impact/
├── mod.rs                    # Module exports
├── engine.rs                 # ImpactEngine (unified, owns all sub-engines)
├── blast_radius.rs           # Blast radius computation (reverse BFS + metrics)
├── risk.rs                   # Multi-dimensional risk scoring (6 factors)
├── dead_code.rs              # DeadCodeDetector (10 FP categories)
├── dead_code_confidence.rs   # Bayesian confidence scoring
├── path_finder.rs            # PathFinder (BFS, Dijkstra, Yen's K-shortest)
├── path_scoring.rs           # Weighted path scoring
├── coverage.rs               # CoverageAnalyzer (call graph × test topology)
├── enrichment.rs             # EnrichmentPipeline (PageRank + remediation)
├── git_impact.rs             # GitImpactAnalyzer (diff-based impact)
├── simulation.rs             # ImpactProvider trait for simulation engine
├── cache.rs                  # LRU cache with invalidation
├── types.rs                  # All types (results, options, enums)
└── error.rs                  # ImpactError enum
```

### 25.2 Build Order

```
Phase 1: Types & Infrastructure (Week 1)
  1. types.rs — all result types, option types, enums
  2. error.rs — ImpactError with thiserror
  3. cache.rs — LRU cache with invalidation keys

Phase 2: Core Engines (Weeks 2-3)
  4. blast_radius.rs — reverse BFS with metric collection
  5. risk.rs — 6-factor weighted risk scoring
  6. engine.rs — ImpactEngine (unified, wires everything together)

Phase 3: Dead Code (Weeks 3-4)
  7. dead_code.rs — DeadCodeDetector with 10 FP categories
  8. dead_code_confidence.rs — Bayesian confidence (noisy-OR)

Phase 4: Path Finding (Week 4)
  9. path_finder.rs — BFS + Dijkstra + Yen's K-shortest
  10. path_scoring.rs — weighted path scoring

Phase 5: Coverage & Enrichment (Weeks 5-6)
  11. coverage.rs — CoverageAnalyzer with minimum test set
  12. enrichment.rs — PageRank scoring + remediation generation

Phase 6: Advanced Features (Weeks 6-7)
  13. git_impact.rs — git2 integration for diff-based impact
  14. simulation.rs — ImpactProvider trait implementation

Phase 7: NAPI + Integration (Week 8)
  15. NAPI bindings for all 8 functions
  16. MCP tool implementations
  17. CLI command implementations
```

### 25.3 Crate Dependencies

```toml
[dependencies]
# Core (from drift-core)
petgraph = "0.6"              # Graph data structure + algorithms
lru = "0.12"                  # LRU cache
regex = "1"                   # Pattern matching
ordered-float = "4"           # OrderedFloat for BinaryHeap
parking_lot = "0.12"          # Mutex (faster than std)

# From drift-core
rusqlite = { version = "0.31", features = ["bundled"] }
rustc-hash = "1"              # FxHashMap
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "1"
tracing = "0.1"

# Git integration
git2 = { version = "0.19", optional = true }

[features]
default = ["git"]
git = ["dep:git2"]
```

### 25.4 Dependency Graph

```
                    ┌─────────────────────────────────────┐
                    │         ImpactEngine                 │
                    │  (engine.rs — owns everything)       │
                    └──┬──────┬──────┬──────┬──────┬──────┘
                       │      │      │      │      │
              ┌────────▼┐ ┌──▼────┐ ┌▼─────┐ ┌──▼──┐ ┌──▼──────┐
              │BlastRad.│ │DeadCd.│ │PathFd.│ │Covg.│ │Enrichmt.│
              │blast_   │ │dead_  │ │path_  │ │covg.│ │enrichmt.│
              │radius.rs│ │code.rs│ │finder │ │.rs  │ │.rs      │
              └────┬────┘ └──┬────┘ └──┬────┘ └──┬──┘ └────┬────┘
                   │         │         │         │          │
                   └─────────┴─────────┴─────────┴──────────┘
                                       │
                              ┌────────▼────────┐
                              │ ReachabilityEng. │
                              │ (Arc<>, shared)  │
                              └────────┬────────┘
                                       │
                              ┌────────▼────────┐
                              │   CallGraph      │
                              │ (petgraph, Arc<>)│
                              └─────────────────┘
```

---

## 26. V1 → V2 Feature Cross-Reference

| V1 Feature | V1 Location | V2 Location | Status |
|-----------|-------------|-------------|--------|
| Impact analysis (TS) | `analysis/impact-analyzer.ts` | `impact/blast_radius.rs` | Ported to Rust |
| Risk scoring (TS) | `analysis/impact-analyzer.ts` | `impact/risk.rs` | Upgraded (6 factors) |
| Dead code detection (TS) | `analysis/dead-code-detector.ts` | `impact/dead_code.rs` | Ported to Rust |
| Dead code FP (5 categories) | `analysis/dead-code-detector.ts` | `impact/dead_code.rs` | Expanded to 10 |
| Path finding (Rust + TS) | `reachability/engine.rs` + `analysis/path-finder.ts` | `impact/path_finder.rs` | Upgraded (3 algorithms) |
| Coverage analysis (TS) | `analysis/coverage-analyzer.ts` | `impact/coverage.rs` | Ported to Rust |
| Sensitivity classifier (TS) | `enrichment/sensitivity-classifier.ts` | Reachability engine | Merged into Rust |
| Impact scorer (TS) | `enrichment/impact-scorer.ts` | `impact/enrichment.rs` | Upgraded (PageRank) |
| Remediation generator (TS) | `enrichment/remediation-generator.ts` | `impact/enrichment.rs` | Ported + expanded |
| MCP: drift_impact_analysis | `packages/mcp` | `packages/mcp` | Preserved + enhanced |
| MCP: drift_callers | `packages/mcp` | `packages/mcp` | Preserved |
| NAPI: get_call_graph_callers | `drift-napi` | `drift-napi` | Preserved |
| Taint-aware impact | N/A | `impact/blast_radius.rs` | NEW |
| Bayesian dead code confidence | N/A | `impact/dead_code_confidence.rs` | NEW |
| Dijkstra weighted paths | N/A | `impact/path_finder.rs` | NEW |
| Yen's K-shortest paths | N/A | `impact/path_finder.rs` | NEW |
| Coverage minimum test set | N/A | `impact/coverage.rs` | NEW |
| PageRank function ranking | N/A | `impact/enrichment.rs` | NEW |
| Git diff impact | N/A | `impact/git_impact.rs` | NEW |
| Batch impact analysis | N/A | `impact/engine.rs` | NEW |
| Cross-service impact | N/A | `impact/engine.rs` (P2) | NEW (P2) |
| LLM false positive reduction | N/A | `impact/engine.rs` (P2) | NEW (P2) |

---

## 27. Inconsistencies & Decisions

### I1: Impact Analysis Scope (Resolved)

**Issue**: The 14-REACHABILITY-ANALYSIS-V2-PREP doc includes impact analysis (§10),
dead code (§11), coverage (§12), and path finding (§13) as subsections. This document
creates a dedicated deep-dive. Which is canonical?

**Decision**: This document (17-IMPACT-ANALYSIS-V2-PREP) is the canonical implementation
spec for impact analysis. The reachability doc provides the BFS engine that impact
analysis consumes. The reachability doc's §10-§13 are architectural overviews; this
document provides the full implementation detail, including types, algorithms, storage,
NAPI, MCP, CLI, and build order.

### I2: Dead Code Confidence Model (Resolved)

**Issue**: V1 uses simple string levels ('high'/'medium'/'low'). The reachability doc
(§11) uses a simple inverse mapping (0 FP → 0.95, 1 → 0.50, 2 → 0.25, 3+ → 0.10).
This document uses Bayesian noisy-OR.

**Decision**: Bayesian noisy-OR is the v2 implementation. The simple inverse mapping
in the reachability doc was a placeholder. The noisy-OR model correctly handles the
case where multiple weak FP reasons compound differently than multiple strong reasons.

### I3: Path Finding Algorithm Selection (Resolved)

**Issue**: V1 only has BFS. Should v2 default to Dijkstra?

**Decision**: Default to BFS for backward compatibility and simplicity. Dijkstra and
Yen's K-shortest are available via the `algorithm` option. BFS is faster for most
queries and produces intuitive results (shortest by hop count). Dijkstra is better
when edge confidence varies significantly.

### I4: Risk Scoring Weights (Resolved)

**Issue**: What should the default risk scoring weights be?

**Decision**: Entry points (0.25) + sensitive data (0.25) + callers (0.20) + coverage
(0.15) + taint (0.10) + depth (0.05) = 1.0. These are calibrated based on the
principle that security impact (entry points + sensitive data = 0.50) should dominate,
followed by breadth (callers = 0.20), then coverage (0.15), then taint (0.10), then
depth (0.05). Weights are configurable in `drift.toml`.

### I5: Git Integration Dependency (Resolved)

**Issue**: Should git2 be a required dependency?

**Decision**: Optional. The `git` feature flag enables git2. Without it, git impact
analysis is unavailable but all other impact features work. This keeps the core
dependency footprint small for environments without git.

### I6: PageRank Iteration Count (Resolved)

**Issue**: How many PageRank iterations?

**Decision**: 10 iterations with damping factor 0.85. This is the standard PageRank
configuration. For 100K functions, 10 iterations converge within 0.001 of the true
values. More iterations provide diminishing returns.

### I7: Dead Code in Reachability vs Impact Module (Resolved)

**Issue**: Should dead code detection live in the reachability module or the impact module?

**Decision**: Impact module. Dead code detection is a change intelligence feature
("what can I safely remove?"), not a reachability feature ("what can this code reach?").
It shares the call graph with reachability but has different consumers (quality gates,
CI agent, MCP tools focused on cleanup).

---

## 28. Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Dead code false positives from dynamic dispatch | High | Medium | 10 FP categories, Bayesian confidence, LLM validation (P2) |
| Risk scoring miscalibration | Medium | Medium | Configurable weights, sigmoid normalization, empirical tuning |
| PageRank convergence for cyclic graphs | Low | Low | 10 iterations sufficient, damping factor prevents divergence |
| Git integration performance for large diffs | Medium | Medium | Batch impact analysis, function-level caching |
| Path finding explosion for dense graphs | Medium | Medium | max_depth (30), max_paths (10), min_confidence filter |
| Coverage analysis false negatives (missed tests) | Medium | Medium | Multiple test detection heuristics, framework-aware |
| Yen's K-shortest performance for K>10 | Low | Low | Default K=5, max K=20, bounded by max_depth |
| Cross-service impact requires service discovery | High | Medium | Defer to P2, require explicit configuration |
| Bayesian confidence cold start | Medium | Low | Conservative base prior (0.95), rapid convergence with evidence |
| Cache invalidation misses (stale results) | Low | High | Conservative invalidation, version-based cache keys |
| Sigmoid normalization parameter sensitivity | Medium | Low | Empirically tuned defaults, configurable per-project |
| LLM false positive reduction cost | Medium | Medium | P2 feature, opt-in, token budget limits |
