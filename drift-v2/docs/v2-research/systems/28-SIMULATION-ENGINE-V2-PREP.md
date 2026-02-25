# Simulation Engine (Speculative Execution) — V2 Implementation Prep

> Comprehensive build specification for Drift v2's Simulation Engine — the pre-flight
> speculative execution system that generates, scores, ranks, and recommends implementation
> approaches before a single line of code is written.
> Synthesized from: 13-advanced/simulation-engine.md (overview, architecture, pipeline),
> 13-advanced/simulation/engine.md (SimulationEngine orchestrator, 6-step pipeline,
> configuration, default weights, confidence calculation),
> 13-advanced/simulation/approach-generator.md (ApproachGenerator, 5-step generation
> pipeline, category detection, language/framework detection, file scanning),
> 13-advanced/simulation/scorers.md (4 scorers: FrictionScorer 5-factor model,
> ImpactScorer call-graph-powered + fallback estimation, PatternAlignmentScorer
> pattern compliance, SecurityScorer data access + auth implications),
> 13-advanced/simulation/language-strategies.md (5 language providers: TypeScript/Python/
> Java/C#/PHP, ~53 strategy templates, 13 task categories, 12 keyword sets,
> LanguageStrategyProvider interface, FrameworkDefinition, StrategyTemplate),
> 13-advanced/simulation/types.md (SimulationTask, SimulationApproach, ScoringWeights,
> SimulationOptions, FrictionMetrics, ImpactMetrics, PatternAlignmentMetrics,
> SecurityMetrics, SimulatedApproach, SimulationResult, ApproachTradeoff),
> 09-QUALITY-GATES-V2-PREP.md (§5.5 ImpactSimulationGate — Rust implementation,
> friction score formula, breaking risk classification, GateViolation generation),
> 19-COUPLING-ANALYSIS-V2-PREP.md (§21 coupling_friction() — coupling contribution
> to simulation friction, zone-based multipliers),
> 04-INFRASTRUCTURE.md (thiserror, tracing, DriftEventHandler, FxHashMap, SmallVec),
> 03-NAPI-BRIDGE-V2-PREP.md (§5 minimize NAPI crossing, §9 batch API, §10 function
> registry, §7 AsyncTask pattern, §6 structured error codes),
> 02-STORAGE-V2-PREP.md (drift.db schema, keyset pagination),
> DRIFT-V2-FULL-SYSTEM-AUDIT.md (Cat 13, A13),
> DRIFT-V2-STACK-HIERARCHY.md (Level 4 Intelligence),
> PLANNING-DRIFT.md (D1-D7),
> CodeScene change coupling analysis (behavioral code analysis, hotspot scoring),
> Monte Carlo simulation research (probabilistic risk assessment for approach ranking),
> Qodo code quality metrics (code churn rate, maintainability index),
> existing cortex-napi patterns (singleton runtime, error codes, batch API).
>
> Purpose: Everything needed to build the Simulation Engine from scratch. All v1 features
> preserved and upgraded. Hybrid architecture: Rust for heavy computation (impact analysis,
> pattern matching, call graph traversal, coupling friction), TypeScript for orchestration
> (approach generation, composite scoring, tradeoff generation, recommendation). Every
> algorithm specified. Every type defined. Every integration point documented. Every
> architectural decision resolved. Zero feature loss.
> Generated: 2026-02-08

---

## Table of Contents

1. Architectural Position
2. V1 Complete Feature Inventory — Preservation Matrix
3. V2 Architecture — Hybrid Simulation Engine
4. Core Data Model (Rust Types)
5. Core Data Model (TypeScript Types)
6. Approach Generator — TS Orchestration Layer
7. Language Strategy System — Static Configuration
8. Friction Scorer — 5-Factor Development Friction Model
9. Impact Scorer — Call-Graph-Powered Blast Radius
10. Pattern Alignment Scorer — Codebase Convention Compliance
11. Security Scorer — Risk Assessment
12. Composite Scoring & Ranking Algorithm
13. Tradeoff Generation & Confidence Calculation
14. Simulation Engine Orchestrator — Main Pipeline
15. Coupling Integration — Zone-Based Friction Contribution
16. Quality Gate Integration — Impact Simulation Gate
17. Caching & Incremental Simulation
18. Graceful Degradation — No Call Graph / No Patterns
19. Persistence — SQLite in drift.db
20. NAPI Bridge Interface
21. MCP Tool Interface
22. CLI Interface
23. Error Handling & Observability
24. License Gating — Tier Mapping
25. V2 Enhancements — Monte Carlo Confidence Intervals
26. V2 Enhancements — Temporal Friction (Git History)
27. V2 Enhancements — Constraint-Aware Simulation
28. V2 Enhancements — Multi-Language Project Support
29. V2 Enhancements — Approach Comparison Visualization
30. Resolved Inconsistencies
31. File Module Structure
32. Build Order & Dependency Chain
33. V1 Feature Verification — Complete Gap Analysis
34. Summary of All Decisions

---

## 1. Architectural Position

The Simulation Engine is Level 4 (Intelligence) in Drift's stack hierarchy. It is the
system that synthesizes upstream analysis (call graph, patterns, boundaries, coupling,
constraints, security) into predictive recommendations — answering "what is the best way
to implement this change?" before any code is written.

Per PLANNING-DRIFT.md D1: Drift is standalone. Simulation lives entirely in drift-core
(Rust computation) + packages/drift (TS orchestration).
Per PLANNING-DRIFT.md D5: Simulation lifecycle events emit via DriftEventHandler.
Per PLANNING-DRIFT.md D6: Simulation results persist in drift.db.

This is an enterprise feature requiring a commercial license for production use.

### What Lives Here

- SimulationEngine orchestrator (TS — main pipeline coordinator)
- ApproachGenerator (TS — candidate approach generation from task descriptions)
- 4 scoring dimensions (Rust-backed computation + TS coordination):
  - FrictionScorer — 5-factor development friction estimation
  - ImpactScorer — call-graph-powered blast radius analysis
  - PatternAlignmentScorer — codebase convention compliance
  - SecurityScorer — data access + auth risk assessment
- Language strategy system (Rust static config — 5 languages, ~53 templates)
- Composite scoring, ranking, and recommendation engine (TS)
- Tradeoff generation and confidence calculation (TS)
- Coupling integration (Rust — zone-based friction contribution)
- Constraint-aware simulation (Rust — constraint verification pre-check)
- Simulation result caching (Rust — SQLite-backed)
- Persistence layer (Rust — drift.db tables)
- NAPI bridge functions (Rust — thin wrappers)
- MCP tool exposure (TS — drift_simulate tool)

### What Does NOT Live Here

- Call graph construction (lives in Call Graph Builder — simulation consumes it)
- Pattern detection (lives in Detector System — simulation consumes patterns)
- Boundary detection (lives in Boundary Detection — simulation consumes security data)
- Coupling analysis (lives in Coupling Analysis — simulation consumes coupling metrics)
- Constraint mining (lives in Constraint System — simulation consumes constraints)
- Taint analysis (lives in Taint Analysis — simulation consumes taint paths)
- Quality gate orchestration (lives in Quality Gates — gates consume simulation results)
- MCP tool routing (lives in MCP Server — calls simulation APIs)
- CLI command parsing (lives in CLI — calls simulation APIs)

### Upstream Dependencies (What Simulation Consumes)

| System | What It Provides | How Simulation Uses It |
|--------|-----------------|----------------------|
| Call Graph (05) | Function edges, reachability, entry points | Impact scorer blast radius analysis |
| Detector System (06) | Approved patterns with confidence | Pattern alignment scoring |
| Boundary Detection (07) | Data access points, sensitive fields | Security scorer data access analysis |
| Coupling Analysis (19) | Module metrics, zone classifications | Coupling friction contribution |
| Constraint System (20) | Active constraints, verification | Constraint-aware approach filtering |
| Taint Analysis (15) | Source→sink paths, CWE mappings | Security scorer enrichment |
| Scanner (00) | File list, content hashes | Approach generator file scanning |
| Parsers (01) | ParseResult with AST data | Language/framework detection |
| Storage (02) | drift.db SQLite with WAL mode | All persistence |
| Infrastructure (04) | Error types, tracing, events, config | Cross-cutting concerns |

### Downstream Consumers (What Depends on Simulation)

| Consumer | What It Reads | Interface |
|----------|--------------|-----------|
| Quality Gates | Impact simulation gate input | Rust API: `simulate_impact()` |
| MCP Server | Simulation results for AI-assisted planning | `drift_simulate` tool |
| CLI | Simulation results for developer planning | `drift simulate` command |
| NAPI Bridge | Simulation execution, result queries | `run_simulation()`, `query_simulations()` |
| IDE / LSP | Real-time simulation on task description | Pre-implementation preview |
| DriftEventHandler | Simulation lifecycle events | `on_simulation_complete` |
| Context Generation | Simulation results for AI context | Simulation summaries |

---

## 2. V1 Complete Feature Inventory — Preservation Matrix

Every v1 feature is accounted for. Nothing is dropped without replacement.

### 2.1 Core Components (v1 → v2)

| v1 Feature | v1 Implementation | v2 Status | v2 Location |
|-----------|-------------------|-----------|-------------|
| SimulationEngine (6-step pipeline) | TS, ~300 lines | **UPGRADED** — TS orchestration + Rust scoring | §14 |
| ApproachGenerator (5-step pipeline) | TS, ~250 lines | **UPGRADED** — TS with Rust-backed file scanning | §6 |
| FrictionScorer (5-factor model) | TS, ~150 lines | **UPGRADED** — Rust computation + coupling integration | §8 |
| ImpactScorer (call graph + fallback) | TS, ~200 lines | **UPGRADED** — Rust call graph traversal | §9 |
| PatternAlignmentScorer | TS, ~100 lines | **UPGRADED** — Rust pattern matching | §10 |
| SecurityScorer (data access + auth) | TS, ~150 lines | **UPGRADED** — Rust + taint integration | §11 |
| Language strategies (5 providers) | TS, ~800 lines | **UPGRADED** — Rust static config structs | §7 |
| Task category detection (13 categories) | TS, keyword matching | **KEPT** — same algorithm, Rust option | §6 |
| Framework detection (12 frameworks) | TS, import/file patterns | **UPGRADED** — Rust parser-backed | §6 |
| Composite scoring (weighted average) | TS, arithmetic | **KEPT** — same formula | §12 |
| Approach ranking (sort by composite) | TS, sort | **KEPT** — same algorithm | §12 |
| Tradeoff generation (pairwise) | TS, comparison | **KEPT** — same algorithm | §13 |
| Confidence calculation | TS, multi-factor | **UPGRADED** — Monte Carlo enhancement | §13 |
| Graceful degradation (no call graph) | TS, estimation fallback | **KEPT** — same fallback logic | §18 |
| SimulationResult output | TS, typed result | **UPGRADED** — persisted to drift.db | §19 |
| Types (~130 lines, 15+ interfaces) | TS types.ts | **UPGRADED** — Rust types + TS mirrors | §4, §5 |

### 2.2 Scoring Algorithms (v1 → v2)

| v1 Algorithm | v1 Complexity | v2 Status | v2 Changes |
|-------------|---------------|-----------|------------|
| Friction: 5-factor composite | O(1) per approach | **UPGRADED** — +coupling factor, +git history | §8 |
| Impact: call graph BFS reachability | O(V+E) per approach | **KEPT** — Rust implementation | §9 |
| Impact: fallback estimation | O(1) per approach | **KEPT** — same heuristics | §9 |
| Impact: risk score (4-component) | O(1) per approach | **KEPT** — same thresholds | §9 |
| Impact: breaking change detection | O(1) per approach | **KEPT** — same 5 conditions | §9 |
| Pattern alignment: keyword matching | O(p×k) per approach | **KEPT** — Rust for large pattern sets | §10 |
| Security: data access classification | O(f) per approach | **UPGRADED** — +taint integration | §11 |
| Composite: weighted average | O(1) per approach | **KEPT** — same weights (0.30/0.25/0.30/0.15) | §12 |
| Ranking: sort by composite score | O(n log n) | **KEPT** — same algorithm | §12 |
| Tradeoff: pairwise comparison | O(n²) | **KEPT** — same algorithm | §13 |
| Confidence: score gap + data quality | O(1) | **UPGRADED** — +Monte Carlo intervals | §13 |

### 2.3 Task Categories (13 — All Preserved)

| Category | v1 Keywords (sample) | v1 Weight | v2 Status |
|----------|---------------------|-----------|-----------|
| `rate-limiting` | rate limit, throttle, quota | 1.0 | **KEPT** |
| `authentication` | auth, login, jwt, token, oauth | 1.0 | **KEPT** |
| `authorization` | permission, role, rbac, acl | 1.0 | **KEPT** |
| `caching` | cache, redis, memcache, ttl | 1.0 | **KEPT** |
| `data-access` | database, query, orm, crud | 0.9 | **KEPT** |
| `error-handling` | error, exception, catch, retry | 0.9 | **KEPT** |
| `validation` | validate, schema, sanitize, dto | 0.9 | **KEPT** |
| `middleware` | middleware, interceptor, filter, guard | 0.9 | **KEPT** |
| `testing` | test, mock, stub, fixture, assert | 0.9 | **KEPT** |
| `api-endpoint` | endpoint, route, api, rest | 0.8 | **KEPT** |
| `logging` | log, trace, audit, telemetry | 0.8 | **KEPT** |
| `refactoring` | refactor, restructure, simplify | 0.7 | **KEPT** |
| `generic` | (fallback when no match) | — | **KEPT** |

### 2.4 Approach Strategies (15 — All Preserved)

| Strategy | v1 Description | v2 Status |
|----------|---------------|-----------|
| `middleware` | Framework middleware pipeline | **KEPT** |
| `decorator` | Decorator/annotation pattern | **KEPT** |
| `wrapper` | Wrapper/adapter around existing code | **KEPT** |
| `per-route` | Per-route/endpoint configuration | **KEPT** |
| `per-function` | Per-function implementation | **KEPT** |
| `centralized` | Single centralized implementation | **KEPT** |
| `distributed` | Distributed across multiple files | **KEPT** |
| `aspect` | Aspect-oriented cross-cutting | **KEPT** |
| `filter` | Filter/pipe pattern | **KEPT** |
| `interceptor` | Request/response interceptor | **KEPT** |
| `guard` | Guard/gate pattern | **KEPT** |
| `policy` | Policy-based authorization | **KEPT** |
| `dependency` | Dependency injection | **KEPT** |
| `mixin` | Mixin/trait composition | **KEPT** |
| `custom` | User-defined strategy | **KEPT** |

### 2.5 Language Coverage (5 Languages, 12 Frameworks — All Preserved)

| Language | v1 Frameworks | v1 Strategy Count | v2 Status |
|----------|--------------|-------------------|-----------|
| TypeScript | Express, NestJS, Fastify | ~15 | **KEPT** + Hono, tRPC |
| Python | FastAPI, Flask, Django | ~12 | **KEPT** + Litestar |
| Java | Spring Boot, Quarkus | ~10 | **KEPT** + Micronaut |
| C# | ASP.NET Core | ~8 | **KEPT** + Minimal APIs |
| PHP | Laravel, Symfony | ~8 | **KEPT** |

JavaScript shares the TypeScript provider (preserved from v1).

### 2.6 Scoring Weights (Preserved Exactly)

| Scorer | v1 Weight | v2 Weight | Status |
|--------|-----------|-----------|--------|
| Friction | 0.30 | 0.30 | **PRESERVED** |
| Impact | 0.25 | 0.25 | **PRESERVED** |
| Pattern Alignment | 0.30 | 0.30 | **PRESERVED** |
| Security | 0.15 | 0.15 | **PRESERVED** |

Weights are configurable per-simulation (v1 feature preserved).

### 2.7 Default Options (Preserved Exactly)

| Option | v1 Default | v2 Default | Status |
|--------|-----------|-----------|--------|
| maxApproaches | 5 | 5 | **PRESERVED** |
| maxDepth | 10 | 10 | **PRESERVED** |
| includeSecurityAnalysis | true | true | **PRESERVED** |
| minPatternConfidence | 0.5 | 0.5 | **PRESERVED** |
| timeout | 30000ms | 30000ms | **PRESERVED** |
| enableCache | true | true | **PRESERVED** |



---

## 3. V2 Architecture — Hybrid Simulation Engine

### Architectural Split: Rust Computation + TS Orchestration

The simulation engine is a hybrid system. Heavy computation (call graph traversal, pattern
matching, coupling analysis, security data flow) runs in Rust for performance. Orchestration
(task parsing, approach generation, composite scoring, tradeoff generation, recommendation
synthesis) stays in TypeScript for flexibility and rapid iteration.

This split is deliberate: the orchestration logic is lightweight coordination that benefits
from TypeScript's flexibility, while the scoring backends are computationally intensive
operations that benefit from Rust's performance.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         PRESENTATION LAYER (TS)                             │
│  CLI (drift simulate)  │  MCP (drift_simulate)  │  IDE/LSP  │  Dashboard   │
├─────────────────────────────────────────────────────────────────────────────┤
│                    SIMULATION ENGINE ORCHESTRATOR (TS)                       │
│  SimulationEngine → ApproachGenerator → ScorerCoordinator → RankingEngine  │
│  → TradeoffGenerator → ConfidenceCalculator → ResultBuilder                │
├──────────┬──────────┬──────────────┬──────────┬─────────────────────────────┤
│ Friction │ Impact   │ Pattern      │ Security │ Coupling                    │
│ Scorer   │ Scorer   │ Alignment    │ Scorer   │ Integration                 │
│ (Hybrid) │ (Rust)   │ (Rust)       │ (Rust)   │ (Rust)                      │
├──────────┴──────────┴──────────────┴──────────┴─────────────────────────────┤
│                    LANGUAGE STRATEGY SYSTEM (Rust Static Config)             │
│  TypeScript │ Python │ Java │ C# │ PHP                                      │
│  (per-framework templates for 13 task categories, ~53+ strategies)          │
├─────────────────────────────────────────────────────────────────────────────┤
│                    EXTERNAL DEPENDENCIES (Rust)                              │
│  CallGraph │ PatternService │ CouplingEngine │ ConstraintEngine │ Taint     │
├─────────────────────────────────────────────────────────────────────────────┤
│                    PERSISTENCE (Rust via drift.db)                           │
│  simulation_runs │ simulation_approaches │ simulation_cache                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                    EVENTS (Rust → TS via DriftEventHandler)                  │
│  on_simulation_started │ on_simulation_complete │ on_approach_scored         │
└─────────────────────────────────────────────────────────────────────────────┘
```

### What Runs in Rust (Performance-Critical)

| Component | Why Rust | Called Via |
|-----------|----------|-----------|
| Impact scorer: call graph BFS/DFS | O(V+E) traversal on large graphs | NAPI `score_impact()` |
| Impact scorer: entry point identification | Graph reachability analysis | NAPI `score_impact()` |
| Impact scorer: sensitive data path tracing | Data flow analysis | NAPI `score_impact()` |
| Pattern alignment: pattern set matching | Large pattern sets (100K+) | NAPI `score_alignment()` |
| Security scorer: data access classification | Boundary + taint integration | NAPI `score_security()` |
| Coupling friction: zone-based calculation | Module graph traversal | NAPI `coupling_friction()` |
| Constraint verification: pre-check | AST predicate evaluation | NAPI `verify_constraints()` |
| Language strategies: template lookup | Static config, zero-cost | NAPI `get_strategies()` |
| Simulation caching: hash-based lookup | SQLite read/write | NAPI `check_simulation_cache()` |
| Result persistence: drift.db writes | SQLite batch inserts | NAPI `persist_simulation()` |

### What Stays in TypeScript (Coordination & Synthesis)

| Component | Why TS | Rationale |
|-----------|--------|-----------|
| SimulationEngine orchestrator | Pure coordination logic | No heavy computation |
| ApproachGenerator | Task parsing + template instantiation | String manipulation, flexible |
| Task category detection | Keyword matching | Lightweight, configurable |
| Framework detection | Import/file pattern matching | Leverages Rust parsers optionally |
| Composite scoring | Weighted arithmetic | Trivial computation |
| Ranking engine | Array sort | Trivial computation |
| Tradeoff generation | Pairwise comparison text | Natural language synthesis |
| Confidence calculation | Multi-factor heuristic | Lightweight math |
| Result builder | Object construction | Data assembly |
| MCP tool handler | Tool routing + response formatting | MCP protocol handling |

### Execution Pipeline (V2 — 10 Steps)

```
 1. parseTask()           — Parse task description → detect category + scope + constraints
 2. detectEnvironment()   — Detect language, framework, project structure
 3. generateApproaches()  — Generate candidate approaches from language strategies
 4. checkCache()          — Check simulation_cache for identical task+context hash
 5. scoreApproaches()     — Score each approach across 4 dimensions (parallel in Rust)
 6. integrateCoupling()   — Enrich friction scores with coupling data (Rust)
 7. rankApproaches()      — Compute composite scores, sort, assign ranks
 8. generateTradeoffs()   — Pairwise comparison between top approaches
 9. calculateConfidence() — Overall confidence in recommendation
10. persistAndReturn()    — Write to drift.db, emit events, return SimulationResult
```

Steps 4, 6, and 10 are new in v2. The core pipeline structure is preserved from v1
with targeted enhancements for caching, coupling integration, and persistence.

---

## 4. Core Data Model (Rust Types)

### 4.1 Task & Constraint Types

```rust
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Task categories for simulation. All 13 v1 categories preserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TaskCategory {
    RateLimiting,
    Authentication,
    Authorization,
    ApiEndpoint,
    DataAccess,
    ErrorHandling,
    Caching,
    Logging,
    Testing,
    Validation,
    Middleware,
    Refactoring,
    Generic,
}

impl TaskCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RateLimiting => "rate-limiting",
            Self::Authentication => "authentication",
            Self::Authorization => "authorization",
            Self::ApiEndpoint => "api-endpoint",
            Self::DataAccess => "data-access",
            Self::ErrorHandling => "error-handling",
            Self::Caching => "caching",
            Self::Logging => "logging",
            Self::Testing => "testing",
            Self::Validation => "validation",
            Self::Middleware => "middleware",
            Self::Refactoring => "refactoring",
            Self::Generic => "generic",
        }
    }

    /// All categories in detection priority order.
    pub fn all() -> &'static [TaskCategory] {
        &[
            Self::RateLimiting, Self::Authentication, Self::Authorization,
            Self::Caching, Self::DataAccess, Self::ErrorHandling,
            Self::Validation, Self::Middleware, Self::Testing,
            Self::ApiEndpoint, Self::Logging, Self::Refactoring,
            Self::Generic,
        ]
    }
}

/// Simulation task scope. Preserved from v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TaskScope {
    Function,
    File,
    Module,
    Codebase,
}

/// Constraint types for simulation tasks. Preserved from v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConstraintType {
    MustWorkWith,
    AvoidChanging,
    MaxFiles,
    PatternRequired,
    FrameworkRequired,
    Custom,
}

/// A constraint on the simulation task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationConstraint {
    pub constraint_type: ConstraintType,
    pub value: String,
    pub description: Option<String>,
    pub required: bool,
}

/// The simulation task — what the developer wants to implement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationTask {
    pub description: String,
    pub category: Option<TaskCategory>,
    pub target: Option<String>,
    pub constraints: Vec<SimulationConstraint>,
    pub scope: Option<TaskScope>,
}
```

### 4.2 Approach & Strategy Types

```rust
/// Approach strategies. All 15 v1 strategies preserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApproachStrategy {
    Middleware,
    Decorator,
    Wrapper,
    PerRoute,
    PerFunction,
    Centralized,
    Distributed,
    Aspect,
    Filter,
    Interceptor,
    Guard,
    Policy,
    Dependency,
    Mixin,
    Custom,
}

impl ApproachStrategy {
    /// Inherent risk factor for impact scoring. Preserved from v1.
    pub fn risk_factor(&self) -> f64 {
        match self {
            Self::Middleware => 5.0,
            Self::Decorator => 4.0,
            Self::Wrapper => 8.0,
            Self::PerRoute => 10.0,
            Self::PerFunction => 12.0,
            Self::Centralized => 3.0,
            Self::Distributed => 12.0,
            Self::Aspect => 6.0,
            Self::Filter => 5.0,
            Self::Interceptor => 6.0,
            Self::Guard => 4.0,
            Self::Policy => 5.0,
            Self::Dependency => 7.0,
            Self::Mixin => 8.0,
            Self::Custom => 10.0,
        }
    }

    /// Testing effort multiplier for friction scoring. Preserved from v1.
    pub fn testing_effort_multiplier(&self) -> f64 {
        match self {
            Self::Middleware | Self::Filter | Self::Interceptor => 0.6,
            Self::Centralized | Self::Guard | Self::Policy => 0.5,
            Self::Decorator | Self::Aspect => 0.7,
            Self::Wrapper | Self::Dependency | Self::Mixin => 0.8,
            Self::PerRoute | Self::PerFunction | Self::Distributed => 1.0,
            Self::Custom => 0.9,
        }
    }
}

/// A candidate implementation approach.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationApproach {
    pub id: String,
    pub name: String,
    pub description: String,
    pub strategy: ApproachStrategy,
    pub language: String,
    pub framework: Option<String>,
    pub target_files: Vec<String>,
    pub target_functions: Option<Vec<String>>,
    pub new_files: Option<Vec<String>>,
    pub follows_patterns: Option<Vec<String>>,
    pub estimated_lines_added: Option<u32>,
    pub estimated_lines_modified: Option<u32>,
    pub template: Option<String>,
    pub framework_notes: Option<String>,
}
```


### 4.3 Scoring Metric Types

```rust
/// Risk level classification. Preserved from v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn from_score(score: f64) -> Self {
        if score >= 75.0 { Self::Critical }
        else if score >= 50.0 { Self::High }
        else if score >= 25.0 { Self::Medium }
        else { Self::Low }
    }
}

/// Friction metrics — 5-factor model. Preserved from v1 + coupling extension.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrictionMetrics {
    pub code_churn: f64,            // 0–100
    pub pattern_deviation: f64,     // 0–100
    pub testing_effort: f64,        // 0–100
    pub refactoring_required: f64,  // 0–100
    pub learning_curve: f64,        // 0–100
    pub coupling_friction: f64,     // 0–100 (NEW v2: from coupling analysis)
    pub temporal_friction: f64,     // 0–100 (NEW v2: from git history)
    pub overall_score: f64,         // 0–100 (composite)
    pub reasoning: Vec<String>,     // Per-factor explanations
}

/// Impact metrics — call-graph-powered. Preserved from v1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactMetrics {
    pub files_affected: u32,
    pub functions_affected: u32,
    pub entry_points_affected: u32,
    pub sensitive_data_paths: u32,
    pub risk_score: f64,            // 0–100
    pub risk_level: RiskLevel,
    pub breaking_changes: bool,
    pub breaking_change_risks: Vec<String>,
    pub max_depth_affected: u32,
}

/// Pattern alignment metrics. Preserved from v1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternAlignmentMetrics {
    pub alignment_score: f64,       // 0–100
    pub aligned_patterns: Vec<String>,
    pub conflicting_patterns: Vec<String>,
    pub outlier_risk: bool,
    pub suggested_patterns: Vec<String>,
}

/// Data access implication for security scoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataAccessImplication {
    pub function_name: String,
    pub file: String,
    pub sensitivity_level: String,  // "low", "medium", "high", "critical"
    pub data_type: String,          // "pii", "financial", "auth", "system"
}

/// Security metrics. Preserved from v1 + taint enrichment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityMetrics {
    pub security_risk: f64,         // 0–100
    pub data_access_implications: Vec<DataAccessImplication>,
    pub auth_implications: Vec<String>,
    pub warnings: Vec<String>,
    pub taint_paths_affected: u32,  // NEW v2: from taint analysis
    pub cwe_ids: Vec<u32>,          // NEW v2: CWE identifiers
}

/// Scored approach — all 4 dimensions + composite. Preserved from v1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulatedApproach {
    pub approach: SimulationApproach,
    pub friction: FrictionMetrics,
    pub impact: ImpactMetrics,
    pub pattern_alignment: PatternAlignmentMetrics,
    pub security: SecurityMetrics,
    pub composite_score: f64,
    pub rank: u32,
    pub reasoning: String,
    pub pros: Vec<String>,
    pub cons: Vec<String>,
    pub warnings: Vec<String>,
    pub next_steps: Vec<String>,
    pub constraint_violations: Vec<String>,  // NEW v2: constraint pre-check
}

/// Tradeoff comparison between two approaches. Preserved from v1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApproachTradeoff {
    pub approach1: String,
    pub approach2: String,
    pub comparison: String,
    pub winner: Option<String>,
}

/// Monte Carlo confidence interval. NEW v2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceInterval {
    pub lower_bound: f64,
    pub upper_bound: f64,
    pub mean: f64,
    pub std_dev: f64,
    pub samples: u32,
}

/// Complete simulation result. Preserved from v1 + v2 extensions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationResult {
    pub id: String,                 // NEW v2: unique simulation ID
    pub task: SimulationTask,
    pub approaches: Vec<SimulatedApproach>,
    pub recommended: SimulatedApproach,
    pub summary: String,
    pub tradeoffs: Vec<ApproachTradeoff>,
    pub confidence: f64,
    pub confidence_interval: Option<ConfidenceInterval>,  // NEW v2
    pub metadata: SimulationMetadata,
}

/// Simulation metadata. Preserved from v1 + v2 extensions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationMetadata {
    pub duration_ms: u64,
    pub call_graph_available: bool,
    pub patterns_available: bool,
    pub coupling_available: bool,       // NEW v2
    pub constraints_available: bool,    // NEW v2
    pub taint_available: bool,          // NEW v2
    pub cache_hit: bool,               // NEW v2
    pub detected_language: String,
    pub detected_framework: Option<String>,
    pub approaches_generated: u32,
    pub approaches_scored: u32,
}
```

### 4.4 Configuration Types

```rust
/// Scoring weights. Preserved from v1 — configurable per-simulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoringWeights {
    pub friction: f64,              // Default: 0.30
    pub impact: f64,                // Default: 0.25
    pub pattern_alignment: f64,     // Default: 0.30
    pub security: f64,              // Default: 0.15
}

impl Default for ScoringWeights {
    fn default() -> Self {
        Self {
            friction: 0.30,
            impact: 0.25,
            pattern_alignment: 0.30,
            security: 0.15,
        }
    }
}

/// Simulation options. Preserved from v1 + v2 extensions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationOptions {
    pub max_approaches: u32,            // Default: 5
    pub max_depth: u32,                 // Default: 10
    pub include_security_analysis: bool, // Default: true
    pub min_pattern_confidence: f64,    // Default: 0.5
    pub timeout_ms: u64,               // Default: 30000
    pub enable_cache: bool,            // Default: true
    pub include_coupling: bool,        // Default: true (NEW v2)
    pub include_constraints: bool,     // Default: true (NEW v2)
    pub include_taint: bool,           // Default: true (NEW v2)
    pub monte_carlo_samples: u32,      // Default: 100 (NEW v2)
    pub include_git_history: bool,     // Default: true (NEW v2)
}

impl Default for SimulationOptions {
    fn default() -> Self {
        Self {
            max_approaches: 5,
            max_depth: 10,
            include_security_analysis: true,
            min_pattern_confidence: 0.5,
            timeout_ms: 30_000,
            enable_cache: true,
            include_coupling: true,
            include_constraints: true,
            include_taint: true,
            monte_carlo_samples: 100,
            include_git_history: true,
        }
    }
}

/// Simulation engine configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationConfig {
    pub enabled: bool,
    pub weights: ScoringWeights,
    pub options: SimulationOptions,
}

impl Default for SimulationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            weights: ScoringWeights::default(),
            options: SimulationOptions::default(),
        }
    }
}
```

### 4.5 Error Types

```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SimulationError {
    #[error("Simulation timed out after {timeout_ms}ms")]
    Timeout { timeout_ms: u64 },

    #[error("No approaches generated for task: {description}")]
    NoApproaches { description: String },

    #[error("Scorer failed: {scorer} — {message}")]
    ScorerFailed { scorer: String, message: String },

    #[error("Call graph not available for impact scoring")]
    CallGraphUnavailable,

    #[error("Pattern service not available for alignment scoring")]
    PatternServiceUnavailable,

    #[error("Invalid scoring weights: sum must equal 1.0, got {sum}")]
    InvalidWeights { sum: f64 },

    #[error("Simulation cancelled")]
    Cancelled,

    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl SimulationError {
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::Timeout { .. } => "SIMULATION_TIMEOUT",
            Self::NoApproaches { .. } => "SIMULATION_NO_APPROACHES",
            Self::ScorerFailed { .. } => "SIMULATION_SCORER_FAILED",
            Self::CallGraphUnavailable => "SIMULATION_NO_CALL_GRAPH",
            Self::PatternServiceUnavailable => "SIMULATION_NO_PATTERNS",
            Self::InvalidWeights { .. } => "SIMULATION_INVALID_WEIGHTS",
            Self::Cancelled => "SIMULATION_CANCELLED",
            Self::Storage(_) => "STORAGE_ERROR",
            Self::Internal(_) => "INTERNAL_ERROR",
        }
    }
}
```

---

## 5. Core Data Model (TypeScript Types)

TypeScript mirrors the Rust types for the orchestration layer. These are the types
used by the SimulationEngine, ApproachGenerator, and scorer coordinators.

```typescript
// packages/drift/src/simulation/types.ts

// ─── Task Types ───────────────────────────────────────────────────────────

type TaskCategory =
  | 'rate-limiting' | 'authentication' | 'authorization'
  | 'api-endpoint' | 'data-access' | 'error-handling'
  | 'caching' | 'logging' | 'testing'
  | 'validation' | 'middleware' | 'refactoring' | 'generic';

interface SimulationTask {
  description: string;
  category?: TaskCategory;
  target?: string;
  constraints?: SimulationConstraint[];
  scope?: 'function' | 'file' | 'module' | 'codebase';
}

type ConstraintType = 'must-work-with' | 'avoid-changing' | 'max-files'
  | 'pattern-required' | 'framework-required' | 'custom';

interface SimulationConstraint {
  type: ConstraintType;
  value: string;
  description?: string;
  required?: boolean;
}

// ─── Approach Types ───────────────────────────────────────────────────────

type ApproachStrategy =
  | 'middleware' | 'decorator' | 'wrapper' | 'per-route' | 'per-function'
  | 'centralized' | 'distributed' | 'aspect' | 'filter' | 'interceptor'
  | 'guard' | 'policy' | 'dependency' | 'mixin' | 'custom';

interface SimulationApproach {
  id: string;
  name: string;
  description: string;
  strategy: ApproachStrategy;
  language: string;
  framework?: string;
  targetFiles: string[];
  targetFunctions?: string[];
  newFiles?: string[];
  followsPatterns?: string[];
  estimatedLinesAdded?: number;
  estimatedLinesModified?: number;
  template?: string;
  frameworkNotes?: string;
}

// ─── Scoring Types ────────────────────────────────────────────────────────

interface ScoringWeights {
  friction: number;            // Default: 0.30
  impact: number;              // Default: 0.25
  patternAlignment: number;    // Default: 0.30
  security: number;            // Default: 0.15
}

interface SimulationOptions {
  maxApproaches: number;       // Default: 5
  maxDepth: number;            // Default: 10
  includeSecurityAnalysis: boolean;
  minPatternConfidence: number;
  timeout: number;             // Default: 30000ms
  enableCache: boolean;
  includeCoupling: boolean;    // NEW v2
  includeConstraints: boolean; // NEW v2
  includeTaint: boolean;       // NEW v2
  monteCarloSamples: number;   // NEW v2
  includeGitHistory: boolean;  // NEW v2
}

// ─── Metric Types ─────────────────────────────────────────────────────────

interface FrictionMetrics {
  codeChurn: number;
  patternDeviation: number;
  testingEffort: number;
  refactoringRequired: number;
  learningCurve: number;
  couplingFriction: number;    // NEW v2
  temporalFriction: number;    // NEW v2
  overallScore: number;
  reasoning: string[];
}

interface ImpactMetrics {
  filesAffected: number;
  functionsAffected: number;
  entryPointsAffected: number;
  sensitiveDataPaths: number;
  riskScore: number;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  breakingChanges: boolean;
  breakingChangeRisks: string[];
  maxDepthAffected: number;
}

interface PatternAlignmentMetrics {
  alignmentScore: number;
  alignedPatterns: string[];
  conflictingPatterns: string[];
  outlierRisk: boolean;
  suggestedPatterns: string[];
}

interface SecurityMetrics {
  securityRisk: number;
  dataAccessImplications: DataAccessImplication[];
  authImplications: string[];
  warnings: string[];
  taintPathsAffected: number;  // NEW v2
  cweIds: number[];            // NEW v2
}

// ─── Result Types ─────────────────────────────────────────────────────────

interface SimulatedApproach {
  approach: SimulationApproach;
  friction: FrictionMetrics;
  impact: ImpactMetrics;
  patternAlignment: PatternAlignmentMetrics;
  security: SecurityMetrics;
  compositeScore: number;
  rank: number;
  reasoning: string;
  pros: string[];
  cons: string[];
  warnings: string[];
  nextSteps: string[];
  constraintViolations: string[];  // NEW v2
}

interface SimulationResult {
  id: string;                  // NEW v2
  task: SimulationTask;
  approaches: SimulatedApproach[];
  recommended: SimulatedApproach;
  summary: string;
  tradeoffs: ApproachTradeoff[];
  confidence: number;
  confidenceInterval?: ConfidenceInterval;  // NEW v2
  metadata: SimulationMetadata;
}

interface ApproachTradeoff {
  approach1: string;
  approach2: string;
  comparison: string;
  winner?: string;
}

interface ConfidenceInterval {
  lowerBound: number;
  upperBound: number;
  mean: number;
  stdDev: number;
  samples: number;
}

interface SimulationMetadata {
  duration: number;
  callGraphAvailable: boolean;
  patternsAvailable: boolean;
  couplingAvailable: boolean;      // NEW v2
  constraintsAvailable: boolean;   // NEW v2
  taintAvailable: boolean;         // NEW v2
  cacheHit: boolean;              // NEW v2
  detectedLanguage: string;
  detectedFramework?: string;
  approachesGenerated: number;
  approachesScored: number;
}
```


---

## 6. Approach Generator — TS Orchestration Layer

### Purpose

Generates candidate implementation approaches for a given task. Detects the task category,
target language, and framework, then produces language-specific strategy templates as
concrete approaches. This is the creative engine — it explores the solution space.

### Pipeline: `generate(task) → GeneratedApproaches`

#### Step 1: Detect Task Category (Preserved from v1)

Uses weighted keyword matching against the task description. 13 category keyword sets:

```typescript
const CATEGORY_KEYWORDS: Record<TaskCategory, { keywords: string[]; weight: number }[]> = {
  'rate-limiting': [
    { keywords: ['rate limit', 'rate-limit', 'ratelimit'], weight: 1.0 },
    { keywords: ['throttle', 'throttling'], weight: 1.0 },
    { keywords: ['quota', 'request limit'], weight: 0.9 },
  ],
  'authentication': [
    { keywords: ['auth', 'authenticate', 'authentication'], weight: 1.0 },
    { keywords: ['login', 'sign in', 'signin'], weight: 1.0 },
    { keywords: ['jwt', 'token', 'oauth', 'session'], weight: 0.9 },
  ],
  'authorization': [
    { keywords: ['permission', 'authorize', 'authorization'], weight: 1.0 },
    { keywords: ['role', 'rbac', 'acl', 'access control'], weight: 1.0 },
  ],
  // ... all 13 categories with full keyword sets
};

function detectTaskCategory(description: string): TaskCategory {
  let bestCategory: TaskCategory = 'generic';
  let bestScore = 0;

  for (const [category, keywordSets] of Object.entries(CATEGORY_KEYWORDS)) {
    let score = 0;
    for (const { keywords, weight } of keywordSets) {
      for (const keyword of keywords) {
        if (description.toLowerCase().includes(keyword)) {
          score += weight;
        }
      }
    }
    if (score > bestScore) {
      bestScore = score;
      bestCategory = category as TaskCategory;
    }
  }

  return bestCategory;
}
```

#### Step 2: Detect Language and Framework (Upgraded in v2)

v1: Scanned project files with TS file system APIs.
v2: Optionally leverages Rust parsers for faster, more accurate detection.

```typescript
async function detectEnvironment(projectRoot: string): Promise<{
  language: string;
  framework?: string;
}> {
  // Try Rust-backed detection first (faster for large projects)
  try {
    const result = await drift.detectProjectEnvironment(projectRoot);
    return { language: result.language, framework: result.framework };
  } catch {
    // Fallback to TS-based detection (v1 algorithm preserved)
    return detectEnvironmentFallback(projectRoot);
  }
}

function detectEnvironmentFallback(projectRoot: string): {
  language: string;
  framework?: string;
} {
  // 1. Scan for language indicators (package.json, requirements.txt, pom.xml, etc.)
  // 2. Read key files to detect framework (import patterns, decorators)
  // 3. Falls back to TypeScript if detection fails
  // Algorithm preserved exactly from v1
}
```

#### Step 3: Find Relevant Files (Preserved from v1)

Searches the project for files matching the task category's keywords.

```typescript
async function findRelevantFiles(
  projectRoot: string,
  category: TaskCategory,
  language: string,
): Promise<string[]> {
  // File path matching + content scanning
  // Uses category-specific file patterns
  // Returns sorted by relevance
}
```

#### Step 4: Find Relevant Patterns (Preserved from v1)

If PatternService is available, queries for patterns matching the task category.

```typescript
async function findRelevantPatterns(
  category: TaskCategory,
): Promise<string[]> {
  if (!patternService) return [];
  const patterns = await patternService.queryByCategory(category);
  return patterns
    .filter(p => p.confidence >= options.minPatternConfidence)
    .map(p => p.name);
}
```

#### Step 5: Generate Approaches (Preserved from v1 + v2 constraint filtering)

For each StrategyTemplate from the language strategy provider:

```typescript
async function generateApproaches(
  task: SimulationTask,
  environment: { language: string; framework?: string },
  relevantFiles: string[],
  relevantPatterns: string[],
): Promise<GeneratedApproaches> {
  // 1. Get strategy templates from language provider (Rust static config)
  const strategies = await drift.getStrategies(
    environment.language,
    task.category ?? 'generic',
    environment.framework,
  );

  const approaches: SimulationApproach[] = [];

  // 2. Instantiate each template as a concrete approach
  for (const template of strategies) {
    approaches.push({
      id: generateApproachId(template),
      name: template.name,
      description: template.description,
      strategy: template.strategy,
      language: environment.language,
      framework: environment.framework,
      targetFiles: relevantFiles.slice(0, 10),
      targetFunctions: callGraph
        ? await findTargetFunctions(relevantFiles, callGraph)
        : undefined,
      newFiles: template.newFiles,
      followsPatterns: relevantPatterns,
      estimatedLinesAdded: template.estimatedLines,
      estimatedLinesModified: Math.floor(template.estimatedLines * 0.3),
      template: template.template,
      frameworkNotes: template.frameworkNotes,
    });
  }

  // 3. Add custom approach (user-defined strategy) — preserved from v1
  approaches.push(createCustomApproach(task, environment, relevantFiles));

  // 4. Add fallback approach (generic implementation) — preserved from v1
  approaches.push(createFallbackApproach(task, environment, relevantFiles));

  // 5. NEW v2: Filter approaches that violate hard constraints
  const filtered = filterByConstraints(approaches, task.constraints ?? []);

  // 6. Limit to maxApproaches
  const limited = filtered.slice(0, options.maxApproaches);

  return {
    task,
    approaches: limited,
    detectedLanguage: environment.language,
    detectedFramework: environment.framework,
    relevantPatterns,
  };
}

// NEW v2: Constraint-aware filtering
function filterByConstraints(
  approaches: SimulationApproach[],
  constraints: SimulationConstraint[],
): SimulationApproach[] {
  return approaches.filter(approach => {
    for (const constraint of constraints) {
      if (!constraint.required) continue;

      switch (constraint.type) {
        case 'avoid-changing':
          if (approach.targetFiles.some(f => f.includes(constraint.value))) {
            return false;
          }
          break;
        case 'max-files':
          if ((approach.targetFiles.length + (approach.newFiles?.length ?? 0))
              > parseInt(constraint.value)) {
            return false;
          }
          break;
        case 'framework-required':
          if (approach.framework !== constraint.value) {
            return false;
          }
          break;
        case 'pattern-required':
          if (!approach.followsPatterns?.includes(constraint.value)) {
            return false;
          }
          break;
      }
    }
    return true;
  });
}
```

---

## 7. Language Strategy System — Static Configuration

### Purpose

Per-language/framework strategy templates that define how specific task categories should
be implemented. Each language provider knows its frameworks and offers tailored approach
templates. In v2, these are Rust static config structs for zero-cost access.

### Rust Implementation

```rust
/// Language strategy provider. One per supported language.
pub struct LanguageStrategyProvider {
    pub language: &'static str,
    pub frameworks: &'static [FrameworkDefinition],
}

/// Framework definition with detection patterns and strategies.
pub struct FrameworkDefinition {
    pub name: &'static str,
    pub language: &'static str,
    pub detect_patterns: &'static [&'static str],   // File patterns
    pub import_patterns: &'static [&'static str],   // Import patterns
    pub strategies: &'static [StrategyTemplate],
}

/// Strategy template — static configuration data.
pub struct StrategyTemplate {
    pub strategy: ApproachStrategy,
    pub name: &'static str,
    pub description: &'static str,
    pub applicable_categories: &'static [TaskCategory],
    pub file_patterns: &'static [&'static str],
    pub pros: &'static [&'static str],
    pub cons: &'static [&'static str],
    pub estimated_lines: u32,
    pub framework_notes: Option<&'static str>,
    pub template: Option<&'static str>,
    pub new_files: Option<&'static [&'static str]>,
}

/// Registry of all language strategy providers.
pub static STRATEGY_PROVIDERS: &[LanguageStrategyProvider] = &[
    TYPESCRIPT_PROVIDER,
    PYTHON_PROVIDER,
    JAVA_PROVIDER,
    CSHARP_PROVIDER,
    PHP_PROVIDER,
];
```

### TypeScript Provider (Example — Express Middleware Strategy)

```rust
static EXPRESS_MIDDLEWARE_RATE_LIMIT: StrategyTemplate = StrategyTemplate {
    strategy: ApproachStrategy::Middleware,
    name: "Express Rate Limiting Middleware",
    description: "Add rate limiting via Express middleware using express-rate-limit",
    applicable_categories: &[TaskCategory::RateLimiting],
    file_patterns: &["**/middleware/**", "**/app.ts", "**/server.ts"],
    pros: &[
        "Centralized — one middleware handles all routes",
        "Well-tested library (express-rate-limit)",
        "Easy to configure per-route overrides",
    ],
    cons: &[
        "Requires Redis for distributed deployments",
        "May need custom key generation for complex auth",
    ],
    estimated_lines: 30,
    framework_notes: Some("Uses express-rate-limit package"),
    template: Some(
        "import rateLimit from 'express-rate-limit';\n\
         const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });\n\
         app.use(limiter);"
    ),
    new_files: Some(&["src/middleware/rate-limiter.ts"]),
};
```

### Language Coverage (v2 — Expanded)

| Language | Frameworks | Strategy Count | v2 Additions |
|----------|-----------|----------------|-------------|
| TypeScript | Express, NestJS, Fastify, Hono, tRPC | ~18 | +Hono, +tRPC |
| Python | FastAPI, Flask, Django, Litestar | ~14 | +Litestar |
| Java | Spring Boot, Quarkus, Micronaut | ~12 | +Micronaut |
| C# | ASP.NET Core, Minimal APIs | ~10 | +Minimal APIs |
| PHP | Laravel, Symfony | ~8 | (unchanged) |

Total: ~62 strategy templates (up from ~53 in v1).

### NAPI Interface for Strategy Lookup

```rust
#[napi(object)]
pub struct StrategyLookupResult {
    pub strategies: Vec<StrategyInfo>,
    pub language: String,
    pub framework: Option<String>,
}

#[napi(object)]
pub struct StrategyInfo {
    pub strategy: String,
    pub name: String,
    pub description: String,
    pub pros: Vec<String>,
    pub cons: Vec<String>,
    pub estimated_lines: u32,
    pub framework_notes: Option<String>,
    pub template: Option<String>,
    pub new_files: Option<Vec<String>>,
}

/// Look up strategy templates for a language/category/framework combination.
/// Returns static config data — zero computation, sub-microsecond.
#[napi]
pub fn get_strategies(
    language: String,
    category: String,
    framework: Option<String>,
) -> napi::Result<StrategyLookupResult> {
    let category = TaskCategory::from_str(&category)
        .map_err(|_| napi::Error::from_reason(
            format!("[SIMULATION_INVALID_CATEGORY] Unknown category: {}", category)
        ))?;

    let provider = find_provider(&language)
        .ok_or_else(|| napi::Error::from_reason(
            format!("[SIMULATION_UNSUPPORTED_LANGUAGE] No strategies for: {}", language)
        ))?;

    let strategies = provider.get_strategies(category, framework.as_deref());

    Ok(StrategyLookupResult {
        strategies: strategies.iter().map(|s| s.into()).collect(),
        language,
        framework,
    })
}
```


---

## 8. Friction Scorer — 5-Factor Development Friction Model

### Purpose

Estimates how much friction a developer would encounter implementing a given approach.
This is the "how hard is this to build?" dimension.

### V1 Algorithm (Preserved) + V2 Extensions

v1 had 5 friction factors. v2 adds 2 more (coupling friction, temporal friction) while
preserving the original 5 exactly.

### Rust Implementation — Scoring Backend

```rust
use crate::types::*;

/// Score the friction of implementing an approach.
/// Returns FrictionMetrics with per-factor breakdown.
///
/// V1 algorithm preserved for the original 5 factors.
/// V2 adds coupling_friction and temporal_friction.
pub fn score_friction(
    approach: &SimulationApproach,
    patterns: &[PatternInfo],
    coupling_data: Option<&CouplingData>,
    git_history: Option<&GitHistoryData>,
) -> FrictionMetrics {
    // Factor 1: Code Churn (PRESERVED from v1)
    // Scales with estimated lines added + modified + new files
    let lines_added = approach.estimated_lines_added.unwrap_or(50) as f64;
    let lines_modified = approach.estimated_lines_modified.unwrap_or(20) as f64;
    let new_files = approach.new_files.as_ref().map_or(0, |f| f.len()) as f64;
    let code_churn = ((lines_added + lines_modified) / 200.0 * 60.0
        + new_files * 10.0).min(100.0);

    // Factor 2: Pattern Deviation (PRESERVED from v1)
    // How far the approach deviates from established patterns
    let pattern_deviation = if patterns.is_empty() {
        50.0 // No patterns = moderate uncertainty
    } else {
        let strategy_name = approach.strategy.as_str();
        let matching = patterns.iter()
            .filter(|p| p.keywords.iter().any(|k| k.contains(strategy_name)))
            .count();
        if matching > 0 {
            // Strategy matches existing patterns — low deviation
            (100.0 - (matching as f64 / patterns.len() as f64 * 100.0)).max(0.0)
        } else {
            // Strategy doesn't match any pattern — high deviation
            80.0
        }
    };

    // Factor 3: Testing Effort (PRESERVED from v1)
    // Estimated test code needed, based on strategy type
    let testing_effort = (lines_added * approach.strategy.testing_effort_multiplier())
        .min(100.0);

    // Factor 4: Refactoring Required (PRESERVED from v1)
    // Scales with number of existing files modified
    let target_files = approach.target_files.len() as f64;
    let refactoring_required = (target_files / 10.0 * 100.0).min(100.0);

    // Factor 5: Learning Curve (PRESERVED from v1)
    // Considers strategy familiarity (common patterns = lower)
    let learning_curve = match approach.strategy {
        ApproachStrategy::Middleware | ApproachStrategy::Filter => 20.0,
        ApproachStrategy::Decorator | ApproachStrategy::Guard => 30.0,
        ApproachStrategy::Centralized | ApproachStrategy::Policy => 25.0,
        ApproachStrategy::Wrapper | ApproachStrategy::Dependency => 40.0,
        ApproachStrategy::Aspect | ApproachStrategy::Mixin => 60.0,
        ApproachStrategy::Interceptor => 35.0,
        ApproachStrategy::PerRoute | ApproachStrategy::PerFunction => 15.0,
        ApproachStrategy::Distributed => 55.0,
        ApproachStrategy::Custom => 50.0,
    };

    // Factor 6: Coupling Friction (NEW v2)
    // From coupling analysis — how tightly coupled are the target modules?
    let coupling_friction = coupling_data
        .map(|cd| calculate_coupling_friction(&approach.target_files, cd))
        .unwrap_or(0.0);

    // Factor 7: Temporal Friction (NEW v2)
    // From git history — how frequently are target files changed?
    // High churn files = more merge conflicts = more friction
    let temporal_friction = git_history
        .map(|gh| calculate_temporal_friction(&approach.target_files, gh))
        .unwrap_or(0.0);

    // Composite score (v1 factors weighted equally, v2 factors contribute 10% each)
    // v1 weight: 80% across 5 factors (16% each)
    // v2 weight: 20% across 2 factors (10% each)
    let overall_score = if coupling_data.is_some() || git_history.is_some() {
        code_churn * 0.16
        + pattern_deviation * 0.16
        + testing_effort * 0.16
        + refactoring_required * 0.16
        + learning_curve * 0.16
        + coupling_friction * 0.10
        + temporal_friction * 0.10
    } else {
        // No v2 data — use v1 equal weighting
        (code_churn + pattern_deviation + testing_effort
         + refactoring_required + learning_curve) / 5.0
    };

    let mut reasoning = Vec::new();
    if code_churn > 60.0 {
        reasoning.push(format!(
            "High code churn: ~{} lines added, ~{} modified",
            lines_added as u32, lines_modified as u32
        ));
    }
    if pattern_deviation > 60.0 {
        reasoning.push("Strategy deviates from established patterns".to_string());
    }
    if testing_effort > 60.0 {
        reasoning.push("Significant testing effort required".to_string());
    }
    if refactoring_required > 60.0 {
        reasoning.push(format!(
            "Refactoring needed across {} existing files",
            approach.target_files.len()
        ));
    }
    if learning_curve > 50.0 {
        reasoning.push("Strategy has a steep learning curve".to_string());
    }
    if coupling_friction > 50.0 {
        reasoning.push("Target modules are tightly coupled".to_string());
    }
    if temporal_friction > 50.0 {
        reasoning.push("Target files have high change frequency (merge conflict risk)".to_string());
    }

    // Invert: high friction = low score (0 = maximum friction, 100 = zero friction)
    FrictionMetrics {
        code_churn,
        pattern_deviation,
        testing_effort,
        refactoring_required,
        learning_curve,
        coupling_friction,
        temporal_friction,
        overall_score: (100.0 - overall_score).max(0.0),
        reasoning,
    }
}
```

### Coupling Friction Calculation (NEW v2)

Integrates with the Coupling Analysis system (19-COUPLING-ANALYSIS-V2-PREP.md §21).

```rust
/// Calculate coupling friction for target files.
/// Uses zone classifications from coupling analysis.
/// Algorithm from 19-COUPLING-ANALYSIS-V2-PREP.md §21.
fn calculate_coupling_friction(
    target_files: &[String],
    coupling_data: &CouplingData,
) -> f64 {
    if target_files.is_empty() {
        return 0.0;
    }

    let mut total_friction = 0.0;

    for file in target_files {
        if let Some(module_metrics) = coupling_data.get_module_metrics(file) {
            // Higher coupling = more friction
            let coupling_factor = (module_metrics.ca + module_metrics.ce) as f64 / 20.0;

            // Zone of pain adds extra friction
            let zone_factor = match module_metrics.zone {
                ZoneClassification::ZoneOfPain => 1.5,
                ZoneClassification::ZoneOfUselessness => 1.2,
                ZoneClassification::Transitional => 1.0,
                ZoneClassification::MainSequence => 0.8,
            };

            total_friction += coupling_factor * zone_factor;
        }
    }

    // Normalize to 0-100
    (total_friction / target_files.len() as f64 * 100.0).min(100.0)
}
```

### Temporal Friction Calculation (NEW v2)

Inspired by [CodeScene's behavioral code analysis](https://codescene.com) — files with
high change frequency have higher merge conflict risk and coordination overhead.

```rust
/// Calculate temporal friction from git history.
/// High churn files = more merge conflicts = more friction.
fn calculate_temporal_friction(
    target_files: &[String],
    git_history: &GitHistoryData,
) -> f64 {
    if target_files.is_empty() || git_history.max_frequency == 0 {
        return 0.0;
    }

    let mut total_friction = 0.0;

    for file in target_files {
        let frequency = git_history.change_frequency.get(file).copied().unwrap_or(0);
        let authors = git_history.author_count.get(file).copied().unwrap_or(1);

        // Normalize frequency to 0-1
        let freq_normalized = frequency as f64 / git_history.max_frequency as f64;

        // Multi-author files have higher coordination friction
        let author_factor = if authors > 3 { 1.5 }
            else if authors > 1 { 1.2 }
            else { 1.0 };

        total_friction += freq_normalized * author_factor * 100.0;
    }

    (total_friction / target_files.len() as f64).min(100.0)
}
```

---

## 9. Impact Scorer — Call-Graph-Powered Blast Radius

### Purpose

Calculates the blast radius of implementing an approach using the call graph.
This is the "how much does this change affect?" dimension.

### With Call Graph (Preserved from v1 — Rust Implementation)

```rust
/// Score the impact of an approach using call graph analysis.
/// Algorithm preserved from v1. Rust implementation for performance.
pub fn score_impact(
    approach: &SimulationApproach,
    call_graph: Option<&CallGraphHandle>,
    max_depth: u32,
) -> ImpactMetrics {
    match call_graph {
        Some(cg) => score_impact_with_call_graph(approach, cg, max_depth),
        None => score_impact_fallback(approach),
    }
}

fn score_impact_with_call_graph(
    approach: &SimulationApproach,
    call_graph: &CallGraphHandle,
    max_depth: u32,
) -> ImpactMetrics {
    let mut files_affected = FxHashSet::default();
    let mut functions_affected = FxHashSet::default();
    let mut entry_points_affected = FxHashSet::default();
    let mut sensitive_data_paths = 0u32;
    let mut max_depth_reached = 0u32;

    // For each target file, find functions in the call graph
    for file in &approach.target_files {
        let functions = call_graph.functions_in_file(file);

        for func in &functions {
            // Trace callers (reverse reachability) — PRESERVED from v1
            let callers = call_graph.reverse_reachability(
                &func.id,
                max_depth as usize,
            );

            for (caller, depth) in &callers {
                functions_affected.insert(caller.id.clone());
                files_affected.insert(caller.file.clone());
                max_depth_reached = max_depth_reached.max(*depth as u32);

                if caller.is_entry_point {
                    entry_points_affected.insert(caller.id.clone());
                }
            }

            // Trace sensitive data paths — PRESERVED from v1
            let paths = call_graph.trace_sensitive_data(&func.id);
            sensitive_data_paths += paths.len() as u32;
        }
    }

    // Risk score calculation — PRESERVED from v1
    // 4-component scoring with exact thresholds
    let files_score = {
        let n = files_affected.len();
        if n > 20 { 25.0 }
        else if n > 10 { 20.0 }
        else if n > 5 { 15.0 }
        else { n as f64 * 2.0 }
    };

    let entry_score = {
        let n = entry_points_affected.len();
        if n > 10 { 30.0 }
        else if n > 5 { 25.0 }
        else if n > 2 { 15.0 }
        else { n as f64 * 5.0 }
    };

    let sensitive_score = {
        let n = sensitive_data_paths;
        if n > 5 { 30.0 }
        else if n > 2 { 20.0 }
        else if n > 0 { 10.0 }
        else { 0.0 }
    };

    let strategy_score = approach.strategy.risk_factor();

    let risk_score = (files_score + entry_score + sensitive_score + strategy_score)
        .min(100.0);

    // Breaking change detection — PRESERVED from v1 (5 conditions)
    let breaking_changes = !entry_points_affected.is_empty()
        || sensitive_data_paths > 0
        || matches!(approach.strategy,
            ApproachStrategy::PerRoute | ApproachStrategy::PerFunction)
        || matches!(approach.strategy, ApproachStrategy::Wrapper)
        || max_depth_reached > 5;

    let mut breaking_change_risks = Vec::new();
    if !entry_points_affected.is_empty() {
        breaking_change_risks.push(format!(
            "{} entry points affected", entry_points_affected.len()
        ));
    }
    if sensitive_data_paths > 0 {
        breaking_change_risks.push(format!(
            "{} sensitive data paths affected", sensitive_data_paths
        ));
    }
    if matches!(approach.strategy,
        ApproachStrategy::PerRoute | ApproachStrategy::PerFunction) {
        breaking_change_risks.push("Distributed changes increase risk".to_string());
    }
    if matches!(approach.strategy, ApproachStrategy::Wrapper) {
        breaking_change_risks.push("Wrapper may change function signatures".to_string());
    }
    if max_depth_reached > 5 {
        breaking_change_risks.push(format!(
            "Impact depth {} exceeds safe threshold (5)", max_depth_reached
        ));
    }

    ImpactMetrics {
        files_affected: files_affected.len() as u32,
        functions_affected: functions_affected.len() as u32,
        entry_points_affected: entry_points_affected.len() as u32,
        sensitive_data_paths,
        risk_score,
        risk_level: RiskLevel::from_score(risk_score),
        breaking_changes,
        breaking_change_risks,
        max_depth_affected: max_depth_reached,
    }
}
```

### Without Call Graph — Fallback Estimation (Preserved from v1)

```rust
/// Fallback impact estimation when call graph is not available.
/// Algorithm preserved exactly from v1.
fn score_impact_fallback(approach: &SimulationApproach) -> ImpactMetrics {
    let target_files = approach.target_files.len() as u32;
    let new_files = approach.new_files.as_ref().map_or(0, |f| f.len()) as u32;

    let files_affected = target_files + new_files;
    let functions_affected = files_affected * 3; // v1 heuristic: 3 functions per file
    let entry_points_affected = match approach.strategy {
        ApproachStrategy::Middleware | ApproachStrategy::Filter
        | ApproachStrategy::Interceptor => 1,
        ApproachStrategy::PerRoute | ApproachStrategy::PerFunction => target_files,
        ApproachStrategy::Centralized => 1,
        ApproachStrategy::Distributed => target_files / 2,
        _ => target_files.min(3),
    };

    let risk_score = {
        let f = if files_affected > 20 { 25.0 }
            else if files_affected > 10 { 20.0 }
            else if files_affected > 5 { 15.0 }
            else { files_affected as f64 * 2.0 };
        let e = if entry_points_affected > 10 { 30.0 }
            else if entry_points_affected > 5 { 25.0 }
            else if entry_points_affected > 2 { 15.0 }
            else { entry_points_affected as f64 * 5.0 };
        let s = approach.strategy.risk_factor();
        (f + e + s).min(100.0)
    };

    ImpactMetrics {
        files_affected,
        functions_affected,
        entry_points_affected,
        sensitive_data_paths: 0, // Cannot estimate without call graph
        risk_score,
        risk_level: RiskLevel::from_score(risk_score),
        breaking_changes: entry_points_affected > 0,
        breaking_change_risks: if entry_points_affected > 0 {
            vec!["Entry points affected (estimated without call graph)".to_string()]
        } else {
            vec![]
        },
        max_depth_affected: 0, // Cannot estimate without call graph
    }
}
```


---

## 10. Pattern Alignment Scorer — Codebase Convention Compliance

### Purpose

Evaluates how well an approach aligns with established codebase patterns.
This is the "does this follow our conventions?" dimension.

### Rust Implementation

```rust
/// Score pattern alignment for an approach.
/// Algorithm preserved from v1. Rust implementation for large pattern sets.
pub fn score_alignment(
    approach: &SimulationApproach,
    patterns: &[PatternInfo],
    min_confidence: f64,
) -> PatternAlignmentMetrics {
    if patterns.is_empty() {
        return PatternAlignmentMetrics {
            alignment_score: 50.0, // Neutral — no patterns to compare against
            aligned_patterns: vec![],
            conflicting_patterns: vec![],
            outlier_risk: false,
            suggested_patterns: vec![],
        };
    }

    // Filter to patterns above confidence threshold
    let relevant: Vec<_> = patterns.iter()
        .filter(|p| p.confidence >= min_confidence)
        .collect();

    if relevant.is_empty() {
        return PatternAlignmentMetrics {
            alignment_score: 50.0,
            aligned_patterns: vec![],
            conflicting_patterns: vec![],
            outlier_risk: false,
            suggested_patterns: vec![],
        };
    }

    let strategy_name = approach.strategy.as_str();
    let mut aligned = Vec::new();
    let mut conflicting = Vec::new();
    let mut suggested = Vec::new();

    for pattern in &relevant {
        // Check if approach strategy matches pattern keywords
        let matches_strategy = pattern.keywords.iter()
            .any(|k| k.to_lowercase().contains(strategy_name));

        // Check if approach targets overlap with pattern locations
        let matches_files = approach.target_files.iter()
            .any(|f| pattern.files.iter().any(|pf| pf.contains(f.as_str())));

        if matches_strategy || matches_files {
            aligned.push(pattern.name.clone());
        } else if pattern.category == approach.strategy.as_str() {
            // Same category but different strategy — potential conflict
            conflicting.push(pattern.name.clone());
        }

        // Suggest patterns that the approach could follow
        if !matches_strategy && pattern.confidence > 0.8 {
            suggested.push(pattern.name.clone());
        }
    }

    // Calculate alignment score (PRESERVED from v1)
    let total = aligned.len() + conflicting.len();
    let alignment_score = if total == 0 {
        50.0 // No relevant patterns — neutral
    } else {
        let ratio = aligned.len() as f64 / total as f64;
        ratio * 100.0
    };

    // Outlier risk: approach would be the only one using this strategy
    let outlier_risk = aligned.is_empty() && !conflicting.is_empty();

    PatternAlignmentMetrics {
        alignment_score,
        aligned_patterns: aligned,
        conflicting_patterns: conflicting,
        outlier_risk,
        suggested_patterns: suggested,
    }
}
```

---

## 11. Security Scorer — Risk Assessment

### Purpose

Assesses security implications of an approach. This is the "is this safe?" dimension.

### Rust Implementation (v1 Algorithm + v2 Taint Enrichment)

```rust
/// Score security risk for an approach.
/// V1 algorithm preserved. V2 adds taint analysis integration.
pub fn score_security(
    approach: &SimulationApproach,
    call_graph: Option<&CallGraphHandle>,
    taint_data: Option<&TaintData>,
) -> SecurityMetrics {
    let mut security_risk = 0.0;
    let mut data_access_implications = Vec::new();
    let mut auth_implications = Vec::new();
    let mut warnings = Vec::new();
    let mut taint_paths_affected = 0u32;
    let mut cwe_ids = Vec::new();

    match call_graph {
        Some(cg) => {
            // 1. Data access implications (PRESERVED from v1)
            for file in &approach.target_files {
                let functions = cg.functions_in_file(file);
                for func in &functions {
                    if let Some(access) = cg.get_data_access(&func.id) {
                        data_access_implications.push(DataAccessImplication {
                            function_name: func.name.clone(),
                            file: file.clone(),
                            sensitivity_level: access.sensitivity.to_string(),
                            data_type: access.data_type.to_string(),
                        });

                        // Scale risk by sensitivity
                        security_risk += match access.sensitivity.as_str() {
                            "critical" => 30.0,
                            "high" => 20.0,
                            "medium" => 10.0,
                            _ => 5.0,
                        };
                    }
                }
            }

            // 2. Auth implications (PRESERVED from v1)
            for file in &approach.target_files {
                let functions = cg.functions_in_file(file);
                for func in &functions {
                    if cg.is_auth_related(&func.id) {
                        auth_implications.push(format!(
                            "Function {} in {} is auth-related",
                            func.name, file
                        ));
                        security_risk += 15.0;
                    }
                }
            }

            // 3. NEW v2: Taint analysis integration
            if let Some(taint) = taint_data {
                for file in &approach.target_files {
                    let paths = taint.paths_through_file(file);
                    taint_paths_affected += paths.len() as u32;

                    for path in &paths {
                        if let Some(cwe) = path.cwe_id {
                            if !cwe_ids.contains(&cwe) {
                                cwe_ids.push(cwe);
                            }
                        }
                        security_risk += 10.0;
                    }
                }
            }
        }
        None => {
            // Fallback estimation (PRESERVED from v1)
            security_risk = estimate_security_risk(approach);
        }
    }

    // 4. Warning generation (PRESERVED from v1)
    if !data_access_implications.is_empty() {
        warnings.push(format!(
            "Approach affects {} functions with data access",
            data_access_implications.len()
        ));
    }
    if !auth_implications.is_empty() {
        warnings.push(format!(
            "Approach affects {} auth-related functions",
            auth_implications.len()
        ));
    }
    if taint_paths_affected > 0 {
        warnings.push(format!(
            "Approach intersects {} taint analysis paths",
            taint_paths_affected
        ));
    }

    // Strategy-specific warnings (PRESERVED from v1)
    match approach.strategy {
        ApproachStrategy::Wrapper => {
            warnings.push("Wrapper pattern may bypass existing security checks".to_string());
            security_risk += 10.0;
        }
        ApproachStrategy::Distributed | ApproachStrategy::PerFunction => {
            warnings.push("Distributed changes increase surface area for security gaps".to_string());
            security_risk += 5.0;
        }
        _ => {}
    }

    SecurityMetrics {
        security_risk: security_risk.min(100.0),
        data_access_implications,
        auth_implications,
        warnings,
        taint_paths_affected,
        cwe_ids,
    }
}

/// Fallback security risk estimation without call graph.
/// Algorithm preserved from v1.
fn estimate_security_risk(approach: &SimulationApproach) -> f64 {
    let mut risk = 0.0;

    // Strategy-based risk
    risk += approach.strategy.risk_factor();

    // File name heuristics
    for file in &approach.target_files {
        let lower = file.to_lowercase();
        if lower.contains("auth") || lower.contains("login") || lower.contains("session") {
            risk += 15.0;
        }
        if lower.contains("admin") || lower.contains("permission") || lower.contains("role") {
            risk += 10.0;
        }
        if lower.contains("payment") || lower.contains("billing") || lower.contains("stripe") {
            risk += 20.0;
        }
        if lower.contains("user") || lower.contains("profile") || lower.contains("account") {
            risk += 5.0;
        }
    }

    risk.min(100.0)
}
```

---

## 12. Composite Scoring & Ranking Algorithm

### Purpose

Combines the 4 scoring dimensions into a single composite score per approach,
then ranks approaches by composite score.

### Algorithm (Preserved from v1)

```typescript
// packages/drift/src/simulation/scoring.ts

function computeCompositeScore(
  friction: FrictionMetrics,
  impact: ImpactMetrics,
  alignment: PatternAlignmentMetrics,
  security: SecurityMetrics,
  weights: ScoringWeights,
): number {
  // Each scorer returns 0-100 where higher = better
  // Friction: overallScore is already inverted (100 = no friction)
  // Impact: invert risk score (100 - riskScore = low impact = good)
  // Alignment: alignmentScore (100 = perfect alignment)
  // Security: invert security risk (100 - securityRisk = low risk = good)

  const frictionScore = friction.overallScore;
  const impactScore = 100.0 - impact.riskScore;
  const alignmentScore = alignment.alignmentScore;
  const securityScore = 100.0 - security.securityRisk;

  return (
    frictionScore * weights.friction +
    impactScore * weights.impact +
    alignmentScore * weights.patternAlignment +
    securityScore * weights.security
  );
}

function rankApproaches(
  scoredApproaches: SimulatedApproach[],
): SimulatedApproach[] {
  // Sort by composite score (highest first) — PRESERVED from v1
  const sorted = [...scoredApproaches].sort(
    (a, b) => b.compositeScore - a.compositeScore,
  );

  // Assign ranks
  return sorted.map((approach, index) => ({
    ...approach,
    rank: index + 1,
  }));
}
```

### Generating Pros, Cons, Warnings, and Next Steps

```typescript
function generateApproachInsights(
  approach: SimulatedApproach,
): { pros: string[]; cons: string[]; warnings: string[]; nextSteps: string[] } {
  const pros: string[] = [];
  const cons: string[] = [];
  const warnings: string[] = [];
  const nextSteps: string[] = [];

  // Friction insights
  if (approach.friction.overallScore > 70) {
    pros.push('Low development friction — straightforward implementation');
  } else if (approach.friction.overallScore < 40) {
    cons.push('High development friction — significant effort required');
  }

  // Impact insights
  if (approach.impact.riskScore < 25) {
    pros.push('Low blast radius — minimal impact on existing code');
  } else if (approach.impact.riskScore > 60) {
    cons.push(`High blast radius — affects ${approach.impact.filesAffected} files`);
  }

  // Pattern alignment insights
  if (approach.patternAlignment.alignmentScore > 80) {
    pros.push('Follows established codebase patterns');
  } else if (approach.patternAlignment.outlierRisk) {
    warnings.push('This approach would be an outlier — no existing patterns match');
  }

  // Security insights
  if (approach.security.securityRisk > 50) {
    warnings.push(`Security risk: ${approach.security.warnings.join('; ')}`);
  }

  // Breaking change warnings
  if (approach.impact.breakingChanges) {
    warnings.push(...approach.impact.breakingChangeRisks);
  }

  // Next steps
  nextSteps.push(`Create ${approach.approach.newFiles?.length ?? 0} new file(s)`);
  nextSteps.push(`Modify ${approach.approach.targetFiles.length} existing file(s)`);
  if (approach.impact.entryPointsAffected > 0) {
    nextSteps.push(`Update ${approach.impact.entryPointsAffected} entry point(s)`);
  }
  nextSteps.push('Write tests for the new implementation');

  return { pros, cons, warnings, nextSteps };
}
```

---

## 13. Tradeoff Generation & Confidence Calculation

### Tradeoff Generation (Preserved from v1)

Pairwise comparison between top approaches, highlighting where each excels.

```typescript
function generateTradeoffs(
  approaches: SimulatedApproach[],
): ApproachTradeoff[] {
  const tradeoffs: ApproachTradeoff[] = [];
  const top = approaches.slice(0, 3); // Compare top 3

  for (let i = 0; i < top.length; i++) {
    for (let j = i + 1; j < top.length; j++) {
      const a = top[i];
      const b = top[j];

      const comparison = compareApproaches(a, b);
      const winner = a.compositeScore > b.compositeScore + 5
        ? a.approach.name
        : b.compositeScore > a.compositeScore + 5
          ? b.approach.name
          : undefined; // Too close to call

      tradeoffs.push({
        approach1: a.approach.name,
        approach2: b.approach.name,
        comparison,
        winner,
      });
    }
  }

  return tradeoffs;
}

function compareApproaches(a: SimulatedApproach, b: SimulatedApproach): string {
  const advantages: string[] = [];

  if (a.friction.overallScore > b.friction.overallScore + 10) {
    advantages.push(`${a.approach.name} has lower friction`);
  } else if (b.friction.overallScore > a.friction.overallScore + 10) {
    advantages.push(`${b.approach.name} has lower friction`);
  }

  if (a.impact.riskScore < b.impact.riskScore - 10) {
    advantages.push(`${a.approach.name} has lower impact`);
  } else if (b.impact.riskScore < a.impact.riskScore - 10) {
    advantages.push(`${b.approach.name} has lower impact`);
  }

  if (a.patternAlignment.alignmentScore > b.patternAlignment.alignmentScore + 10) {
    advantages.push(`${a.approach.name} better aligns with patterns`);
  } else if (b.patternAlignment.alignmentScore > a.patternAlignment.alignmentScore + 10) {
    advantages.push(`${b.approach.name} better aligns with patterns`);
  }

  if (a.security.securityRisk < b.security.securityRisk - 10) {
    advantages.push(`${a.approach.name} has lower security risk`);
  } else if (b.security.securityRisk < a.security.securityRisk - 10) {
    advantages.push(`${b.approach.name} has lower security risk`);
  }

  return advantages.length > 0
    ? advantages.join('. ')
    : 'Both approaches are comparable across all dimensions';
}
```

### Confidence Calculation (v1 Algorithm + v2 Monte Carlo Enhancement)

```typescript
function calculateConfidence(
  approaches: SimulatedApproach[],
  metadata: SimulationMetadata,
  options: SimulationOptions,
): { confidence: number; confidenceInterval?: ConfidenceInterval } {
  if (approaches.length < 2) {
    return { confidence: 0.5 }; // Can't be confident with only one approach
  }

  // V1 confidence factors (PRESERVED)
  const scoreGap = approaches[0].compositeScore - approaches[1].compositeScore;
  const gapFactor = Math.min(scoreGap / 20.0, 1.0); // 20+ point gap = max confidence

  const dataFactor = (
    (metadata.callGraphAvailable ? 0.4 : 0.0) +
    (metadata.patternsAvailable ? 0.3 : 0.0) +
    (metadata.couplingAvailable ? 0.15 : 0.0) +
    (metadata.constraintsAvailable ? 0.15 : 0.0)
  );

  const alignmentFactor = approaches[0].patternAlignment.alignmentScore / 100.0;

  // V1 confidence formula (PRESERVED)
  const baseConfidence = gapFactor * 0.4 + dataFactor * 0.35 + alignmentFactor * 0.25;

  // V2 enhancement: Monte Carlo confidence intervals
  let confidenceInterval: ConfidenceInterval | undefined;

  if (options.monteCarloSamples > 0 && approaches.length >= 2) {
    confidenceInterval = computeMonteCarloInterval(
      approaches,
      options.monteCarloSamples,
    );

    // Adjust confidence based on interval width
    // Narrow interval = high confidence, wide interval = low confidence
    const intervalWidth = confidenceInterval.upperBound - confidenceInterval.lowerBound;
    const intervalFactor = 1.0 - Math.min(intervalWidth / 50.0, 0.3);

    return {
      confidence: Math.min(baseConfidence * intervalFactor, 1.0),
      confidenceInterval,
    };
  }

  return { confidence: Math.min(baseConfidence, 1.0) };
}
```


---

## 14. Simulation Engine Orchestrator — Main Pipeline

### Purpose

Main orchestrator for the speculative execution engine. Coordinates approach generation,
multi-dimensional scoring, ranking, and recommendation. This is the entry point.

### TypeScript Implementation

```typescript
// packages/drift/src/simulation/simulation-engine.ts

export class SimulationEngine {
  private approachGenerator: ApproachGenerator;
  private drift: DriftClient;
  private config: SimulationConfig;

  constructor(config: SimulationEngineConfig) {
    this.drift = config.driftClient;
    this.config = {
      weights: { ...DEFAULT_WEIGHTS, ...config.weights },
      options: { ...DEFAULT_OPTIONS, ...config.options },
      enabled: true,
    };
    this.approachGenerator = new ApproachGenerator({
      projectRoot: config.projectRoot,
      driftClient: this.drift,
    });
  }

  /**
   * Main simulation pipeline — 10 steps.
   * V1 pipeline preserved (steps 1-3, 5, 7-9). V2 adds steps 4, 6, 10.
   */
  async simulate(task: SimulationTask): Promise<SimulationResult> {
    const startTime = Date.now();
    const simulationId = generateSimulationId();

    // Emit start event
    this.drift.emitEvent('simulation_started', { task, simulationId });

    try {
      // Step 1: Parse task (detect category if not provided) — PRESERVED
      const resolvedTask = this.resolveTask(task);

      // Step 2: Detect environment (language, framework) — PRESERVED
      const environment = await this.approachGenerator.detectEnvironment();

      // Step 3: Generate candidate approaches — PRESERVED
      const generated = await this.approachGenerator.generate(resolvedTask);

      if (generated.approaches.length === 0) {
        throw new SimulationError('NO_APPROACHES', resolvedTask.description);
      }

      // Step 4: Check cache (NEW v2)
      if (this.config.options.enableCache) {
        const cached = await this.checkCache(resolvedTask, environment);
        if (cached) {
          return { ...cached, metadata: { ...cached.metadata, cacheHit: true } };
        }
      }

      // Step 5: Score each approach across 4 dimensions (PRESERVED — parallel)
      const scored = await this.scoreApproaches(generated.approaches);

      // Step 6: Integrate coupling data (NEW v2)
      if (this.config.options.includeCoupling) {
        await this.integrateCoupling(scored);
      }

      // Step 7: Rank by composite score (PRESERVED)
      const ranked = this.rankApproaches(scored);

      // Step 8: Generate tradeoffs (PRESERVED)
      const tradeoffs = generateTradeoffs(ranked);

      // Step 9: Calculate confidence (PRESERVED + Monte Carlo)
      const metadata: SimulationMetadata = {
        duration: Date.now() - startTime,
        callGraphAvailable: await this.drift.hasCallGraph(),
        patternsAvailable: await this.drift.hasPatterns(),
        couplingAvailable: this.config.options.includeCoupling,
        constraintsAvailable: this.config.options.includeConstraints,
        taintAvailable: this.config.options.includeTaint,
        cacheHit: false,
        detectedLanguage: environment.language,
        detectedFramework: environment.framework,
        approachesGenerated: generated.approaches.length,
        approachesScored: scored.length,
      };

      const { confidence, confidenceInterval } = calculateConfidence(
        ranked, metadata, this.config.options,
      );

      // Build result
      const result: SimulationResult = {
        id: simulationId,
        task: resolvedTask,
        approaches: ranked,
        recommended: ranked[0],
        summary: this.generateSummary(ranked[0], ranked, confidence),
        tradeoffs,
        confidence,
        confidenceInterval,
        metadata,
      };

      // Step 10: Persist and return (NEW v2)
      if (this.config.options.enableCache) {
        await this.persistResult(result);
      }

      // Emit complete event
      this.drift.emitEvent('simulation_complete', {
        simulationId,
        recommended: ranked[0].approach.name,
        confidence,
        duration: metadata.duration,
      });

      return result;

    } catch (error) {
      this.drift.emitEvent('simulation_error', {
        simulationId,
        error: error instanceof Error ? error.message : String(error),
      });
      throw error;
    }
  }

  /**
   * Score all approaches across 4 dimensions.
   * Calls Rust backends via NAPI for heavy computation.
   * V1: all 4 scorers run in parallel. V2: same, via Rust.
   */
  private async scoreApproaches(
    approaches: SimulationApproach[],
  ): Promise<SimulatedApproach[]> {
    const results: SimulatedApproach[] = [];

    for (const approach of approaches) {
      // All 4 scorers run in parallel via Rust NAPI calls
      const [friction, impact, alignment, security] = await Promise.all([
        this.drift.scoreFriction(approach),
        this.drift.scoreImpact(approach, this.config.options.maxDepth),
        this.drift.scoreAlignment(approach, this.config.options.minPatternConfidence),
        this.config.options.includeSecurityAnalysis
          ? this.drift.scoreSecurity(approach)
          : Promise.resolve(neutralSecurityMetrics()),
      ]);

      const compositeScore = computeCompositeScore(
        friction, impact, alignment, security, this.config.weights,
      );

      // Check constraints (NEW v2)
      const constraintViolations = this.config.options.includeConstraints
        ? await this.checkConstraints(approach)
        : [];

      const insights = generateApproachInsights({
        approach, friction, impact, patternAlignment: alignment,
        security, compositeScore, rank: 0,
        reasoning: '', pros: [], cons: [], warnings: [],
        nextSteps: [], constraintViolations,
      });

      results.push({
        approach,
        friction,
        impact,
        patternAlignment: alignment,
        security,
        compositeScore,
        rank: 0, // Assigned in ranking step
        reasoning: this.generateReasoning(approach, compositeScore, friction, impact),
        ...insights,
        constraintViolations,
      });
    }

    return results;
  }

  private generateSummary(
    recommended: SimulatedApproach,
    all: SimulatedApproach[],
    confidence: number,
  ): string {
    const confLabel = confidence > 0.8 ? 'high' :
      confidence > 0.5 ? 'moderate' : 'low';

    return `Recommended: ${recommended.approach.name} ` +
      `(score: ${recommended.compositeScore.toFixed(1)}, ` +
      `confidence: ${confLabel}). ` +
      `${all.length} approaches evaluated. ` +
      `Friction: ${recommended.friction.overallScore.toFixed(0)}/100, ` +
      `Impact: ${(100 - recommended.impact.riskScore).toFixed(0)}/100, ` +
      `Alignment: ${recommended.patternAlignment.alignmentScore.toFixed(0)}/100, ` +
      `Security: ${(100 - recommended.security.securityRisk).toFixed(0)}/100.`;
  }

  private generateReasoning(
    approach: SimulationApproach,
    score: number,
    friction: FrictionMetrics,
    impact: ImpactMetrics,
  ): string {
    const parts: string[] = [];
    parts.push(`${approach.name} scores ${score.toFixed(1)}/100.`);

    if (friction.overallScore > 70) {
      parts.push('Low friction makes this easy to implement.');
    }
    if (impact.riskScore < 25) {
      parts.push('Minimal blast radius keeps risk low.');
    }
    if (impact.breakingChanges) {
      parts.push('Warning: potential breaking changes detected.');
    }

    return parts.join(' ');
  }
}
```

---

## 15. Coupling Integration — Zone-Based Friction Contribution

### Purpose

Enriches friction scores with coupling analysis data. Modules in the "Zone of Pain"
(high coupling, high instability) add extra friction to approaches that touch them.

### Integration Point

From 19-COUPLING-ANALYSIS-V2-PREP.md §21: coupling score contributes to the overall
simulation friction. The coupling_friction() function is called during Step 6 of the
simulation pipeline.

```typescript
// Step 6 in SimulationEngine.simulate()
private async integrateCoupling(
  approaches: SimulatedApproach[],
): Promise<void> {
  try {
    for (const scored of approaches) {
      // Call Rust coupling_friction via NAPI
      const couplingFriction = await this.drift.couplingFriction(
        scored.approach.targetFiles,
      );

      // Update friction metrics with coupling data
      scored.friction.couplingFriction = couplingFriction;

      // Recalculate overall friction score with coupling factor
      scored.friction.overallScore = recalculateFrictionWithCoupling(
        scored.friction,
      );

      // Recalculate composite score
      scored.compositeScore = computeCompositeScore(
        scored.friction,
        scored.impact,
        scored.patternAlignment,
        scored.security,
        this.config.weights,
      );
    }
  } catch {
    // Coupling data unavailable — degrade gracefully
    // Friction scores remain as-is (v1 behavior)
  }
}
```

---

## 16. Quality Gate Integration — Impact Simulation Gate

### Purpose

The Quality Gates system (09-QUALITY-GATES-V2-PREP.md §5.5) includes an Impact Simulation
Gate that uses the simulation engine's impact scoring to evaluate the blast radius of
actual code changes (not hypothetical approaches).

### Integration Contract

The simulation engine exposes a focused API for the quality gate:

```rust
/// Impact simulation for quality gate consumption.
/// This is a subset of the full simulation — only impact scoring.
/// Called by ImpactSimulationGate.evaluate().
///
/// Friction score formula PRESERVED from v1:
///   f = files_affected / max_files * 25
///   fn = functions_affected / max_functions * 25
///   ep = entry_points_affected / max_entry_points * 30
///   sd = sensitive_data_paths * 20
///   friction = min(f + fn + ep + sd, 100)
pub fn simulate_impact_for_gate(
    changed_files: &[String],
    call_graph: &CallGraphHandle,
    config: &ImpactSimulationConfig,
) -> DriftResult<ImpactSimulationGateResult> {
    let mut files_affected = FxHashSet::default();
    let mut functions_affected = FxHashSet::default();
    let mut entry_points_affected = FxHashSet::default();
    let mut sensitive_data_paths = Vec::new();

    for file in changed_files {
        let functions = call_graph.functions_in_file(file);

        for func in &functions {
            let callers = call_graph.reverse_reachability(
                &func.id,
                config.max_data_flow_depth as usize,
            );

            for caller in &callers {
                functions_affected.insert(caller.id.clone());
                files_affected.insert(caller.file.clone());

                if caller.is_entry_point {
                    entry_points_affected.insert(caller.id.clone());
                }
            }

            if config.analyze_sensitive_data {
                let paths = call_graph.trace_sensitive_data(&func.id);
                sensitive_data_paths.extend(paths);
            }
        }
    }

    // Friction score formula — PRESERVED EXACTLY from v1
    let friction_score = {
        let f = files_affected.len() as f64
            / config.max_files_affected as f64 * 25.0;
        let fn_ = functions_affected.len() as f64
            / config.max_functions_affected as f64 * 25.0;
        let ep = entry_points_affected.len() as f64
            / config.max_entry_points_affected as f64 * 30.0;
        let sd = sensitive_data_paths.len() as f64 * 20.0;
        (f + fn_ + ep + sd).min(100.0)
    };

    // Breaking risk classification — PRESERVED from v1
    let breaking_risk = if friction_score > 80.0 {
        BreakingRisk::Critical
    } else if friction_score > 60.0 {
        BreakingRisk::High
    } else if friction_score > 40.0 {
        BreakingRisk::Medium
    } else {
        BreakingRisk::Low
    };

    Ok(ImpactSimulationGateResult {
        files_affected: files_affected.len() as u32,
        functions_affected: functions_affected.len() as u32,
        entry_points_affected: entry_points_affected.len() as u32,
        sensitive_data_paths,
        friction_score,
        breaking_risk,
    })
}
```

---

## 17. Caching & Incremental Simulation

### Purpose

Avoid re-running expensive simulations when the task and codebase context haven't changed.
NEW in v2 — v1 had no caching.

### Cache Key Generation

```rust
use sha2::{Sha256, Digest};

/// Generate a cache key from the simulation inputs.
/// If the key matches a previous run, return cached results.
pub fn simulation_cache_key(
    task: &SimulationTask,
    language: &str,
    framework: Option<&str>,
    scan_hash: &str,       // Content hash from last scan
    call_graph_hash: &str, // Call graph structure hash
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(task.description.as_bytes());
    hasher.update(task.category.map_or("auto", |c| c.as_str()).as_bytes());
    hasher.update(language.as_bytes());
    hasher.update(framework.unwrap_or("none").as_bytes());
    hasher.update(scan_hash.as_bytes());
    hasher.update(call_graph_hash.as_bytes());
    format!("{:x}", hasher.finalize())
}
```

### SQLite Cache Table

```sql
CREATE TABLE IF NOT EXISTS simulation_cache (
    cache_key TEXT PRIMARY KEY,
    task_description TEXT NOT NULL,
    result_json TEXT NOT NULL,       -- Serialized SimulationResult
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,        -- TTL-based expiration
    scan_hash TEXT NOT NULL,         -- Invalidated when scan changes
    call_graph_hash TEXT NOT NULL    -- Invalidated when call graph changes
);

CREATE INDEX idx_simulation_cache_expires ON simulation_cache(expires_at);
```

### Cache TTL

Default: 1 hour. Configurable via `drift.toml`:

```toml
[simulation]
cache_ttl_seconds = 3600
```

Cache is automatically invalidated when:
- A new scan completes (scan_hash changes)
- The call graph is rebuilt (call_graph_hash changes)
- The TTL expires
- The user explicitly clears cache via CLI

---

## 18. Graceful Degradation — No Call Graph / No Patterns

### Purpose

The simulation engine works without a call graph or pattern service. It degrades
gracefully by using estimation heuristics instead of real data. This is a core
design principle preserved from v1.

### Degradation Matrix

| Data Source | Available | Unavailable | Impact |
|------------|-----------|-------------|--------|
| Call Graph | Real BFS/DFS traversal | Estimation heuristics | Impact accuracy ↓ |
| Pattern Service | Real pattern matching | Neutral alignment (50/100) | Alignment accuracy ↓ |
| Coupling Data | Zone-based friction | Skip coupling factor | Friction accuracy ↓ |
| Taint Data | Real taint paths | Skip taint enrichment | Security accuracy ↓ |
| Constraint Data | Constraint pre-check | Skip constraint filtering | Approach quality ↓ |
| Git History | Temporal friction | Skip temporal factor | Friction accuracy ↓ |

### Confidence Adjustment

When data sources are unavailable, confidence is automatically reduced:

```typescript
const dataFactor = (
  (metadata.callGraphAvailable ? 0.4 : 0.0) +
  (metadata.patternsAvailable ? 0.3 : 0.0) +
  (metadata.couplingAvailable ? 0.15 : 0.0) +
  (metadata.constraintsAvailable ? 0.15 : 0.0)
);
```

With all data: dataFactor = 1.0 (full confidence contribution).
With no data: dataFactor = 0.0 (confidence relies only on score gap and alignment).


---

## 19. Persistence — SQLite in drift.db

### Purpose

v1 had no persistence — simulation results were ephemeral. v2 persists results to
drift.db for history, caching, and trend analysis.

### Schema

```sql
-- Simulation run history
CREATE TABLE IF NOT EXISTS simulation_runs (
    id TEXT PRIMARY KEY,
    task_description TEXT NOT NULL,
    task_category TEXT,
    detected_language TEXT NOT NULL,
    detected_framework TEXT,
    recommended_approach TEXT NOT NULL,
    recommended_strategy TEXT NOT NULL,
    composite_score REAL NOT NULL,
    confidence REAL NOT NULL,
    approaches_count INTEGER NOT NULL,
    duration_ms INTEGER NOT NULL,
    call_graph_available INTEGER NOT NULL DEFAULT 0,
    patterns_available INTEGER NOT NULL DEFAULT 0,
    coupling_available INTEGER NOT NULL DEFAULT 0,
    cache_hit INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_simulation_runs_created ON simulation_runs(created_at);
CREATE INDEX idx_simulation_runs_category ON simulation_runs(task_category);

-- Individual approach scores per simulation
CREATE TABLE IF NOT EXISTS simulation_approaches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    simulation_id TEXT NOT NULL REFERENCES simulation_runs(id),
    approach_name TEXT NOT NULL,
    strategy TEXT NOT NULL,
    rank INTEGER NOT NULL,
    composite_score REAL NOT NULL,
    friction_score REAL NOT NULL,
    impact_score REAL NOT NULL,
    alignment_score REAL NOT NULL,
    security_score REAL NOT NULL,
    coupling_friction REAL,
    temporal_friction REAL,
    files_affected INTEGER NOT NULL,
    functions_affected INTEGER NOT NULL,
    entry_points_affected INTEGER NOT NULL,
    breaking_changes INTEGER NOT NULL DEFAULT 0,
    constraint_violations TEXT,  -- JSON array
    reasoning TEXT NOT NULL,
    pros TEXT NOT NULL,          -- JSON array
    cons TEXT NOT NULL,          -- JSON array
    warnings TEXT NOT NULL,      -- JSON array
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_simulation_approaches_sim ON simulation_approaches(simulation_id);
CREATE INDEX idx_simulation_approaches_strategy ON simulation_approaches(strategy);
```

### Retention Policy

Default: 90 days, configurable via `drift.toml`:

```toml
[simulation]
retention_days = 90
max_cached_results = 1000
```

### Cleanup

```rust
/// Purge expired simulation data.
/// Called during drift_shutdown() or on schedule.
pub fn purge_expired_simulations(db: &DatabaseManager, retention_days: u32) -> DriftResult<u32> {
    let cutoff = format!("datetime('now', '-{} days')", retention_days);
    let deleted = db.execute(
        &format!("DELETE FROM simulation_runs WHERE created_at < {}", cutoff),
        [],
    )?;
    // Cascade deletes simulation_approaches via FK
    Ok(deleted as u32)
}
```

---

## 20. NAPI Bridge Interface

### Simulation Functions (5)

| Function | Sync/Async | Returns | Description |
|----------|-----------|---------|-------------|
| `run_simulation(task, options?)` | Async | `SimulationSummary` | Full simulation pipeline |
| `score_impact(approach, max_depth)` | Sync | `ImpactMetrics` | Impact scoring only |
| `score_friction(approach)` | Sync | `FrictionMetrics` | Friction scoring only |
| `score_alignment(approach, min_confidence)` | Sync | `PatternAlignmentMetrics` | Alignment scoring only |
| `score_security(approach)` | Sync | `SecurityMetrics` | Security scoring only |

### Query Functions (4)

| Function | Sync/Async | Returns | Description |
|----------|-----------|---------|-------------|
| `query_simulations(filter, pagination?)` | Sync | `PaginatedResult<SimulationSummary>` | Query simulation history |
| `query_simulation_detail(id)` | Sync | `SimulationDetail` | Full simulation with all approaches |
| `get_strategies(language, category, framework?)` | Sync | `StrategyLookupResult` | Strategy template lookup |
| `coupling_friction(files)` | Sync | `f64` | Coupling friction for files |

### Utility Functions (2)

| Function | Sync/Async | Returns | Description |
|----------|-----------|---------|-------------|
| `clear_simulation_cache()` | Sync | `u32` | Clear cache, return count deleted |
| `detect_project_environment(root)` | Sync | `EnvironmentResult` | Detect language + framework |

### Total: 11 NAPI Functions

### NAPI Implementation — run_simulation

```rust
#[napi(object)]
pub struct SimulationTaskInput {
    pub description: String,
    pub category: Option<String>,
    pub target: Option<String>,
    pub constraints: Option<Vec<ConstraintInput>>,
    pub scope: Option<String>,
}

#[napi(object)]
pub struct SimulationOptionsInput {
    pub max_approaches: Option<u32>,
    pub max_depth: Option<u32>,
    pub include_security_analysis: Option<bool>,
    pub min_pattern_confidence: Option<f64>,
    pub timeout_ms: Option<u64>,
    pub enable_cache: Option<bool>,
    pub include_coupling: Option<bool>,
    pub include_constraints: Option<bool>,
    pub include_taint: Option<bool>,
    pub monte_carlo_samples: Option<u32>,
    pub include_git_history: Option<bool>,
    pub weights: Option<WeightsInput>,
}

#[napi(object)]
pub struct SimulationSummary {
    pub id: String,
    pub task_description: String,
    pub task_category: Option<String>,
    pub recommended_approach: String,
    pub recommended_strategy: String,
    pub composite_score: f64,
    pub confidence: f64,
    pub approaches_count: u32,
    pub duration_ms: u64,
    pub detected_language: String,
    pub detected_framework: Option<String>,
    pub cache_hit: bool,
}

pub struct SimulationTask_ {
    task: SimulationTaskInput,
    options: Option<SimulationOptionsInput>,
}

#[napi]
impl Task for SimulationTask_ {
    type Output = SimulationSummary;
    type JsValue = SimulationSummary;

    fn compute(&mut self) -> napi::Result<Self::Output> {
        let rt = crate::runtime::get()?;

        // Convert inputs
        let task = convert_task(&self.task)?;
        let options = self.options.as_ref()
            .map(convert_options)
            .transpose()?
            .unwrap_or_default();

        // Run scoring backends (Rust-side)
        let result = drift_core::simulation::run_scoring_pipeline(
            &task, &options, &rt.db, &rt.config,
        ).map_err(to_napi_error)?;

        // Persist to drift.db
        drift_core::simulation::persist_result(&rt.db, &result)
            .map_err(to_napi_error)?;

        Ok(SimulationSummary::from(&result))
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> napi::Result<Self::JsValue> {
        Ok(output)
    }
}

#[napi]
pub fn run_simulation(
    task: SimulationTaskInput,
    options: Option<SimulationOptionsInput>,
) -> AsyncTask<SimulationTask_> {
    AsyncTask::new(SimulationTask_ { task, options })
}
```

---

## 21. MCP Tool Interface

### drift_simulate Tool

```typescript
// packages/drift/src/mcp/tools/simulate.ts

export const driftSimulateTool: McpTool = {
  name: 'drift_simulate',
  description:
    'Simulate implementation approaches for a task before writing code. ' +
    'Generates candidate approaches, scores them across friction, impact, ' +
    'pattern alignment, and security dimensions, then recommends the best path.',
  inputSchema: {
    type: 'object',
    properties: {
      task: {
        type: 'string',
        description: 'Description of what you want to implement (e.g., "add rate limiting to the API")',
      },
      category: {
        type: 'string',
        enum: [
          'rate-limiting', 'authentication', 'authorization', 'api-endpoint',
          'data-access', 'error-handling', 'caching', 'logging', 'testing',
          'validation', 'middleware', 'refactoring', 'generic',
        ],
        description: 'Task category (auto-detected if not provided)',
      },
      maxApproaches: {
        type: 'number',
        description: 'Maximum approaches to generate (default: 5)',
      },
      includeTradeoffs: {
        type: 'boolean',
        description: 'Include pairwise tradeoff comparisons (default: true)',
      },
    },
    required: ['task'],
  },

  async handler(params: SimulateParams): Promise<McpToolResult> {
    const engine = getSimulationEngine();
    const result = await engine.simulate({
      description: params.task,
      category: params.category,
    });

    return formatSimulationResult(result, params.includeTradeoffs ?? true);
  },
};

function formatSimulationResult(
  result: SimulationResult,
  includeTradeoffs: boolean,
): McpToolResult {
  const lines: string[] = [];

  lines.push(`## Simulation: ${result.task.description}`);
  lines.push(`**Confidence:** ${(result.confidence * 100).toFixed(0)}%`);
  lines.push(`**Category:** ${result.task.category ?? 'auto-detected'}`);
  lines.push(`**Language:** ${result.metadata.detectedLanguage}`);
  if (result.metadata.detectedFramework) {
    lines.push(`**Framework:** ${result.metadata.detectedFramework}`);
  }
  lines.push('');

  // Recommended approach
  const rec = result.recommended;
  lines.push(`### Recommended: ${rec.approach.name}`);
  lines.push(`**Strategy:** ${rec.approach.strategy}`);
  lines.push(`**Score:** ${rec.compositeScore.toFixed(1)}/100`);
  lines.push(`**Reasoning:** ${rec.reasoning}`);
  lines.push('');

  // Score breakdown
  lines.push('| Dimension | Score |');
  lines.push('|-----------|-------|');
  lines.push(`| Friction | ${rec.friction.overallScore.toFixed(0)}/100 |`);
  lines.push(`| Impact | ${(100 - rec.impact.riskScore).toFixed(0)}/100 |`);
  lines.push(`| Alignment | ${rec.patternAlignment.alignmentScore.toFixed(0)}/100 |`);
  lines.push(`| Security | ${(100 - rec.security.securityRisk).toFixed(0)}/100 |`);
  lines.push('');

  // Pros/cons
  if (rec.pros.length > 0) {
    lines.push('**Pros:**');
    rec.pros.forEach(p => lines.push(`- ${p}`));
  }
  if (rec.cons.length > 0) {
    lines.push('**Cons:**');
    rec.cons.forEach(c => lines.push(`- ${c}`));
  }
  if (rec.warnings.length > 0) {
    lines.push('**Warnings:**');
    rec.warnings.forEach(w => lines.push(`- ⚠️ ${w}`));
  }

  // All approaches summary
  lines.push('');
  lines.push('### All Approaches');
  lines.push('| Rank | Approach | Strategy | Score |');
  lines.push('|------|----------|----------|-------|');
  for (const a of result.approaches) {
    lines.push(`| ${a.rank} | ${a.approach.name} | ${a.approach.strategy} | ${a.compositeScore.toFixed(1)} |`);
  }

  // Tradeoffs
  if (includeTradeoffs && result.tradeoffs.length > 0) {
    lines.push('');
    lines.push('### Tradeoffs');
    for (const t of result.tradeoffs) {
      lines.push(`- **${t.approach1} vs ${t.approach2}:** ${t.comparison}`);
    }
  }

  return { content: [{ type: 'text', text: lines.join('\n') }] };
}
```

---

## 22. CLI Interface

### Commands

```
drift simulate <task>              Run simulation for a task description
drift simulate --category <cat>    Override auto-detected category
drift simulate --max <n>           Limit approaches (default: 5)
drift simulate --json              Output raw JSON
drift simulate --no-cache          Skip cache lookup
drift simulate history             Show simulation history
drift simulate history --limit <n> Limit history entries
drift simulate clear-cache         Clear simulation cache
drift simulate strategies          List available strategies
drift simulate strategies --lang   Filter by language
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Simulation completed successfully |
| 1 | Simulation failed (error) |
| 2 | No approaches generated |
| 3 | Simulation timed out |

---

## 23. Error Handling & Observability

### Error Codes

| Code | Meaning |
|------|---------|
| `SIMULATION_TIMEOUT` | Simulation exceeded timeout_ms |
| `SIMULATION_NO_APPROACHES` | No approaches generated for task |
| `SIMULATION_SCORER_FAILED` | A scorer failed (partial results may be available) |
| `SIMULATION_NO_CALL_GRAPH` | Call graph unavailable (degrades gracefully) |
| `SIMULATION_NO_PATTERNS` | Pattern service unavailable (degrades gracefully) |
| `SIMULATION_INVALID_WEIGHTS` | Scoring weights don't sum to 1.0 |
| `SIMULATION_CANCELLED` | Simulation was cancelled |
| `SIMULATION_INVALID_CATEGORY` | Unknown task category |
| `SIMULATION_UNSUPPORTED_LANGUAGE` | No strategies for language |

### Tracing Spans

```rust
#[instrument(skip(task, options), fields(
    task_category = %task.category.map_or("auto", |c| c.as_str()),
    max_approaches = options.max_approaches,
))]
pub fn run_scoring_pipeline(
    task: &SimulationTask,
    options: &SimulationOptions,
    db: &DatabaseManager,
    config: &DriftConfig,
) -> Result<SimulationResult, SimulationError> {
    // ...
}

#[instrument(skip(approach, call_graph), fields(
    strategy = %approach.strategy.as_str(),
    target_files = approach.target_files.len(),
))]
pub fn score_impact(
    approach: &SimulationApproach,
    call_graph: Option<&CallGraphHandle>,
    max_depth: u32,
) -> ImpactMetrics {
    // ...
}
```

### Key Metrics

| Metric | Span | Why |
|--------|------|-----|
| `simulation_duration_ms` | `run_scoring_pipeline` | Overall simulation time |
| `approach_generation_ms` | `generate_approaches` | Approach generation time |
| `scorer_duration_ms` | Per-scorer spans | Individual scorer performance |
| `cache_hit_rate` | `check_cache` | Cache effectiveness |
| `approaches_generated` | `generate_approaches` | Approach count |
| `approaches_filtered` | `filter_by_constraints` | Constraint filtering |

---

## 24. License Gating — Tier Mapping

The simulation engine is an enterprise feature. License tiers control access:

| Feature | Community | Team | Enterprise |
|---------|-----------|------|------------|
| Simulation engine | ❌ | ❌ | ✅ |
| Impact scoring (standalone) | ✅ | ✅ | ✅ |
| Strategy lookup | ✅ | ✅ | ✅ |
| Simulation history | ❌ | ❌ | ✅ |
| Monte Carlo confidence | ❌ | ❌ | ✅ |
| Coupling integration | ❌ | ❌ | ✅ |
| Constraint-aware simulation | ❌ | ❌ | ✅ |
| MCP drift_simulate tool | ❌ | ❌ | ✅ |
| CLI drift simulate | ❌ | ❌ | ✅ |

Impact scoring is available standalone (used by quality gates at all tiers).
Strategy lookup is available standalone (useful for developer guidance).


---

## 25. V2 Enhancements — Monte Carlo Confidence Intervals

### Purpose

v1 confidence was a single heuristic number. v2 adds Monte Carlo simulation to produce
confidence intervals — a range of likely composite scores for the recommended approach.

This is inspired by [Monte Carlo methods in risk assessment](https://openpracticelibrary.com/practice/monte-carlo-simulation/) — using random sampling to model uncertainty in scoring inputs.

### Algorithm

```typescript
/**
 * Monte Carlo confidence interval for the recommended approach.
 *
 * Perturbs scoring inputs randomly within uncertainty bounds,
 * re-scores, and builds a distribution of composite scores.
 * The interval width indicates how sensitive the recommendation
 * is to scoring uncertainty.
 */
function computeMonteCarloInterval(
  approaches: SimulatedApproach[],
  samples: number,
): ConfidenceInterval {
  const recommended = approaches[0];
  const scores: number[] = [];

  for (let i = 0; i < samples; i++) {
    // Perturb each scoring dimension by ±10% (uniform random)
    const perturbedFriction = perturb(recommended.friction.overallScore, 0.10);
    const perturbedImpact = perturb(100 - recommended.impact.riskScore, 0.10);
    const perturbedAlignment = perturb(
      recommended.patternAlignment.alignmentScore, 0.10,
    );
    const perturbedSecurity = perturb(100 - recommended.security.securityRisk, 0.10);

    const score =
      perturbedFriction * 0.30 +
      perturbedImpact * 0.25 +
      perturbedAlignment * 0.30 +
      perturbedSecurity * 0.15;

    scores.push(score);
  }

  // Sort for percentile calculation
  scores.sort((a, b) => a - b);

  const mean = scores.reduce((a, b) => a + b, 0) / scores.length;
  const variance = scores.reduce((a, b) => a + (b - mean) ** 2, 0) / scores.length;
  const stdDev = Math.sqrt(variance);

  // 90% confidence interval (5th and 95th percentiles)
  const p5 = scores[Math.floor(scores.length * 0.05)];
  const p95 = scores[Math.floor(scores.length * 0.95)];

  return {
    lowerBound: p5,
    upperBound: p95,
    mean,
    stdDev,
    samples,
  };
}

function perturb(value: number, maxPerturbation: number): number {
  const perturbation = (Math.random() * 2 - 1) * maxPerturbation * value;
  return Math.max(0, Math.min(100, value + perturbation));
}
```

### Interpretation

- Narrow interval (width < 10): High confidence — recommendation is robust
- Medium interval (width 10-25): Moderate confidence — recommendation is likely correct
- Wide interval (width > 25): Low confidence — recommendation is sensitive to assumptions

---

## 26. V2 Enhancements — Temporal Friction (Git History)

### Purpose

Files that change frequently have higher merge conflict risk and coordination overhead.
This is inspired by [CodeScene's behavioral code analysis](https://codescene.com) which
combines code quality metrics with version control data to identify hidden risks.

### Data Source

Git history data is loaded from drift.db (populated by the scanner during `drift scan`):

```sql
-- Query change frequency for target files (last 90 days)
SELECT file_path, COUNT(*) as change_count, COUNT(DISTINCT author) as author_count
FROM file_changes
WHERE changed_at > datetime('now', '-90 days')
AND file_path IN (?, ?, ...)
GROUP BY file_path;
```

### Integration

Temporal friction is Factor 7 in the friction scorer (§8). It contributes 10% of the
overall friction score when git history data is available.

High temporal friction files:
- Changed >20 times in 90 days
- Modified by >3 distinct authors
- Both conditions = maximum temporal friction

---

## 27. V2 Enhancements — Constraint-Aware Simulation

### Purpose

v1 generated approaches without considering active constraints. v2 pre-checks approaches
against the constraint system (20-CONSTRAINT-SYSTEM-V2-PREP.md) and filters or warns
about constraint violations.

### Integration

```typescript
private async checkConstraints(
  approach: SimulationApproach,
): Promise<string[]> {
  try {
    const result = await this.drift.verifyConstraints(approach.targetFiles);
    const violations: string[] = [];

    for (const violation of result.violations) {
      if (violation.severity === 'error') {
        violations.push(
          `Constraint "${violation.constraintName}" violated: ${violation.message}`,
        );
      }
    }

    return violations;
  } catch {
    return []; // Constraint system unavailable — degrade gracefully
  }
}
```

Approaches with constraint violations are not filtered out (they may still be the best
option), but violations are surfaced in the `constraintViolations` field and factored
into the reasoning text.

---

## 28. V2 Enhancements — Multi-Language Project Support

### Purpose

v1 detected a single primary language per project. v2 supports multi-language projects
(e.g., TypeScript frontend + Python backend) by detecting languages per-directory and
generating approaches for each relevant language.

### Detection

```typescript
async function detectMultiLanguageEnvironment(
  projectRoot: string,
): Promise<LanguageEnvironment[]> {
  // Scan top-level directories for language indicators
  // Returns array of { directory, language, framework } tuples
  // Example: [
  //   { directory: 'frontend', language: 'typescript', framework: 'nextjs' },
  //   { directory: 'backend', language: 'python', framework: 'fastapi' },
  // ]
}
```

### Approach Generation

For multi-language projects, the approach generator produces approaches for each
relevant language, then merges them into a unified set. Cross-language approaches
(e.g., "add rate limiting to both frontend and backend") are generated as composite
approaches with sub-steps per language.

---

## 29. V2 Enhancements — Approach Comparison Visualization

### Purpose

v1 returned text-based tradeoff comparisons. v2 adds structured comparison data
suitable for rendering as radar charts, bar charts, or comparison tables in IDEs
and dashboards.

### Data Structure

```typescript
interface ApproachComparisonData {
  approaches: Array<{
    name: string;
    strategy: string;
    scores: {
      friction: number;
      impact: number;
      alignment: number;
      security: number;
      composite: number;
    };
  }>;
  dimensions: ['friction', 'impact', 'alignment', 'security'];
  weights: ScoringWeights;
}
```

This data is included in the `SimulationResult.metadata` for visualization consumers.

---

## 30. Resolved Inconsistencies

### Inconsistency 1: Orchestration Language

The v1 research docs say "this is AI-heavy orchestration — stays in TypeScript" but
the quality gates V2 prep doc implements ImpactSimulationGate entirely in Rust.

**Resolution**: The simulation engine orchestrator stays in TypeScript. Individual
scoring backends (impact, alignment, security, friction computation) run in Rust.
The quality gate's ImpactSimulationGate calls the Rust impact scoring directly
without going through the TS orchestrator. Both paths are valid:
- Full simulation: TS orchestrator → Rust scorers → TS ranking → result
- Gate impact check: Rust gate → Rust impact scorer → gate result

### Inconsistency 2: Scorer Weight Normalization

The v1 types show weights as `{ friction: 0.30, impact: 0.25, patternAlignment: 0.30,
security: 0.15 }` which sums to 1.0. But the composite formula multiplies each score
by its weight without verifying the sum.

**Resolution**: v2 validates that weights sum to 1.0 (±0.01 tolerance) at configuration
time. If custom weights don't sum to 1.0, return `SIMULATION_INVALID_WEIGHTS` error.

### Inconsistency 3: Friction Score Direction

The friction scorer returns `overallScore` where higher = less friction (inverted).
But the composite formula treats all scores as "higher = better". The impact scorer
returns `riskScore` where higher = more risk (not inverted).

**Resolution**: Standardize in the composite scoring function:
- `frictionScore = friction.overallScore` (already inverted by scorer)
- `impactScore = 100 - impact.riskScore` (invert at composite time)
- `alignmentScore = alignment.alignmentScore` (already correct direction)
- `securityScore = 100 - security.securityRisk` (invert at composite time)

This is documented in §12 and enforced in the `computeCompositeScore` function.

### Inconsistency 4: Category Count

The overview doc says "13 task categories" but the types doc lists 12 entries in the
TaskCategory union (missing `generic`). The approach generator doc says "12 category
keyword sets."

**Resolution**: 13 categories total. `generic` is the 13th — it's the fallback when
no keyword match is found. It has no keyword set (it's selected by default). All docs
updated to say 13.

---

## 31. File Module Structure

### Rust (drift-core)

```
crates/drift-core/src/simulation/
├── mod.rs                      # Module declarations, public API
├── types.rs                    # All Rust types (§4)
├── errors.rs                   # SimulationError enum (§4.5)
├── config.rs                   # SimulationConfig, ScoringWeights, SimulationOptions
├── scoring/
│   ├── mod.rs                  # Scorer trait, coordinator
│   ├── friction.rs             # score_friction() — 7-factor model (§8)
│   ├── impact.rs               # score_impact() — call graph BFS + fallback (§9)
│   ├── alignment.rs            # score_alignment() — pattern matching (§10)
│   └── security.rs             # score_security() — data access + taint (§11)
├── strategies/
│   ├── mod.rs                  # STRATEGY_PROVIDERS registry
│   ├── types.rs                # StrategyTemplate, FrameworkDefinition
│   ├── typescript.rs           # Express, NestJS, Fastify, Hono, tRPC
│   ├── python.rs               # FastAPI, Flask, Django, Litestar
│   ├── java.rs                 # Spring Boot, Quarkus, Micronaut
│   ├── csharp.rs               # ASP.NET Core, Minimal APIs
│   └── php.rs                  # Laravel, Symfony
├── coupling.rs                 # coupling_friction() integration (§15)
├── gate_integration.rs         # simulate_impact_for_gate() (§16)
├── cache.rs                    # simulation_cache_key(), cache lookup/store (§17)
├── persistence.rs              # persist_result(), query functions (§19)
└── monte_carlo.rs              # Monte Carlo confidence intervals (§25)
```

### TypeScript (packages/drift)

```
packages/drift/src/simulation/
├── index.ts                    # Public exports
├── simulation-engine.ts        # SimulationEngine class — main orchestrator (§14)
├── approach-generator.ts       # ApproachGenerator class — candidate generation (§6)
├── scoring.ts                  # computeCompositeScore(), rankApproaches() (§12)
├── tradeoffs.ts                # generateTradeoffs(), compareApproaches() (§13)
├── confidence.ts               # calculateConfidence(), computeMonteCarloInterval() (§13, §25)
├── insights.ts                 # generateApproachInsights() — pros/cons/warnings (§12)
├── constraints.ts              # checkConstraints() integration (§27)
├── multi-language.ts           # detectMultiLanguageEnvironment() (§28)
└── types.ts                    # All TypeScript types (§5)
```

### NAPI Bridge

```
crates/drift-napi/src/bindings/simulation.rs    # 11 NAPI functions (§20)
crates/drift-napi/src/conversions/simulation_types.rs  # Type conversions
```

### MCP Tool

```
packages/drift/src/mcp/tools/simulate.ts        # drift_simulate tool (§21)
```

---

## 32. Build Order & Dependency Chain

### Phase 1: Types & Configuration (Week 1)
1. `simulation/types.rs` — All Rust types
2. `simulation/errors.rs` — SimulationError enum
3. `simulation/config.rs` — SimulationConfig, defaults
4. `packages/drift/src/simulation/types.ts` — TS type mirrors
5. Verify: Types compile, match between Rust and TS

### Phase 2: Strategy System (Week 1-2)
6. `simulation/strategies/types.rs` — StrategyTemplate, FrameworkDefinition
7. `simulation/strategies/typescript.rs` — TypeScript strategies (~18)
8. `simulation/strategies/python.rs` — Python strategies (~14)
9. `simulation/strategies/java.rs` — Java strategies (~12)
10. `simulation/strategies/csharp.rs` — C# strategies (~10)
11. `simulation/strategies/php.rs` — PHP strategies (~8)
12. `simulation/strategies/mod.rs` — STRATEGY_PROVIDERS registry
13. NAPI: `get_strategies()` function
14. Verify: Strategy lookup works from TS

### Phase 3: Scoring Backends (Week 2-3)
15. `simulation/scoring/friction.rs` — 7-factor friction scorer
16. `simulation/scoring/impact.rs` — Call graph impact scorer + fallback
17. `simulation/scoring/alignment.rs` — Pattern alignment scorer
18. `simulation/scoring/security.rs` — Security scorer + taint integration
19. `simulation/scoring/mod.rs` — Scorer coordinator
20. NAPI: `score_friction()`, `score_impact()`, `score_alignment()`, `score_security()`
21. Verify: All 4 scorers return correct metrics from TS

### Phase 4: Coupling & Gate Integration (Week 3)
22. `simulation/coupling.rs` — coupling_friction() integration
23. `simulation/gate_integration.rs` — simulate_impact_for_gate()
24. NAPI: `coupling_friction()`
25. Verify: Coupling friction enriches friction scores, gate integration works

### Phase 5: Persistence & Caching (Week 3-4)
26. `simulation/persistence.rs` — SQLite schema, persist/query functions
27. `simulation/cache.rs` — Cache key generation, lookup, store
28. NAPI: `query_simulations()`, `query_simulation_detail()`, `clear_simulation_cache()`
29. Verify: Results persist and cache hits work

### Phase 6: TS Orchestrator (Week 4)
30. `simulation/approach-generator.ts` — ApproachGenerator class
31. `simulation/scoring.ts` — Composite scoring + ranking
32. `simulation/tradeoffs.ts` — Tradeoff generation
33. `simulation/confidence.ts` — Confidence calculation + Monte Carlo
34. `simulation/insights.ts` — Pros/cons/warnings generation
35. `simulation/simulation-engine.ts` — SimulationEngine orchestrator
36. NAPI: `run_simulation()` (AsyncTask wrapping full pipeline)
37. Verify: Full simulation pipeline works end-to-end

### Phase 7: MCP & CLI (Week 5)
38. `mcp/tools/simulate.ts` — drift_simulate MCP tool
39. CLI: `drift simulate` command
40. Verify: MCP tool returns formatted results, CLI works

### Phase 8: V2 Enhancements (Week 5-6)
41. `simulation/monte_carlo.rs` — Monte Carlo confidence intervals
42. `simulation/constraints.ts` — Constraint-aware simulation
43. `simulation/multi-language.ts` — Multi-language project support
44. Verify: All v2 enhancements functional

---

## 33. V1 Feature Verification — Complete Gap Analysis

### V1 Features — 100% Coverage

| v1 Feature | v2 Status | v2 Section |
|-----------|-----------|------------|
| SimulationEngine orchestrator (6-step pipeline) | **UPGRADED** to 10-step | §14 |
| ApproachGenerator (5-step pipeline) | **UPGRADED** + constraint filtering | §6 |
| FrictionScorer (5-factor model) | **UPGRADED** to 7-factor | §8 |
| ImpactScorer (call graph + fallback) | **KEPT** — Rust implementation | §9 |
| PatternAlignmentScorer | **KEPT** — Rust implementation | §10 |
| SecurityScorer (data access + auth) | **UPGRADED** + taint integration | §11 |
| 13 task categories | **KEPT** — all 13 preserved | §2.3 |
| 15 approach strategies | **KEPT** — all 15 preserved | §2.4 |
| 5 language providers | **KEPT** — all 5 preserved + expanded | §7 |
| 12 framework definitions | **KEPT** — all 12 preserved + expanded | §7 |
| ~53 strategy templates | **UPGRADED** to ~62 | §7 |
| Scoring weights (0.30/0.25/0.30/0.15) | **PRESERVED** exactly | §2.6 |
| Default options (5/10/true/0.5/30000/true) | **PRESERVED** exactly | §2.7 |
| Composite scoring (weighted average) | **PRESERVED** exactly | §12 |
| Approach ranking (sort by composite) | **PRESERVED** exactly | §12 |
| Tradeoff generation (pairwise) | **PRESERVED** exactly | §13 |
| Confidence calculation (multi-factor) | **UPGRADED** + Monte Carlo | §13 |
| Graceful degradation (no call graph) | **PRESERVED** exactly | §18 |
| Graceful degradation (no patterns) | **PRESERVED** exactly | §18 |
| Risk score calculation (4-component) | **PRESERVED** exactly | §9 |
| Risk level classification (4 levels) | **PRESERVED** exactly | §4.3 |
| Breaking change detection (5 conditions) | **PRESERVED** exactly | §9 |
| Strategy risk factors | **PRESERVED** exactly | §4.2 |
| Testing effort multipliers | **PRESERVED** exactly | §4.2 |
| Keyword-based category detection | **PRESERVED** exactly | §6 |
| Framework detection (import patterns) | **UPGRADED** + Rust parsers | §6 |
| Custom approach generation | **PRESERVED** | §6 |
| Fallback approach generation | **PRESERVED** | §6 |
| SimulationResult output structure | **UPGRADED** + persistence | §4.3, §19 |
| SimulationTask input structure | **PRESERVED** + constraints | §4.1 |
| SimulationApproach structure | **PRESERVED** exactly | §4.2 |
| All metric types (Friction/Impact/Alignment/Security) | **PRESERVED** + extensions | §4.3 |
| ApproachTradeoff structure | **PRESERVED** exactly | §4.3 |
| Enterprise license requirement | **PRESERVED** | §24 |

### New V2 Features NOT in V1

| New Feature | Why | Section |
|------------|-----|---------|
| Coupling friction integration | Richer friction model from coupling analysis | §8, §15 |
| Temporal friction (git history) | Merge conflict risk from change frequency | §8, §26 |
| Taint analysis integration | Security scorer enrichment | §11 |
| Constraint-aware simulation | Pre-check approaches against constraints | §27 |
| Monte Carlo confidence intervals | Probabilistic confidence assessment | §25 |
| Simulation result persistence | History, trends, caching | §19 |
| Simulation caching | Avoid redundant re-computation | §17 |
| Multi-language project support | Polyglot codebase handling | §28 |
| Approach comparison visualization | Structured data for charts | §29 |
| NAPI bridge functions (11) | Rust-backed scoring via NAPI | §20 |
| MCP drift_simulate tool | AI-assisted simulation | §21 |
| CLI drift simulate command | Developer-facing simulation | §22 |
| Structured error codes (9) | Programmatic error handling | §23 |
| Tracing instrumentation | Observability for scoring pipeline | §23 |
| Expanded framework support (+5) | Hono, tRPC, Litestar, Micronaut, Minimal APIs | §7 |
| Expanded strategy templates (+9) | ~62 total (up from ~53) | §7 |
| DriftEventHandler events | Simulation lifecycle events | §3 |

---

## 34. Summary of All Decisions

| Decision | Choice | Confidence | Source |
|----------|--------|------------|--------|
| Architecture | Hybrid: Rust scoring + TS orchestration | Very High | v1 research, audit |
| Scoring weights | 0.30/0.25/0.30/0.15 (preserved, configurable) | Very High | v1 preserved |
| Default options | 5/10/true/0.5/30000/true (preserved) | Very High | v1 preserved |
| Task categories | 13 (all preserved) | Very High | v1 preserved |
| Approach strategies | 15 (all preserved) | Very High | v1 preserved |
| Language providers | 5 (all preserved + expanded) | Very High | v1 preserved |
| Friction model | 7-factor (v1 5 + coupling + temporal) | High | v1 + CodeScene research |
| Impact scoring | Rust call graph BFS + fallback estimation | Very High | v1 preserved |
| Pattern alignment | Rust pattern matching | High | v1 preserved |
| Security scoring | Rust + taint integration | High | v1 + taint system |
| Confidence | v1 heuristic + Monte Carlo intervals | High | v1 + Monte Carlo research |
| Persistence | SQLite in drift.db (90-day retention) | High | v2 architecture |
| Caching | SHA-256 hash key, 1-hour TTL | High | v2 enhancement |
| Constraint integration | Pre-check, warn (don't filter) | Medium-High | v2 enhancement |
| Multi-language | Per-directory detection, composite approaches | Medium | v2 enhancement |
| NAPI functions | 11 total (5 simulation + 4 query + 2 utility) | High | NAPI bridge pattern |
| Error handling | thiserror, 9 error codes | Very High | Infrastructure pattern |
| Observability | tracing spans per scorer | Very High | Infrastructure pattern |
| License gating | Enterprise only (impact scoring standalone) | Very High | v1 preserved |
| Orchestration language | TypeScript (lightweight coordination) | Very High | v1 research |
| Scoring backends | Rust (heavy computation) | Very High | v2 architecture |
| Strategy storage | Rust static config (&'static) | High | Zero-cost access |
| Build order | 8 phases, 44 steps, ~6 weeks | High | Dependency chain |
| Independence | Zero imports from cortex (D1) | Very High | PLANNING-DRIFT.md |
