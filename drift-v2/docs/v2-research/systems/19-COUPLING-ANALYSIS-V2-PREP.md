# Coupling Analysis (Tarjan's SCC, Zones, Metrics) — V2 Implementation Prep

> Comprehensive build specification for Drift v2's Coupling Analysis subsystem (System 19).
> Synthesized from: 05-analyzers/module-coupling.md (TS ModuleCouplingAnalyzer ~900 LOC,
> Rust CouplingAnalyzer ~600 LOC, Robert C. Martin metrics, Tarjan's SCC, module roles),
> 01-rust-core/coupling.md (Rust types, DFS cycle detection, NAPI exposure, TS feature gap),
> .research/05-analyzers/RECAP.md (dual implementation inventory, 22K+ LOC analyzer system),
> .research/05-analyzers/RECOMMENDATIONS.md (R1 Salsa incremental, R2 layered architecture),
> DRIFT-V2-FULL-SYSTEM-AUDIT.md (Cat 05 — Coupling Analysis Rust, coupling_metrics tables,
> AD1 incremental-first, AD12 performance data structures, coupling analyzer Rust parity),
> DRIFT-V2-STACK-HIERARCHY.md (Level 2C — Structural Intelligence, consumed by DNA/sim/gates),
> DRIFT-V2-SYSTEMS-REFERENCE.md §21 (Module Coupling — TOC entry, consumer of call graph),
> 05-CALL-GRAPH-V2-PREP.md (petgraph StableGraph, CallGraphDb, resolution index),
> 06-UNIFIED-ANALYSIS-ENGINE-V2-PREP.md (4-phase pipeline, ParseResult contract, GAST),
> 14-REACHABILITY-ANALYSIS-V2-PREP.md (BFS engines, graph traversal patterns),
> 02-STORAGE-V2-PREP.md (drift.db schema, batch writer, medallion architecture),
> 03-NAPI-BRIDGE-V2-PREP.md (command/query pattern, async tasks, napi-rs v3, §10.10),
> 04-INFRASTRUCTURE-V2-PREP.md (thiserror, tracing, FxHashMap, rayon, petgraph),
> 09-quality-gates/gates.md (6 gates — coupling feeds impact simulation gate),
> 07-mcp/tools-by-category.md (drift_coupling — analysis category, ~1000-2500 tokens),
> 10-cli/commands.md (drift coupling: default/cycles/hotspots/analyze subcommands),
> 08-storage/sqlite-schema.md (module_coupling, coupling_cycles tables),
> 13-advanced/dna-system.md (DNA gene extractors consume coupling metrics),
> cortex-causal/src/graph/dag_enforcement.rs (Tarjan's SCC via petgraph::algo::tarjan_scc),
> cortex-causal/src/graph/stable_graph.rs (IndexedGraph wrapper pattern),
> petgraph 0.6 API (tarjan_scc, condensation, StableGraph, Dfs, Bfs),
> Robert C. Martin — Agile Software Development (Ca, Ce, I, A, D, Main Sequence),
> cp-algorithms.com (SCC + condensation graph theory),
> Incrementalizing Production CodeQL (function-level invalidation for incremental analysis),
> PLANNING-DRIFT.md (D1-D7).
>
> Purpose: Everything needed to build the Coupling Analysis subsystem from scratch.
> This is the DEDICATED deep-dive — the 06-UNIFIED-ANALYSIS-ENGINE doc covers the
> per-file detection pipeline; the 05-CALL-GRAPH-V2-PREP doc covers the call graph
> builder that coupling analysis consumes; this document covers the full coupling
> analysis engine: dependency graph construction, Robert C. Martin metrics, Tarjan's
> SCC cycle detection, condensation graph generation, zone classification, module role
> assignment, cycle break suggestions, refactor impact analysis, incremental coupling,
> and the full integration with call graph, DNA, quality gates, and simulation.
> Every v1 feature accounted for. Zero feature loss. Every algorithm specified.
> Every type defined. Every integration point documented. Every architectural
> decision resolved.
> Generated: 2026-02-08

---

## Table of Contents

1. Architectural Position
2. V1 Complete Feature Inventory
3. V2 Architecture — Unified Coupling Engine
4. Core Data Model
5. Phase 1: Dependency Graph Construction (Import/Export AST Extraction)
6. Phase 2: Module Aggregation & Metrics Calculation
7. Phase 3: Tarjan's SCC Cycle Detection
8. Phase 4: Condensation Graph Generation
9. Phase 5: Zone Classification (Main Sequence Analysis)
10. Phase 6: Module Role Assignment
11. Phase 7: Cycle Break Suggestion Engine
12. Phase 8: Refactor Impact Analysis
13. Phase 9: Unused Export Detection
14. Phase 10: Health Score Calculation
15. Auto-Selection: In-Memory (petgraph) vs SQLite CTE
16. Incremental Coupling Analysis (Content-Hash + Dependency Tracking)
17. Integration with Call Graph Builder
18. Integration with Unified Analysis Engine
19. Integration with DNA System
20. Integration with Quality Gates
21. Integration with Simulation Engine
22. Integration with Constraints System
23. Integration with Cortex Grounding (D7)
24. Storage Schema (drift.db Coupling Tables)
25. NAPI Interface
26. MCP Tool Interface (drift_coupling — 5 Actions)
27. CLI Interface (drift coupling — 4 Subcommands)
28. Event Interface
29. Tracing & Observability
30. Performance Targets & Benchmarks
31. Build Order & Dependencies
32. V1 → V2 Feature Cross-Reference
33. Inconsistencies & Decisions
34. Risk Register

---

## 1. Architectural Position

Coupling Analysis is **Level 2C — Structural Intelligence** in the Drift v2 stack
hierarchy. It is the system that transforms Drift's import/export dependency data and
call graph into actionable architecture health intelligence — answering questions like
"which modules are tightly coupled?", "are there dependency cycles?", "is this module
in the zone of pain?", "what's the safest edge to break in this cycle?", and "what
would be the blast radius of refactoring this module?"

Per DRIFT-V2-STACK-HIERARCHY.md:

> Coupling Analysis: Afferent/efferent, Tarjan's SCC, zones, cycle break suggestions.
> Architecture health. Consumed by DNA, simulation, quality gates.

Per DRIFT-V2-FULL-SYSTEM-AUDIT.md Category 05:

> Coupling Analysis (Rust): Module-level coupling metrics, import/export dependency
> tracking, afferent (Ca) / efferent (Ce) coupling calculation, Instability (I),
> Abstractness (A), Distance (D), Tarjan's SCC for cycle detection, condensation
> graph generation, zone detection, module role classification, cycle break suggestions.

Per DRIFT-V2-FULL-SYSTEM-AUDIT.md Supplemental:

> Coupling analyzer Rust parity: Port Tarjan's SCC algorithm (more efficient than DFS
> for cycle detection), module roles (Hub/Authority/Balanced/Isolated), zone detection
> (MainSequence/ZoneOfPain/ZoneOfUselessness), break point suggestions
> (ExtractInterface/DependencyInversion/MergeModules/IntroduceMediator), refactor
> impact analysis.

### Core Thesis

Coupling analysis is the architectural health monitor. It operates on the dependency
graph (import/export relationships between modules) and optionally enriches with call
graph data for transitive dependency analysis. The v1 implementation is split across
two implementations with significant feature gaps — v2 unifies everything in Rust with
zero feature loss.

The key insight: coupling analysis is a graph problem. petgraph provides Tarjan's SCC,
condensation, BFS, and DFS out of the box. The Rust implementation should leverage
petgraph's algorithms directly rather than reimplementing them. The v1 Rust
implementation uses hand-rolled DFS for cycle detection — v2 uses petgraph's
`tarjan_scc()` which is proven correct, O(V+E), and handles edge cases (self-loops,
disconnected components) that hand-rolled DFS misses.

### What Lives Here

- Dependency graph construction from import/export AST data
- Module aggregation (file → directory grouping, configurable granularity)
- Robert C. Martin metrics: Ca, Ce, Instability, Abstractness, Distance
- Tarjan's SCC cycle detection (petgraph::algo::tarjan_scc)
- Condensation graph generation (petgraph::algo::condensation)
- Zone classification: Main Sequence, Zone of Pain, Zone of Uselessness
- Module role assignment: Hub, Authority, Balanced, Isolated
- Cycle break suggestion engine with effort estimation
- Refactor impact analysis with transitive dependency tracking
- Unused export detection with reason inference
- Health score calculation (multi-factor, 0-100)
- Incremental coupling (content-hash aware, dependency-tracked invalidation)
- Auto-selection: in-memory petgraph vs SQLite CTE for large codebases
- Coupling result persistence (drift.db coupling tables)

### What Does NOT Live Here

- Import/export extraction from AST (lives in Unified Analysis Engine / Parsers)
- Call graph construction (lives in Call Graph Builder)
- Pattern detection (lives in Detector System)
- Quality gate evaluation logic (lives in Quality Gates)
- DNA gene extraction (lives in DNA System — consumes coupling metrics)
- Simulation scoring (lives in Simulation Engine — consumes coupling data)

### Downstream Consumers

| Consumer | What It Reads | Interface |
|----------|--------------|-----------|
| DNA System | Module metrics, health score, cycle count | `CouplingSnapshot` |
| Simulation Engine | Coupling metrics for friction scoring | `ModuleMetrics` |
| Quality Gates | Cycle count, health score, hotspot count | `CouplingGateInput` |
| Impact Simulation Gate | Module coupling depth for blast radius | `RefactorImpact` |
| Constraints System | Coupling limits as enforceable constraints | `CouplingMetrics` |
| CI Agent | Coupling score (10% of PR score) | `CouplingSummary` |
| MCP Server | drift_coupling tool responses | `CouplingResult` |
| CLI | drift coupling command output | `CouplingResult` |
| Context Generation | Architecture health summary | `CouplingSnapshot` |

### Upstream Dependencies

| Dependency | What It Provides | Contract |
|-----------|-----------------|----------|
| Parsers (Level 0) | ParseResult with imports/exports | `Vec<ImportInfo>`, `Vec<ExportInfo>` |
| Scanner (Level 0) | File list, content hashes | `ScanDiff`, `ContentHash` |
| Storage (Level 0) | DatabaseManager for persistence | `batch_writer`, `keyset_pagination` |
| Call Graph (Level 1) | Function→function edges for transitive analysis | `CallGraphDb` |
| Unified Analysis (Level 1) | Resolution index for import resolution | `ResolutionIndex` |
| Infrastructure (Level 0) | thiserror, tracing, events, config | Error enums, spans, handlers |

---

## 2. V1 Complete Feature Inventory

Every feature from both v1 implementations (Rust + TypeScript) must be preserved in v2.
This is the zero-feature-loss guarantee.

### 2.1 Rust v1 Features (crates/drift-core/src/coupling/ — ~600 LOC)

| # | Feature | Status | V2 Action |
|---|---------|--------|-----------|
| R1 | `CouplingAnalyzer` struct with tree-sitter integration | ✅ Exists | Replace with `CouplingEngine` |
| R2 | `build_file_graph_from_ast()` — parse imports/exports via tree-sitter | ✅ Exists | Consume from ParseResult instead |
| R3 | `resolve_import()` — relative import path resolution | ✅ Exists | Use ResolutionIndex from unified engine |
| R4 | `build_module_map()` — group files by directory | ✅ Exists | Preserve, add configurable granularity |
| R5 | `calculate_module_metrics()` — Ca, Ce, I, A, D | ✅ Exists | Preserve exactly |
| R6 | `detect_cycles()` — DFS with recursion stack | ✅ Exists | Replace with Tarjan's SCC |
| R7 | `dfs_cycles()` — recursive DFS helper | ✅ Exists | Replace with petgraph::algo::tarjan_scc |
| R8 | `find_hotspots()` — modules with total coupling ≥ 3 | ✅ Exists | Preserve, add configurable threshold |
| R9 | `find_unused_exports()` — exports never imported | ✅ Exists | Preserve, add reason inference |
| R10 | `calculate_health_score()` — 0-100 score | ✅ Exists | Preserve, enhance formula |
| R11 | `ModuleMetrics` — path, ca, ce, instability, abstractness, distance, files | ✅ Exists | Preserve all fields |
| R12 | `DependencyCycle` — modules, severity, files_affected | ✅ Exists | Preserve, add break_points |
| R13 | `CouplingHotspot` — module, total_coupling, incoming, outgoing | ✅ Exists | Preserve all fields |
| R14 | `UnusedExport` — name, file, line, export_type | ✅ Exists | Preserve, add reasons |
| R15 | `CouplingAnalysisResult` — modules, cycles, hotspots, unused_exports, health_score | ✅ Exists | Preserve, extend |
| R16 | `FileGraph` — path, imports, exports (internal) | ✅ Exists | Replace with petgraph |
| R17 | `ImportEdge` — source, symbols, line | ✅ Exists | Preserve |
| R18 | `ExportNode` — name, line, is_default | ✅ Exists | Preserve, add kind |
| R19 | `CycleSeverity` — Info/Warning/Critical | ✅ Exists | Preserve |
| R20 | NAPI: `analyze_coupling(files: Vec<String>) -> JsCouplingResult` | ✅ Exists | Replace with command/query pattern |

### 2.2 TypeScript v1 Features (packages/core/src/module-coupling/ — ~900 LOC)

| # | Feature | Status | V2 Action |
|---|---------|--------|-----------|
| T1 | `ModuleCouplingAnalyzer` class with call graph integration | ✅ Exists | Port to Rust CouplingEngine |
| T2 | `build()` — full coupling graph from call graph data | ✅ Exists | Port to Rust |
| T3 | `analyzeModule(path)` — detailed single-module analysis | ✅ Exists | Port to Rust |
| T4 | `analyzeRefactorImpact(path)` — blast radius estimation | ✅ Exists | Port to Rust |
| T5 | `getCycles(options)` — cycle detection with options | ✅ Exists | Port to Rust (Tarjan's) |
| T6 | `getHotspots(options)` — configurable hotspot detection | ✅ Exists | Port to Rust |
| T7 | `getUnusedExports()` — unused export analysis | ✅ Exists | Port to Rust |
| T8 | Tarjan's SCC algorithm for cycle detection | ✅ Exists | Use petgraph::algo::tarjan_scc |
| T9 | Module roles: hub, authority, balanced, isolated | ✅ Exists | Port to Rust |
| T10 | Cycle break suggestions with effort estimation | ✅ Exists | Port to Rust |
| T11 | Refactor impact with transitive dependencies | ✅ Exists | Port to Rust |
| T12 | Zone of Pain detection (low I, low A) | ✅ Exists | Port to Rust |
| T13 | Zone of Uselessness detection (high I, high A) | ✅ Exists | Port to Rust |
| T14 | Module health scoring (multi-factor) | ✅ Exists | Port to Rust |
| T15 | Call graph integration for transitive analysis | ✅ Exists | Port to Rust |
| T16 | `CouplingMetrics` — Ca, Ce, I, A, totalExports, usedExports, unusedExports | ✅ Exists | Port to Rust |
| T17 | `ModuleNode` — path, language, exports, role, metrics | ✅ Exists | Port to Rust |
| T18 | `ImportEdge` — source, target, symbols, isTypeOnly | ✅ Exists | Port to Rust |
| T19 | `DependencyCycle` — path, severity, breakPoints | ✅ Exists | Port to Rust |
| T20 | `BreakPoint` — from, to, effort, rationale, approach | ✅ Exists | Port to Rust |
| T21 | `UnusedExportAnalysis` — file, symbol, kind, line, reasons, confidence | ✅ Exists | Port to Rust |
| T22 | `RefactorImpact` — directDependents, transitiveDependents, affectedTests, health, effort, risk | ✅ Exists | Port to Rust |
| T23 | Cycle severity: critical (>5), high (>3), medium (>2), low (2) | ✅ Exists | Preserve thresholds |
| T24 | Break effort: low (re-export), medium (interface extraction), high (major refactor) | ✅ Exists | Preserve |
| T25 | Unused export reasons: dead-code, test-only, internal, deprecated | ✅ Exists | Preserve |

### 2.3 MCP Tool Features

| # | Feature | Status | V2 Action |
|---|---------|--------|-----------|
| M1 | `drift_coupling` MCP tool | ✅ Exists | Preserve, expand actions |
| M2 | Module coupling analysis response (~1000-2500 tokens) | ✅ Exists | Preserve token budget |

### 2.4 CLI Features

| # | Feature | Status | V2 Action |
|---|---------|--------|-----------|
| C1 | `drift coupling` — overview | ✅ Exists | Preserve |
| C2 | `drift coupling cycles` — cycle detection | ✅ Exists | Preserve |
| C3 | `drift coupling hotspots` — hotspot listing | ✅ Exists | Preserve |
| C4 | `drift coupling analyze <module>` — single module analysis | ✅ Exists | Preserve |

### 2.5 Storage Features

| # | Feature | Status | V2 Action |
|---|---------|--------|-----------|
| S1 | `module_coupling` table | ✅ Exists | Preserve, extend schema |
| S2 | `coupling_cycles` table | ✅ Exists | Preserve, extend schema |

### 2.6 Integration Features

| # | Feature | Status | V2 Action |
|---|---------|--------|-----------|
| I1 | CI Agent coupling score (10% of PR score) | ✅ Exists | Preserve |
| I2 | Setup wizard CouplingRunner | ✅ Exists | Preserve |
| I3 | JSON↔SQLite sync for coupling data | ✅ Exists | Remove (SQLite-only in v2) |
| I4 | Quality gate consumption of coupling data | ✅ Exists | Preserve |

### 2.7 V2 Net-New Features (From Audit + Research)

| # | Feature | Source | Priority |
|---|---------|--------|----------|
| N1 | Condensation graph generation (DAG of SCCs) | Audit | P1 |
| N2 | Auto-selection: in-memory petgraph vs SQLite CTE | Audit AD12 | P1 |
| N3 | Incremental coupling (content-hash + dependency invalidation) | Audit AD1 | P1 |
| N4 | Configurable module granularity (file/directory/package) | Research | P2 |
| N5 | Type-only import distinction (isTypeOnly) | TS v1 | P1 |
| N6 | Approach suggestions: ExtractInterface, DependencyInversion, MergeModules, IntroduceMediator | Audit | P1 |
| N7 | Coupling quality gate criterion | Research | P2 |
| N8 | TOML-configurable coupling thresholds | AD3 | P2 |
| N9 | Event emission via DriftEventHandler | D5 | P1 |
| N10 | Keyset pagination for module/cycle queries | Storage V2 | P1 |

---

## 3. V2 Architecture — Unified Coupling Engine

### 3.1 Design Philosophy

The v2 coupling engine unifies the Rust (~600 LOC) and TypeScript (~900 LOC)
implementations into a single Rust engine with zero feature loss. The key architectural
decisions:

1. **petgraph as the graph backbone** — Use `petgraph::StableGraph<ModuleNode, DependencyEdge>`
   for the in-memory dependency graph. Leverage `tarjan_scc()` for cycle detection and
   `condensation()` for DAG generation. No hand-rolled graph algorithms.

2. **Consume ParseResult, don't re-parse** — The v1 Rust implementation calls tree-sitter
   directly to extract imports/exports. V2 consumes `ParseResult` from the unified analysis
   engine, which already has `imports: Vec<ImportInfo>` and `exports: Vec<ExportInfo>`.

3. **Call graph integration for transitive analysis** — When the call graph is available,
   use it for transitive dependency tracking and more accurate refactor impact analysis.
   When unavailable, fall back to import-only analysis (still useful, just less precise).

4. **Auto-selection for scale** — For codebases with <5,000 modules, use in-memory petgraph.
   For larger codebases, use SQLite recursive CTEs for cycle detection and metrics
   calculation. The threshold is configurable.

5. **Incremental by design** — Track which modules changed (via content hash) and which
   modules depend on changed modules (via the dependency graph itself). Only recompute
   metrics for affected modules. Full Tarjan's SCC runs on the complete graph but is
   O(V+E) and fast even for large graphs.

### 3.2 Engine Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        CouplingEngine (Public API)                          │
│                                                                             │
│  analyze(config) → CouplingResult                                          │
│  analyze_module(path) → ModuleAnalysis                                     │
│  analyze_refactor_impact(path) → RefactorImpact                           │
│  get_cycles(options) → Vec<DependencyCycle>                                │
│  get_hotspots(options) → Vec<CouplingHotspot>                              │
│  get_unused_exports() → Vec<UnusedExportAnalysis>                          │
│  get_condensation_graph() → CondensationGraph                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                        10-Phase Pipeline                                    │
│                                                                             │
│  Phase 1: Dependency Graph Construction (import/export → petgraph)          │
│  Phase 2: Module Aggregation & Metrics (Ca, Ce, I, A, D)                   │
│  Phase 3: Tarjan's SCC Cycle Detection                                     │
│  Phase 4: Condensation Graph Generation (DAG of SCCs)                      │
│  Phase 5: Zone Classification (Pain/Uselessness/Main Sequence)             │
│  Phase 6: Module Role Assignment (Hub/Authority/Balanced/Isolated)          │
│  Phase 7: Cycle Break Suggestion Engine                                    │
│  Phase 8: Refactor Impact Analysis                                         │
│  Phase 9: Unused Export Detection                                          │
│  Phase 10: Health Score Calculation                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                        Auto-Selection Layer                                 │
│                                                                             │
│  InMemoryCouplingBackend (petgraph — <5K modules)                          │
│  SqliteCouplingBackend (recursive CTEs — ≥5K modules)                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                        Upstream Data Sources                                │
│                                                                             │
│  ParseResult.imports / ParseResult.exports (from Unified Analysis)         │
│  CallGraphDb (optional — for transitive analysis)                          │
│  ResolutionIndex (for import path resolution)                              │
│  drift.db (for persistence and incremental state)                          │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 3.3 Configuration

```toml
# drift.toml — coupling analysis configuration
[coupling]
enabled = true

# Module granularity: "file" | "directory" | "package"
# "file" — each file is a module (finest granularity)
# "directory" — files grouped by parent directory (default, matches v1)
# "package" — files grouped by package.json/Cargo.toml/pyproject.toml scope
granularity = "directory"

# Hotspot threshold: modules with total coupling (Ca + Ce) >= this are hotspots
hotspot_threshold = 3

# Auto-selection threshold: use SQLite CTE backend above this module count
sqlite_threshold = 5000

# Zone thresholds (Robert C. Martin)
zone_of_pain_instability_max = 0.3
zone_of_pain_abstractness_max = 0.3
zone_of_uselessness_instability_min = 0.7
zone_of_uselessness_abstractness_min = 0.7

# Cycle severity thresholds
cycle_severity_critical = 5    # >5 modules in cycle
cycle_severity_high = 3        # >3 modules
cycle_severity_medium = 2      # >2 modules

# Health score weights
health_weight_cycles = 0.30
health_weight_zones = 0.20
health_weight_hotspots = 0.15
health_weight_unused = 0.10
health_weight_distance = 0.25

# Incremental analysis
incremental = true
```

---

## 4. Core Data Model

All types defined in Rust. NAPI serialization via `#[napi(object)]` or serde.
TypeScript types auto-generated by napi-rs v3.

### 4.1 Graph Types (Internal — Not Crossing NAPI)

```rust
use petgraph::stable_graph::{StableGraph, NodeIndex, EdgeIndex};
use petgraph::Directed;
use rustc_hash::FxHashMap;

/// A node in the coupling dependency graph, representing a module.
#[derive(Debug, Clone)]
pub struct ModuleNode {
    /// Module path (directory path for directory granularity, file path for file).
    pub path: String,
    /// Primary language of the module.
    pub language: Language,
    /// All exported symbols from this module.
    pub exports: Vec<ExportedSymbol>,
    /// Files belonging to this module.
    pub files: Vec<String>,
    /// Content hashes of files (for incremental tracking).
    pub content_hashes: Vec<ContentHash>,
}

/// An exported symbol from a module.
#[derive(Debug, Clone)]
pub struct ExportedSymbol {
    pub name: String,
    pub kind: ExportKind,
    pub file: String,
    pub line: u32,
    pub is_default: bool,
    pub is_type_only: bool,
}

/// Kind of exported symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExportKind {
    Function,
    Class,
    Interface,
    Type,
    Constant,
    Enum,
    Variable,
    ReExport,
    Unknown,
}

/// An edge in the coupling dependency graph, representing an import relationship.
#[derive(Debug, Clone)]
pub struct DependencyEdge {
    /// Imported symbol names.
    pub symbols: Vec<String>,
    /// Whether this is a type-only import (import type { ... }).
    pub is_type_only: bool,
    /// Source file where the import occurs.
    pub source_file: String,
    /// Line number of the import statement.
    pub line: u32,
}

/// The coupling dependency graph type.
pub type CouplingGraph = StableGraph<ModuleNode, DependencyEdge, Directed>;

/// Indexed wrapper for O(1) module lookup by path.
pub struct IndexedCouplingGraph {
    pub graph: CouplingGraph,
    pub module_index: FxHashMap<String, NodeIndex>,
}
```


### 4.2 Metrics Types (Cross NAPI)

```rust
use serde::{Deserialize, Serialize};

/// Robert C. Martin coupling metrics for a single module.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "napi", derive(napi_derive::napi))]
pub struct ModuleMetrics {
    /// Module path.
    pub path: String,
    /// Primary language.
    pub language: String,
    /// Afferent coupling: number of modules that depend on this one.
    pub ca: u32,
    /// Efferent coupling: number of modules this one depends on.
    pub ce: u32,
    /// Instability: Ce / (Ca + Ce). 0 = maximally stable, 1 = maximally unstable.
    pub instability: f64,
    /// Abstractness: abstract exports / total exports. 0 = concrete, 1 = abstract.
    pub abstractness: f64,
    /// Distance from main sequence: |A + I - 1|. 0 = ideal, 1 = worst.
    pub distance: f64,
    /// Total exported symbols.
    pub total_exports: u32,
    /// Exports consumed by at least one other module.
    pub used_exports: u32,
    /// Exports not consumed by any other module.
    pub unused_exports: u32,
    /// Files in this module.
    pub files: Vec<String>,
    /// Module role classification.
    pub role: ModuleRole,
    /// Zone classification.
    pub zone: ZoneClassification,
}

/// Module role based on coupling characteristics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "napi", derive(napi_derive::napi))]
pub enum ModuleRole {
    /// High Ca AND high Ce — central connector, many dependencies in and out.
    Hub,
    /// High Ca, low Ce — heavily depended upon, few outgoing dependencies.
    Authority,
    /// Moderate Ca and Ce — balanced coupling profile.
    Balanced,
    /// Low Ca AND low Ce — minimal connections, potentially dead or self-contained.
    Isolated,
}

/// Zone classification per Robert C. Martin's main sequence analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "napi", derive(napi_derive::napi))]
pub enum ZoneClassification {
    /// On or near the main sequence (D < 0.3). Ideal balance of stability and abstractness.
    MainSequence,
    /// Zone of Pain: low instability (stable) AND low abstractness (concrete).
    /// Hard to change because many modules depend on it, but not abstract enough
    /// to accommodate change through polymorphism. Examples: utility libraries,
    /// database schemas, core data models.
    ZoneOfPain,
    /// Zone of Uselessness: high instability (unstable) AND high abstractness.
    /// Too abstract for its instability — interfaces/abstractions that nothing
    /// concrete implements or that change too frequently. Dead abstractions.
    ZoneOfUselessness,
    /// Between zones — not clearly in any zone (D >= 0.3 but not in pain/uselessness).
    Transitional,
}

/// Cycle severity classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "napi", derive(napi_derive::napi))]
pub enum CycleSeverity {
    /// 2 modules in cycle.
    Low,
    /// 3 modules in cycle (>2).
    Medium,
    /// 4-5 modules in cycle (>3).
    High,
    /// 6+ modules in cycle (>5).
    Critical,
}
```

### 4.3 Result Types (Cross NAPI)

```rust
/// A dependency cycle detected by Tarjan's SCC.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "napi", derive(napi_derive::napi))]
pub struct DependencyCycle {
    /// Module paths in the cycle (ordered by discovery).
    pub modules: Vec<String>,
    /// Cycle severity based on module count.
    pub severity: CycleSeverity,
    /// Total files affected across all modules in the cycle.
    pub files_affected: u32,
    /// Suggested break points to eliminate this cycle.
    pub break_points: Vec<BreakPoint>,
    /// Cycle ID (hash of sorted module paths — stable across runs).
    pub id: String,
}

/// A suggested break point to eliminate a dependency cycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "napi", derive(napi_derive::napi))]
pub struct BreakPoint {
    /// Source module (the one doing the importing).
    pub from: String,
    /// Target module (the one being imported).
    pub to: String,
    /// Estimated effort to break this edge.
    pub effort: BreakEffort,
    /// Human-readable rationale for why this edge is a good break point.
    pub rationale: String,
    /// Suggested approach for breaking this dependency.
    pub approach: BreakApproach,
    /// Score: lower = better break point. Based on Ce(from) / Ca(to).
    pub score: f64,
}

/// Effort estimation for breaking a dependency edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "napi", derive(napi_derive::napi))]
pub enum BreakEffort {
    /// Simple re-export or re-organization. <1 hour.
    Low,
    /// Interface extraction or dependency inversion. 1-4 hours.
    Medium,
    /// Major refactor, module restructuring. >4 hours.
    High,
}

/// Approach for breaking a dependency cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "napi", derive(napi_derive::napi))]
pub enum BreakApproach {
    /// Extract a shared interface that both modules depend on.
    ExtractInterface,
    /// Invert the dependency direction using dependency injection.
    DependencyInversion,
    /// Merge the two modules into one (if they're tightly coupled).
    MergeModules,
    /// Introduce a mediator module that both depend on.
    IntroduceMediator,
    /// Move shared code to a common utility module.
    ExtractCommon,
}

/// A coupling hotspot — a module with unusually high coupling.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "napi", derive(napi_derive::napi))]
pub struct CouplingHotspot {
    /// Module path.
    pub module: String,
    /// Total coupling (Ca + Ce).
    pub total_coupling: u32,
    /// Modules that depend on this one.
    pub incoming: Vec<String>,
    /// Modules this one depends on.
    pub outgoing: Vec<String>,
    /// Module role.
    pub role: ModuleRole,
    /// Risk level based on coupling and zone.
    pub risk: HotspotRisk,
}

/// Risk level for a coupling hotspot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "napi", derive(napi_derive::napi))]
pub enum HotspotRisk {
    /// High coupling but in a good zone — manageable.
    Low,
    /// High coupling with some zone concerns.
    Medium,
    /// High coupling AND in zone of pain — dangerous.
    High,
    /// Extreme coupling, in zone of pain, involved in cycles — critical.
    Critical,
}

/// Analysis of an unused export with reason inference.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "napi", derive(napi_derive::napi))]
pub struct UnusedExportAnalysis {
    /// File containing the export.
    pub file: String,
    /// Exported symbol name.
    pub symbol: String,
    /// Kind of export (function, class, type, constant, etc.).
    pub kind: String,
    /// Line number of the export.
    pub line: u32,
    /// Inferred reasons for non-usage.
    pub reasons: Vec<UnusedReason>,
    /// Confidence that this export is truly unused (0.0-1.0).
    pub confidence: f64,
}

/// Reason an export is unused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "napi", derive(napi_derive::napi))]
pub enum UnusedReason {
    /// No references found anywhere in the codebase.
    DeadCode,
    /// Only referenced from test files.
    TestOnly,
    /// Only used within the same directory/module.
    Internal,
    /// Marked with @deprecated or similar annotation.
    Deprecated,
    /// Recently added, may not have consumers yet.
    NewExport,
}

/// Refactor impact analysis for a module.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "napi", derive(napi_derive::napi))]
pub struct RefactorImpact {
    /// Module being analyzed.
    pub module: String,
    /// Modules that directly depend on this one.
    pub direct_dependents: Vec<String>,
    /// Modules that transitively depend on this one (via call graph if available).
    pub transitive_dependents: Vec<String>,
    /// Test files that would be affected.
    pub affected_tests: Vec<String>,
    /// Module health assessment.
    pub health: ModuleHealth,
    /// Estimated refactoring effort.
    pub effort: RefactorEffort,
    /// Risk level of the refactoring.
    pub risk: RefactorRisk,
    /// Actionable suggestions.
    pub suggestions: Vec<String>,
}

/// Module health assessment.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "napi", derive(napi_derive::napi))]
pub struct ModuleHealth {
    /// Health score 0-100.
    pub score: u32,
    /// Issues found.
    pub issues: Vec<String>,
    /// Improvement suggestions.
    pub suggestions: Vec<String>,
}

/// Refactoring effort estimation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "napi", derive(napi_derive::napi))]
pub enum RefactorEffort {
    /// Few dependents, simple changes. <1 day.
    Low,
    /// Moderate dependents, some interface changes. 1-3 days.
    Medium,
    /// Many dependents, significant restructuring. 3-5 days.
    High,
    /// Massive blast radius, architectural change. >5 days.
    VeryHigh,
}

/// Refactoring risk level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "napi", derive(napi_derive::napi))]
pub enum RefactorRisk {
    Low,
    Medium,
    High,
    Critical,
}

/// The condensation graph — DAG of strongly connected components.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "napi", derive(napi_derive::napi))]
pub struct CondensationGraph {
    /// Nodes: each is an SCC (may contain 1+ modules).
    pub components: Vec<CondensationNode>,
    /// Edges between SCCs (guaranteed acyclic).
    pub edges: Vec<CondensationEdge>,
    /// Total number of SCCs.
    pub component_count: u32,
    /// Number of SCCs with >1 module (i.e., actual cycles).
    pub cyclic_component_count: u32,
}

/// A node in the condensation graph (one SCC).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "napi", derive(napi_derive::napi))]
pub struct CondensationNode {
    /// SCC index.
    pub id: u32,
    /// Module paths in this SCC.
    pub modules: Vec<String>,
    /// Whether this SCC represents a cycle (>1 module).
    pub is_cyclic: bool,
    /// Aggregate metrics for the SCC.
    pub aggregate_ca: u32,
    pub aggregate_ce: u32,
}

/// An edge in the condensation graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "napi", derive(napi_derive::napi))]
pub struct CondensationEdge {
    /// Source SCC index.
    pub from: u32,
    /// Target SCC index.
    pub to: u32,
    /// Number of cross-SCC import edges this represents.
    pub weight: u32,
}


### 4.4 Summary Types (Cross NAPI — Lightweight for Command Pattern)

```rust
/// Lightweight summary returned by the analyze_coupling command.
/// Full data is in drift.db — query via query functions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "napi", derive(napi_derive::napi))]
pub struct CouplingSummary {
    /// Total modules analyzed.
    pub modules_analyzed: u32,
    /// Total files analyzed.
    pub files_analyzed: u32,
    /// Number of dependency cycles found.
    pub cycle_count: u32,
    /// Number of critical cycles (>5 modules).
    pub critical_cycle_count: u32,
    /// Number of coupling hotspots.
    pub hotspot_count: u32,
    /// Number of unused exports.
    pub unused_export_count: u32,
    /// Overall health score (0-100).
    pub health_score: f64,
    /// Average instability across all modules.
    pub avg_instability: f64,
    /// Average distance from main sequence.
    pub avg_distance: f64,
    /// Modules in zone of pain.
    pub zone_of_pain_count: u32,
    /// Modules in zone of uselessness.
    pub zone_of_uselessness_count: u32,
    /// Number of SCCs in condensation graph.
    pub condensation_component_count: u32,
    /// Analysis duration in milliseconds.
    pub duration_ms: u32,
    /// Whether incremental analysis was used.
    pub incremental: bool,
    /// Number of modules recomputed (if incremental).
    pub modules_recomputed: u32,
}

/// Snapshot of coupling state for DNA system consumption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CouplingSnapshot {
    pub health_score: f64,
    pub cycle_count: u32,
    pub hotspot_count: u32,
    pub avg_instability: f64,
    pub avg_distance: f64,
    pub zone_of_pain_count: u32,
    pub zone_of_uselessness_count: u32,
    pub total_modules: u32,
}

/// Input for quality gate coupling checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CouplingGateInput {
    pub health_score: f64,
    pub cycle_count: u32,
    pub critical_cycle_count: u32,
    pub hotspot_count: u32,
    pub new_cycles_since_baseline: u32,
    pub health_score_delta: f64,
}
```

---

## 5. Phase 1: Dependency Graph Construction (Import/Export AST Extraction)

### 5.1 Input: ParseResult

The coupling engine does NOT parse files directly. It consumes `ParseResult` from the
unified analysis engine, which already contains extracted imports and exports:

```rust
// From ParseResult (defined in unified analysis engine)
pub struct ImportInfo {
    pub source: String,          // Import source path (e.g., "./utils", "lodash")
    pub symbols: Vec<String>,    // Imported symbol names
    pub is_default: bool,        // Default import
    pub is_namespace: bool,      // Namespace import (import * as X)
    pub is_type_only: bool,      // Type-only import (import type { ... })
    pub line: u32,
    pub resolved_path: Option<String>,  // Resolved absolute path (from ResolutionIndex)
}

pub struct ExportInfo {
    pub name: String,
    pub kind: ExportKind,
    pub line: u32,
    pub is_default: bool,
    pub is_type_only: bool,
    pub is_abstract: bool,       // Abstract class, interface, type alias
}
```

### 5.2 Graph Construction Algorithm

```rust
impl CouplingEngine {
    /// Build the dependency graph from parse results.
    /// O(F + E) where F = files, E = import edges.
    pub fn build_dependency_graph(
        &mut self,
        parse_results: &[ParseResult],
        resolution_index: &ResolutionIndex,
        config: &CouplingConfig,
    ) -> Result<(), CouplingError> {
        let _span = tracing::info_span!("coupling_build_graph",
            files = parse_results.len()
        ).entered();

        // Step 1: Build module map (group files by module based on granularity)
        let module_map = self.build_module_map(parse_results, config.granularity)?;

        // Step 2: Create graph nodes (one per module)
        for (module_path, files) in &module_map {
            let exports = self.collect_module_exports(files, parse_results);
            let content_hashes = files.iter()
                .map(|f| f.content_hash.clone())
                .collect();
            let language = self.infer_module_language(files);

            let node = ModuleNode {
                path: module_path.clone(),
                language,
                exports,
                files: files.iter().map(|f| f.path.clone()).collect(),
                content_hashes,
            };
            let idx = self.graph.graph.add_node(node);
            self.graph.module_index.insert(module_path.clone(), idx);
        }

        // Step 3: Create edges (import relationships between modules)
        for parse_result in parse_results {
            let source_module = self.file_to_module(&parse_result.file, config.granularity);
            let source_idx = match self.graph.module_index.get(&source_module) {
                Some(&idx) => idx,
                None => continue, // File not in any module (shouldn't happen)
            };

            for import in &parse_result.imports {
                // Resolve import to target module
                let target_path = match &import.resolved_path {
                    Some(p) => p.clone(),
                    None => match resolution_index.resolve(&import.source, &parse_result.file) {
                        Some(p) => p,
                        None => continue, // External dependency, skip
                    },
                };

                let target_module = self.file_to_module(&target_path, config.granularity);

                // Skip self-imports (same module)
                if target_module == source_module {
                    continue;
                }

                let target_idx = match self.graph.module_index.get(&target_module) {
                    Some(&idx) => idx,
                    None => continue, // External module, skip
                };

                // Add or merge edge
                let edge = DependencyEdge {
                    symbols: import.symbols.clone(),
                    is_type_only: import.is_type_only,
                    source_file: parse_result.file.clone(),
                    line: import.line,
                };

                self.graph.graph.add_edge(source_idx, target_idx, edge);
            }
        }

        tracing::info!(
            modules = self.graph.graph.node_count(),
            edges = self.graph.graph.edge_count(),
            "Dependency graph built"
        );

        Ok(())
    }
}
```

### 5.3 Module Granularity

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleGranularity {
    /// Each file is its own module. Finest granularity.
    File,
    /// Files grouped by parent directory. Default, matches v1 behavior.
    Directory,
    /// Files grouped by package scope (package.json, Cargo.toml, etc.).
    Package,
}

impl CouplingEngine {
    fn file_to_module(&self, file_path: &str, granularity: ModuleGranularity) -> String {
        match granularity {
            ModuleGranularity::File => file_path.to_string(),
            ModuleGranularity::Directory => {
                std::path::Path::new(file_path)
                    .parent()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_else(|| file_path.to_string())
            }
            ModuleGranularity::Package => {
                // Walk up from file to find nearest package manifest
                self.find_package_root(file_path)
                    .unwrap_or_else(|| {
                        // Fallback to directory granularity
                        std::path::Path::new(file_path)
                            .parent()
                            .map(|p| p.to_string_lossy().to_string())
                            .unwrap_or_else(|| file_path.to_string())
                    })
            }
        }
    }
}
```

---

## 6. Phase 2: Module Aggregation & Metrics Calculation

### 6.1 Robert C. Martin Metrics

These are the foundational coupling metrics. Every module gets all five metrics computed.

```rust
impl CouplingEngine {
    /// Calculate Robert C. Martin metrics for all modules.
    /// O(V + E) — single pass over graph.
    pub fn calculate_metrics(&mut self) -> Result<(), CouplingError> {
        let _span = tracing::info_span!("coupling_calculate_metrics").entered();

        let node_indices: Vec<NodeIndex> = self.graph.graph.node_indices().collect();

        for &idx in &node_indices {
            // Ca: count incoming edges (modules that depend on this one)
            let ca = self.graph.graph
                .neighbors_directed(idx, petgraph::Direction::Incoming)
                .count() as u32;

            // Ce: count outgoing edges (modules this one depends on)
            let ce = self.graph.graph
                .neighbors_directed(idx, petgraph::Direction::Outgoing)
                .count() as u32;

            // I: Instability = Ce / (Ca + Ce)
            let instability = if ca + ce == 0 {
                0.0 // Isolated module — defined as stable
            } else {
                ce as f64 / (ca + ce) as f64
            };

            // A: Abstractness = abstract exports / total exports
            let node = &self.graph.graph[idx];
            let total_exports = node.exports.len() as u32;
            let abstract_exports = node.exports.iter()
                .filter(|e| e.is_type_only || matches!(e.kind,
                    ExportKind::Interface | ExportKind::Type))
                .count() as u32;
            let abstractness = if total_exports == 0 {
                0.0
            } else {
                abstract_exports as f64 / total_exports as f64
            };

            // D: Distance from main sequence = |A + I - 1|
            let distance = (abstractness + instability - 1.0).abs();

            // Count used vs unused exports
            let used_exports = self.count_used_exports(idx);
            let unused_exports = total_exports.saturating_sub(used_exports);

            // Store metrics (will be enriched with role and zone in later phases)
            self.metrics.insert(idx, RawMetrics {
                ca, ce, instability, abstractness, distance,
                total_exports, used_exports, unused_exports,
            });
        }

        Ok(())
    }

    /// Count how many of a module's exports are imported by other modules.
    fn count_used_exports(&self, module_idx: NodeIndex) -> u32 {
        let node = &self.graph.graph[module_idx];
        let export_names: FxHashSet<&str> = node.exports.iter()
            .map(|e| e.name.as_str())
            .collect();

        let mut used = FxHashSet::default();

        // Check all incoming edges for which symbols they import
        for edge_idx in self.graph.graph.edges_directed(module_idx, petgraph::Direction::Incoming) {
            for symbol in &edge_idx.weight().symbols {
                if export_names.contains(symbol.as_str()) {
                    used.insert(symbol.as_str());
                }
            }
        }

        used.len() as u32
    }
}
```

### 6.2 Metrics Interpretation

| Metric | Formula | Range | Interpretation |
|--------|---------|-------|----------------|
| Ca | Count of incoming module dependencies | 0..∞ | High = many dependents = harder to change |
| Ce | Count of outgoing module dependencies | 0..∞ | High = many dependencies = more reasons to change |
| I | Ce / (Ca + Ce) | 0.0-1.0 | 0 = maximally stable, 1 = maximally unstable |
| A | abstract_exports / total_exports | 0.0-1.0 | 0 = concrete, 1 = abstract |
| D | \|A + I - 1\| | 0.0-1.0 | 0 = on main sequence (ideal), 1 = far from ideal |

---

## 7. Phase 3: Tarjan's SCC Cycle Detection

### 7.1 Why Tarjan's Over DFS

The v1 Rust implementation uses hand-rolled DFS with a recursion stack for cycle detection.
This has several problems:

1. **Incomplete**: DFS finds cycles but may miss some SCCs or report duplicate cycles
2. **Non-canonical**: The same cycle can be reported multiple times from different starting nodes
3. **No condensation**: DFS doesn't produce the condensation graph needed for architecture visualization
4. **Edge cases**: Self-loops and disconnected components require special handling

Tarjan's SCC algorithm (via `petgraph::algo::tarjan_scc`) solves all of these:

1. **Complete**: Finds ALL strongly connected components in O(V+E)
2. **Canonical**: Each SCC is reported exactly once
3. **Condensation-ready**: SCCs directly feed into `petgraph::algo::condensation()`
4. **Proven correct**: petgraph's implementation is well-tested and handles all edge cases

### 7.2 Algorithm

```rust
use petgraph::algo::tarjan_scc;

impl CouplingEngine {
    /// Detect all dependency cycles using Tarjan's SCC algorithm.
    /// O(V + E) — single pass over the graph.
    pub fn detect_cycles(&mut self, config: &CouplingConfig) -> Result<Vec<DependencyCycle>, CouplingError> {
        let _span = tracing::info_span!("coupling_detect_cycles").entered();

        // Run Tarjan's SCC on the dependency graph
        let sccs = tarjan_scc(&self.graph.graph);

        let mut cycles = Vec::new();

        for scc in sccs {
            // SCCs with only 1 node are not cycles (unless self-loop)
            if scc.len() <= 1 {
                // Check for self-loop
                let idx = scc[0];
                let has_self_loop = self.graph.graph
                    .edges_directed(idx, petgraph::Direction::Outgoing)
                    .any(|e| e.target() == idx);
                if !has_self_loop {
                    continue;
                }
            }

            let modules: Vec<String> = scc.iter()
                .map(|&idx| self.graph.graph[idx].path.clone())
                .collect();

            let files_affected: u32 = scc.iter()
                .map(|&idx| self.graph.graph[idx].files.len() as u32)
                .sum();

            let severity = Self::classify_cycle_severity(modules.len(), config);

            // Generate cycle ID (hash of sorted module paths for stability)
            let mut sorted_modules = modules.clone();
            sorted_modules.sort();
            let id = blake3::hash(sorted_modules.join("|").as_bytes())
                .to_hex()[..16]
                .to_string();

            // Break point suggestions computed in Phase 7
            let cycle = DependencyCycle {
                modules,
                severity,
                files_affected,
                break_points: Vec::new(), // Populated in Phase 7
                id,
            };

            cycles.push(cycle);
        }

        // Sort by severity (critical first) then by size (largest first)
        cycles.sort_by(|a, b| {
            b.severity.cmp(&a.severity)
                .then_with(|| b.modules.len().cmp(&a.modules.len()))
        });

        tracing::info!(
            total_cycles = cycles.len(),
            critical = cycles.iter().filter(|c| c.severity == CycleSeverity::Critical).count(),
            "Cycle detection complete"
        );

        Ok(cycles)
    }

    fn classify_cycle_severity(module_count: usize, config: &CouplingConfig) -> CycleSeverity {
        if module_count > config.cycle_severity_critical as usize {
            CycleSeverity::Critical
        } else if module_count > config.cycle_severity_high as usize {
            CycleSeverity::High
        } else if module_count > config.cycle_severity_medium as usize {
            CycleSeverity::Medium
        } else {
            CycleSeverity::Low
        }
    }
}
```

### 7.3 Tarjan's vs Kosaraju's

Both are O(V+E). Tarjan's is preferred because:
- Single DFS pass (Kosaraju's requires two passes)
- Produces SCCs in reverse topological order (useful for condensation)
- petgraph provides `tarjan_scc()` out of the box
- Already proven in the codebase (cortex-causal uses it for DAG enforcement)

---

## 8. Phase 4: Condensation Graph Generation

### 8.1 What Is a Condensation Graph

The condensation graph (also called the component graph or metagraph) is formed by
contracting each SCC into a single node. The resulting graph is guaranteed to be a DAG
(directed acyclic graph). This is invaluable for architecture visualization — it shows
the "true" dependency structure with cycles collapsed into single nodes.

### 8.2 Algorithm

```rust
use petgraph::algo::condensation;

impl CouplingEngine {
    /// Generate the condensation graph (DAG of SCCs).
    /// Uses petgraph::algo::condensation with make_acyclic=true.
    pub fn build_condensation_graph(&self) -> Result<CondensationGraph, CouplingError> {
        let _span = tracing::info_span!("coupling_condensation").entered();

        // petgraph's condensation() requires Graph (not StableGraph),
        // so we convert. This is O(V+E) and acceptable since condensation
        // is called once per analysis run.
        let regular_graph = self.to_regular_graph();

        // condensation(graph, make_acyclic=true) collapses SCCs and removes
        // self-loops and multi-edges, guaranteeing a DAG output.
        let condensed = condensation(regular_graph, true);

        let mut components = Vec::new();
        let mut edges = Vec::new();

        for (i, node_weight) in condensed.node_weights().enumerate() {
            // node_weight is Vec<ModuleNode> — all modules in this SCC
            let modules: Vec<String> = node_weight.iter()
                .map(|n| n.path.clone())
                .collect();
            let is_cyclic = modules.len() > 1;

            // Aggregate metrics for the SCC
            let (aggregate_ca, aggregate_ce) = self.aggregate_scc_metrics(node_weight);

            components.push(CondensationNode {
                id: i as u32,
                modules,
                is_cyclic,
                aggregate_ca,
                aggregate_ce,
            });
        }

        for edge in condensed.edge_indices() {
            let (source, target) = condensed.edge_endpoints(edge).unwrap();
            edges.push(CondensationEdge {
                from: source.index() as u32,
                to: target.index() as u32,
                weight: 1, // Could count actual cross-SCC edges
            });
        }

        let cyclic_count = components.iter().filter(|c| c.is_cyclic).count() as u32;

        Ok(CondensationGraph {
            component_count: components.len() as u32,
            cyclic_component_count: cyclic_count,
            components,
            edges,
        })
    }
}
```

### 8.3 Use Cases for Condensation Graph

1. **Architecture visualization** — Show the "true" dependency DAG in the dashboard/IDE
2. **Topological ordering** — Build order for modules (which modules can be built independently)
3. **Layer detection** — Identify architectural layers from the DAG structure
4. **Cycle impact** — Understand how many modules are "trapped" in each cycle
5. **Refactoring priority** — Largest cyclic components should be broken first


---

## 9. Phase 5: Zone Classification (Main Sequence Analysis)

### 9.1 Robert C. Martin's Main Sequence

The main sequence is the line A + I = 1 on the Abstractness-Instability graph.
Modules on or near this line have an ideal balance: stable modules are abstract
(easy to extend), unstable modules are concrete (easy to change).

Modules far from the main sequence are problematic:

```
A (Abstractness)
1.0 ┌──────────────────────────────┐
    │  Zone of                     │
    │  Uselessness    Main         │
    │  (dead          Sequence     │
    │   abstractions) ╲            │
    │                  ╲           │
0.5 │                   ╲          │
    │                    ╲         │
    │                     ╲        │
    │                      ╲       │
    │  Zone of              ╲      │
    │  Pain (rigid,          ╲     │
    │  hard to change)        ╲    │
0.0 └──────────────────────────────┘
    0.0                        1.0
                I (Instability)
```

### 9.2 Classification Algorithm

```rust
impl CouplingEngine {
    /// Classify each module into a zone based on its metrics.
    pub fn classify_zones(&mut self, config: &CouplingConfig) -> Result<(), CouplingError> {
        let _span = tracing::info_span!("coupling_classify_zones").entered();

        let node_indices: Vec<NodeIndex> = self.graph.graph.node_indices().collect();

        for &idx in &node_indices {
            let metrics = self.metrics.get(&idx).unwrap();

            let zone = if metrics.instability <= config.zone_of_pain_instability_max
                && metrics.abstractness <= config.zone_of_pain_abstractness_max
            {
                // Low I (stable) + Low A (concrete) = Zone of Pain
                // This module is hard to change (many dependents) but not abstract
                // enough to accommodate change through polymorphism.
                ZoneClassification::ZoneOfPain
            } else if metrics.instability >= config.zone_of_uselessness_instability_min
                && metrics.abstractness >= config.zone_of_uselessness_abstractness_min
            {
                // High I (unstable) + High A (abstract) = Zone of Uselessness
                // This module is too abstract for its instability — dead abstractions
                // that nothing concrete implements.
                ZoneClassification::ZoneOfUselessness
            } else if metrics.distance < 0.3 {
                // Close to main sequence — ideal
                ZoneClassification::MainSequence
            } else {
                // Between zones — not clearly problematic but not ideal
                ZoneClassification::Transitional
            };

            self.zone_classifications.insert(idx, zone);
        }

        let pain_count = self.zone_classifications.values()
            .filter(|&&z| z == ZoneClassification::ZoneOfPain).count();
        let useless_count = self.zone_classifications.values()
            .filter(|&&z| z == ZoneClassification::ZoneOfUselessness).count();

        tracing::info!(
            zone_of_pain = pain_count,
            zone_of_uselessness = useless_count,
            main_sequence = self.zone_classifications.values()
                .filter(|&&z| z == ZoneClassification::MainSequence).count(),
            "Zone classification complete"
        );

        Ok(())
    }
}
```

### 9.3 Zone-Specific Guidance

| Zone | Problem | Guidance |
|------|---------|----------|
| Zone of Pain | Stable + concrete = rigid | Extract interfaces, increase abstractness |
| Zone of Uselessness | Unstable + abstract = dead weight | Remove unused abstractions, or add concrete implementations |
| Main Sequence | Balanced | No action needed |
| Transitional | Slightly off | Monitor, may drift into a problem zone |

---

## 10. Phase 6: Module Role Assignment

### 10.1 Role Classification

Module roles describe the structural position of a module in the dependency graph.
This is a v2 feature ported from the TypeScript implementation.

```rust
impl CouplingEngine {
    /// Assign roles to each module based on coupling characteristics.
    pub fn assign_roles(&mut self, config: &CouplingConfig) -> Result<(), CouplingError> {
        let _span = tracing::info_span!("coupling_assign_roles").entered();

        // Calculate median coupling for threshold determination
        let all_ca: Vec<u32> = self.metrics.values().map(|m| m.ca).collect();
        let all_ce: Vec<u32> = self.metrics.values().map(|m| m.ce).collect();
        let median_ca = Self::median(&all_ca);
        let median_ce = Self::median(&all_ce);

        // Use median as the threshold for "high" coupling
        // This adapts to the codebase rather than using fixed thresholds
        let high_ca_threshold = median_ca.max(2.0);
        let high_ce_threshold = median_ce.max(2.0);

        let node_indices: Vec<NodeIndex> = self.graph.graph.node_indices().collect();

        for &idx in &node_indices {
            let metrics = self.metrics.get(&idx).unwrap();

            let role = if metrics.ca as f64 >= high_ca_threshold
                && metrics.ce as f64 >= high_ce_threshold
            {
                // High incoming AND outgoing — central connector
                ModuleRole::Hub
            } else if metrics.ca as f64 >= high_ca_threshold
                && (metrics.ce as f64) < high_ce_threshold
            {
                // High incoming, low outgoing — heavily depended upon
                ModuleRole::Authority
            } else if metrics.ca == 0 && metrics.ce == 0 {
                // No connections at all
                ModuleRole::Isolated
            } else {
                // Everything else — moderate coupling
                ModuleRole::Balanced
            };

            self.role_assignments.insert(idx, role);
        }

        Ok(())
    }

    fn median(values: &[u32]) -> f64 {
        if values.is_empty() {
            return 0.0;
        }
        let mut sorted = values.to_vec();
        sorted.sort();
        let mid = sorted.len() / 2;
        if sorted.len() % 2 == 0 {
            (sorted[mid - 1] as f64 + sorted[mid] as f64) / 2.0
        } else {
            sorted[mid] as f64
        }
    }
}
```

### 10.2 Role Interpretation

| Role | Ca | Ce | Interpretation | Action |
|------|----|----|----------------|--------|
| Hub | High | High | Central connector — many deps in and out | Monitor closely, consider splitting |
| Authority | High | Low | Foundation module — heavily depended upon | Keep stable, increase abstractness |
| Balanced | Moderate | Moderate | Normal module | No special action |
| Isolated | Low | Low | Self-contained or dead | Verify it's intentional |

---

## 11. Phase 7: Cycle Break Suggestion Engine

### 11.1 Break Point Scoring

For each edge in a cycle, compute a break score. Lower score = better break point.
The score is based on the coupling characteristics of the source and target modules.

```rust
impl CouplingEngine {
    /// Generate break point suggestions for each cycle.
    pub fn suggest_break_points(
        &self,
        cycles: &mut [DependencyCycle],
    ) -> Result<(), CouplingError> {
        let _span = tracing::info_span!("coupling_break_suggestions").entered();

        for cycle in cycles.iter_mut() {
            let mut break_points = Vec::new();

            // For each pair of adjacent modules in the cycle
            for i in 0..cycle.modules.len() {
                let from = &cycle.modules[i];
                let to = &cycle.modules[(i + 1) % cycle.modules.len()];

                let from_idx = match self.graph.module_index.get(from) {
                    Some(&idx) => idx,
                    None => continue,
                };
                let to_idx = match self.graph.module_index.get(to) {
                    Some(&idx) => idx,
                    None => continue,
                };

                let from_metrics = self.metrics.get(&from_idx).unwrap();
                let to_metrics = self.metrics.get(&to_idx).unwrap();

                // Score: Ce(from) / max(Ca(to), 1)
                // Lower score = from has fewer outgoing deps relative to to's incoming deps
                // = easier to redirect this dependency
                let score = from_metrics.ce as f64 / (to_metrics.ca as f64).max(1.0);

                // Count symbols imported across this edge
                let symbol_count = self.count_edge_symbols(from_idx, to_idx);

                // Determine effort based on symbol count and module roles
                let effort = if symbol_count <= 2 {
                    BreakEffort::Low
                } else if symbol_count <= 5 {
                    BreakEffort::Medium
                } else {
                    BreakEffort::High
                };

                // Determine approach based on module characteristics
                let from_role = self.role_assignments.get(&from_idx).copied()
                    .unwrap_or(ModuleRole::Balanced);
                let to_role = self.role_assignments.get(&to_idx).copied()
                    .unwrap_or(ModuleRole::Balanced);

                let approach = self.suggest_approach(from_role, to_role, symbol_count);

                let rationale = self.generate_rationale(
                    from, to, from_role, to_role, symbol_count, &approach,
                );

                break_points.push(BreakPoint {
                    from: from.clone(),
                    to: to.clone(),
                    effort,
                    rationale,
                    approach,
                    score,
                });
            }

            // Sort by score (lowest = best break point)
            break_points.sort_by(|a, b| a.score.partial_cmp(&b.score).unwrap());

            cycle.break_points = break_points;
        }

        Ok(())
    }

    fn suggest_approach(
        &self,
        from_role: ModuleRole,
        to_role: ModuleRole,
        symbol_count: usize,
    ) -> BreakApproach {
        match (from_role, to_role) {
            // If target is an Authority (heavily depended upon), extract interface
            (_, ModuleRole::Authority) => BreakApproach::ExtractInterface,
            // If both are Hubs, introduce a mediator
            (ModuleRole::Hub, ModuleRole::Hub) => BreakApproach::IntroduceMediator,
            // If few symbols, dependency inversion is straightforward
            _ if symbol_count <= 2 => BreakApproach::DependencyInversion,
            // If modules are tightly coupled (many symbols), consider merging
            _ if symbol_count > 10 => BreakApproach::MergeModules,
            // Default: extract common code
            _ => BreakApproach::ExtractCommon,
        }
    }

    fn generate_rationale(
        &self,
        from: &str,
        to: &str,
        from_role: ModuleRole,
        to_role: ModuleRole,
        symbol_count: usize,
        approach: &BreakApproach,
    ) -> String {
        let role_context = match to_role {
            ModuleRole::Authority => format!("{to} is an authority module (heavily depended upon)"),
            ModuleRole::Hub => format!("{to} is a hub module (central connector)"),
            ModuleRole::Isolated => format!("{to} is isolated (minimal connections)"),
            ModuleRole::Balanced => format!("{to} has balanced coupling"),
        };

        let approach_text = match approach {
            BreakApproach::ExtractInterface =>
                "Extract a shared interface that both modules can depend on",
            BreakApproach::DependencyInversion =>
                "Invert the dependency using dependency injection or callbacks",
            BreakApproach::MergeModules =>
                "Consider merging these tightly coupled modules into one",
            BreakApproach::IntroduceMediator =>
                "Introduce a mediator module that both can depend on",
            BreakApproach::ExtractCommon =>
                "Extract shared code into a common utility module",
        };

        format!(
            "{from} imports {symbol_count} symbol(s) from {to}. {role_context}. \
             Suggestion: {approach_text}."
        )
    }
}
```

---

## 12. Phase 8: Refactor Impact Analysis

### 12.1 Algorithm

Refactor impact analysis answers: "What would break if I changed this module?"
It uses both the dependency graph (direct dependents) and optionally the call graph
(transitive dependents via function-level analysis).

```rust
impl CouplingEngine {
    /// Analyze the impact of refactoring a specific module.
    pub fn analyze_refactor_impact(
        &self,
        module_path: &str,
        call_graph: Option<&CallGraphDb>,
    ) -> Result<RefactorImpact, CouplingError> {
        let _span = tracing::info_span!("coupling_refactor_impact",
            module = module_path
        ).entered();

        let module_idx = self.graph.module_index.get(module_path)
            .ok_or_else(|| CouplingError::ModuleNotFound(module_path.to_string()))?;

        // Direct dependents: modules that import from this one
        let direct_dependents: Vec<String> = self.graph.graph
            .neighbors_directed(*module_idx, petgraph::Direction::Incoming)
            .map(|idx| self.graph.graph[idx].path.clone())
            .collect();

        // Transitive dependents: use call graph if available
        let transitive_dependents = if let Some(cg) = call_graph {
            self.compute_transitive_dependents(module_path, &direct_dependents, cg)?
        } else {
            // Fallback: BFS on dependency graph for transitive imports
            self.bfs_transitive_dependents(*module_idx)
        };

        // Affected tests: files in test directories that depend on this module
        let affected_tests: Vec<String> = transitive_dependents.iter()
            .chain(direct_dependents.iter())
            .filter(|p| self.is_test_file(p))
            .cloned()
            .collect();

        // Module health
        let health = self.compute_module_health(*module_idx);

        // Effort estimation based on dependent count
        let total_affected = direct_dependents.len() + transitive_dependents.len();
        let effort = if total_affected <= 3 {
            RefactorEffort::Low
        } else if total_affected <= 10 {
            RefactorEffort::Medium
        } else if total_affected <= 25 {
            RefactorEffort::High
        } else {
            RefactorEffort::VeryHigh
        };

        // Risk based on transitive impact and zone
        let zone = self.zone_classifications.get(module_idx).copied()
            .unwrap_or(ZoneClassification::Transitional);
        let risk = match (total_affected, zone) {
            (_, ZoneClassification::ZoneOfPain) if total_affected > 10 => RefactorRisk::Critical,
            (n, _) if n > 25 => RefactorRisk::Critical,
            (n, ZoneClassification::ZoneOfPain) if n > 5 => RefactorRisk::High,
            (n, _) if n > 10 => RefactorRisk::High,
            (n, _) if n > 3 => RefactorRisk::Medium,
            _ => RefactorRisk::Low,
        };

        // Generate suggestions
        let suggestions = self.generate_refactor_suggestions(
            module_path, *module_idx, &direct_dependents, zone,
        );

        Ok(RefactorImpact {
            module: module_path.to_string(),
            direct_dependents,
            transitive_dependents,
            affected_tests,
            health,
            effort,
            risk,
            suggestions,
        })
    }

    /// BFS on dependency graph for transitive dependents (no call graph).
    fn bfs_transitive_dependents(&self, start: NodeIndex) -> Vec<String> {
        use petgraph::visit::Bfs;

        let mut result = Vec::new();
        // Reverse BFS: follow incoming edges
        let reversed = petgraph::visit::Reversed(&self.graph.graph);
        let mut bfs = Bfs::new(&reversed, start);

        // Skip the start node itself
        bfs.next(&reversed);

        while let Some(node) = bfs.next(&reversed) {
            let path = &self.graph.graph[node].path;
            result.push(path.clone());
        }

        result
    }

    fn compute_module_health(&self, idx: NodeIndex) -> ModuleHealth {
        let metrics = self.metrics.get(&idx).unwrap();
        let zone = self.zone_classifications.get(&idx).copied()
            .unwrap_or(ZoneClassification::Transitional);

        let mut score = 100u32;
        let mut issues = Vec::new();
        let mut suggestions = Vec::new();

        // Penalize high coupling
        let total_coupling = metrics.ca + metrics.ce;
        if total_coupling > 20 {
            score = score.saturating_sub(30);
            issues.push(format!("Very high coupling ({total_coupling})"));
            suggestions.push("Consider splitting into smaller modules".to_string());
        } else if total_coupling > 10 {
            score = score.saturating_sub(15);
            issues.push(format!("High coupling ({total_coupling})"));
        }

        // Penalize zone of pain
        if zone == ZoneClassification::ZoneOfPain {
            score = score.saturating_sub(20);
            issues.push("In zone of pain (stable but concrete)".to_string());
            suggestions.push("Extract interfaces to increase abstractness".to_string());
        }

        // Penalize zone of uselessness
        if zone == ZoneClassification::ZoneOfUselessness {
            score = score.saturating_sub(15);
            issues.push("In zone of uselessness (unstable and abstract)".to_string());
            suggestions.push("Add concrete implementations or remove unused abstractions".to_string());
        }

        // Penalize unused exports
        if metrics.unused_exports > 3 {
            score = score.saturating_sub(10);
            issues.push(format!("{} unused exports", metrics.unused_exports));
            suggestions.push("Remove or document unused exports".to_string());
        }

        // Penalize high distance from main sequence
        if metrics.distance > 0.7 {
            score = score.saturating_sub(10);
            issues.push(format!("High distance from main sequence ({:.2})", metrics.distance));
        }

        ModuleHealth { score, issues, suggestions }
    }
}
```


---

## 13. Phase 9: Unused Export Detection

### 13.1 Algorithm

```rust
impl CouplingEngine {
    /// Find all unused exports across all modules with reason inference.
    pub fn find_unused_exports(&self) -> Result<Vec<UnusedExportAnalysis>, CouplingError> {
        let _span = tracing::info_span!("coupling_unused_exports").entered();

        let mut results = Vec::new();

        for idx in self.graph.graph.node_indices() {
            let node = &self.graph.graph[idx];

            // Collect all symbols imported from this module
            let imported_symbols: FxHashSet<String> = self.graph.graph
                .edges_directed(idx, petgraph::Direction::Incoming)
                .flat_map(|e| e.weight().symbols.iter().cloned())
                .collect();

            for export in &node.exports {
                if !imported_symbols.contains(&export.name) {
                    let reasons = self.infer_unused_reasons(export, &node.path);
                    let confidence = self.calculate_unused_confidence(&reasons, export);

                    results.push(UnusedExportAnalysis {
                        file: export.file.clone(),
                        symbol: export.name.clone(),
                        kind: format!("{:?}", export.kind).to_lowercase(),
                        line: export.line,
                        reasons,
                        confidence,
                    });
                }
            }
        }

        // Sort by confidence (highest first)
        results.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());

        tracing::info!(unused_exports = results.len(), "Unused export detection complete");

        Ok(results)
    }

    fn infer_unused_reasons(
        &self,
        export: &ExportedSymbol,
        module_path: &str,
    ) -> Vec<UnusedReason> {
        let mut reasons = Vec::new();

        // Check if it's only used in test files
        let test_only = self.is_used_only_in_tests(&export.name, module_path);
        if test_only {
            reasons.push(UnusedReason::TestOnly);
        }

        // Check if it's only used within the same directory
        let internal_only = self.is_used_only_internally(&export.name, module_path);
        if internal_only {
            reasons.push(UnusedReason::Internal);
        }

        // Check for deprecation markers (from export metadata if available)
        if export.name.starts_with("deprecated") || export.name.starts_with("_") {
            reasons.push(UnusedReason::Deprecated);
        }

        // If no specific reason found, it's dead code
        if reasons.is_empty() {
            reasons.push(UnusedReason::DeadCode);
        }

        reasons
    }

    fn calculate_unused_confidence(
        &self,
        reasons: &[UnusedReason],
        export: &ExportedSymbol,
    ) -> f64 {
        let mut confidence = 0.8; // Base confidence

        // Higher confidence for dead code (no references at all)
        if reasons.contains(&UnusedReason::DeadCode) {
            confidence = 0.95;
        }

        // Lower confidence for test-only (might be intentional test helpers)
        if reasons.contains(&UnusedReason::TestOnly) {
            confidence = 0.6;
        }

        // Lower confidence for internal-only (might be used via re-exports)
        if reasons.contains(&UnusedReason::Internal) {
            confidence = 0.5;
        }

        // Default exports are more likely intentionally public
        if export.is_default {
            confidence -= 0.1;
        }

        confidence.clamp(0.0, 1.0)
    }
}
```

---

## 14. Phase 10: Health Score Calculation

### 14.1 Multi-Factor Health Score

The health score is a single 0-100 number that summarizes the overall coupling health
of the codebase. It's consumed by DNA, quality gates, and the CI agent.

```rust
impl CouplingEngine {
    /// Calculate the overall coupling health score (0-100).
    pub fn calculate_health_score(
        &self,
        cycles: &[DependencyCycle],
        hotspots: &[CouplingHotspot],
        unused_exports: &[UnusedExportAnalysis],
        config: &CouplingConfig,
    ) -> f64 {
        let _span = tracing::info_span!("coupling_health_score").entered();

        let module_count = self.graph.graph.node_count();
        if module_count == 0 {
            return 100.0;
        }

        // Component 1: Cycle penalty (0-100, higher = worse)
        let cycle_penalty = self.calculate_cycle_penalty(cycles);

        // Component 2: Zone penalty (0-100, higher = worse)
        let zone_penalty = self.calculate_zone_penalty(module_count);

        // Component 3: Hotspot penalty (0-100, higher = worse)
        let hotspot_penalty = self.calculate_hotspot_penalty(hotspots, module_count);

        // Component 4: Unused export penalty (0-100, higher = worse)
        let unused_penalty = self.calculate_unused_penalty(unused_exports, module_count);

        // Component 5: Distance penalty (0-100, higher = worse)
        let distance_penalty = self.calculate_distance_penalty();

        // Weighted combination
        let total_penalty =
            cycle_penalty * config.health_weight_cycles +
            zone_penalty * config.health_weight_zones +
            hotspot_penalty * config.health_weight_hotspots +
            unused_penalty * config.health_weight_unused +
            distance_penalty * config.health_weight_distance;

        let score = (100.0 - total_penalty).clamp(0.0, 100.0);

        tracing::info!(
            health_score = score,
            cycle_penalty, zone_penalty, hotspot_penalty,
            unused_penalty, distance_penalty,
            "Health score calculated"
        );

        score
    }

    fn calculate_cycle_penalty(&self, cycles: &[DependencyCycle]) -> f64 {
        let mut penalty = 0.0;
        for cycle in cycles {
            match cycle.severity {
                CycleSeverity::Critical => penalty += 25.0,
                CycleSeverity::High => penalty += 15.0,
                CycleSeverity::Medium => penalty += 8.0,
                CycleSeverity::Low => penalty += 3.0,
            }
        }
        penalty.min(100.0)
    }

    fn calculate_zone_penalty(&self, module_count: usize) -> f64 {
        let pain_count = self.zone_classifications.values()
            .filter(|&&z| z == ZoneClassification::ZoneOfPain).count();
        let useless_count = self.zone_classifications.values()
            .filter(|&&z| z == ZoneClassification::ZoneOfUselessness).count();

        let pain_ratio = pain_count as f64 / module_count as f64;
        let useless_ratio = useless_count as f64 / module_count as f64;

        // Zone of pain is worse than zone of uselessness
        let penalty = (pain_ratio * 150.0) + (useless_ratio * 100.0);
        penalty.min(100.0)
    }

    fn calculate_hotspot_penalty(
        &self,
        hotspots: &[CouplingHotspot],
        module_count: usize,
    ) -> f64 {
        let hotspot_ratio = hotspots.len() as f64 / module_count as f64;
        let critical_hotspots = hotspots.iter()
            .filter(|h| h.risk == HotspotRisk::Critical).count();

        let penalty = (hotspot_ratio * 80.0) + (critical_hotspots as f64 * 10.0);
        penalty.min(100.0)
    }

    fn calculate_unused_penalty(
        &self,
        unused: &[UnusedExportAnalysis],
        module_count: usize,
    ) -> f64 {
        let unused_ratio = unused.len() as f64 / (module_count as f64 * 5.0).max(1.0);
        (unused_ratio * 100.0).min(100.0)
    }

    fn calculate_distance_penalty(&self) -> f64 {
        if self.metrics.is_empty() {
            return 0.0;
        }
        let avg_distance: f64 = self.metrics.values()
            .map(|m| m.distance)
            .sum::<f64>() / self.metrics.len() as f64;

        // Average distance > 0.5 is concerning
        (avg_distance * 200.0).min(100.0)
    }
}
```

---

## 15. Auto-Selection: In-Memory (petgraph) vs SQLite CTE

### 15.1 Decision Criteria

For most codebases (<5,000 modules), the in-memory petgraph approach is optimal.
For very large codebases (≥5,000 modules), SQLite recursive CTEs provide O(1) memory
usage and can leverage existing indexes.

```rust
pub trait CouplingBackend {
    fn build_graph(&mut self, parse_results: &[ParseResult], config: &CouplingConfig)
        -> Result<(), CouplingError>;
    fn calculate_metrics(&mut self) -> Result<(), CouplingError>;
    fn detect_cycles(&self) -> Result<Vec<DependencyCycle>, CouplingError>;
    fn get_module_metrics(&self, path: &str) -> Result<ModuleMetrics, CouplingError>;
    fn get_dependents(&self, path: &str) -> Result<Vec<String>, CouplingError>;
    fn get_dependencies(&self, path: &str) -> Result<Vec<String>, CouplingError>;
}

/// In-memory backend using petgraph. Fast for <5K modules.
pub struct InMemoryCouplingBackend {
    engine: CouplingEngine,
}

/// SQLite CTE backend. Scales to 100K+ modules with O(1) memory.
pub struct SqliteCouplingBackend {
    db: DatabaseManager,
}

/// Auto-select backend based on module count.
pub fn create_backend(
    module_count: usize,
    config: &CouplingConfig,
    db: &DatabaseManager,
) -> Box<dyn CouplingBackend> {
    if module_count < config.sqlite_threshold as usize {
        Box::new(InMemoryCouplingBackend::new())
    } else {
        Box::new(SqliteCouplingBackend::new(db.clone()))
    }
}
```

### 15.2 SQLite CTE Cycle Detection

For the SQLite backend, cycle detection uses recursive CTEs:

```sql
-- Find all modules reachable from a given module (forward reachability)
WITH RECURSIVE reachable(module_path, depth) AS (
    SELECT target_module, 1
    FROM module_dependencies
    WHERE source_module = ?1
    
    UNION
    
    SELECT md.target_module, r.depth + 1
    FROM module_dependencies md
    JOIN reachable r ON md.source_module = r.module_path
    WHERE r.depth < 100  -- Safety limit
)
SELECT module_path, depth FROM reachable;

-- Detect cycles: a module that can reach itself
WITH RECURSIVE cycle_check(module_path, start_module, depth, path) AS (
    SELECT target_module, source_module, 1, source_module || '|' || target_module
    FROM module_dependencies
    WHERE source_module = ?1
    
    UNION
    
    SELECT md.target_module, cc.start_module, cc.depth + 1,
           cc.path || '|' || md.target_module
    FROM module_dependencies md
    JOIN cycle_check cc ON md.source_module = cc.module_path
    WHERE cc.depth < 100
      AND md.target_module != cc.start_module  -- Avoid premature termination
      AND instr(cc.path, md.target_module) = 0  -- Avoid revisiting
)
SELECT path FROM cycle_check
WHERE module_path = start_module;

-- Calculate Ca (afferent coupling) for all modules
SELECT target_module AS module_path,
       COUNT(DISTINCT source_module) AS ca
FROM module_dependencies
GROUP BY target_module;

-- Calculate Ce (efferent coupling) for all modules
SELECT source_module AS module_path,
       COUNT(DISTINCT target_module) AS ce
FROM module_dependencies
GROUP BY source_module;
```

### 15.3 When to Use Which

| Criterion | In-Memory (petgraph) | SQLite CTE |
|-----------|---------------------|------------|
| Module count | <5,000 | ≥5,000 |
| Memory usage | O(V+E) | O(1) |
| Cycle detection | Tarjan's SCC O(V+E) | Recursive CTE (slower) |
| Condensation | petgraph::condensation | Not available |
| Incremental | Rebuild graph | Update rows |
| Best for | Most projects | Enterprise monorepos |

---

## 16. Incremental Coupling Analysis (Content-Hash + Dependency Tracking)

### 16.1 Incremental Strategy

Per AD1 (Incremental-First Architecture), coupling analysis supports incremental updates:

1. **File-level skip**: If a file's content hash hasn't changed, skip re-extracting its imports/exports
2. **Module-level invalidation**: If any file in a module changed, recompute that module's metrics
3. **Dependency-level invalidation**: If a module's exports changed, invalidate all modules that depend on it
4. **Full SCC rerun**: Tarjan's SCC always runs on the complete graph (O(V+E) is fast enough)

```rust
impl CouplingEngine {
    /// Incremental coupling analysis: only recompute what changed.
    pub fn analyze_incremental(
        &mut self,
        changed_files: &[String],
        parse_results: &[ParseResult],
        config: &CouplingConfig,
    ) -> Result<CouplingSummary, CouplingError> {
        let _span = tracing::info_span!("coupling_incremental",
            changed_files = changed_files.len()
        ).entered();

        // Step 1: Identify changed modules
        let changed_modules: FxHashSet<String> = changed_files.iter()
            .map(|f| self.file_to_module(f, config.granularity))
            .collect();

        // Step 2: Identify affected modules (changed + their dependents)
        let mut affected_modules = changed_modules.clone();
        for module in &changed_modules {
            if let Some(&idx) = self.graph.module_index.get(module) {
                // Add all modules that depend on the changed module
                for neighbor in self.graph.graph
                    .neighbors_directed(idx, petgraph::Direction::Incoming)
                {
                    affected_modules.insert(self.graph.graph[neighbor].path.clone());
                }
            }
        }

        // Step 3: Update graph nodes for changed modules
        for module in &changed_modules {
            self.update_module_node(module, parse_results, config)?;
        }

        // Step 4: Update edges for changed modules
        for module in &changed_modules {
            self.update_module_edges(module, parse_results, config)?;
        }

        // Step 5: Recompute metrics for affected modules only
        for module in &affected_modules {
            if let Some(&idx) = self.graph.module_index.get(module) {
                self.recompute_module_metrics(idx)?;
            }
        }

        // Step 6: Full Tarjan's SCC (always runs on complete graph — O(V+E))
        let mut cycles = self.detect_cycles(config)?;
        self.suggest_break_points(&mut cycles)?;

        // Step 7: Recompute zones and roles for affected modules
        self.classify_zones(config)?;
        self.assign_roles(config)?;

        // Step 8: Recompute hotspots and unused exports
        let hotspots = self.find_hotspots(config)?;
        let unused_exports = self.find_unused_exports()?;

        // Step 9: Recompute health score
        let health_score = self.calculate_health_score(
            &cycles, &hotspots, &unused_exports, config,
        );

        // Step 10: Persist to drift.db
        self.persist_results(&cycles, &hotspots, &unused_exports, health_score)?;

        Ok(CouplingSummary {
            modules_analyzed: self.graph.graph.node_count() as u32,
            files_analyzed: parse_results.len() as u32,
            cycle_count: cycles.len() as u32,
            critical_cycle_count: cycles.iter()
                .filter(|c| c.severity == CycleSeverity::Critical).count() as u32,
            hotspot_count: hotspots.len() as u32,
            unused_export_count: unused_exports.len() as u32,
            health_score,
            avg_instability: self.avg_metric(|m| m.instability),
            avg_distance: self.avg_metric(|m| m.distance),
            zone_of_pain_count: self.count_zone(ZoneClassification::ZoneOfPain),
            zone_of_uselessness_count: self.count_zone(ZoneClassification::ZoneOfUselessness),
            condensation_component_count: 0, // Computed on demand
            duration_ms: 0, // Set by caller
            incremental: true,
            modules_recomputed: affected_modules.len() as u32,
        })
    }
}
```

---

## 17. Integration with Call Graph Builder

### 17.1 How Call Graph Enriches Coupling

The call graph provides function-level dependency data that enriches module-level
coupling analysis in three ways:

1. **Transitive dependency tracking**: Import-only analysis shows direct dependencies.
   Call graph analysis reveals transitive dependencies (A calls B which calls C).

2. **Accurate refactor impact**: When analyzing refactor impact, the call graph shows
   which specific functions would be affected, not just which modules.

3. **Test file identification**: The call graph can identify which test files exercise
   functions in a given module, enabling accurate `affected_tests` in RefactorImpact.

### 17.2 Integration Contract

```rust
/// The coupling engine optionally consumes call graph data.
/// When available, it enriches transitive analysis and refactor impact.
/// When unavailable, it falls back to import-only analysis.
impl CouplingEngine {
    pub fn set_call_graph(&mut self, call_graph: Arc<CallGraphDb>) {
        self.call_graph = Some(call_graph);
    }

    fn compute_transitive_dependents(
        &self,
        module_path: &str,
        direct_dependents: &[String],
        call_graph: &CallGraphDb,
    ) -> Result<Vec<String>, CouplingError> {
        let module_files = self.get_module_files(module_path);
        let mut transitive = FxHashSet::default();

        // For each function in the module, find all callers transitively
        for file in &module_files {
            let functions = call_graph.get_functions_in_file(file)?;
            for func in functions {
                let callers = call_graph.get_transitive_callers(&func.id, 10)?;
                for caller in callers {
                    let caller_module = self.file_to_module(
                        &caller.file, ModuleGranularity::Directory,
                    );
                    if caller_module != module_path
                        && !direct_dependents.contains(&caller_module)
                    {
                        transitive.insert(caller_module);
                    }
                }
            }
        }

        Ok(transitive.into_iter().collect())
    }
}
```

---

## 18. Integration with Unified Analysis Engine

The coupling engine consumes `ParseResult` from the unified analysis engine.
It does NOT run its own tree-sitter parsing. This is a key architectural change from v1
where the Rust coupling analyzer called tree-sitter directly.

### 18.1 Contract

```rust
// CouplingEngine expects these fields from ParseResult:
// - file: String (file path)
// - language: Language
// - imports: Vec<ImportInfo>
// - exports: Vec<ExportInfo>
// - content_hash: ContentHash (for incremental tracking)
```

### 18.2 Batch API Integration

The coupling engine is one of the analyses available in the batch API:

```rust
// In the batch task (from 03-NAPI-BRIDGE-V2-PREP.md §9):
AnalysisType::Coupling => {
    let summary = drift_core::coupling::analyze(
        &parse_results, &rt.db, &rt.config.coupling,
    ).map_err(to_napi_error)?;
    result.coupling = Some(summary);
}
```

---

## 19. Integration with DNA System

The DNA system extracts "genes" from the codebase — coupling metrics are one gene.

### 19.1 Coupling Gene

```rust
/// The coupling gene for the DNA system.
pub struct CouplingGene {
    /// Average instability across all modules.
    pub avg_instability: f64,
    /// Average distance from main sequence.
    pub avg_distance: f64,
    /// Cycle density: cycles / modules.
    pub cycle_density: f64,
    /// Hotspot density: hotspots / modules.
    pub hotspot_density: f64,
    /// Zone of pain ratio.
    pub pain_ratio: f64,
    /// Overall health score.
    pub health_score: f64,
}

impl From<&CouplingSnapshot> for CouplingGene {
    fn from(snapshot: &CouplingSnapshot) -> Self {
        let total = snapshot.total_modules.max(1) as f64;
        CouplingGene {
            avg_instability: snapshot.avg_instability,
            avg_distance: snapshot.avg_distance,
            cycle_density: snapshot.cycle_count as f64 / total,
            hotspot_density: snapshot.hotspot_count as f64 / total,
            pain_ratio: snapshot.zone_of_pain_count as f64 / total,
            health_score: snapshot.health_score,
        }
    }
}
```

---

## 20. Integration with Quality Gates

### 20.1 Coupling Quality Gate Criterion

Coupling data feeds into the Impact Simulation Gate and can be used as a standalone
quality gate criterion.

```rust
/// Quality gate check for coupling health.
pub fn check_coupling_gate(
    input: &CouplingGateInput,
    config: &CouplingGateConfig,
) -> GateResult {
    let mut violations = Vec::new();

    // Check for new cycles
    if input.new_cycles_since_baseline > config.max_new_cycles {
        violations.push(GateViolation {
            severity: Severity::Error,
            message: format!(
                "{} new dependency cycle(s) introduced (max: {})",
                input.new_cycles_since_baseline, config.max_new_cycles
            ),
        });
    }

    // Check health score threshold
    if input.health_score < config.min_health_score {
        violations.push(GateViolation {
            severity: Severity::Error,
            message: format!(
                "Coupling health score {:.1} below threshold {:.1}",
                input.health_score, config.min_health_score
            ),
        });
    }

    // Check health score regression
    if input.health_score_delta < -config.max_health_regression {
        violations.push(GateViolation {
            severity: Severity::Warning,
            message: format!(
                "Coupling health regressed by {:.1} points (max: {:.1})",
                -input.health_score_delta, config.max_health_regression
            ),
        });
    }

    // Check critical cycles
    if input.critical_cycle_count > config.max_critical_cycles {
        violations.push(GateViolation {
            severity: Severity::Error,
            message: format!(
                "{} critical cycle(s) (max: {})",
                input.critical_cycle_count, config.max_critical_cycles
            ),
        });
    }

    GateResult::from_violations(violations)
}

pub struct CouplingGateConfig {
    pub max_new_cycles: u32,          // Default: 0
    pub min_health_score: f64,        // Default: 60.0
    pub max_health_regression: f64,   // Default: 5.0
    pub max_critical_cycles: u32,     // Default: 0
}
```


---

## 21. Integration with Simulation Engine

The simulation engine uses coupling data to estimate the friction of proposed changes.
Coupling score contributes 10% of the overall PR score in the CI agent.

```rust
/// Coupling contribution to simulation friction score.
pub fn coupling_friction(
    changed_modules: &[String],
    coupling_data: &CouplingEngine,
) -> f64 {
    if changed_modules.is_empty() {
        return 0.0;
    }

    let mut total_friction = 0.0;

    for module in changed_modules {
        if let Some(&idx) = coupling_data.graph.module_index.get(module) {
            let metrics = coupling_data.metrics.get(&idx).unwrap();
            let zone = coupling_data.zone_classifications.get(&idx).copied()
                .unwrap_or(ZoneClassification::Transitional);

            // Higher coupling = more friction
            let coupling_factor = (metrics.ca + metrics.ce) as f64 / 20.0;

            // Zone of pain adds extra friction
            let zone_factor = match zone {
                ZoneClassification::ZoneOfPain => 1.5,
                ZoneClassification::ZoneOfUselessness => 1.2,
                ZoneClassification::Transitional => 1.0,
                ZoneClassification::MainSequence => 0.8,
            };

            total_friction += coupling_factor * zone_factor;
        }
    }

    // Normalize to 0-100
    (total_friction / changed_modules.len() as f64 * 100.0).min(100.0)
}
```

---

## 22. Integration with Constraints System

Coupling metrics can be enforced as architectural constraints:

```toml
# Example constraint: no module should have Ca > 15
[[constraints]]
id = "max-afferent-coupling"
type = "coupling_limit"
target = "**"
metric = "ca"
max_value = 15
severity = "warning"

# Example constraint: no new cycles allowed
[[constraints]]
id = "no-new-cycles"
type = "coupling_cycles"
max_new_cycles = 0
severity = "error"
```

---

## 23. Integration with Cortex Grounding (D7)

Per PLANNING-DRIFT.md D7, the grounding feedback loop reads coupling data from drift.db
to validate Cortex memories. This is a one-way read — Drift computes coupling
independently, the bridge consumes it.

```rust
// Bridge crate reads coupling snapshot for grounding
pub fn get_coupling_snapshot(db: &DatabaseManager) -> Result<CouplingSnapshot, Error> {
    let row = db.query_row(
        "SELECT health_score, cycle_count, hotspot_count, avg_instability,
                avg_distance, zone_of_pain_count, zone_of_uselessness_count,
                total_modules
         FROM coupling_snapshots
         ORDER BY created_at DESC LIMIT 1",
        [],
        |row| Ok(CouplingSnapshot {
            health_score: row.get(0)?,
            cycle_count: row.get(1)?,
            hotspot_count: row.get(2)?,
            avg_instability: row.get(3)?,
            avg_distance: row.get(4)?,
            zone_of_pain_count: row.get(5)?,
            zone_of_uselessness_count: row.get(6)?,
            total_modules: row.get(7)?,
        }),
    )?;
    Ok(row)
}
```

---

## 24. Storage Schema (drift.db Coupling Tables)

### 24.1 Tables

```sql
-- Module coupling metrics (one row per module per analysis run)
CREATE TABLE module_coupling (
    id INTEGER PRIMARY KEY,
    run_id TEXT NOT NULL,           -- Analysis run ID
    module_path TEXT NOT NULL,
    language TEXT NOT NULL,
    ca INTEGER NOT NULL,            -- Afferent coupling
    ce INTEGER NOT NULL,            -- Efferent coupling
    instability REAL NOT NULL,      -- Ce / (Ca + Ce)
    abstractness REAL NOT NULL,     -- Abstract exports / total exports
    distance REAL NOT NULL,         -- |A + I - 1|
    total_exports INTEGER NOT NULL,
    used_exports INTEGER NOT NULL,
    unused_exports INTEGER NOT NULL,
    role TEXT NOT NULL,             -- hub, authority, balanced, isolated
    zone TEXT NOT NULL,             -- main_sequence, zone_of_pain, zone_of_uselessness, transitional
    files TEXT NOT NULL,            -- JSON array of file paths
    content_hash TEXT NOT NULL,     -- Combined hash of all files in module
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

CREATE INDEX idx_module_coupling_run ON module_coupling(run_id);
CREATE INDEX idx_module_coupling_path ON module_coupling(module_path);
CREATE INDEX idx_module_coupling_zone ON module_coupling(zone);
CREATE INDEX idx_module_coupling_role ON module_coupling(role);

-- Dependency cycles (one row per cycle per analysis run)
CREATE TABLE coupling_cycles (
    id INTEGER PRIMARY KEY,
    run_id TEXT NOT NULL,
    cycle_id TEXT NOT NULL,         -- Stable hash of sorted module paths
    modules TEXT NOT NULL,          -- JSON array of module paths
    severity TEXT NOT NULL,         -- low, medium, high, critical
    files_affected INTEGER NOT NULL,
    break_points TEXT NOT NULL,     -- JSON array of BreakPoint objects
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

CREATE INDEX idx_coupling_cycles_run ON coupling_cycles(run_id);
CREATE INDEX idx_coupling_cycles_severity ON coupling_cycles(severity);
CREATE INDEX idx_coupling_cycles_id ON coupling_cycles(cycle_id);

-- Module dependencies (edge table for SQLite CTE backend)
CREATE TABLE module_dependencies (
    id INTEGER PRIMARY KEY,
    run_id TEXT NOT NULL,
    source_module TEXT NOT NULL,
    target_module TEXT NOT NULL,
    symbols TEXT NOT NULL,          -- JSON array of imported symbol names
    is_type_only INTEGER NOT NULL DEFAULT 0,
    edge_count INTEGER NOT NULL DEFAULT 1,  -- Number of import statements
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

CREATE INDEX idx_module_deps_run ON module_dependencies(run_id);
CREATE INDEX idx_module_deps_source ON module_dependencies(source_module);
CREATE INDEX idx_module_deps_target ON module_dependencies(target_module);

-- Coupling analysis snapshots (one row per analysis run)
CREATE TABLE coupling_snapshots (
    id INTEGER PRIMARY KEY,
    run_id TEXT NOT NULL UNIQUE,
    modules_analyzed INTEGER NOT NULL,
    files_analyzed INTEGER NOT NULL,
    cycle_count INTEGER NOT NULL,
    critical_cycle_count INTEGER NOT NULL,
    hotspot_count INTEGER NOT NULL,
    unused_export_count INTEGER NOT NULL,
    health_score REAL NOT NULL,
    avg_instability REAL NOT NULL,
    avg_distance REAL NOT NULL,
    zone_of_pain_count INTEGER NOT NULL,
    zone_of_uselessness_count INTEGER NOT NULL,
    condensation_component_count INTEGER NOT NULL,
    duration_ms INTEGER NOT NULL,
    incremental INTEGER NOT NULL DEFAULT 0,
    modules_recomputed INTEGER NOT NULL DEFAULT 0,
    total_modules INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

CREATE INDEX idx_coupling_snapshots_created ON coupling_snapshots(created_at);

-- Unused exports (one row per unused export per analysis run)
CREATE TABLE coupling_unused_exports (
    id INTEGER PRIMARY KEY,
    run_id TEXT NOT NULL,
    file TEXT NOT NULL,
    symbol TEXT NOT NULL,
    kind TEXT NOT NULL,
    line INTEGER NOT NULL,
    reasons TEXT NOT NULL,          -- JSON array of UnusedReason strings
    confidence REAL NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

CREATE INDEX idx_unused_exports_run ON coupling_unused_exports(run_id);
CREATE INDEX idx_unused_exports_file ON coupling_unused_exports(file);

-- Coupling hotspots (one row per hotspot per analysis run)
CREATE TABLE coupling_hotspots (
    id INTEGER PRIMARY KEY,
    run_id TEXT NOT NULL,
    module_path TEXT NOT NULL,
    total_coupling INTEGER NOT NULL,
    incoming TEXT NOT NULL,         -- JSON array of module paths
    outgoing TEXT NOT NULL,         -- JSON array of module paths
    role TEXT NOT NULL,
    risk TEXT NOT NULL,             -- low, medium, high, critical
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

CREATE INDEX idx_coupling_hotspots_run ON coupling_hotspots(run_id);
CREATE INDEX idx_coupling_hotspots_risk ON coupling_hotspots(risk);
```

### 24.2 Batch Writer Pattern

Following the storage v2 prep pattern, all writes use the batch writer:

```rust
impl CouplingEngine {
    fn persist_results(
        &self,
        cycles: &[DependencyCycle],
        hotspots: &[CouplingHotspot],
        unused_exports: &[UnusedExportAnalysis],
        health_score: f64,
    ) -> Result<(), CouplingError> {
        let run_id = uuid::Uuid::new_v4().to_string();

        self.db.batch_write(|tx| {
            // Write module metrics
            for (idx, metrics) in &self.metrics {
                let node = &self.graph.graph[*idx];
                let role = self.role_assignments.get(idx).unwrap();
                let zone = self.zone_classifications.get(idx).unwrap();

                tx.execute(
                    "INSERT INTO module_coupling (run_id, module_path, language, ca, ce,
                     instability, abstractness, distance, total_exports, used_exports,
                     unused_exports, role, zone, files, content_hash)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                    params![
                        run_id, node.path, format!("{:?}", node.language),
                        metrics.ca, metrics.ce, metrics.instability,
                        metrics.abstractness, metrics.distance,
                        metrics.total_exports, metrics.used_exports, metrics.unused_exports,
                        format!("{:?}", role).to_lowercase(),
                        format!("{:?}", zone).to_lowercase(),
                        serde_json::to_string(&node.files).unwrap(),
                        "hash_placeholder",
                    ],
                )?;
            }

            // Write cycles
            for cycle in cycles {
                tx.execute(
                    "INSERT INTO coupling_cycles (run_id, cycle_id, modules, severity,
                     files_affected, break_points)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        run_id, cycle.id,
                        serde_json::to_string(&cycle.modules).unwrap(),
                        format!("{:?}", cycle.severity).to_lowercase(),
                        cycle.files_affected,
                        serde_json::to_string(&cycle.break_points).unwrap(),
                    ],
                )?;
            }

            // Write snapshot
            tx.execute(
                "INSERT INTO coupling_snapshots (run_id, modules_analyzed, files_analyzed,
                 cycle_count, critical_cycle_count, hotspot_count, unused_export_count,
                 health_score, avg_instability, avg_distance, zone_of_pain_count,
                 zone_of_uselessness_count, condensation_component_count, duration_ms,
                 incremental, modules_recomputed, total_modules)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
                params![
                    run_id,
                    self.graph.graph.node_count(),
                    0, // files_analyzed set by caller
                    cycles.len(),
                    cycles.iter().filter(|c| c.severity == CycleSeverity::Critical).count(),
                    hotspots.len(),
                    unused_exports.len(),
                    health_score,
                    self.avg_metric(|m| m.instability),
                    self.avg_metric(|m| m.distance),
                    self.count_zone(ZoneClassification::ZoneOfPain),
                    self.count_zone(ZoneClassification::ZoneOfUselessness),
                    0, // condensation computed on demand
                    0, // duration set by caller
                    false, 0,
                    self.graph.graph.node_count(),
                ],
            )?;

            Ok(())
        })?;

        Ok(())
    }
}
```


---

## 25. NAPI Interface

### 25.1 Command Functions (Write-Heavy, Return Summary)

Following the command/query pattern from 03-NAPI-BRIDGE-V2-PREP.md §5:

```rust
/// Run full coupling analysis. Writes results to drift.db, returns summary.
/// Async — runs on libuv thread pool via AsyncTask.
#[napi]
pub fn analyze_coupling(root: String, options: Option<CouplingOptions>) -> AsyncTask<CouplingTask> {
    AsyncTask::new(CouplingTask { root, options: options.unwrap_or_default() })
}

#[napi(object)]
pub struct CouplingOptions {
    /// Module granularity: "file" | "directory" | "package". Default: "directory".
    pub granularity: Option<String>,
    /// Whether to use incremental analysis. Default: true.
    pub incremental: Option<bool>,
    /// Hotspot threshold. Default: 3.
    pub hotspot_threshold: Option<u32>,
    /// Whether to include condensation graph in results. Default: false.
    pub include_condensation: Option<bool>,
}

pub struct CouplingTask {
    root: String,
    options: CouplingOptions,
}

#[napi]
impl Task for CouplingTask {
    type Output = CouplingSummary;
    type JsValue = CouplingSummary;

    fn compute(&mut self) -> napi::Result<Self::Output> {
        let rt = crate::runtime::get()?;
        let start = std::time::Instant::now();

        let config = self.build_config(&rt.config)?;

        // Get parse results (from cache or re-parse)
        let parse_results = drift_core::parser::get_cached_results(&rt.db)
            .map_err(to_napi_error)?;

        // Build or update coupling engine
        let mut engine = CouplingEngine::new();

        let summary = if config.incremental {
            let changed = drift_core::scanner::get_changed_files(&rt.db)
                .map_err(to_napi_error)?;
            engine.analyze_incremental(&changed, &parse_results, &config)
                .map_err(to_napi_error)?
        } else {
            engine.analyze_full(&parse_results, &rt.db, &config)
                .map_err(to_napi_error)?
        };

        let mut summary = summary;
        summary.duration_ms = start.elapsed().as_millis() as u32;

        Ok(summary)
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> napi::Result<Self::JsValue> {
        Ok(output)
    }
}
```

### 25.2 Query Functions (Read-Only, Return Paginated Data)

```rust
/// Query module coupling metrics with filters and pagination.
#[napi]
pub fn query_coupling_modules(
    filter: Option<CouplingModuleFilter>,
    pagination: Option<PaginationOptions>,
) -> napi::Result<PaginatedResult> {
    let rt = crate::runtime::get()?;
    let page = pagination.unwrap_or_default();
    let limit = page.limit.unwrap_or(50).min(100) as usize;

    drift_core::coupling::query_modules(&rt.db, &filter, &page, limit)
        .map_err(to_napi_error)
}

#[napi(object)]
pub struct CouplingModuleFilter {
    /// Filter by zone: "main_sequence", "zone_of_pain", "zone_of_uselessness", "transitional".
    pub zone: Option<String>,
    /// Filter by role: "hub", "authority", "balanced", "isolated".
    pub role: Option<String>,
    /// Minimum total coupling (Ca + Ce).
    pub min_coupling: Option<u32>,
    /// Maximum instability.
    pub max_instability: Option<f64>,
    /// Module path prefix filter.
    pub path_prefix: Option<String>,
}

/// Query dependency cycles with filters.
#[napi]
pub fn query_coupling_cycles(
    filter: Option<CouplingCycleFilter>,
    pagination: Option<PaginationOptions>,
) -> napi::Result<PaginatedResult> {
    let rt = crate::runtime::get()?;
    drift_core::coupling::query_cycles(&rt.db, &filter, &pagination)
        .map_err(to_napi_error)
}

#[napi(object)]
pub struct CouplingCycleFilter {
    /// Minimum severity: "low", "medium", "high", "critical".
    pub min_severity: Option<String>,
    /// Module path that must be in the cycle.
    pub contains_module: Option<String>,
}

/// Query coupling hotspots.
#[napi]
pub fn query_coupling_hotspots(
    filter: Option<CouplingHotspotFilter>,
    pagination: Option<PaginationOptions>,
) -> napi::Result<PaginatedResult> {
    let rt = crate::runtime::get()?;
    drift_core::coupling::query_hotspots(&rt.db, &filter, &pagination)
        .map_err(to_napi_error)
}

#[napi(object)]
pub struct CouplingHotspotFilter {
    /// Minimum risk: "low", "medium", "high", "critical".
    pub min_risk: Option<String>,
    /// Minimum total coupling.
    pub min_coupling: Option<u32>,
}

/// Query unused exports.
#[napi]
pub fn query_unused_exports(
    filter: Option<UnusedExportFilter>,
    pagination: Option<PaginationOptions>,
) -> napi::Result<PaginatedResult> {
    let rt = crate::runtime::get()?;
    drift_core::coupling::query_unused_exports(&rt.db, &filter, &pagination)
        .map_err(to_napi_error)
}

#[napi(object)]
pub struct UnusedExportFilter {
    /// Filter by file path prefix.
    pub path_prefix: Option<String>,
    /// Filter by reason: "dead_code", "test_only", "internal", "deprecated".
    pub reason: Option<String>,
    /// Minimum confidence.
    pub min_confidence: Option<f64>,
}

/// Analyze refactor impact for a specific module.
#[napi]
pub fn analyze_refactor_impact(
    module_path: String,
    use_call_graph: Option<bool>,
) -> napi::Result<RefactorImpact> {
    let rt = crate::runtime::get()?;
    let call_graph = if use_call_graph.unwrap_or(true) {
        drift_core::call_graph::get_cached(&rt.db).ok()
    } else {
        None
    };

    drift_core::coupling::analyze_refactor_impact(
        &module_path, call_graph.as_ref(), &rt.db,
    ).map_err(to_napi_error)
}

/// Get the condensation graph (DAG of SCCs).
#[napi]
pub fn get_condensation_graph() -> napi::Result<CondensationGraph> {
    let rt = crate::runtime::get()?;
    drift_core::coupling::get_condensation_graph(&rt.db)
        .map_err(to_napi_error)
}

/// Get coupling health trend over time.
#[napi]
pub fn query_coupling_trends(days: Option<u32>) -> napi::Result<Vec<CouplingTrendPoint>> {
    let rt = crate::runtime::get()?;
    let days = days.unwrap_or(30);
    drift_core::coupling::query_trends(&rt.db, days)
        .map_err(to_napi_error)
}

#[napi(object)]
pub struct CouplingTrendPoint {
    pub date: String,
    pub health_score: f64,
    pub cycle_count: u32,
    pub hotspot_count: u32,
    pub modules_analyzed: u32,
}
```

### 25.3 NAPI Function Registry

| Function | Sync/Async | Returns | Description |
|----------|-----------|---------|-------------|
| `analyze_coupling(root, options)` | Async | `CouplingSummary` | Full coupling analysis |
| `query_coupling_modules(filter, pagination)` | Sync | `PaginatedResult` | Query module metrics |
| `query_coupling_cycles(filter, pagination)` | Sync | `PaginatedResult` | Query dependency cycles |
| `query_coupling_hotspots(filter, pagination)` | Sync | `PaginatedResult` | Query hotspots |
| `query_unused_exports(filter, pagination)` | Sync | `PaginatedResult` | Query unused exports |
| `analyze_refactor_impact(module, use_call_graph)` | Sync | `RefactorImpact` | Refactor blast radius |
| `get_condensation_graph()` | Sync | `CondensationGraph` | DAG of SCCs |
| `query_coupling_trends(days)` | Sync | `CouplingTrendPoint[]` | Health trend over time |

Total: 8 NAPI functions (1 command + 7 queries).

---

## 26. MCP Tool Interface (drift_coupling — 5 Actions)

### 26.1 Tool Definition

```typescript
const drift_coupling: Tool = {
    name: "drift_coupling",
    description: "Module coupling analysis — dependency cycles, hotspots, metrics, refactor impact",
    inputSchema: {
        type: "object",
        properties: {
            action: {
                type: "string",
                enum: ["overview", "cycles", "hotspots", "analyze", "impact"],
                description: "Analysis action to perform",
            },
            module: {
                type: "string",
                description: "Module path (required for 'analyze' and 'impact' actions)",
            },
            min_severity: {
                type: "string",
                enum: ["low", "medium", "high", "critical"],
                description: "Minimum severity filter for cycles (default: low)",
            },
            limit: {
                type: "number",
                description: "Maximum results to return (default: 10)",
            },
        },
        required: ["action"],
    },
};
```

### 26.2 Actions

| Action | Description | Token Cost | NAPI Call |
|--------|-------------|------------|-----------|
| `overview` | Summary: health score, cycle count, hotspot count, zone distribution | ~500-800 | `query_coupling_modules` + snapshot |
| `cycles` | List dependency cycles with break suggestions | ~800-1500 | `query_coupling_cycles` |
| `hotspots` | List coupling hotspots with risk levels | ~600-1200 | `query_coupling_hotspots` |
| `analyze` | Deep analysis of a specific module | ~800-1500 | `query_coupling_modules` (filtered) |
| `impact` | Refactor impact analysis for a module | ~1000-2000 | `analyze_refactor_impact` |

### 26.3 Response Format

```typescript
// overview action response
interface CouplingOverview {
    health_score: number;
    modules_analyzed: number;
    cycles: { total: number; critical: number; high: number; medium: number; low: number };
    hotspots: { total: number; critical: number; high: number };
    zones: { main_sequence: number; pain: number; uselessness: number; transitional: number };
    avg_instability: number;
    avg_distance: number;
    top_hotspots: Array<{ module: string; coupling: number; role: string }>;
    worst_cycles: Array<{ modules: string[]; severity: string }>;
}
```

---

## 27. CLI Interface (drift coupling — 4 Subcommands)

### 27.1 Commands

```
drift coupling                    # Overview (default)
drift coupling cycles             # List dependency cycles
drift coupling hotspots           # List coupling hotspots
drift coupling analyze <module>   # Analyze specific module
```

### 27.2 Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--json` | boolean | false | JSON output |
| `-v, --verbose` | boolean | false | Verbose output (include break suggestions, zone details) |
| `--severity <level>` | string | "low" | Minimum cycle severity to show |
| `--limit <n>` | number | 20 | Maximum results |
| `--granularity <g>` | string | "directory" | Module granularity: file/directory/package |

### 27.3 Output Examples

```
$ drift coupling
╭─────────────────────────────────────────────╮
│  Module Coupling Analysis                    │
│  Health Score: 72/100                        │
│  Modules: 45  │  Files: 312                  │
├─────────────────────────────────────────────┤
│  Cycles: 3 (1 critical, 1 high, 1 medium)   │
│  Hotspots: 5 (1 critical, 2 high)           │
│  Zone of Pain: 4 modules                     │
│  Zone of Uselessness: 2 modules              │
│  Avg Instability: 0.52                       │
│  Avg Distance: 0.28                          │
╰─────────────────────────────────────────────╯

$ drift coupling cycles --severity high
╭─ Critical Cycle (6 modules) ─────────────────╮
│  src/auth → src/users → src/permissions →     │
│  src/roles → src/policies → src/auth          │
│  Break suggestion: src/permissions → src/roles │
│  Approach: Extract interface                   │
│  Effort: Medium                                │
╰───────────────────────────────────────────────╯
```

---

## 28. Event Interface

Per D5 (DriftEventHandler trait with no-op defaults):

```rust
pub trait DriftEventHandler: Send + Sync {
    // ... existing events ...

    /// Emitted when coupling analysis completes.
    fn on_coupling_analysis_complete(&self, _summary: &CouplingSummary) {}

    /// Emitted when a new dependency cycle is detected.
    fn on_new_cycle_detected(&self, _cycle: &DependencyCycle) {}

    /// Emitted when coupling health score changes significantly.
    fn on_coupling_health_change(&self, _old_score: f64, _new_score: f64) {}
}
```

---

## 29. Tracing & Observability

Per AD10 (tracing crate from first line of code):

```rust
// Key spans and events for coupling analysis
tracing::info_span!("coupling_analysis", modules = %count, incremental = %is_incremental);
tracing::info_span!("coupling_build_graph", files = %file_count);
tracing::info_span!("coupling_calculate_metrics");
tracing::info_span!("coupling_detect_cycles");
tracing::info_span!("coupling_condensation");
tracing::info_span!("coupling_classify_zones");
tracing::info_span!("coupling_assign_roles");
tracing::info_span!("coupling_break_suggestions");
tracing::info_span!("coupling_refactor_impact", module = %path);
tracing::info_span!("coupling_unused_exports");
tracing::info_span!("coupling_health_score");
tracing::info_span!("coupling_persist");

// Key metrics
tracing::info!(
    modules = %module_count,
    edges = %edge_count,
    cycles = %cycle_count,
    health_score = %score,
    duration_ms = %elapsed,
    "Coupling analysis complete"
);
```

### Key Metrics to Track

| Metric | Description | Target |
|--------|-------------|--------|
| `coupling.analysis_duration_ms` | Total analysis time | <500ms for <1K modules |
| `coupling.graph_build_ms` | Graph construction time | <100ms |
| `coupling.tarjan_scc_ms` | Tarjan's SCC time | <50ms for <5K modules |
| `coupling.metrics_calculation_ms` | Metrics computation time | <50ms |
| `coupling.modules_analyzed` | Number of modules | — |
| `coupling.edges_count` | Number of dependency edges | — |
| `coupling.cycle_count` | Number of cycles found | — |
| `coupling.health_score` | Overall health score | — |
| `coupling.incremental_skip_ratio` | % of modules skipped (incremental) | >80% on typical runs |

---

## 30. Performance Targets & Benchmarks

| Scenario | Target | Measurement |
|----------|--------|-------------|
| 100 modules, full analysis | <100ms | End-to-end including persistence |
| 1,000 modules, full analysis | <500ms | End-to-end including persistence |
| 5,000 modules, full analysis | <2s | End-to-end including persistence |
| 10,000 modules, SQLite CTE | <5s | End-to-end including persistence |
| Incremental (10 files changed) | <100ms | Regardless of total module count |
| Tarjan's SCC (5,000 nodes) | <50ms | Algorithm only |
| Condensation graph (5,000 nodes) | <50ms | Algorithm only |
| Single module analysis | <10ms | Query from drift.db |
| Refactor impact analysis | <50ms | With call graph |

### Benchmark Setup

```rust
use criterion::{criterion_group, criterion_main, Criterion};

fn bench_coupling(c: &mut Criterion) {
    let mut group = c.benchmark_group("coupling");

    group.bench_function("100_modules_full", |b| {
        let parse_results = generate_parse_results(100, 5); // 100 modules, 5 files each
        b.iter(|| {
            let mut engine = CouplingEngine::new();
            engine.analyze_full(&parse_results, &db, &config).unwrap();
        });
    });

    group.bench_function("1000_modules_full", |b| {
        let parse_results = generate_parse_results(1000, 3);
        b.iter(|| {
            let mut engine = CouplingEngine::new();
            engine.analyze_full(&parse_results, &db, &config).unwrap();
        });
    });

    group.bench_function("tarjan_scc_5000", |b| {
        let engine = build_engine_with_modules(5000);
        b.iter(|| engine.detect_cycles(&config).unwrap());
    });

    group.bench_function("incremental_10_changed", |b| {
        let mut engine = build_engine_with_modules(1000);
        engine.analyze_full(&parse_results, &db, &config).unwrap();
        let changed = pick_random_files(10);
        b.iter(|| engine.analyze_incremental(&changed, &parse_results, &config).unwrap());
    });

    group.finish();
}

criterion_group!(benches, bench_coupling);
criterion_main!(benches);
```

---

## 31. Build Order & Dependencies

### 31.1 Prerequisites (Must Exist Before Coupling)

| Dependency | Why | Status |
|-----------|-----|--------|
| Parsers (Level 0) | ParseResult with imports/exports | Must be complete |
| Scanner (Level 0) | File list, content hashes | Must be complete |
| Storage (Level 0) | drift.db with coupling tables | Must be complete |
| Infrastructure (Level 0) | thiserror, tracing, config | Must be complete |
| Unified Analysis Engine (Level 1) | ResolutionIndex for import resolution | Must be complete |
| Call Graph Builder (Level 1) | Optional — enriches transitive analysis | Can be added later |

### 31.2 Build Phases

| Phase | What | Effort | Dependencies |
|-------|------|--------|-------------|
| Phase 1 | Core types + graph construction | 2 days | Parsers, Storage |
| Phase 2 | Metrics calculation (Ca, Ce, I, A, D) | 1 day | Phase 1 |
| Phase 3 | Tarjan's SCC + condensation | 1 day | Phase 1, petgraph |
| Phase 4 | Zone classification + role assignment | 1 day | Phase 2 |
| Phase 5 | Cycle break suggestions | 1 day | Phase 3, Phase 4 |
| Phase 6 | Refactor impact analysis | 2 days | Phase 2, Call Graph (optional) |
| Phase 7 | Unused export detection | 1 day | Phase 1 |
| Phase 8 | Health score calculation | 0.5 days | Phase 3, Phase 4, Phase 7 |
| Phase 9 | Storage persistence | 1 day | Storage |
| Phase 10 | NAPI interface | 1 day | All phases |
| Phase 11 | Incremental analysis | 2 days | Phase 9 |
| Phase 12 | SQLite CTE backend | 2 days | Phase 9 |
| Phase 13 | MCP tool + CLI | 1 day | Phase 10 |
| Phase 14 | Integration (DNA, gates, sim) | 1 day | Phase 8 |
| Phase 15 | Benchmarks + tests | 2 days | All phases |

**Total estimated effort: ~17.5 days**

### 31.3 Cargo.toml

```toml
# In drift-core/Cargo.toml
[dependencies]
petgraph = "0.6"
rustc-hash = "2"          # FxHashMap, FxHashSet
blake3 = "1"              # Cycle ID hashing
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "2"
tracing = "0.1"
uuid = { version = "1", features = ["v4"] }
rusqlite = { version = "0.32", features = ["bundled"] }
rayon = "1"               # Parallel file processing in Phase 1
```

---

## 32. V1 → V2 Feature Cross-Reference

| V1 Feature | V1 Location | V2 Location | Status |
|-----------|-------------|-------------|--------|
| Basic metrics (Ca, Ce, I, A, D) | Rust analyzer.rs | CouplingEngine Phase 2 | ✅ Preserved |
| DFS cycle detection | Rust analyzer.rs | Replaced by Tarjan's SCC Phase 3 | ✅ Upgraded |
| Hotspot detection | Rust analyzer.rs | CouplingEngine Phase 2 + hotspot query | ✅ Preserved |
| Unused export detection | Rust analyzer.rs | CouplingEngine Phase 9 | ✅ Enhanced |
| Health score | Rust analyzer.rs | CouplingEngine Phase 10 | ✅ Enhanced |
| Tarjan's SCC | TS coupling-analyzer.ts | CouplingEngine Phase 3 (petgraph) | ✅ Ported |
| Module roles | TS coupling-analyzer.ts | CouplingEngine Phase 6 | ✅ Ported |
| Cycle break suggestions | TS coupling-analyzer.ts | CouplingEngine Phase 7 | ✅ Ported |
| Refactor impact | TS coupling-analyzer.ts | CouplingEngine Phase 8 | ✅ Ported |
| Zone detection | TS coupling-analyzer.ts | CouplingEngine Phase 5 | ✅ Ported |
| Module health | TS coupling-analyzer.ts | CouplingEngine Phase 8 | ✅ Ported |
| Call graph integration | TS coupling-analyzer.ts | CouplingEngine §17 | ✅ Ported |
| Unused export reasons | TS coupling-analyzer.ts | CouplingEngine Phase 9 | ✅ Ported |
| NAPI analyze_coupling | Rust NAPI binding | drift-napi §25 | ✅ Expanded |
| drift_coupling MCP tool | TS coupling.ts | MCP §26 (5 actions) | ✅ Expanded |
| drift coupling CLI | TS coupling.ts | CLI §27 (4 subcommands) | ✅ Preserved |
| module_coupling table | drift.db | drift.db §24 (6 tables) | ✅ Expanded |
| CI coupling score | TS CI agent | CouplingGateInput §20 | ✅ Preserved |
| Condensation graph | — (net-new) | CouplingEngine Phase 4 | 🆕 New |
| Auto-selection backend | — (net-new) | §15 | 🆕 New |
| Incremental analysis | — (net-new) | §16 | 🆕 New |
| Configurable granularity | — (net-new) | §5.3 | 🆕 New |
| TOML configuration | — (net-new) | §3.3 | 🆕 New |
| Event emission | — (net-new) | §28 | 🆕 New |
| Keyset pagination | — (net-new) | §25.2 | 🆕 New |
| Coupling trends | — (net-new) | §25.2 | 🆕 New |

**Zero feature loss confirmed. All 25 v1 features preserved or upgraded. 8 net-new features added.**

---

## 33. Inconsistencies & Decisions

### 33.1 Resolved Inconsistencies

| # | Inconsistency | Resolution |
|---|--------------|------------|
| I1 | v1 Rust uses DFS, v1 TS uses Tarjan's SCC | V2 uses Tarjan's SCC exclusively (petgraph) |
| I2 | v1 Rust has CycleSeverity::Info, v1 TS has "low" | V2 uses Low/Medium/High/Critical (4 levels) |
| I3 | v1 TS has "hub/authority/balanced/isolated", research doc has "hub/leaf/bridge/isolated" | V2 uses Hub/Authority/Balanced/Isolated (matches TS v1) |
| I4 | v1 Rust parses AST directly, v1 TS uses call graph | V2 consumes ParseResult (no direct AST parsing) |
| I5 | v1 Rust hotspot threshold hardcoded at 3, v1 TS configurable | V2 configurable via drift.toml (default: 3) |
| I6 | v1 Rust health score uses fixed penalties, v1 TS uses percentage-based | V2 uses weighted multi-factor formula (§14) |
| I7 | Audit says "condensation graph generation" but no v1 implementation exists | V2 implements via petgraph::algo::condensation (§8) |
| I8 | module_coupling table schema not fully specified in storage docs | V2 defines complete schema with 6 tables (§24) |

### 33.2 Architectural Decisions

| # | Decision | Rationale |
|---|---------|-----------|
| D1 | Use petgraph for all graph operations | Proven library, Tarjan's + condensation built-in, already in workspace |
| D2 | Consume ParseResult instead of re-parsing | Eliminates duplicate tree-sitter work, consistent with unified engine |
| D3 | Auto-select in-memory vs SQLite at 5K modules | Balances performance (petgraph) with scalability (SQLite) |
| D4 | Tarjan's SCC always runs on full graph | O(V+E) is fast enough; incremental SCC is complex and error-prone |
| D5 | Break score = Ce(from) / Ca(to) | Lower score = easier to redirect; matches intuition |
| D6 | Zone thresholds configurable in drift.toml | Different codebases have different norms |
| D7 | Module roles use adaptive thresholds (median) | Fixed thresholds don't work across different codebase sizes |
| D8 | Condensation graph computed on demand (not persisted) | Rarely needed, fast to compute, avoids stale data |
| D9 | 6 SQLite tables for coupling data | Normalized for query flexibility; denormalized snapshot for fast reads |

---

## 34. Risk Register

| # | Risk | Likelihood | Impact | Mitigation |
|---|------|-----------|--------|------------|
| R1 | petgraph condensation requires Graph (not StableGraph) | Certain | Low | O(V+E) conversion is acceptable; only called once per run |
| R2 | SQLite CTE cycle detection slower than Tarjan's | High | Medium | Only used for >5K modules; most projects use in-memory |
| R3 | Import resolution accuracy affects all metrics | Medium | High | Leverage ResolutionIndex from unified engine; fallback to path-based |
| R4 | Type-only imports may skew abstractness metric | Medium | Low | Track is_type_only flag; optionally exclude from Ce calculation |
| R5 | Incremental analysis may miss transitive invalidation | Low | Medium | Conservative: invalidate all dependents of changed modules |
| R6 | Large cycles (>20 modules) make break suggestions less useful | Low | Low | Limit break suggestions to top 5 per cycle |
| R7 | Package granularity requires manifest discovery | Medium | Low | Fallback to directory granularity if manifest not found |
| R8 | Health score formula may need tuning per codebase | Medium | Medium | Configurable weights in drift.toml; sensible defaults |
| R9 | Condensation graph may be large for highly cyclic codebases | Low | Low | Computed on demand, not persisted; paginate if needed |
| R10 | Call graph unavailable during first run (not yet built) | Certain | Low | Graceful fallback to import-only analysis; suggest running call graph first |
