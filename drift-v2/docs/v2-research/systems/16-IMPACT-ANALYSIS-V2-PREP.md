# Impact Analysis (Blast Radius, Change Propagation, Risk Scoring) — V2 Implementation Prep

> Comprehensive build specification for Drift v2's Impact Analysis subsystem (System 16).
> Synthesized from: 14-REACHABILITY-ANALYSIS-V2-PREP.md (§10 Impact Analysis Engine),
> .research/04-call-graph/RECOMMENDATIONS.md (R6 Impact Analysis in Rust, R7 Dead Code in Rust),
> .research/16-gap-analysis/RESEARCH.md (§9.1 PyCG, §10.1 Tricorder),
> .research/16-gap-analysis/RECOMMENDATIONS.md (GE4 Security Roadmap),
> .research/21-security/RECOMMENDATIONS.md (BR1 Sensitivity Propagation),
> 04-call-graph/analysis.md (v1 ImpactAnalyzer, DeadCodeDetector, CoverageAnalyzer),
> 04-call-graph/enrichment.md (ImpactScorer, RemediationGenerator),
> 04-call-graph/overview.md (capabilities matrix, consumer list),
> 04-call-graph/types.md (ImpactResult, BlastRadius, DeadCodeCandidate),
> 05-CALL-GRAPH-V2-PREP.md (petgraph StableGraph, Resolution, CallEdge),
> 07-BOUNDARY-DETECTION-V2-PREP.md (DataAccessPoint, SensitiveField),
> 15-TAINT-ANALYSIS-V2-PREP.md (TaintFlow, TaintSummary — taint-enriched impact),
> 03-NAPI-BRIDGE-V2-PREP.md (§10.6 analyze_impact, find_dead_code, find_path),
> 02-STORAGE-V2-PREP.md (batch writer, keyset pagination, medallion architecture),
> 04-INFRASTRUCTURE-V2-PREP.md (thiserror, tracing, FxHashMap, petgraph),
> DRIFT-V2-FULL-SYSTEM-AUDIT.md (AD1 incremental, AD12 data structures),
> DRIFT-V2-STACK-HIERARCHY.md (Level 2B — Graph Intelligence),
> DRIFT-V2-SYSTEMS-REFERENCE.md (impact capabilities),
> PLANNING-DRIFT.md (D1-D7),
> Sweep.io impact analysis guide (5-step framework, blast radius),
> ACM JSS static change impact analysis techniques (Lehnert 2015),
> in-com.com inter-procedural analysis for impact accuracy (2026),
> Wikipedia change impact analysis (Bohnner & Arnold definition),
> Google Tricorder (feedback loop, effective FP rate).
>
> Purpose: Everything needed to build the Impact Analysis subsystem from scratch.
> This is the DEDICATED deep-dive — the 14-REACHABILITY-ANALYSIS-V2-PREP doc covers
> the reachability engine that impact analysis extends; this document covers the
> impact-specific machinery: blast radius computation, change propagation analysis,
> risk scoring, dead code detection, coverage analysis, path finding, the enrichment
> pipeline (sensitivity → impact scoring → remediation generation), and the full
> integration with the call graph, taint analysis, and security pipeline.
> Every v1 feature accounted for. Zero feature loss. Every algorithm specified.
> Generated: 2026-02-07

---

## Table of Contents

1. Architectural Position
2. V1 Complete Feature Inventory
3. V2 Architecture — Unified Impact Engine
4. Core Data Model
5. Blast Radius Computation
6. Change Propagation Analysis
7. Risk Scoring Engine
8. Dead Code Detection Engine
9. Coverage Analysis Engine (Call Graph × Test Topology)
10. Path Finding Engine
11. Enrichment Pipeline (Sensitivity → Impact → Remediation)
12. Incremental Impact Analysis
13. Integration with Taint Analysis
14. Integration with Test Topology
15. Storage Schema
16. NAPI Interface
17. MCP Tool Interface
18. CLI Interface
19. Tracing & Observability
20. Performance Targets & Benchmarks
21. Build Order & Dependencies
22. V1 → V2 Feature Cross-Reference
23. Inconsistencies & Decisions
24. Risk Register

---

## 1. Architectural Position

Impact Analysis is **Level 2B — Graph Intelligence** in the Drift v2 stack hierarchy.
It answers the question every developer asks before making a change: "What breaks if
I change this?" It transforms the structural call graph into actionable engineering
intelligence about change risk, blast radius, and test coverage gaps.

Per DRIFT-V2-STACK-HIERARCHY.md:

> Impact Analysis: Transitive caller analysis, blast radius, risk scoring.
> Powers "what breaks if I change this?", dead code detection, test coverage gaps.
> High leverage — one engine, many consumers.

### What Lives Here

- Blast radius computation (direct + transitive callers, affected entry points)
- Change propagation analysis (which functions are affected by a change)
- Risk scoring engine (multi-factor: callers, entry points, sensitive data, taint)
- Dead code detection (unreachable functions with false positive filtering)
- Coverage analysis (call graph × test topology for data path coverage)
- Path finding (BFS with path tracking between any two functions)
- Enrichment pipeline (sensitivity classification → impact scoring → remediation)
- Incremental impact analysis (re-compute only for changed functions)
- Taint-enriched impact (unsanitized taint paths increase risk score)
- Impact result persistence (drift.db impact tables)

### What Does NOT Live Here

- Call graph construction → Call Graph Builder (Level 1)
- Reachability BFS engine → Reachability Analysis (Level 2B)
- Taint analysis → Taint Analysis (Level 2B, provides taint-enriched risk)
- Data access detection → Boundary Detection (Level 1)
- Quality gate evaluation → Quality Gates (Level 3)
- MCP tool routing → MCP Server (Level 5)

### Critical Path Position

```
Scanner (Level 0)
  → Parsers (Level 0)
    → Call Graph Builder (Level 1)
      → Boundary Detection (Level 1)
        → Reachability Engine (Level 2B)
          → Taint Analysis (Level 2B)
            → Impact Analysis (Level 2B) ← YOU ARE HERE
              → Quality Gates (Level 3) — impact gate
                → MCP Tools (Level 5) — drift_impact_analysis
                  → CLI (Level 5) — drift impact
```

### Consumer Count: 7+ Downstream Systems

| Consumer | What It Reads | Why |
|----------|--------------|-----|
| Quality Gates | Impact risk scores, blast radius | Impact gate blocks on high-risk changes |
| MCP Tools | Impact results, dead code, coverage | drift_impact_analysis, drift_dead_code |
| CLI | Impact summary, change risk report | drift impact, drift dead-code |
| IDE/LSP | Per-function impact indicators | Inline risk badges |
| Context Generation | Impact context for AI | AI-ready change risk summaries |
| Simulation Engine | Blast radius for what-if analysis | "What if I change this?" |
| DNA System | Impact health metrics | Change risk in DNA profile |

---

## 2. V1 Complete Feature Inventory

### 2.1 V1 Impact Analyzer (TS Only)

**Location**: `packages/core/src/call-graph/analysis/impact-analyzer.ts`

```typescript
function analyzeImpact(graph: CallGraph, functionId: string): {
    affectedFunctions: string[];
    affectedDataPaths: DataPath[];
    risk: 'low' | 'medium' | 'high' | 'critical';
}
```

V1 risk factors:
- Affected function count (more callers = higher risk)
- Entry point impact (affects HTTP handlers = higher risk)
- Sensitive data paths (touches credentials/PII = higher risk)
- Depth of impact (deeper call chains = higher risk)

### 2.2 V1 Dead Code Detector (TS Only)

**Location**: `packages/core/src/call-graph/analysis/dead-code-detector.ts`

```typescript
function detectDeadCode(graph: CallGraph): {
    candidates: DeadCodeCandidate[];
    confidence: 'high' | 'medium' | 'low';
    falsePositiveReasons: string[];
}
```

V1 false positive handling:
- Entry points (HTTP handlers, CLI commands, main functions)
- Framework hooks (lifecycle methods, event handlers)
- Dynamic dispatch (reflection, eval, computed property access)
- Event handlers (addEventListener, on/emit patterns)
- Exported functions (may be used by external consumers)
- Test functions (test utilities, fixtures)

### 2.3 V1 Coverage Analyzer (TS Only)

**Location**: `packages/core/src/call-graph/analysis/coverage-analyzer.ts`

```typescript
function analyzeCoverage(graph: CallGraph, testTopology: TestTopology): {
    fieldCoverage: FieldCoverage[];
    uncoveredPaths: DataPath[];
}
```

### 2.4 V1 Path Finder

**Location**: `packages/core/src/call-graph/analysis/path-finder.ts` + Rust

BFS with path tracking between any two functions. Returns multiple paths.

### 2.5 V1 Enrichment Pipeline (TS Only)

**Location**: `packages/core/src/call-graph/enrichment/`

3 components:
1. **Sensitivity Classifier** — classifies data access by sensitivity level
2. **Impact Scorer** — scores function impact (centrality, entry point, sensitive data)
3. **Remediation Generator** — generates actionable fix suggestions

### 2.6 V1 NAPI Functions

```
analyze_reachability(options) → JsReachabilityResult
analyze_inverse_reachability(options) → JsInverseReachabilityResult
```

Impact analysis was TS-only in v1 — no NAPI exposure.

### 2.7 V1 MCP Tools

- `drift_impact_analysis` — Change blast radius (TS implementation)

### 2.8 V1 Feature Inventory (Exhaustive)

| # | Feature | V1 Behavior | V2 Status |
|---|---------|-------------|-----------|
| I1 | Impact analysis (TS) | Reverse BFS, 4-level risk scoring | Ported → Rust with enhanced scoring (§5-7) |
| I2 | Dead code detection (TS) | calledBy.length == 0, 6 FP categories | Ported → Rust with 8 FP categories (§8) |
| I3 | Coverage analysis (TS) | Call graph × test topology | Ported → Rust with field-level coverage (§9) |
| I4 | Path finding (TS + Rust) | BFS with path tracking | Upgraded → petgraph all_simple_paths (§10) |
| I5 | Sensitivity classifier (TS) | 4 levels, pattern matching | Upgraded → 6 categories, composite scoring (§11) |
| I6 | Impact scorer (TS) | Centrality + entry point + sensitive data | Upgraded → PageRank-inspired + taint (§11) |
| I7 | Remediation generator (TS) | Heuristic suggestions | Preserved → Rust heuristics + AI-assisted (§11) |
| I8 | Blast radius (TS) | Direct callers count | Upgraded → transitive + entry point + data (§5) |
| I9 | Risk scoring (TS) | 4 levels (low/medium/high/critical) | Upgraded → continuous 0-100 + 4 levels (§7) |
| I10 | MCP: drift_impact_analysis | TS-only blast radius | Ported → Rust-native via NAPI (§17) |
| I11 | No impact in Rust | TS-only | Added → full Rust engine (§3) |
| I12 | No dead code in Rust | TS-only | Added → Rust dead code engine (§8) |
| I13 | No coverage in Rust | TS-only | Added → Rust coverage engine (§9) |
| I14 | No taint-enriched impact | No taint analysis | Added → taint flows increase risk (§13) |
| I15 | No incremental impact | Full recompute | Added → incremental invalidation (§12) |

**Coverage**: 15/15 features accounted for. 0 features lost.

---

## 3. V2 Architecture — Unified Impact Engine

### 3.1 Design Philosophy

V1's impact analysis is entirely in TypeScript, disconnected from the Rust call graph.
V2 moves everything to Rust for 10x performance and direct petgraph access.

Key design principles:
1. **Rust-native** — Direct petgraph traversal, no NAPI round-trips for graph queries
2. **Multi-factor risk** — Combine structural (callers), security (taint), and data (sensitivity)
3. **Incremental** — Re-compute only for changed functions and their transitive callers
4. **Taint-enriched** — Unsanitized taint paths through a function increase its risk score
5. **Test-aware** — Functions without test coverage get higher risk scores

### 3.2 Engine Architecture

```rust
/// The impact analysis engine. Operates on the call graph and enrichment data.
pub struct ImpactEngine {
    /// Call graph (petgraph StableGraph).
    graph: Arc<CallGraph>,

    /// Database for querying boundary/sensitivity data.
    db: Arc<DatabaseManager>,

    /// Taint summaries (from taint analysis engine).
    taint_summaries: Option<Arc<FxHashMap<FunctionId, TaintSummary>>>,

    /// Test topology (from test topology engine).
    test_coverage: Option<Arc<TestCoverageMap>>,

    /// Sensitivity classifier.
    sensitivity: SensitivityClassifier,

    /// Configuration.
    config: ImpactConfig,

    /// LRU cache for impact results.
    cache: Mutex<LruCache<String, ImpactResult>>,
}

impl ImpactEngine {
    /// Analyze the impact of changing a specific function.
    pub fn analyze_impact(
        &self,
        function_id: &str,
    ) -> Result<ImpactResult, ImpactError> {
        // Check cache
        if let Some(cached) = self.cache.lock().unwrap().get(function_id) {
            return Ok(cached.clone());
        }

        let node_idx = self.graph.find_node(function_id)
            .ok_or(ImpactError::FunctionNotFound(function_id.to_string()))?;

        // Step 1: Compute blast radius (reverse BFS)
        let blast_radius = self.compute_blast_radius(node_idx)?;

        // Step 2: Identify affected entry points
        let affected_entry_points = self.find_affected_entry_points(&blast_radius);

        // Step 3: Identify affected data paths
        let affected_data_paths = self.find_affected_data_paths(node_idx)?;

        // Step 4: Compute risk score
        let risk_score = self.compute_risk_score(
            &blast_radius,
            &affected_entry_points,
            &affected_data_paths,
            function_id,
        );

        // Step 5: Generate remediation suggestions
        let remediation = self.generate_remediation(
            function_id,
            &blast_radius,
            &risk_score,
        );

        let result = ImpactResult {
            function_id: function_id.to_string(),
            blast_radius,
            affected_entry_points,
            affected_data_paths,
            risk_score,
            risk_level: RiskLevel::from_score(risk_score.total),
            remediation,
            taint_risk: self.compute_taint_risk(function_id),
            test_coverage: self.compute_test_coverage(function_id),
        };

        // Cache result
        self.cache.lock().unwrap().put(function_id.to_string(), result.clone());

        Ok(result)
    }

    /// Analyze impact for multiple changed functions (batch).
    pub fn analyze_changes(
        &self,
        changed_functions: &[String],
    ) -> Result<ChangeImpactResult, ImpactError> {
        let mut results = Vec::new();
        let mut aggregate_risk = 0.0f64;
        let mut all_affected = FxHashSet::default();

        for func_id in changed_functions {
            let result = self.analyze_impact(func_id)?;
            aggregate_risk = aggregate_risk.max(result.risk_score.total);
            for func in &result.blast_radius.transitive_callers {
                all_affected.insert(func.clone());
            }
            results.push(result);
        }

        Ok(ChangeImpactResult {
            changed_functions: changed_functions.to_vec(),
            individual_impacts: results,
            aggregate_risk_score: aggregate_risk,
            aggregate_risk_level: RiskLevel::from_score(aggregate_risk),
            total_affected_functions: all_affected.len(),
            recommended_tests: self.recommend_tests(&all_affected),
        })
    }
}
```

---

## 4. Core Data Model

### 4.1 ImpactResult — The Primary Output

```rust
/// Impact analysis result for a single function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactResult {
    /// The function being analyzed.
    pub function_id: String,

    /// Blast radius: who is affected by changes to this function.
    pub blast_radius: BlastRadius,

    /// Entry points (HTTP handlers, CLI commands) affected by this change.
    pub affected_entry_points: Vec<EntryPointImpact>,

    /// Data paths affected by this change.
    pub affected_data_paths: Vec<DataPathImpact>,

    /// Multi-factor risk score (0-100).
    pub risk_score: RiskScore,

    /// Risk level (derived from score).
    pub risk_level: RiskLevel,

    /// Remediation suggestions.
    pub remediation: Vec<RemediationSuggestion>,

    /// Taint risk: unsanitized taint flows through this function.
    pub taint_risk: Option<TaintRisk>,

    /// Test coverage for this function.
    pub test_coverage: Option<TestCoverage>,
}

/// Blast radius: the set of functions affected by a change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlastRadius {
    /// Functions that directly call the changed function.
    pub direct_callers: Vec<CallerInfo>,

    /// All functions transitively affected (direct + indirect callers).
    pub transitive_callers: Vec<String>,

    /// Number of direct callers.
    pub direct_count: usize,

    /// Number of transitive callers.
    pub transitive_count: usize,

    /// Maximum depth of the impact chain.
    pub max_depth: u32,

    /// Number of affected files.
    pub affected_files: usize,

    /// Number of affected packages/modules.
    pub affected_modules: usize,
}

/// Information about a direct caller.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallerInfo {
    pub function_id: String,
    pub file: String,
    pub line: u32,
    pub call_site_line: u32,
    pub resolution_confidence: f64,
    pub is_entry_point: bool,
    pub is_test: bool,
}

/// An entry point affected by the change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryPointImpact {
    pub function_id: String,
    pub entry_type: EntryPointType,
    pub file: String,
    pub line: u32,
    /// Depth from changed function to this entry point.
    pub depth: u32,
    /// Path from changed function to entry point.
    pub path: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum EntryPointType {
    HttpHandler,
    CliCommand,
    MainFunction,
    EventHandler,
    CronJob,
    MessageConsumer,
    GrpcHandler,
    GraphqlResolver,
    WebSocketHandler,
    TestFunction,
}

/// A data path affected by the change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataPathImpact {
    pub table: String,
    pub fields: Vec<String>,
    pub operation: String,
    pub sensitivity: SensitivityLevel,
    pub depth: u32,
}

/// Multi-factor risk score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    /// Total risk score (0-100).
    pub total: f64,

    /// Structural risk: based on caller count and depth.
    pub structural: f64,

    /// Entry point risk: based on affected entry points.
    pub entry_point: f64,

    /// Data risk: based on sensitive data paths.
    pub data: f64,

    /// Taint risk: based on unsanitized taint flows.
    pub taint: f64,

    /// Coverage risk: based on test coverage gaps.
    pub coverage: f64,

    /// Breakdown explanation.
    pub explanation: String,
}

/// Risk level (derived from score).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskLevel {
    Critical,   // 80-100
    High,       // 60-79
    Medium,     // 40-59
    Low,        // 0-39
}

impl RiskLevel {
    pub fn from_score(score: f64) -> Self {
        match score as u32 {
            80..=100 => RiskLevel::Critical,
            60..=79 => RiskLevel::High,
            40..=59 => RiskLevel::Medium,
            _ => RiskLevel::Low,
        }
    }
}

/// Remediation suggestion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationSuggestion {
    pub priority: u32,
    pub action: String,
    pub reason: String,
    pub affected_functions: Vec<String>,
}

/// Change impact result for multiple changed functions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeImpactResult {
    pub changed_functions: Vec<String>,
    pub individual_impacts: Vec<ImpactResult>,
    pub aggregate_risk_score: f64,
    pub aggregate_risk_level: RiskLevel,
    pub total_affected_functions: usize,
    pub recommended_tests: Vec<String>,
}
```


---

## 5. Blast Radius Computation

### 5.1 Algorithm: Reverse BFS with Depth Tracking

Blast radius answers: "If I change function X, which functions are affected?"
This is a reverse BFS (following `called_by` edges) from the changed function,
collecting all transitive callers with depth tracking.

V1 only counted direct callers. V2 computes the full transitive closure with
depth, file, and module attribution.

```rust
impl ImpactEngine {
    /// Compute blast radius for a function via reverse BFS on petgraph.
    /// Returns all transitive callers with depth tracking.
    pub fn compute_blast_radius(
        &self,
        node_idx: NodeIndex,
    ) -> Result<BlastRadius, ImpactError> {
        let mut direct_callers = Vec::new();
        let mut transitive_callers = Vec::new();
        let mut visited = FxHashSet::default();
        let mut queue = VecDeque::new();
        let mut max_depth = 0u32;
        let mut affected_files = FxHashSet::default();
        let mut affected_modules = FxHashSet::default();

        // Seed: all direct callers of the target function
        for edge in self.graph.graph.edges_directed(node_idx, petgraph::Direction::Incoming) {
            let caller_idx = edge.source();
            let caller_node = &self.graph.graph[caller_idx];
            let caller_id = self.graph.interner.resolve(&caller_node.id).to_string();
            let caller_file = self.graph.interner.resolve(&caller_node.file).to_string();

            direct_callers.push(CallerInfo {
                function_id: caller_id.clone(),
                file: caller_file.clone(),
                line: caller_node.line,
                call_site_line: edge.weight().call_site_line,
                resolution_confidence: edge.weight().confidence,
                is_entry_point: caller_node.is_entry_point,
                is_test: self.is_test_function(&caller_id),
            });

            if visited.insert(caller_idx) {
                transitive_callers.push(caller_id);
                affected_files.insert(caller_file.clone());
                affected_modules.insert(self.extract_module(&caller_file));
                queue.push_back((caller_idx, 1u32));
            }
        }

        // BFS: follow reverse edges to find all transitive callers
        while let Some((current, depth)) = queue.pop_front() {
            max_depth = max_depth.max(depth);

            if depth >= self.config.max_blast_radius_depth {
                continue;
            }

            for edge in self.graph.graph.edges_directed(current, petgraph::Direction::Incoming) {
                let caller_idx = edge.source();
                if visited.insert(caller_idx) {
                    let caller_node = &self.graph.graph[caller_idx];
                    let caller_id = self.graph.interner.resolve(&caller_node.id).to_string();
                    let caller_file = self.graph.interner.resolve(&caller_node.file).to_string();

                    transitive_callers.push(caller_id);
                    affected_files.insert(caller_file.clone());
                    affected_modules.insert(self.extract_module(&caller_file));
                    queue.push_back((caller_idx, depth + 1));
                }
            }
        }

        Ok(BlastRadius {
            direct_callers,
            transitive_callers: transitive_callers.clone(),
            direct_count: direct_callers.len(),
            transitive_count: transitive_callers.len(),
            max_depth,
            affected_files: affected_files.len(),
            affected_modules: affected_modules.len(),
        })
    }

    /// Extract module name from file path.
    /// e.g., "src/services/user-service.ts" → "services"
    fn extract_module(&self, file: &str) -> String {
        let path = std::path::Path::new(file);
        path.parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .unwrap_or("root")
            .to_string()
    }
}
```

### 5.2 Entry Point Impact Discovery

After computing the blast radius, identify which entry points (HTTP handlers, CLI
commands, main functions) are affected. This tells developers which user-facing
features are impacted by the change.

```rust
impl ImpactEngine {
    /// Find all entry points affected by the change.
    /// Walks the blast radius and filters for entry point functions.
    pub fn find_affected_entry_points(
        &self,
        blast_radius: &BlastRadius,
    ) -> Vec<EntryPointImpact> {
        let mut entry_points = Vec::new();

        // Check direct callers first (depth 1)
        for caller in &blast_radius.direct_callers {
            if caller.is_entry_point {
                entry_points.push(EntryPointImpact {
                    function_id: caller.function_id.clone(),
                    entry_type: self.classify_entry_point(&caller.function_id),
                    file: caller.file.clone(),
                    line: caller.line,
                    depth: 1,
                    path: vec![caller.function_id.clone()],
                });
            }
        }

        // BFS through transitive callers to find deeper entry points
        // with path tracking for each entry point found
        for caller_id in &blast_radius.transitive_callers {
            if let Some(node_idx) = self.graph.find_node(caller_id) {
                let node = &self.graph.graph[node_idx];
                if node.is_entry_point {
                    let path = self.find_path_to_entry_point(
                        caller_id,
                        &blast_radius.transitive_callers,
                    );
                    let depth = path.len() as u32;
                    entry_points.push(EntryPointImpact {
                        function_id: caller_id.clone(),
                        entry_type: self.classify_entry_point(caller_id),
                        file: self.graph.interner.resolve(&node.file).to_string(),
                        line: node.line,
                        depth,
                        path,
                    });
                }
            }
        }

        // Sort by depth (closest entry points first)
        entry_points.sort_by_key(|ep| ep.depth);
        entry_points
    }

    /// Classify an entry point by its type.
    fn classify_entry_point(&self, function_id: &str) -> EntryPointType {
        let lower = function_id.to_lowercase();
        if lower.contains("handler") || lower.contains("route") || lower.contains("controller") {
            EntryPointType::HttpHandler
        } else if lower.contains("main") {
            EntryPointType::MainFunction
        } else if lower.contains("command") || lower.contains("cli") {
            EntryPointType::CliCommand
        } else if lower.contains("cron") || lower.contains("schedule") {
            EntryPointType::CronJob
        } else if lower.contains("consumer") || lower.contains("subscriber") {
            EntryPointType::MessageConsumer
        } else if lower.contains("grpc") {
            EntryPointType::GrpcHandler
        } else if lower.contains("resolver") || lower.contains("graphql") {
            EntryPointType::GraphqlResolver
        } else if lower.contains("websocket") || lower.contains("ws") {
            EntryPointType::WebSocketHandler
        } else if lower.contains("test") || lower.contains("spec") {
            EntryPointType::TestFunction
        } else {
            EntryPointType::EventHandler
        }
    }
}
```

### 5.3 Data Path Impact Discovery

Identify which data access points (database tables, fields) are affected by the change.
This tells developers which data is at risk.

```rust
impl ImpactEngine {
    /// Find all data paths affected by the change.
    /// Queries boundary detection results for functions in the blast radius.
    pub fn find_affected_data_paths(
        &self,
        node_idx: NodeIndex,
    ) -> Result<Vec<DataPathImpact>, ImpactError> {
        let mut data_paths = Vec::new();

        // Forward BFS from changed function to find data access points
        let mut visited = FxHashSet::default();
        let mut queue = VecDeque::new();
        queue.push_back((node_idx, 0u32));
        visited.insert(node_idx);

        while let Some((current, depth)) = queue.pop_front() {
            if depth > self.config.max_data_path_depth {
                continue;
            }

            let func_id = self.graph.node_id(current);

            // Query drift.db for data access points in this function
            let accesses = self.db.query_data_access(&func_id)?;
            for access in accesses {
                let sensitivity = self.classify_sensitivity(&access);
                data_paths.push(DataPathImpact {
                    table: access.table.clone(),
                    fields: access.fields.clone(),
                    operation: access.operation.to_string(),
                    sensitivity,
                    depth,
                });
            }

            // Continue BFS to callees
            for edge in self.graph.graph.edges(current) {
                let callee = edge.target();
                if visited.insert(callee) {
                    queue.push_back((callee, depth + 1));
                }
            }
        }

        // Deduplicate by table+operation, keep lowest depth
        data_paths.sort_by_key(|dp| (dp.table.clone(), dp.operation.clone(), dp.depth));
        data_paths.dedup_by(|a, b| a.table == b.table && a.operation == b.operation);

        Ok(data_paths)
    }
}
```

---

## 6. Change Propagation Analysis

### 6.1 Multi-Function Change Analysis

When a developer changes multiple functions (e.g., a PR with 5 modified functions),
the impact engine computes the union of all blast radii and identifies overlapping
impact zones — areas where multiple changes compound risk.

```rust
/// Result of analyzing multiple changed functions together.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangePropagationResult {
    /// Individual blast radii per changed function.
    pub per_function: Vec<(String, BlastRadius)>,

    /// Union of all affected functions (deduplicated).
    pub all_affected: Vec<String>,

    /// Functions affected by 2+ changes (overlap zones).
    pub overlap_zones: Vec<OverlapZone>,

    /// Files affected by the change set.
    pub affected_files: Vec<String>,

    /// Modules affected by the change set.
    pub affected_modules: Vec<String>,

    /// Aggregate risk score for the entire change set.
    pub aggregate_risk: RiskScore,
}

/// An overlap zone where multiple changes compound.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverlapZone {
    /// Function affected by multiple changes.
    pub function_id: String,
    /// Which changed functions affect this function.
    pub affected_by: Vec<String>,
    /// Risk multiplier (more overlapping changes = higher risk).
    pub risk_multiplier: f64,
}

impl ImpactEngine {
    /// Analyze propagation of a set of changes.
    pub fn analyze_change_propagation(
        &self,
        changed_functions: &[String],
    ) -> Result<ChangePropagationResult, ImpactError> {
        let mut per_function = Vec::new();
        let mut all_affected = FxHashSet::default();
        let mut affect_count: FxHashMap<String, Vec<String>> = FxHashMap::default();

        // Compute blast radius for each changed function
        for func_id in changed_functions {
            let node_idx = self.graph.find_node(func_id)
                .ok_or(ImpactError::FunctionNotFound(func_id.clone()))?;

            let blast = self.compute_blast_radius(node_idx)?;

            // Track which functions are affected by which changes
            for affected in &blast.transitive_callers {
                all_affected.insert(affected.clone());
                affect_count
                    .entry(affected.clone())
                    .or_default()
                    .push(func_id.clone());
            }

            per_function.push((func_id.clone(), blast));
        }

        // Identify overlap zones (functions affected by 2+ changes)
        let overlap_zones: Vec<OverlapZone> = affect_count
            .into_iter()
            .filter(|(_, sources)| sources.len() > 1)
            .map(|(func_id, sources)| {
                let risk_multiplier = 1.0 + (sources.len() as f64 - 1.0) * 0.3;
                OverlapZone {
                    function_id: func_id,
                    affected_by: sources,
                    risk_multiplier,
                }
            })
            .collect();

        // Collect affected files and modules
        let mut affected_files = FxHashSet::default();
        let mut affected_modules = FxHashSet::default();
        for (_, blast) in &per_function {
            for caller in &blast.direct_callers {
                affected_files.insert(caller.file.clone());
                affected_modules.insert(self.extract_module(&caller.file));
            }
        }

        // Compute aggregate risk
        let aggregate_risk = self.compute_aggregate_risk(
            &per_function,
            &overlap_zones,
            &all_affected,
        )?;

        Ok(ChangePropagationResult {
            per_function,
            all_affected: all_affected.into_iter().collect(),
            overlap_zones,
            affected_files: affected_files.into_iter().collect(),
            affected_modules: affected_modules.into_iter().collect(),
            aggregate_risk,
        })
    }
}
```

### 6.2 Git Diff Integration

The change propagation engine integrates with git diff to automatically identify
changed functions from a commit or PR.

```rust
/// Identify changed functions from a git diff.
pub fn functions_from_diff(
    graph: &CallGraph,
    diff_files: &[(String, Vec<u32>)],  // (file_path, changed_lines)
) -> Vec<String> {
    let mut changed_functions = Vec::new();

    for (file, changed_lines) in diff_files {
        // Find all functions in this file
        if let Some(node_indices) = graph.file_nodes.get(file) {
            for &node_idx in node_indices {
                let node = &graph.graph[node_idx];
                // Check if any changed line falls within this function's range
                for &line in changed_lines {
                    if line >= node.line && line <= node.end_line {
                        let func_id = graph.interner.resolve(&node.id).to_string();
                        changed_functions.push(func_id);
                        break;
                    }
                }
            }
        }
    }

    changed_functions.sort();
    changed_functions.dedup();
    changed_functions
}
```

---

## 7. Risk Scoring Engine

### 7.1 Multi-Factor Risk Model

V1 used a simple 4-level risk (low/medium/high/critical) based on caller count.
V2 uses a continuous 0-100 score with 5 weighted factors, then maps to 4 levels.

```
Risk Score = (structural × 0.25) + (entry_point × 0.20) + (data × 0.20)
           + (taint × 0.20) + (coverage × 0.15)

Each factor is independently scored 0-100, then weighted.
```

| Factor | Weight | What It Measures | Source |
|--------|--------|-----------------|--------|
| Structural | 0.25 | Caller count, depth, affected files | Blast radius computation |
| Entry Point | 0.20 | Number and type of affected entry points | Entry point discovery |
| Data | 0.20 | Sensitivity of affected data paths | Boundary detection |
| Taint | 0.20 | Unsanitized taint flows through function | Taint analysis engine |
| Coverage | 0.15 | Test coverage gaps for affected paths | Test topology engine |

### 7.2 Factor Scoring Algorithms

```rust
impl ImpactEngine {
    /// Compute the full multi-factor risk score.
    pub fn compute_risk_score(
        &self,
        blast_radius: &BlastRadius,
        entry_points: &[EntryPointImpact],
        data_paths: &[DataPathImpact],
        function_id: &str,
    ) -> RiskScore {
        let structural = self.score_structural(blast_radius);
        let entry_point = self.score_entry_points(entry_points);
        let data = self.score_data_paths(data_paths);
        let taint = self.score_taint(function_id);
        let coverage = self.score_coverage(function_id);

        let total = (structural * 0.25)
            + (entry_point * 0.20)
            + (data * 0.20)
            + (taint * 0.20)
            + (coverage * 0.15);

        // Clamp to 0-100
        let total = total.clamp(0.0, 100.0);

        let explanation = format!(
            "structural={:.0} (w=0.25), entry_point={:.0} (w=0.20), \
             data={:.0} (w=0.20), taint={:.0} (w=0.20), coverage={:.0} (w=0.15) → {:.1}",
            structural, entry_point, data, taint, coverage, total
        );

        RiskScore {
            total,
            structural,
            entry_point,
            data,
            taint,
            coverage,
            explanation,
        }
    }

    /// Structural risk: based on caller count and depth.
    /// More callers and deeper chains = higher risk.
    fn score_structural(&self, blast: &BlastRadius) -> f64 {
        // Direct callers: 0-10 maps to 0-50, capped at 50
        let direct_score = (blast.direct_count as f64 * 5.0).min(50.0);

        // Transitive callers: 0-100 maps to 0-30, capped at 30
        let transitive_score = (blast.transitive_count as f64 * 0.3).min(30.0);

        // Depth: 0-10 maps to 0-10, capped at 10
        let depth_score = (blast.max_depth as f64).min(10.0);

        // Affected files: 0-20 maps to 0-10, capped at 10
        let file_score = (blast.affected_files as f64 * 0.5).min(10.0);

        (direct_score + transitive_score + depth_score + file_score).min(100.0)
    }

    /// Entry point risk: based on number and type of affected entry points.
    fn score_entry_points(&self, entry_points: &[EntryPointImpact]) -> f64 {
        if entry_points.is_empty() {
            return 0.0;
        }

        let mut score = 0.0;

        for ep in entry_points {
            let type_weight = match ep.entry_type {
                EntryPointType::HttpHandler => 20.0,
                EntryPointType::GrpcHandler => 18.0,
                EntryPointType::GraphqlResolver => 18.0,
                EntryPointType::WebSocketHandler => 15.0,
                EntryPointType::MessageConsumer => 12.0,
                EntryPointType::CronJob => 10.0,
                EntryPointType::CliCommand => 8.0,
                EntryPointType::MainFunction => 5.0,
                EntryPointType::EventHandler => 10.0,
                EntryPointType::TestFunction => 2.0,
            };

            // Closer entry points (lower depth) are higher risk
            let depth_factor = 1.0 / (ep.depth as f64 + 1.0);
            score += type_weight * depth_factor;
        }

        score.min(100.0)
    }

    /// Data risk: based on sensitivity of affected data paths.
    fn score_data_paths(&self, data_paths: &[DataPathImpact]) -> f64 {
        if data_paths.is_empty() {
            return 0.0;
        }

        let mut score = 0.0;

        for dp in data_paths {
            let sensitivity_weight = match dp.sensitivity {
                SensitivityLevel::Critical => 40.0,   // Credentials, secrets
                SensitivityLevel::High => 25.0,       // PII, financial
                SensitivityLevel::Medium => 10.0,     // Internal data
                SensitivityLevel::Low => 3.0,         // Public data
            };

            let operation_weight = match dp.operation.as_str() {
                "write" | "delete" | "update" => 1.5,
                "read" => 1.0,
                _ => 0.8,
            };

            // Closer data paths (lower depth) are higher risk
            let depth_factor = 1.0 / (dp.depth as f64 + 1.0);
            score += sensitivity_weight * operation_weight * depth_factor;
        }

        score.min(100.0)
    }

    /// Taint risk: based on unsanitized taint flows through this function.
    fn score_taint(&self, function_id: &str) -> f64 {
        let summaries = match &self.taint_summaries {
            Some(s) => s,
            None => return 0.0,  // Taint analysis not available
        };

        let summary = match summaries.get(function_id) {
            Some(s) => s,
            None => return 0.0,
        };

        let mut score = 0.0;

        // Unsanitized param-to-sink flows are high risk
        for flow in &summary.param_to_sink {
            if !flow.is_sanitized {
                let sink_weight = match flow.sink.sink_type {
                    SinkType::SqlQuery | SinkType::OsCommand | SinkType::CodeExecution => 40.0,
                    SinkType::HtmlOutput | SinkType::HttpRequest => 25.0,
                    SinkType::FileWrite | SinkType::FileRead => 20.0,
                    SinkType::Deserialization => 30.0,
                    _ => 15.0,
                };
                score += sink_weight;
            }
        }

        score.min(100.0)
    }

    /// Coverage risk: functions without test coverage get higher risk.
    fn score_coverage(&self, function_id: &str) -> f64 {
        let coverage = match &self.test_coverage {
            Some(c) => c,
            None => return 50.0,  // Unknown coverage = medium risk
        };

        match coverage.get(function_id) {
            Some(cov) => {
                // 0% coverage = 100 risk, 100% coverage = 0 risk
                (1.0 - cov.coverage_ratio) * 100.0
            }
            None => 80.0,  // No coverage data = high risk
        }
    }
}
```

### 7.3 Aggregate Risk for Change Sets

When multiple functions change, the aggregate risk accounts for overlap zones
where multiple changes compound.

```rust
impl ImpactEngine {
    /// Compute aggregate risk for a set of changes.
    fn compute_aggregate_risk(
        &self,
        per_function: &[(String, BlastRadius)],
        overlap_zones: &[OverlapZone],
        all_affected: &FxHashSet<String>,
    ) -> Result<RiskScore, ImpactError> {
        // Start with the maximum individual risk
        let mut max_risk = 0.0f64;
        let mut total_structural = 0.0f64;
        let mut total_entry = 0.0f64;
        let mut total_data = 0.0f64;
        let mut total_taint = 0.0f64;
        let mut total_coverage = 0.0f64;

        for (func_id, blast) in per_function {
            let entry_points = self.find_affected_entry_points(blast);
            let node_idx = self.graph.find_node(func_id)
                .ok_or(ImpactError::FunctionNotFound(func_id.clone()))?;
            let data_paths = self.find_affected_data_paths(node_idx)?;
            let score = self.compute_risk_score(blast, &entry_points, &data_paths, func_id);

            max_risk = max_risk.max(score.total);
            total_structural = total_structural.max(score.structural);
            total_entry = total_entry.max(score.entry_point);
            total_data = total_data.max(score.data);
            total_taint = total_taint.max(score.taint);
            total_coverage = total_coverage.max(score.coverage);
        }

        // Apply overlap multiplier: each overlap zone increases risk
        let overlap_bonus = overlap_zones.iter()
            .map(|oz| (oz.risk_multiplier - 1.0) * 10.0)
            .sum::<f64>();

        let total = (max_risk + overlap_bonus).clamp(0.0, 100.0);

        Ok(RiskScore {
            total,
            structural: total_structural,
            entry_point: total_entry,
            data: total_data,
            taint: total_taint,
            coverage: total_coverage,
            explanation: format!(
                "max_individual={:.1}, overlap_bonus={:.1}, zones={} → {:.1}",
                max_risk, overlap_bonus, overlap_zones.len(), total
            ),
        })
    }
}
```


---

## 8. Dead Code Detection Engine

### 8.1 Algorithm

Dead code detection identifies functions that are never called from any entry point.
V1 used `calledBy.length == 0` with 6 false positive categories. V2 uses petgraph
reverse reachability from entry points with 8 false positive categories and confidence
scoring.

```rust
/// Dead code detection engine.
pub struct DeadCodeEngine<'a> {
    graph: &'a CallGraph,
    db: &'a DatabaseManager,
    config: &'a DeadCodeConfig,
}

/// A dead code candidate with confidence and false positive analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadCodeCandidate {
    /// The function identified as potentially dead.
    pub function_id: String,
    /// File containing the function.
    pub file: String,
    /// Line number.
    pub line: u32,
    /// End line.
    pub end_line: u32,
    /// Language.
    pub language: Language,
    /// Confidence that this is truly dead code (0.0 - 1.0).
    pub confidence: f64,
    /// Reasons this might be a false positive.
    pub false_positive_reasons: Vec<FalsePositiveReason>,
    /// Whether this function is exported.
    pub is_exported: bool,
    /// Lines of code in this function.
    pub loc: u32,
}

/// Reasons a dead code candidate might be a false positive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FalsePositiveReason {
    /// Function is an entry point (HTTP handler, CLI command, main).
    EntryPoint,
    /// Function is a framework lifecycle hook (componentDidMount, on_event).
    FrameworkHook,
    /// Function may be called via dynamic dispatch (reflection, eval).
    DynamicDispatch,
    /// Function is an event handler (addEventListener, on/emit).
    EventHandler,
    /// Function is exported and may be used by external consumers.
    Exported,
    /// Function is a test function or test utility.
    TestFunction,
    /// Function may be called via reflection or metaprogramming.
    Reflection,
    /// Function is a decorator target or has decorators that register it.
    DecoratorTarget,
}

impl<'a> DeadCodeEngine<'a> {
    /// Detect all dead code candidates in the call graph.
    pub fn detect(&self) -> Result<Vec<DeadCodeCandidate>, ImpactError> {
        // Step 1: Find all entry points
        let entry_points: Vec<NodeIndex> = self.graph.graph
            .node_indices()
            .filter(|&idx| self.graph.graph[idx].is_entry_point)
            .collect();

        // Step 2: BFS from all entry points to find all reachable functions
        let mut reachable = FxHashSet::default();
        let mut queue = VecDeque::new();

        for &ep in &entry_points {
            reachable.insert(ep);
            queue.push_back(ep);
        }

        while let Some(current) = queue.pop_front() {
            for edge in self.graph.graph.edges(current) {
                let callee = edge.target();
                if reachable.insert(callee) {
                    queue.push_back(callee);
                }
            }
        }

        // Step 3: All functions NOT in reachable set are dead code candidates
        let mut candidates = Vec::new();

        for node_idx in self.graph.graph.node_indices() {
            if reachable.contains(&node_idx) {
                continue;
            }

            let node = &self.graph.graph[node_idx];
            let func_id = self.graph.interner.resolve(&node.id).to_string();
            let file = self.graph.interner.resolve(&node.file).to_string();

            // Compute false positive reasons
            let fp_reasons = self.analyze_false_positives(&func_id, node);

            // Compute confidence (higher = more likely truly dead)
            let confidence = self.compute_confidence(&fp_reasons, node);

            // Skip if confidence is below threshold
            if confidence < self.config.min_confidence {
                continue;
            }

            candidates.push(DeadCodeCandidate {
                function_id: func_id,
                file,
                line: node.line,
                end_line: node.end_line,
                language: node.language,
                confidence,
                false_positive_reasons: fp_reasons,
                is_exported: node.is_exported,
                loc: node.end_line.saturating_sub(node.line) + 1,
            });
        }

        // Sort by confidence (highest first), then by LOC (largest first)
        candidates.sort_by(|a, b| {
            b.confidence.partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(b.loc.cmp(&a.loc))
        });

        Ok(candidates)
    }

    /// Analyze potential false positive reasons for a dead code candidate.
    fn analyze_false_positives(
        &self,
        func_id: &str,
        node: &FunctionNode,
    ) -> Vec<FalsePositiveReason> {
        let mut reasons = Vec::new();
        let lower = func_id.to_lowercase();

        // Entry point check (should have been caught by is_entry_point, but double-check)
        if self.looks_like_entry_point(&lower) {
            reasons.push(FalsePositiveReason::EntryPoint);
        }

        // Framework hook patterns
        if self.is_framework_hook(&lower, node.language) {
            reasons.push(FalsePositiveReason::FrameworkHook);
        }

        // Dynamic dispatch indicators
        if self.has_dynamic_dispatch_risk(&lower) {
            reasons.push(FalsePositiveReason::DynamicDispatch);
        }

        // Event handler patterns
        if self.is_event_handler(&lower) {
            reasons.push(FalsePositiveReason::EventHandler);
        }

        // Exported functions
        if node.is_exported {
            reasons.push(FalsePositiveReason::Exported);
        }

        // Test functions
        if self.is_test_function(&lower) {
            reasons.push(FalsePositiveReason::TestFunction);
        }

        // Reflection/metaprogramming
        if self.has_reflection_risk(&lower, node.language) {
            reasons.push(FalsePositiveReason::Reflection);
        }

        // Decorator targets
        if self.is_decorator_target(&lower, node.language) {
            reasons.push(FalsePositiveReason::DecoratorTarget);
        }

        reasons
    }

    /// Compute confidence that a function is truly dead code.
    /// More false positive reasons = lower confidence.
    fn compute_confidence(
        &self,
        fp_reasons: &[FalsePositiveReason],
        node: &FunctionNode,
    ) -> f64 {
        let mut confidence = 1.0;

        for reason in fp_reasons {
            let penalty = match reason {
                FalsePositiveReason::EntryPoint => 0.9,      // Almost certainly not dead
                FalsePositiveReason::FrameworkHook => 0.7,    // Likely called by framework
                FalsePositiveReason::DynamicDispatch => 0.5,  // May be called dynamically
                FalsePositiveReason::EventHandler => 0.6,     // May be registered elsewhere
                FalsePositiveReason::Exported => 0.4,         // May be used externally
                FalsePositiveReason::TestFunction => 0.8,     // Test runner calls it
                FalsePositiveReason::Reflection => 0.5,       // May be called via reflection
                FalsePositiveReason::DecoratorTarget => 0.6,  // Decorator may register it
            };
            confidence *= 1.0 - penalty;
        }

        // Boost confidence if function has no callers at all (not even unresolved)
        if !node.is_exported {
            confidence = (confidence + 0.1).min(1.0);
        }

        confidence
    }

    /// Framework hook patterns by language.
    fn is_framework_hook(&self, name: &str, language: Language) -> bool {
        match language {
            Language::TypeScript | Language::JavaScript => {
                // React lifecycle, Angular hooks, Vue hooks
                name.contains("componentdidmount") || name.contains("componentwillunmount")
                    || name.contains("ngoninit") || name.contains("ngondestroy")
                    || name.contains("mounted") || name.contains("beforedestroy")
                    || name.contains("useeffect") || name.contains("usememo")
            }
            Language::Python => {
                // Django signals, FastAPI lifespan, pytest fixtures
                name.contains("__init__") || name.contains("__del__")
                    || name.contains("__enter__") || name.contains("__exit__")
                    || name.contains("setup") || name.contains("teardown")
                    || name.starts_with("on_") || name.starts_with("handle_")
            }
            Language::Java => {
                // Spring lifecycle, JUnit setup
                name.contains("postconstruct") || name.contains("predestroy")
                    || name.contains("afterpropertieset")
                    || name.contains("setup") || name.contains("teardown")
            }
            _ => false,
        }
    }

    fn looks_like_entry_point(&self, name: &str) -> bool {
        name.contains("main") || name.contains("handler") || name.contains("route")
            || name.contains("endpoint") || name.contains("controller")
            || name.contains("command") || name.contains("cli")
    }

    fn has_dynamic_dispatch_risk(&self, name: &str) -> bool {
        name.contains("dispatch") || name.contains("invoke")
            || name.contains("callback") || name.contains("delegate")
    }

    fn is_event_handler(&self, name: &str) -> bool {
        name.starts_with("on") || name.contains("listener")
            || name.contains("subscriber") || name.contains("handler")
    }

    fn is_test_function(&self, name: &str) -> bool {
        name.starts_with("test") || name.starts_with("it_")
            || name.contains("_test") || name.contains("_spec")
            || name.starts_with("describe") || name.starts_with("should")
    }

    fn has_reflection_risk(&self, name: &str, language: Language) -> bool {
        match language {
            Language::Java => name.contains("invoke") || name.contains("reflect"),
            Language::Python => name.starts_with("__") && name.ends_with("__"),
            _ => false,
        }
    }

    fn is_decorator_target(&self, name: &str, language: Language) -> bool {
        match language {
            Language::Python => {
                // FastAPI routes, Flask routes, Django views
                name.contains("route") || name.contains("view")
                    || name.contains("endpoint") || name.contains("task")
            }
            Language::TypeScript | Language::JavaScript => {
                // NestJS controllers, Angular components
                name.contains("controller") || name.contains("component")
                    || name.contains("service") || name.contains("module")
            }
            _ => false,
        }
    }
}
```

---

## 9. Coverage Analysis Engine (Call Graph × Test Topology)

### 9.1 Architecture

Coverage analysis crosses the call graph with the test topology to identify:
1. Functions with no test coverage
2. Data paths with no test coverage
3. Sensitive data paths that are untested

V1 did this in TypeScript. V2 does it in Rust with field-level granularity.

```rust
/// Coverage analysis engine.
pub struct CoverageEngine<'a> {
    graph: &'a CallGraph,
    test_coverage: &'a TestCoverageMap,
    db: &'a DatabaseManager,
}

/// Test coverage map: function_id → coverage info.
pub type TestCoverageMap = FxHashMap<String, FunctionCoverage>;

/// Coverage information for a single function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionCoverage {
    /// Function ID.
    pub function_id: String,
    /// Test functions that cover this function (directly or transitively).
    pub covering_tests: Vec<String>,
    /// Coverage ratio (0.0 = no coverage, 1.0 = fully covered).
    pub coverage_ratio: f64,
    /// Whether this function is directly tested (vs transitively covered).
    pub is_directly_tested: bool,
}

/// Coverage analysis result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageAnalysisResult {
    /// Functions with no test coverage.
    pub uncovered_functions: Vec<UncoveredFunction>,
    /// Data paths with no test coverage.
    pub uncovered_data_paths: Vec<UncoveredDataPath>,
    /// Sensitive data paths that are untested.
    pub uncovered_sensitive_paths: Vec<UncoveredSensitivePath>,
    /// Overall coverage statistics.
    pub stats: CoverageStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UncoveredFunction {
    pub function_id: String,
    pub file: String,
    pub line: u32,
    pub is_entry_point: bool,
    pub caller_count: usize,
    pub risk_if_uncovered: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UncoveredDataPath {
    pub function_id: String,
    pub table: String,
    pub fields: Vec<String>,
    pub operation: String,
    pub sensitivity: SensitivityLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UncoveredSensitivePath {
    pub entry_point: String,
    pub data_access: String,
    pub table: String,
    pub fields: Vec<String>,
    pub sensitivity: SensitivityLevel,
    pub path: Vec<String>,
    pub risk_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageStats {
    pub total_functions: usize,
    pub covered_functions: usize,
    pub uncovered_functions: usize,
    pub coverage_percentage: f64,
    pub total_data_paths: usize,
    pub covered_data_paths: usize,
    pub uncovered_data_paths: usize,
    pub data_path_coverage_percentage: f64,
    pub sensitive_uncovered_count: usize,
}

impl<'a> CoverageEngine<'a> {
    /// Analyze test coverage across the call graph.
    pub fn analyze(&self) -> Result<CoverageAnalysisResult, ImpactError> {
        let mut uncovered_functions = Vec::new();
        let mut uncovered_data_paths = Vec::new();
        let mut uncovered_sensitive_paths = Vec::new();
        let mut covered_count = 0usize;
        let mut total_count = 0usize;

        for node_idx in self.graph.graph.node_indices() {
            let node = &self.graph.graph[node_idx];
            let func_id = self.graph.interner.resolve(&node.id).to_string();
            total_count += 1;

            match self.test_coverage.get(&func_id) {
                Some(cov) if cov.coverage_ratio > 0.0 => {
                    covered_count += 1;
                }
                _ => {
                    // Function has no test coverage
                    let caller_count = self.graph.graph
                        .edges_directed(node_idx, petgraph::Direction::Incoming)
                        .count();

                    uncovered_functions.push(UncoveredFunction {
                        function_id: func_id.clone(),
                        file: self.graph.interner.resolve(&node.file).to_string(),
                        line: node.line,
                        is_entry_point: node.is_entry_point,
                        caller_count,
                        risk_if_uncovered: self.estimate_uncovered_risk(
                            node_idx, caller_count, node.is_entry_point,
                        ),
                    });

                    // Check if this uncovered function accesses data
                    if let Ok(accesses) = self.db.query_data_access(&func_id) {
                        for access in accesses {
                            let sensitivity = classify_sensitivity(&access);
                            uncovered_data_paths.push(UncoveredDataPath {
                                function_id: func_id.clone(),
                                table: access.table.clone(),
                                fields: access.fields.clone(),
                                operation: access.operation.to_string(),
                                sensitivity,
                            });

                            // If sensitive and uncovered, flag as high priority
                            if matches!(sensitivity,
                                SensitivityLevel::Critical | SensitivityLevel::High)
                            {
                                uncovered_sensitive_paths.push(UncoveredSensitivePath {
                                    entry_point: String::new(), // Filled below
                                    data_access: func_id.clone(),
                                    table: access.table.clone(),
                                    fields: access.fields.clone(),
                                    sensitivity,
                                    path: Vec::new(),
                                    risk_score: 80.0 + (sensitivity as u8 as f64 * 5.0),
                                });
                            }
                        }
                    }
                }
            }
        }

        // Sort uncovered functions by risk (highest first)
        uncovered_functions.sort_by(|a, b| {
            b.risk_if_uncovered.partial_cmp(&a.risk_if_uncovered)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let coverage_pct = if total_count > 0 {
            (covered_count as f64 / total_count as f64) * 100.0
        } else {
            0.0
        };

        Ok(CoverageAnalysisResult {
            stats: CoverageStats {
                total_functions: total_count,
                covered_functions: covered_count,
                uncovered_functions: uncovered_functions.len(),
                coverage_percentage: coverage_pct,
                total_data_paths: uncovered_data_paths.len() + covered_count, // Approximate
                covered_data_paths: covered_count,
                uncovered_data_paths: uncovered_data_paths.len(),
                data_path_coverage_percentage: 0.0, // Computed separately
                sensitive_uncovered_count: uncovered_sensitive_paths.len(),
            },
            uncovered_functions,
            uncovered_data_paths,
            uncovered_sensitive_paths,
        })
    }

    /// Estimate risk of a function being uncovered.
    fn estimate_uncovered_risk(
        &self,
        node_idx: NodeIndex,
        caller_count: usize,
        is_entry_point: bool,
    ) -> f64 {
        let mut risk = 0.0;

        // More callers = higher risk if uncovered
        risk += (caller_count as f64 * 5.0).min(40.0);

        // Entry points are high risk if uncovered
        if is_entry_point {
            risk += 30.0;
        }

        // Functions that access data are higher risk
        let func_id = self.graph.node_id(node_idx);
        if let Ok(accesses) = self.db.query_data_access(&func_id) {
            if !accesses.is_empty() {
                risk += 20.0;
            }
        }

        risk.min(100.0)
    }
}
```


---

## 10. Path Finding Engine

### 10.1 Algorithm: petgraph all_simple_paths

V1 used a custom BFS with path tracking. V2 uses petgraph's `all_simple_paths`
algorithm which is optimized for finding all acyclic paths between two nodes.

```rust
use petgraph::algo::all_simple_paths;

/// Path finding engine — find all paths between two functions.
pub struct PathFinder<'a> {
    graph: &'a CallGraph,
    config: &'a PathFinderConfig,
}

/// A path between two functions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionPath {
    /// Ordered list of function IDs from source to target.
    pub nodes: Vec<String>,
    /// Length of the path (number of edges).
    pub length: usize,
    /// Total confidence (product of edge confidences).
    pub confidence: f64,
    /// Whether this path passes through an entry point.
    pub passes_through_entry_point: bool,
    /// Whether this path touches sensitive data.
    pub touches_sensitive_data: bool,
}

#[derive(Debug, Clone)]
pub struct PathFinderConfig {
    /// Maximum path length to search.
    pub max_depth: usize,
    /// Maximum number of paths to return.
    pub max_paths: usize,
    /// Minimum confidence threshold for paths.
    pub min_confidence: f64,
}

impl Default for PathFinderConfig {
    fn default() -> Self {
        Self {
            max_depth: 15,
            max_paths: 20,
            min_confidence: 0.1,
        }
    }
}

impl<'a> PathFinder<'a> {
    /// Find all paths between two functions.
    pub fn find_paths(
        &self,
        from: &str,
        to: &str,
    ) -> Result<Vec<FunctionPath>, ImpactError> {
        let from_idx = self.graph.find_node(from)
            .ok_or(ImpactError::FunctionNotFound(from.to_string()))?;
        let to_idx = self.graph.find_node(to)
            .ok_or(ImpactError::FunctionNotFound(to.to_string()))?;

        // Use petgraph's all_simple_paths (DFS-based, avoids cycles)
        let raw_paths: Vec<Vec<NodeIndex>> = all_simple_paths(
            &self.graph.graph,
            from_idx,
            to_idx,
            0,                          // min intermediate nodes
            Some(self.config.max_depth), // max intermediate nodes
        )
        .take(self.config.max_paths)
        .collect();

        let mut paths = Vec::new();

        for raw_path in raw_paths {
            let nodes: Vec<String> = raw_path.iter()
                .map(|&idx| self.graph.node_id(idx).to_string())
                .collect();

            // Compute path confidence (product of edge confidences)
            let confidence = self.compute_path_confidence(&raw_path);

            if confidence < self.config.min_confidence {
                continue;
            }

            let passes_through_entry_point = raw_path.iter()
                .any(|&idx| self.graph.graph[idx].is_entry_point);

            let touches_sensitive_data = self.path_touches_sensitive_data(&raw_path);

            paths.push(FunctionPath {
                length: nodes.len() - 1,
                nodes,
                confidence,
                passes_through_entry_point,
                touches_sensitive_data,
            });
        }

        // Sort by length (shortest first), then by confidence (highest first)
        paths.sort_by(|a, b| {
            a.length.cmp(&b.length)
                .then(b.confidence.partial_cmp(&a.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal))
        });

        Ok(paths)
    }

    /// Compute path confidence as the product of edge confidences.
    fn compute_path_confidence(&self, path: &[NodeIndex]) -> f64 {
        let mut confidence = 1.0;

        for window in path.windows(2) {
            let from = window[0];
            let to = window[1];

            // Find the edge between these nodes
            if let Some(edge) = self.graph.graph.find_edge(from, to) {
                confidence *= self.graph.graph[edge].confidence;
            } else {
                confidence *= 0.1; // Edge not found — very low confidence
            }
        }

        confidence
    }

    /// Check if any function on the path accesses sensitive data.
    fn path_touches_sensitive_data(&self, path: &[NodeIndex]) -> bool {
        for &node_idx in path {
            let func_id = self.graph.node_id(node_idx);
            // Check drift.db for data access points
            if let Ok(accesses) = self.graph.db.query_data_access(&func_id) {
                for access in &accesses {
                    let sensitivity = classify_sensitivity(access);
                    if matches!(sensitivity,
                        SensitivityLevel::Critical | SensitivityLevel::High)
                    {
                        return true;
                    }
                }
            }
        }
        false
    }
}
```

---

## 11. Enrichment Pipeline (Sensitivity → Impact → Remediation)

### 11.1 Pipeline Architecture

The enrichment pipeline transforms raw impact data into actionable intelligence.
It runs after blast radius computation and risk scoring, adding:
1. Sensitivity classification (6 categories)
2. PageRank-inspired impact scoring
3. Remediation suggestion generation

V1 had 3 separate TypeScript components. V2 unifies them in a single Rust pipeline.

```rust
/// The enrichment pipeline. Runs after impact analysis to add
/// sensitivity, scoring, and remediation data.
pub struct EnrichmentPipeline<'a> {
    graph: &'a CallGraph,
    db: &'a DatabaseManager,
    config: &'a EnrichmentConfig,
}

impl<'a> EnrichmentPipeline<'a> {
    /// Enrich an impact result with sensitivity, scoring, and remediation.
    pub fn enrich(
        &self,
        result: &mut ImpactResult,
    ) -> Result<(), ImpactError> {
        // Step 1: Classify sensitivity of affected data paths
        self.classify_data_sensitivity(result)?;

        // Step 2: Compute PageRank-inspired impact score
        self.compute_impact_score(result)?;

        // Step 3: Generate remediation suggestions
        self.generate_remediation(result)?;

        Ok(())
    }
}
```

### 11.2 Sensitivity Classification (6 Categories)

V1 had 4 categories (PII, Credentials, Financial, Health). V2 adds Infrastructure
and Compliance for enterprise use cases.

```rust
/// Sensitivity category for data access points.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SensitivityCategory {
    /// Personally Identifiable Information (names, emails, addresses, SSN).
    PII,
    /// Authentication credentials (passwords, tokens, API keys, secrets).
    Credentials,
    /// Financial data (credit cards, bank accounts, transactions).
    Financial,
    /// Health/medical data (diagnoses, prescriptions, insurance).
    Health,
    /// Infrastructure secrets (connection strings, certificates, private keys).
    Infrastructure,
    /// Compliance-regulated data (GDPR, HIPAA, PCI-DSS, SOX).
    Compliance,
}

/// Sensitivity level (severity within a category).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SensitivityLevel {
    Critical = 4,   // Credentials, financial account numbers
    High = 3,       // PII (SSN, DOB), health records
    Medium = 2,     // Internal data, non-sensitive PII (display name)
    Low = 1,        // Public data, non-sensitive fields
}

/// Sensitivity classification result for a data access point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensitivityClassification {
    pub category: SensitivityCategory,
    pub level: SensitivityLevel,
    pub confidence: f64,
    pub matched_patterns: Vec<String>,
    pub field_name: String,
    pub table_name: String,
}

/// Sensitivity classifier with pattern-based detection.
pub struct SensitivityClassifier {
    /// Patterns organized by category.
    patterns: FxHashMap<SensitivityCategory, Vec<SensitivityPattern>>,
}

struct SensitivityPattern {
    regex: regex::Regex,
    category: SensitivityCategory,
    level: SensitivityLevel,
    confidence: f64,
    description: String,
}

impl SensitivityClassifier {
    /// Classify a field by its name and context.
    pub fn classify(
        &self,
        field_name: &str,
        table_name: &str,
    ) -> Option<SensitivityClassification> {
        let combined = format!("{}.{}", table_name, field_name);
        let mut best_match: Option<SensitivityClassification> = None;

        for (category, patterns) in &self.patterns {
            for pattern in patterns {
                if pattern.regex.is_match(&combined) || pattern.regex.is_match(field_name) {
                    let classification = SensitivityClassification {
                        category: *category,
                        level: pattern.level,
                        confidence: pattern.confidence,
                        matched_patterns: vec![pattern.description.clone()],
                        field_name: field_name.to_string(),
                        table_name: table_name.to_string(),
                    };

                    // Keep highest sensitivity match
                    match &best_match {
                        Some(existing) if existing.level >= classification.level => {}
                        _ => best_match = Some(classification),
                    }
                }
            }
        }

        best_match
    }

    /// Built-in patterns for sensitivity classification.
    pub fn default_patterns() -> Self {
        let mut patterns = FxHashMap::default();

        // Credentials patterns
        patterns.insert(SensitivityCategory::Credentials, vec![
            pattern(r"(?i)(password|passwd|pwd|secret|token|api_key|apikey|auth_token)", SensitivityLevel::Critical, "Authentication credential"),
            pattern(r"(?i)(private_key|secret_key|encryption_key|signing_key)", SensitivityLevel::Critical, "Cryptographic key"),
            pattern(r"(?i)(access_token|refresh_token|bearer|jwt|session_id)", SensitivityLevel::Critical, "Session/token"),
            pattern(r"(?i)(connection_string|database_url|db_password)", SensitivityLevel::Critical, "Connection credential"),
        ]);

        // PII patterns
        patterns.insert(SensitivityCategory::PII, vec![
            pattern(r"(?i)(ssn|social_security|national_id)", SensitivityLevel::Critical, "Government ID"),
            pattern(r"(?i)(email|phone|mobile|telephone)", SensitivityLevel::High, "Contact information"),
            pattern(r"(?i)(first_name|last_name|full_name|surname)", SensitivityLevel::High, "Personal name"),
            pattern(r"(?i)(address|street|city|zip|postal)", SensitivityLevel::High, "Physical address"),
            pattern(r"(?i)(date_of_birth|dob|birthday|birth_date)", SensitivityLevel::High, "Date of birth"),
            pattern(r"(?i)(display_name|username|nickname)", SensitivityLevel::Medium, "Display identifier"),
        ]);

        // Financial patterns
        patterns.insert(SensitivityCategory::Financial, vec![
            pattern(r"(?i)(credit_card|card_number|cvv|cvc|expiry)", SensitivityLevel::Critical, "Payment card"),
            pattern(r"(?i)(bank_account|routing_number|iban|swift)", SensitivityLevel::Critical, "Bank account"),
            pattern(r"(?i)(balance|amount|salary|income|revenue)", SensitivityLevel::High, "Financial amount"),
            pattern(r"(?i)(transaction|payment|invoice|billing)", SensitivityLevel::Medium, "Transaction data"),
        ]);

        // Health patterns
        patterns.insert(SensitivityCategory::Health, vec![
            pattern(r"(?i)(diagnosis|condition|symptom|disease)", SensitivityLevel::Critical, "Medical diagnosis"),
            pattern(r"(?i)(prescription|medication|drug|dosage)", SensitivityLevel::Critical, "Prescription"),
            pattern(r"(?i)(insurance|policy|claim|coverage)", SensitivityLevel::High, "Insurance data"),
            pattern(r"(?i)(blood_type|allergy|medical_record)", SensitivityLevel::High, "Medical record"),
        ]);

        // Infrastructure patterns
        patterns.insert(SensitivityCategory::Infrastructure, vec![
            pattern(r"(?i)(certificate|cert|ca_cert|tls_cert)", SensitivityLevel::Critical, "Certificate"),
            pattern(r"(?i)(aws_access|aws_secret|gcp_key|azure_key)", SensitivityLevel::Critical, "Cloud credential"),
            pattern(r"(?i)(redis_url|mongo_uri|postgres_url|mysql_host)", SensitivityLevel::High, "Service endpoint"),
        ]);

        // Compliance patterns
        patterns.insert(SensitivityCategory::Compliance, vec![
            pattern(r"(?i)(gdpr|consent|data_subject|right_to_delete)", SensitivityLevel::High, "GDPR-regulated"),
            pattern(r"(?i)(hipaa|phi|protected_health)", SensitivityLevel::Critical, "HIPAA-regulated"),
            pattern(r"(?i)(pci|cardholder|pan|primary_account)", SensitivityLevel::Critical, "PCI-DSS-regulated"),
        ]);

        Self { patterns }
    }
}

fn pattern(regex: &str, level: SensitivityLevel, desc: &str) -> SensitivityPattern {
    SensitivityPattern {
        regex: regex::Regex::new(regex).unwrap(),
        category: SensitivityCategory::PII, // Overridden by insert key
        level,
        confidence: 0.85,
        description: desc.to_string(),
    }
}
```

### 11.3 PageRank-Inspired Impact Scoring

Beyond the multi-factor risk score (§7), the enrichment pipeline computes a
PageRank-inspired "importance" score for each function. Functions called by many
important functions are themselves important — this captures transitive importance
that simple caller counting misses.

```rust
impl<'a> EnrichmentPipeline<'a> {
    /// Compute PageRank-inspired impact score for a function.
    /// Functions called by important functions are themselves important.
    pub fn compute_pagerank_score(
        &self,
        function_id: &str,
        iterations: u32,
        damping: f64,
    ) -> f64 {
        let n = self.graph.graph.node_count() as f64;
        if n == 0.0 {
            return 0.0;
        }

        // Initialize all scores to 1/N
        let mut scores: FxHashMap<NodeIndex, f64> = self.graph.graph
            .node_indices()
            .map(|idx| (idx, 1.0 / n))
            .collect();

        // Iterate PageRank
        for _ in 0..iterations {
            let mut new_scores: FxHashMap<NodeIndex, f64> = self.graph.graph
                .node_indices()
                .map(|idx| (idx, (1.0 - damping) / n))
                .collect();

            for node in self.graph.graph.node_indices() {
                let out_degree = self.graph.graph.edges(node).count() as f64;
                if out_degree == 0.0 {
                    continue;
                }

                let share = scores[&node] / out_degree;
                for edge in self.graph.graph.edges(node) {
                    let target = edge.target();
                    *new_scores.entry(target).or_insert(0.0) += damping * share;
                }
            }

            scores = new_scores;
        }

        // Return score for the target function
        if let Some(node_idx) = self.graph.find_node(function_id) {
            // Normalize to 0-100 scale
            let max_score = scores.values().cloned().fold(0.0f64, f64::max);
            if max_score > 0.0 {
                (scores[&node_idx] / max_score) * 100.0
            } else {
                0.0
            }
        } else {
            0.0
        }
    }
}
```

### 11.4 Remediation Suggestion Generation

The remediation generator produces actionable suggestions based on the impact analysis.
V1 used heuristic suggestions. V2 preserves heuristics and adds structured remediation
with priority ordering.

```rust
impl ImpactEngine {
    /// Generate remediation suggestions based on impact analysis.
    pub fn generate_remediation(
        &self,
        function_id: &str,
        blast_radius: &BlastRadius,
        risk_score: &RiskScore,
    ) -> Vec<RemediationSuggestion> {
        let mut suggestions = Vec::new();
        let mut priority = 1u32;

        // High structural risk → suggest adding tests
        if risk_score.structural > 60.0 {
            suggestions.push(RemediationSuggestion {
                priority,
                action: "Add integration tests for this function and its callers".into(),
                reason: format!(
                    "This function has {} direct callers and {} transitive callers. \
                     Changes here have a wide blast radius.",
                    blast_radius.direct_count, blast_radius.transitive_count
                ),
                affected_functions: blast_radius.direct_callers
                    .iter()
                    .take(5)
                    .map(|c| c.function_id.clone())
                    .collect(),
            });
            priority += 1;
        }

        // High entry point risk → suggest careful review
        if risk_score.entry_point > 50.0 {
            suggestions.push(RemediationSuggestion {
                priority,
                action: "Review all affected entry points before deploying".into(),
                reason: "Changes to this function affect user-facing endpoints.".into(),
                affected_functions: Vec::new(),
            });
            priority += 1;
        }

        // High data risk → suggest data migration review
        if risk_score.data > 50.0 {
            suggestions.push(RemediationSuggestion {
                priority,
                action: "Verify data access patterns are preserved after changes".into(),
                reason: "This function accesses sensitive data. Changes may affect \
                         data integrity or security.".into(),
                affected_functions: Vec::new(),
            });
            priority += 1;
        }

        // High taint risk → suggest security review
        if risk_score.taint > 40.0 {
            suggestions.push(RemediationSuggestion {
                priority,
                action: "Run taint analysis to verify no new unsanitized data flows".into(),
                reason: "This function is on a taint path. Changes may introduce \
                         security vulnerabilities.".into(),
                affected_functions: Vec::new(),
            });
            priority += 1;
        }

        // High coverage risk → suggest adding tests first
        if risk_score.coverage > 60.0 {
            suggestions.push(RemediationSuggestion {
                priority,
                action: "Add test coverage before making changes".into(),
                reason: "This function has insufficient test coverage. Adding tests \
                         first ensures changes don't introduce regressions.".into(),
                affected_functions: Vec::new(),
            });
        }

        suggestions
    }
}
```


---

## 12. Incremental Impact Analysis

### 12.1 Design

V1 recomputed impact from scratch on every query. V2 uses incremental invalidation:
when functions change, only their impact results and the impact results of their
transitive callers are invalidated. Everything else is served from cache.

```rust
/// Incremental impact invalidation engine.
pub struct IncrementalImpact {
    /// LRU cache of impact results.
    cache: Mutex<LruCache<String, ImpactResult>>,
    /// Set of function IDs whose impact results are stale.
    stale: Mutex<FxHashSet<String>>,
}

impl IncrementalImpact {
    /// Invalidate impact results for changed functions and their transitive callers.
    /// Called after a scan detects file changes.
    pub fn invalidate(
        &self,
        graph: &CallGraph,
        changed_functions: &[String],
    ) {
        let mut stale = self.stale.lock().unwrap();
        let mut cache = self.cache.lock().unwrap();

        for func_id in changed_functions {
            // Invalidate the changed function itself
            stale.insert(func_id.clone());
            cache.pop(func_id);

            // Invalidate all transitive callers (reverse BFS)
            if let Some(node_idx) = graph.find_node(func_id) {
                let mut visited = FxHashSet::default();
                let mut queue = VecDeque::new();
                queue.push_back(node_idx);

                while let Some(current) = queue.pop_front() {
                    for edge in graph.graph.edges_directed(
                        current, petgraph::Direction::Incoming
                    ) {
                        let caller = edge.source();
                        if visited.insert(caller) {
                            let caller_id = graph.node_id(caller).to_string();
                            stale.insert(caller_id.clone());
                            cache.pop(&caller_id);
                            queue.push_back(caller);
                        }
                    }
                }
            }
        }

        tracing::info!(
            changed = changed_functions.len(),
            invalidated = stale.len(),
            "Impact cache invalidated"
        );
    }

    /// Check if a function's impact result is fresh (not stale).
    pub fn is_fresh(&self, function_id: &str) -> bool {
        !self.stale.lock().unwrap().contains(function_id)
    }

    /// Get cached impact result if fresh.
    pub fn get_cached(&self, function_id: &str) -> Option<ImpactResult> {
        if self.is_fresh(function_id) {
            self.cache.lock().unwrap().get(function_id).cloned()
        } else {
            None
        }
    }

    /// Store a freshly computed impact result.
    pub fn store(&self, function_id: &str, result: ImpactResult) {
        self.stale.lock().unwrap().remove(function_id);
        self.cache.lock().unwrap().put(function_id.to_string(), result);
    }
}
```

### 12.2 Integration with Scan Pipeline

```rust
impl ImpactEngine {
    /// Analyze impact with incremental caching.
    pub fn analyze_impact_incremental(
        &self,
        function_id: &str,
    ) -> Result<ImpactResult, ImpactError> {
        // Check incremental cache first
        if let Some(cached) = self.incremental.get_cached(function_id) {
            tracing::debug!(function_id, "Impact cache hit");
            return Ok(cached);
        }

        // Cache miss — compute fresh
        tracing::debug!(function_id, "Impact cache miss, computing");
        let result = self.analyze_impact(function_id)?;

        // Store in cache
        self.incremental.store(function_id, result.clone());

        Ok(result)
    }
}
```

---

## 13. Integration with Taint Analysis

### 13.1 Taint-Enriched Impact

The impact engine consumes taint analysis results to enrich risk scoring.
Functions with unsanitized taint flows through them receive higher risk scores.

Per 15-TAINT-ANALYSIS-V2-PREP.md: the taint engine produces `TaintSummary` per
function, containing `param_to_return` and `param_to_sink` flows. The impact engine
reads these summaries to compute the taint factor of the risk score.

```rust
/// Taint risk information for a function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintRisk {
    /// Number of unsanitized taint flows through this function.
    pub unsanitized_flow_count: usize,
    /// Number of sanitized taint flows through this function.
    pub sanitized_flow_count: usize,
    /// Highest severity CWE reachable through this function.
    pub highest_cwe: Option<u32>,
    /// Sink types reachable from this function.
    pub reachable_sink_types: Vec<String>,
    /// Taint risk score (0-100).
    pub taint_score: f64,
}

impl ImpactEngine {
    /// Compute taint risk for a function.
    pub fn compute_taint_risk(&self, function_id: &str) -> Option<TaintRisk> {
        let summaries = self.taint_summaries.as_ref()?;
        let summary = summaries.get(function_id)?;

        let unsanitized_count = summary.param_to_sink.iter()
            .filter(|f| !f.is_sanitized)
            .count();

        let sanitized_count = summary.param_to_sink.iter()
            .filter(|f| f.is_sanitized)
            .count();

        let highest_cwe = summary.param_to_sink.iter()
            .filter(|f| !f.is_sanitized)
            .flat_map(|f| &f.sink.cwe_ids)
            .min()  // Lower CWE numbers tend to be more severe
            .copied();

        let reachable_sink_types: Vec<String> = summary.param_to_sink.iter()
            .map(|f| format!("{:?}", f.sink.sink_type))
            .collect::<FxHashSet<_>>()
            .into_iter()
            .collect();

        // Score: more unsanitized flows and more severe sinks = higher score
        let mut taint_score = 0.0;
        for flow in &summary.param_to_sink {
            if !flow.is_sanitized {
                let sink_weight = match flow.sink.sink_type {
                    SinkType::SqlQuery | SinkType::OsCommand | SinkType::CodeExecution => 40.0,
                    SinkType::HtmlOutput | SinkType::HttpRequest => 25.0,
                    SinkType::Deserialization => 30.0,
                    SinkType::FileWrite | SinkType::FileRead => 20.0,
                    _ => 15.0,
                };
                taint_score += sink_weight;
            }
        }

        Some(TaintRisk {
            unsanitized_flow_count: unsanitized_count,
            sanitized_flow_count: sanitized_count,
            highest_cwe,
            reachable_sink_types,
            taint_score: taint_score.min(100.0),
        })
    }
}
```

### 13.2 Bidirectional Integration

The integration is bidirectional:
- **Impact → Taint**: Impact analysis uses taint summaries to enrich risk scores (§7.2)
- **Taint → Impact**: Taint analysis uses blast radius to prioritize which taint flows
  to report first (flows through high-impact functions are reported with higher priority)

```rust
/// Prioritize taint flows by impact.
/// Flows through high-impact functions are reported first.
pub fn prioritize_taint_by_impact(
    flows: &mut Vec<TaintFlow>,
    impact_engine: &ImpactEngine,
) {
    // Compute impact score for each function in the taint flows
    let mut impact_cache: FxHashMap<String, f64> = FxHashMap::default();

    for flow in flows.iter() {
        for step in &flow.path {
            if !impact_cache.contains_key(&step.function_id) {
                let score = impact_engine
                    .analyze_impact(&step.function_id)
                    .map(|r| r.risk_score.total)
                    .unwrap_or(0.0);
                impact_cache.insert(step.function_id.clone(), score);
            }
        }
    }

    // Sort flows by maximum impact score along their path
    flows.sort_by(|a, b| {
        let a_max = a.path.iter()
            .filter_map(|s| impact_cache.get(&s.function_id))
            .cloned()
            .fold(0.0f64, f64::max);
        let b_max = b.path.iter()
            .filter_map(|s| impact_cache.get(&s.function_id))
            .cloned()
            .fold(0.0f64, f64::max);
        b_max.partial_cmp(&a_max).unwrap_or(std::cmp::Ordering::Equal)
    });
}
```

---

## 14. Integration with Test Topology

### 14.1 Test Coverage Map Construction

The test topology engine (separate system) produces a mapping of which test functions
cover which production functions. The impact engine consumes this to compute the
coverage factor of the risk score.

```rust
/// Test coverage information consumed by the impact engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCoverage {
    /// Test functions that directly test this function.
    pub direct_tests: Vec<String>,
    /// Test functions that transitively cover this function.
    pub transitive_tests: Vec<String>,
    /// Coverage ratio (0.0 - 1.0).
    pub coverage_ratio: f64,
}

impl ImpactEngine {
    /// Compute test coverage for a function.
    pub fn compute_test_coverage(&self, function_id: &str) -> Option<TestCoverage> {
        let coverage_map = self.test_coverage.as_ref()?;
        let cov = coverage_map.get(function_id)?;

        Some(TestCoverage {
            direct_tests: cov.covering_tests.iter()
                .filter(|t| self.is_direct_test(t, function_id))
                .cloned()
                .collect(),
            transitive_tests: cov.covering_tests.clone(),
            coverage_ratio: cov.coverage_ratio,
        })
    }

    /// Check if a test directly tests a function (calls it directly).
    fn is_direct_test(&self, test_id: &str, function_id: &str) -> bool {
        if let (Some(test_idx), Some(func_idx)) = (
            self.graph.find_node(test_id),
            self.graph.find_node(function_id),
        ) {
            // Check if there's a direct edge from test to function
            self.graph.graph.find_edge(test_idx, func_idx).is_some()
        } else {
            false
        }
    }

    /// Recommend tests to run for a set of affected functions.
    pub fn recommend_tests(
        &self,
        affected_functions: &FxHashSet<String>,
    ) -> Vec<String> {
        let coverage_map = match &self.test_coverage {
            Some(c) => c,
            None => return Vec::new(),
        };

        let mut recommended_tests = FxHashSet::default();

        for func_id in affected_functions {
            if let Some(cov) = coverage_map.get(func_id) {
                for test in &cov.covering_tests {
                    recommended_tests.insert(test.clone());
                }
            }
        }

        let mut tests: Vec<String> = recommended_tests.into_iter().collect();
        tests.sort();
        tests
    }
}
```

### 14.2 Coverage Gap Detection

When the impact engine identifies functions in the blast radius that have no test
coverage, it flags these as coverage gaps — areas where changes are risky because
there are no tests to catch regressions.

```rust
/// A coverage gap: a function in the blast radius with no test coverage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageGap {
    pub function_id: String,
    pub file: String,
    pub line: u32,
    /// Why this gap is concerning.
    pub reason: String,
    /// Risk score for this gap.
    pub risk: f64,
}

impl ImpactEngine {
    /// Find coverage gaps in the blast radius.
    pub fn find_coverage_gaps(
        &self,
        blast_radius: &BlastRadius,
    ) -> Vec<CoverageGap> {
        let coverage_map = match &self.test_coverage {
            Some(c) => c,
            None => return Vec::new(),
        };

        let mut gaps = Vec::new();

        for caller_id in &blast_radius.transitive_callers {
            let has_coverage = coverage_map.get(caller_id)
                .map(|c| c.coverage_ratio > 0.0)
                .unwrap_or(false);

            if !has_coverage {
                if let Some(node_idx) = self.graph.find_node(caller_id) {
                    let node = &self.graph.graph[node_idx];
                    let file = self.graph.interner.resolve(&node.file).to_string();

                    let reason = if node.is_entry_point {
                        "Entry point in blast radius with no test coverage".into()
                    } else {
                        "Function in blast radius with no test coverage".into()
                    };

                    let risk = if node.is_entry_point { 80.0 } else { 50.0 };

                    gaps.push(CoverageGap {
                        function_id: caller_id.clone(),
                        file,
                        line: node.line,
                        reason,
                        risk,
                    });
                }
            }
        }

        gaps.sort_by(|a, b| {
            b.risk.partial_cmp(&a.risk).unwrap_or(std::cmp::Ordering::Equal)
        });

        gaps
    }
}
```


---

## 15. Storage Schema

### 15.1 Impact Tables in drift.db

```sql
-- Impact analysis results (primary output)
CREATE TABLE IF NOT EXISTS impact_results (
    function_id TEXT PRIMARY KEY,
    blast_radius_json TEXT NOT NULL,       -- JSON: BlastRadius
    entry_points_json TEXT NOT NULL,       -- JSON: Vec<EntryPointImpact>
    data_paths_json TEXT NOT NULL,         -- JSON: Vec<DataPathImpact>
    risk_score_total REAL NOT NULL,
    risk_score_structural REAL NOT NULL,
    risk_score_entry_point REAL NOT NULL,
    risk_score_data REAL NOT NULL,
    risk_score_taint REAL NOT NULL,
    risk_score_coverage REAL NOT NULL,
    risk_level TEXT NOT NULL,              -- 'critical', 'high', 'medium', 'low'
    risk_explanation TEXT NOT NULL,
    remediation_json TEXT,                 -- JSON: Vec<RemediationSuggestion>
    taint_risk_json TEXT,                  -- JSON: TaintRisk (nullable)
    test_coverage_json TEXT,               -- JSON: TestCoverage (nullable)
    direct_caller_count INTEGER NOT NULL,
    transitive_caller_count INTEGER NOT NULL,
    max_depth INTEGER NOT NULL,
    affected_files INTEGER NOT NULL,
    affected_modules INTEGER NOT NULL,
    computed_at TEXT NOT NULL DEFAULT (datetime('now')),
    scan_id TEXT                           -- Links to scan that produced this result
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_impact_risk_level ON impact_results(risk_level);
CREATE INDEX IF NOT EXISTS idx_impact_risk_total ON impact_results(risk_score_total);
CREATE INDEX IF NOT EXISTS idx_impact_caller_count ON impact_results(transitive_caller_count);
CREATE INDEX IF NOT EXISTS idx_impact_scan ON impact_results(scan_id);

-- Dead code candidates
CREATE TABLE IF NOT EXISTS dead_code_candidates (
    function_id TEXT PRIMARY KEY,
    file TEXT NOT NULL,
    line INTEGER NOT NULL,
    end_line INTEGER NOT NULL,
    language TEXT NOT NULL,
    confidence REAL NOT NULL,
    false_positive_reasons TEXT NOT NULL,  -- JSON: Vec<FalsePositiveReason>
    is_exported INTEGER NOT NULL DEFAULT 0,
    loc INTEGER NOT NULL,
    computed_at TEXT NOT NULL DEFAULT (datetime('now')),
    scan_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_dead_code_confidence ON dead_code_candidates(confidence);
CREATE INDEX IF NOT EXISTS idx_dead_code_file ON dead_code_candidates(file);
CREATE INDEX IF NOT EXISTS idx_dead_code_loc ON dead_code_candidates(loc);

-- Coverage gaps
CREATE TABLE IF NOT EXISTS coverage_gaps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    function_id TEXT NOT NULL,
    file TEXT NOT NULL,
    line INTEGER NOT NULL,
    reason TEXT NOT NULL,
    risk REAL NOT NULL,
    is_entry_point INTEGER NOT NULL DEFAULT 0,
    computed_at TEXT NOT NULL DEFAULT (datetime('now')),
    scan_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_coverage_gaps_risk ON coverage_gaps(risk);
CREATE INDEX IF NOT EXISTS idx_coverage_gaps_function ON coverage_gaps(function_id);

-- Change impact results (for multi-function change analysis)
CREATE TABLE IF NOT EXISTS change_impact_results (
    id TEXT PRIMARY KEY,
    changed_functions_json TEXT NOT NULL,  -- JSON: Vec<String>
    aggregate_risk_score REAL NOT NULL,
    aggregate_risk_level TEXT NOT NULL,
    total_affected_functions INTEGER NOT NULL,
    recommended_tests_json TEXT,           -- JSON: Vec<String>
    overlap_zones_json TEXT,               -- JSON: Vec<OverlapZone>
    computed_at TEXT NOT NULL DEFAULT (datetime('now')),
    scan_id TEXT
);
```

### 15.2 Materialized View: Impact Summary

```sql
-- Materialized view for quick impact summary queries
CREATE TABLE IF NOT EXISTS impact_summary_mv (
    id INTEGER PRIMARY KEY,
    total_functions INTEGER NOT NULL,
    critical_risk_count INTEGER NOT NULL,
    high_risk_count INTEGER NOT NULL,
    medium_risk_count INTEGER NOT NULL,
    low_risk_count INTEGER NOT NULL,
    dead_code_count INTEGER NOT NULL,
    dead_code_total_loc INTEGER NOT NULL,
    coverage_gap_count INTEGER NOT NULL,
    avg_risk_score REAL NOT NULL,
    max_risk_score REAL NOT NULL,
    last_computed TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Refresh materialized view
-- Called after impact analysis completes
INSERT OR REPLACE INTO impact_summary_mv (id, total_functions, critical_risk_count,
    high_risk_count, medium_risk_count, low_risk_count, dead_code_count,
    dead_code_total_loc, coverage_gap_count, avg_risk_score, max_risk_score)
SELECT
    1,
    COUNT(*),
    SUM(CASE WHEN risk_level = 'critical' THEN 1 ELSE 0 END),
    SUM(CASE WHEN risk_level = 'high' THEN 1 ELSE 0 END),
    SUM(CASE WHEN risk_level = 'medium' THEN 1 ELSE 0 END),
    SUM(CASE WHEN risk_level = 'low' THEN 1 ELSE 0 END),
    (SELECT COUNT(*) FROM dead_code_candidates),
    (SELECT COALESCE(SUM(loc), 0) FROM dead_code_candidates),
    (SELECT COUNT(*) FROM coverage_gaps),
    AVG(risk_score_total),
    MAX(risk_score_total)
FROM impact_results;
```

### 15.3 Persistence Implementation

```rust
impl ImpactEngine {
    /// Persist impact results to drift.db.
    pub fn persist_results(
        &self,
        results: &[ImpactResult],
    ) -> Result<(), ImpactError> {
        let batch = self.db.batch_writer("impact_results")?;

        for result in results {
            batch.insert(
                &result.function_id,
                &serde_json::to_string(&result.blast_radius)?,
                &serde_json::to_string(&result.affected_entry_points)?,
                &serde_json::to_string(&result.affected_data_paths)?,
                result.risk_score.total,
                result.risk_score.structural,
                result.risk_score.entry_point,
                result.risk_score.data,
                result.risk_score.taint,
                result.risk_score.coverage,
                &format!("{:?}", result.risk_level).to_lowercase(),
                &result.risk_score.explanation,
                &serde_json::to_string(&result.remediation)?,
                &result.taint_risk.as_ref().map(|t| serde_json::to_string(t).ok()).flatten(),
                &result.test_coverage.as_ref().map(|t| serde_json::to_string(t).ok()).flatten(),
                result.blast_radius.direct_count as i64,
                result.blast_radius.transitive_count as i64,
                result.blast_radius.max_depth as i64,
                result.blast_radius.affected_files as i64,
                result.blast_radius.affected_modules as i64,
            )?;
        }

        batch.flush()?;

        // Refresh materialized view
        self.db.execute_raw(include_str!("sql/refresh_impact_summary.sql"))?;

        tracing::info!(
            results = results.len(),
            "Impact results persisted to drift.db"
        );

        Ok(())
    }

    /// Persist dead code candidates to drift.db.
    pub fn persist_dead_code(
        &self,
        candidates: &[DeadCodeCandidate],
    ) -> Result<(), ImpactError> {
        let batch = self.db.batch_writer("dead_code_candidates")?;

        for candidate in candidates {
            batch.insert(
                &candidate.function_id,
                &candidate.file,
                candidate.line as i64,
                candidate.end_line as i64,
                &format!("{:?}", candidate.language).to_lowercase(),
                candidate.confidence,
                &serde_json::to_string(&candidate.false_positive_reasons)?,
                candidate.is_exported as i64,
                candidate.loc as i64,
            )?;
        }

        batch.flush()?;

        tracing::info!(
            candidates = candidates.len(),
            "Dead code candidates persisted to drift.db"
        );

        Ok(())
    }
}
```

---

## 16. NAPI Interface

Per 03-NAPI-BRIDGE-V2-PREP.md §10.6:

```rust
/// Analyze impact of changing a specific function.
#[napi]
pub fn analyze_impact(options: ImpactAnalysisOptions) -> AsyncTask<ImpactAnalysisTask> {
    AsyncTask::new(ImpactAnalysisTask { options })
}

#[napi(object)]
pub struct ImpactAnalysisOptions {
    /// Root directory of the project.
    pub root: String,
    /// Function ID to analyze.
    pub function_id: String,
    /// Whether to include taint-enriched risk scoring.
    pub include_taint: Option<bool>,
    /// Whether to include test coverage data.
    pub include_coverage: Option<bool>,
}

#[napi(object)]
pub struct JsImpactResult {
    pub function_id: String,
    pub blast_radius: JsBlastRadius,
    pub affected_entry_points: Vec<JsEntryPointImpact>,
    pub affected_data_paths: Vec<JsDataPathImpact>,
    pub risk_score: JsRiskScore,
    pub risk_level: String,
    pub remediation: Vec<JsRemediationSuggestion>,
    pub taint_risk: Option<JsTaintRisk>,
    pub test_coverage: Option<JsTestCoverage>,
}

#[napi(object)]
pub struct JsBlastRadius {
    pub direct_callers: Vec<JsCallerInfo>,
    pub transitive_caller_count: u32,
    pub max_depth: u32,
    pub affected_files: u32,
    pub affected_modules: u32,
}

#[napi(object)]
pub struct JsRiskScore {
    pub total: f64,
    pub structural: f64,
    pub entry_point: f64,
    pub data: f64,
    pub taint: f64,
    pub coverage: f64,
    pub explanation: String,
}

/// Detect dead code in the project.
#[napi]
pub fn find_dead_code(options: DeadCodeOptions) -> AsyncTask<DeadCodeTask> {
    AsyncTask::new(DeadCodeTask { options })
}

#[napi(object)]
pub struct DeadCodeOptions {
    /// Root directory of the project.
    pub root: String,
    /// Minimum confidence threshold (0.0 - 1.0).
    pub min_confidence: Option<f64>,
    /// Whether to include exported functions.
    pub include_exported: Option<bool>,
    /// Maximum number of candidates to return.
    pub limit: Option<u32>,
}

#[napi(object)]
pub struct JsDeadCodeResult {
    pub candidates: Vec<JsDeadCodeCandidate>,
    pub total_dead_loc: u32,
    pub total_candidates: u32,
}

/// Find paths between two functions.
#[napi]
pub fn find_path(options: PathOptions) -> AsyncTask<PathTask> {
    AsyncTask::new(PathTask { options })
}

#[napi(object)]
pub struct PathOptions {
    /// Root directory of the project.
    pub root: String,
    /// Source function ID.
    pub from: String,
    /// Target function ID.
    pub to: String,
    /// Maximum path depth.
    pub max_depth: Option<u32>,
    /// Maximum number of paths to return.
    pub max_paths: Option<u32>,
}

/// Analyze impact of multiple changed functions (batch).
#[napi]
pub fn analyze_changes(options: ChangeAnalysisOptions) -> AsyncTask<ChangeAnalysisTask> {
    AsyncTask::new(ChangeAnalysisTask { options })
}

#[napi(object)]
pub struct ChangeAnalysisOptions {
    /// Root directory of the project.
    pub root: String,
    /// List of changed function IDs.
    pub changed_functions: Vec<String>,
    /// Whether to include taint-enriched risk scoring.
    pub include_taint: Option<bool>,
}

/// Analyze test coverage across the call graph.
#[napi]
pub fn analyze_coverage(options: CoverageOptions) -> AsyncTask<CoverageTask> {
    AsyncTask::new(CoverageTask { options })
}

#[napi(object)]
pub struct CoverageOptions {
    /// Root directory of the project.
    pub root: String,
    /// Whether to include only sensitive uncovered paths.
    pub sensitive_only: Option<bool>,
}
```

---

## 17. MCP Tool Interface

Per .research/21-security/RECOMMENDATIONS.md and 03-NAPI-BRIDGE-V2-PREP.md:

```typescript
// drift_impact_analysis — Analyze change impact
{
    name: "drift_impact_analysis",
    description: "Analyze the impact of changing a function. Returns blast radius, \
                  affected entry points, risk score, and remediation suggestions.",
    parameters: {
        function_id: {
            type: "string",
            required: true,
            description: "Function ID to analyze (e.g., 'UserService.getUser')"
        },
        include_taint: {
            type: "boolean",
            optional: true,
            default: true,
            description: "Include taint-enriched risk scoring"
        },
        include_coverage: {
            type: "boolean",
            optional: true,
            default: true,
            description: "Include test coverage data"
        },
    },
    returns: "ImpactResult with blast radius, risk score, entry points, remediation"
}

// drift_dead_code — Detect dead code
{
    name: "drift_dead_code",
    description: "Detect potentially dead (unreachable) code in the project. \
                  Returns candidates with confidence scores and false positive analysis.",
    parameters: {
        min_confidence: {
            type: "number",
            optional: true,
            default: 0.5,
            description: "Minimum confidence threshold (0.0 - 1.0)"
        },
        include_exported: {
            type: "boolean",
            optional: true,
            default: false,
            description: "Include exported functions (may be used externally)"
        },
        limit: {
            type: "number",
            optional: true,
            default: 50,
            description: "Maximum number of candidates to return"
        },
    },
    returns: "Array of DeadCodeCandidate with confidence and false positive reasons"
}

// drift_path — Find paths between functions
{
    name: "drift_path",
    description: "Find all call paths between two functions. Returns paths with \
                  confidence scores and metadata.",
    parameters: {
        from: {
            type: "string",
            required: true,
            description: "Source function ID"
        },
        to: {
            type: "string",
            required: true,
            description: "Target function ID"
        },
        max_depth: {
            type: "number",
            optional: true,
            default: 15,
            description: "Maximum path depth"
        },
    },
    returns: "Array of FunctionPath with nodes, confidence, and metadata"
}

// drift_change_impact — Analyze impact of multiple changes
{
    name: "drift_change_impact",
    description: "Analyze the combined impact of multiple function changes. \
                  Identifies overlap zones where changes compound risk.",
    parameters: {
        changed_functions: {
            type: "array",
            items: { type: "string" },
            required: true,
            description: "List of changed function IDs"
        },
    },
    returns: "ChangeImpactResult with aggregate risk, overlap zones, recommended tests"
}

// drift_coverage_gaps — Find test coverage gaps
{
    name: "drift_coverage_gaps",
    description: "Find functions and data paths with no test coverage. \
                  Prioritizes sensitive uncovered paths.",
    parameters: {
        sensitive_only: {
            type: "boolean",
            optional: true,
            default: false,
            description: "Only show sensitive uncovered paths"
        },
    },
    returns: "CoverageAnalysisResult with uncovered functions, data paths, and stats"
}
```

---

## 18. CLI Interface

```
drift impact [SUBCOMMAND] [OPTIONS]

SUBCOMMANDS:
    analyze     Analyze impact of changing a function
    changes     Analyze impact of multiple changed functions
    dead-code   Detect dead code
    path        Find paths between two functions
    coverage    Analyze test coverage gaps

drift impact analyze <FUNCTION_ID> [OPTIONS]
    --root <PATH>           Project root (default: current directory)
    --include-taint         Include taint-enriched risk scoring (default: true)
    --include-coverage      Include test coverage data (default: true)
    --format <FORMAT>       Output format (table, json, sarif)
    --output <FILE>         Write output to file

drift impact changes [OPTIONS]
    --root <PATH>           Project root
    --functions <IDS>       Comma-separated function IDs
    --git-diff              Auto-detect changed functions from git diff
    --base <REF>            Git base ref for diff (default: HEAD~1)
    --format <FORMAT>       Output format (table, json)

drift impact dead-code [OPTIONS]
    --root <PATH>           Project root
    --min-confidence <N>    Minimum confidence (0.0-1.0, default: 0.5)
    --include-exported      Include exported functions
    --limit <N>             Maximum candidates (default: 50)
    --format <FORMAT>       Output format (table, json)

drift impact path <FROM> <TO> [OPTIONS]
    --root <PATH>           Project root
    --max-depth <N>         Maximum path depth (default: 15)
    --max-paths <N>         Maximum paths to return (default: 20)
    --format <FORMAT>       Output format (table, json)

drift impact coverage [OPTIONS]
    --root <PATH>           Project root
    --sensitive-only        Only show sensitive uncovered paths
    --format <FORMAT>       Output format (table, json)

EXAMPLES:
    drift impact analyze UserService.getUser
    drift impact changes --git-diff --base main
    drift impact dead-code --min-confidence 0.7
    drift impact path handleLogin db.query
    drift impact coverage --sensitive-only
```


---

## 19. Tracing & Observability

```rust
impl ImpactEngine {
    pub fn analyze_impact(
        &self,
        function_id: &str,
    ) -> Result<ImpactResult, ImpactError> {
        let span = tracing::info_span!("impact_analysis",
            function_id = function_id,
        );
        let _guard = span.enter();

        let start = std::time::Instant::now();

        // Check cache
        if let Some(cached) = self.cache.lock().unwrap().get(function_id) {
            tracing::debug!("Impact cache hit");
            return Ok(cached.clone());
        }

        let node_idx = self.graph.find_node(function_id)
            .ok_or(ImpactError::FunctionNotFound(function_id.to_string()))?;

        // Step 1: Blast radius
        let blast_span = tracing::debug_span!("blast_radius");
        let _blast_guard = blast_span.enter();
        let blast_radius = self.compute_blast_radius(node_idx)?;
        tracing::debug!(
            direct = blast_radius.direct_count,
            transitive = blast_radius.transitive_count,
            depth = blast_radius.max_depth,
            files = blast_radius.affected_files,
            "Blast radius computed"
        );
        drop(_blast_guard);

        // Step 2: Entry points
        let ep_span = tracing::debug_span!("entry_points");
        let _ep_guard = ep_span.enter();
        let affected_entry_points = self.find_affected_entry_points(&blast_radius);
        tracing::debug!(
            entry_points = affected_entry_points.len(),
            "Entry points identified"
        );
        drop(_ep_guard);

        // Step 3: Data paths
        let dp_span = tracing::debug_span!("data_paths");
        let _dp_guard = dp_span.enter();
        let affected_data_paths = self.find_affected_data_paths(node_idx)?;
        tracing::debug!(
            data_paths = affected_data_paths.len(),
            "Data paths identified"
        );
        drop(_dp_guard);

        // Step 4: Risk score
        let risk_score = self.compute_risk_score(
            &blast_radius,
            &affected_entry_points,
            &affected_data_paths,
            function_id,
        );

        // Step 5: Remediation
        let remediation = self.generate_remediation(
            function_id,
            &blast_radius,
            &risk_score,
        );

        let result = ImpactResult {
            function_id: function_id.to_string(),
            blast_radius,
            affected_entry_points,
            affected_data_paths,
            risk_score: risk_score.clone(),
            risk_level: RiskLevel::from_score(risk_score.total),
            remediation,
            taint_risk: self.compute_taint_risk(function_id),
            test_coverage: self.compute_test_coverage(function_id),
        };

        // Cache result
        self.cache.lock().unwrap().put(function_id.to_string(), result.clone());

        tracing::info!(
            risk_level = ?result.risk_level,
            risk_score = format!("{:.1}", risk_score.total),
            direct_callers = result.blast_radius.direct_count,
            transitive_callers = result.blast_radius.transitive_count,
            entry_points = result.affected_entry_points.len(),
            data_paths = result.affected_data_paths.len(),
            duration_ms = start.elapsed().as_millis(),
            "Impact analysis complete"
        );

        Ok(result)
    }
}

impl<'a> DeadCodeEngine<'a> {
    pub fn detect_with_tracing(&self) -> Result<Vec<DeadCodeCandidate>, ImpactError> {
        let span = tracing::info_span!("dead_code_detection");
        let _guard = span.enter();

        let start = std::time::Instant::now();
        let candidates = self.detect()?;

        tracing::info!(
            total_candidates = candidates.len(),
            high_confidence = candidates.iter().filter(|c| c.confidence > 0.8).count(),
            total_dead_loc = candidates.iter().map(|c| c.loc as u64).sum::<u64>(),
            duration_ms = start.elapsed().as_millis(),
            "Dead code detection complete"
        );

        Ok(candidates)
    }
}
```

---

## 20. Performance Targets & Benchmarks

| Metric | Target | Rationale |
|--------|--------|-----------|
| Single function impact analysis | <50ms | IDE integration requires sub-100ms |
| Blast radius (10K function graph) | <100ms | Reverse BFS is O(V+E) |
| Dead code detection (10K functions) | <200ms | Single forward BFS from entry points |
| Path finding (depth 15) | <500ms | petgraph all_simple_paths with limit |
| Coverage analysis (10K functions) | <1s | Single pass through function set |
| Change propagation (10 functions) | <500ms | 10 × blast radius + overlap |
| Risk scoring per function | <1ms | Arithmetic on pre-computed data |
| Enrichment pipeline (PageRank, 20 iterations) | <5s | O(iterations × edges) |
| Incremental invalidation (10 changed files) | <10ms | Reverse BFS for invalidation |
| Persistence (1000 results) | <500ms | Batch writer to drift.db |
| Impact summary materialized view refresh | <100ms | Single aggregate query |
| Memory: impact cache (1000 entries) | <50MB | LRU with bounded size |
| Memory: dead code candidates (10K) | <10MB | Compact struct per candidate |

### Benchmark Strategy

```rust
#[cfg(test)]
mod benchmarks {
    use criterion::{criterion_group, criterion_main, Criterion};

    fn bench_blast_radius(c: &mut Criterion) {
        // Benchmark reverse BFS on a 10K node graph
        // Target: <100ms
        c.bench_function("blast_radius_10k", |b| {
            let graph = create_test_graph(10_000, 50_000);
            let engine = ImpactEngine::new(graph);
            let target = graph.random_node();
            b.iter(|| engine.compute_blast_radius(target))
        });
    }

    fn bench_dead_code(c: &mut Criterion) {
        // Benchmark dead code detection on a 10K node graph
        // Target: <200ms
        c.bench_function("dead_code_10k", |b| {
            let graph = create_test_graph(10_000, 50_000);
            let engine = DeadCodeEngine::new(&graph);
            b.iter(|| engine.detect())
        });
    }

    fn bench_path_finding(c: &mut Criterion) {
        // Benchmark path finding between two nodes
        // Target: <500ms
        c.bench_function("path_finding_depth15", |b| {
            let graph = create_test_graph(10_000, 50_000);
            let finder = PathFinder::new(&graph);
            let (from, to) = graph.random_pair();
            b.iter(|| finder.find_paths(&from, &to))
        });
    }

    fn bench_risk_scoring(c: &mut Criterion) {
        // Benchmark risk score computation
        // Target: <1ms
        c.bench_function("risk_scoring", |b| {
            let engine = create_test_engine();
            let blast = create_test_blast_radius();
            let eps = create_test_entry_points();
            let dps = create_test_data_paths();
            b.iter(|| engine.compute_risk_score(&blast, &eps, &dps, "test_func"))
        });
    }

    fn bench_pagerank(c: &mut Criterion) {
        // Benchmark PageRank computation
        // Target: <5s for 10K nodes, 20 iterations
        c.bench_function("pagerank_10k_20iter", |b| {
            let graph = create_test_graph(10_000, 50_000);
            let pipeline = EnrichmentPipeline::new(&graph);
            b.iter(|| pipeline.compute_pagerank_score("test_func", 20, 0.85))
        });
    }

    criterion_group!(benches,
        bench_blast_radius,
        bench_dead_code,
        bench_path_finding,
        bench_risk_scoring,
        bench_pagerank,
    );
    criterion_main!(benches);
}
```

---

## 21. Build Order & Dependencies

### Phase 1: Foundation (Week 1)
1. Core data model (ImpactResult, BlastRadius, CallerInfo, RiskScore, RiskLevel)
2. EntryPointImpact, DataPathImpact, RemediationSuggestion types
3. DeadCodeCandidate, FalsePositiveReason types
4. ImpactConfig, DeadCodeConfig, PathFinderConfig
5. Error types (ImpactError enum with thiserror)

### Phase 2: Blast Radius & Risk (Week 2)
6. ImpactEngine struct with petgraph + db references
7. Blast radius computation (reverse BFS)
8. Entry point impact discovery
9. Data path impact discovery
10. Multi-factor risk scoring engine (5 factors, weighted)
11. RiskLevel derivation from score

### Phase 3: Dead Code & Path Finding (Week 3)
12. DeadCodeEngine with 8 false positive categories
13. Confidence scoring for dead code candidates
14. Framework hook detection per language
15. PathFinder using petgraph all_simple_paths
16. Path confidence computation

### Phase 4: Coverage & Enrichment (Week 4)
17. CoverageEngine (call graph × test topology)
18. Uncovered function detection
19. Uncovered sensitive path detection
20. SensitivityClassifier (6 categories, pattern-based)
21. PageRank-inspired impact scoring
22. Remediation suggestion generation

### Phase 5: Change Propagation & Incremental (Week 5)
23. Change propagation analysis (multi-function)
24. Overlap zone detection
25. Git diff integration (functions_from_diff)
26. Incremental impact invalidation
27. LRU cache with invalidation

### Phase 6: Integration (Week 6)
28. Taint-enriched impact (TaintRisk, taint factor scoring)
29. Test topology integration (TestCoverage, recommend_tests)
30. Coverage gap detection
31. Bidirectional taint ↔ impact prioritization

### Phase 7: Interfaces & Persistence (Week 7)
32. Storage persistence (drift.db impact tables)
33. Materialized view refresh
34. NAPI bindings (analyze_impact, find_dead_code, find_path, analyze_changes, analyze_coverage)
35. MCP tool integration (drift_impact_analysis, drift_dead_code, drift_path, drift_change_impact, drift_coverage_gaps)
36. CLI integration (drift impact subcommands)
37. Tracing and observability

### Dependencies

```
Call Graph (Level 1) ──→ petgraph StableGraph ──→ Blast Radius, Dead Code, Path Finding
Boundary Detection (Level 1) ──→ DataAccessPoint[] ──→ Data Path Impact, Sensitivity
Taint Analysis (Level 2B) ──→ TaintSummary ──→ Taint-Enriched Risk Scoring
Test Topology (Level 2B) ──→ TestCoverageMap ──→ Coverage Analysis, Coverage Risk
Reachability Engine (Level 2B) ──→ BFS primitives ──→ Shared traversal utilities
Storage (Level 0) ──→ drift.db ──→ Impact persistence
Infrastructure (Level 0) ──→ thiserror, tracing, FxHashMap, LruCache ──→ Core utilities
NAPI Bridge (Level 4) ──→ napi-rs ──→ TypeScript bindings
MCP Server (Level 5) ──→ Tool routing ──→ MCP tool exposure
```


---

## 22. V1 → V2 Feature Cross-Reference

Complete matrix mapping every v1 feature to its v2 implementation. Zero feature loss.

| # | V1 Feature | V1 Location | V1 Behavior | V2 Section | V2 Status | Notes |
|---|-----------|-------------|-------------|------------|-----------|-------|
| I1 | Impact analysis | `impact-analyzer.ts` | Reverse BFS, 4-level risk | §5, §7 | Ported → Rust | Enhanced: 5-factor scoring, continuous 0-100 |
| I2 | Dead code detection | `dead-code-detector.ts` | `calledBy.length == 0`, 6 FP categories | §8 | Ported → Rust | Enhanced: 8 FP categories, confidence scoring |
| I3 | Coverage analysis | `coverage-analyzer.ts` | Call graph × test topology | §9 | Ported → Rust | Enhanced: field-level, sensitive path detection |
| I4 | Path finding | `path-finder.ts` + Rust BFS | BFS with path tracking | §10 | Upgraded | petgraph `all_simple_paths`, confidence scoring |
| I5 | Sensitivity classifier | `sensitivity-classifier.ts` | 4 levels, pattern matching | §11.2 | Upgraded | 6 categories (+ Infrastructure, Compliance) |
| I6 | Impact scorer | `impact-scorer.ts` | Centrality + entry point + sensitive data | §11.3 | Upgraded | PageRank-inspired + taint-enriched |
| I7 | Remediation generator | `remediation-generator.ts` | Heuristic suggestions | §11.4 | Preserved | Rust heuristics, structured output |
| I8 | Blast radius | `impact-analyzer.ts` | Direct callers count | §5 | Upgraded | Transitive + entry point + data + depth |
| I9 | Risk scoring | `impact-analyzer.ts` | 4 levels (low/med/high/crit) | §7 | Upgraded | Continuous 0-100, 5 weighted factors |
| I10 | MCP: drift_impact_analysis | TS-only blast radius | Basic impact query | §17 | Ported → Rust | Full Rust engine via NAPI |
| I11 | No Rust impact engine | N/A | TS-only | §3 | Added | Full Rust engine with petgraph |
| I12 | No Rust dead code | N/A | TS-only | §8 | Added | Rust dead code with 8 FP categories |
| I13 | No Rust coverage | N/A | TS-only | §9 | Added | Rust coverage with field-level |
| I14 | No taint-enriched impact | N/A | No taint analysis | §13 | Added | Taint flows increase risk score |
| I15 | No incremental impact | N/A | Full recompute | §12 | Added | Incremental invalidation + LRU cache |
| I16 | No change propagation | N/A | Single function only | §6 | Added | Multi-function + overlap zones |
| I17 | No git diff integration | N/A | Manual function selection | §6.2 | Added | Auto-detect from git diff |
| I18 | No coverage gaps | N/A | No gap detection | §14.2 | Added | Coverage gap detection in blast radius |
| I19 | No MCP dead code tool | N/A | No MCP exposure | §17 | Added | drift_dead_code MCP tool |
| I20 | No MCP path tool | N/A | No MCP exposure | §17 | Added | drift_path MCP tool |
| I21 | No MCP change impact | N/A | No MCP exposure | §17 | Added | drift_change_impact MCP tool |
| I22 | No MCP coverage gaps | N/A | No MCP exposure | §17 | Added | drift_coverage_gaps MCP tool |
| I23 | No CLI impact commands | N/A | No CLI exposure | §18 | Added | drift impact subcommands |
| I24 | No impact persistence | N/A | In-memory only | §15 | Added | drift.db impact tables |
| I25 | No PageRank scoring | N/A | Simple centrality | §11.3 | Added | PageRank-inspired importance |

**Coverage**: 25/25 features accounted for. 0 features lost. 15 features added.

---

## 23. Inconsistencies & Decisions

### 23.1 Resolved Inconsistencies

| Issue | Resolution | Confidence |
|-------|-----------|------------|
| 14-REACHABILITY §10 defines impact analysis as part of reachability; this doc separates it | Both are correct — reachability provides BFS primitives, impact is a dedicated engine that uses them. Separation enables independent testing and caching | High |
| R6 (RECOMMENDATIONS.md) defines ImpactResult in TypeScript; this doc defines it in Rust | Rust is authoritative (v2 is Rust-first). TS types are generated from Rust via napi-rs | High |
| V1 risk scoring uses 4 discrete levels; V2 uses continuous 0-100 | V2 preserves the 4 levels as derived from the continuous score. No feature loss — the levels are still available via `RiskLevel::from_score()` | High |
| V1 dead code uses `calledBy.length == 0`; V2 uses entry-point reachability | V2 is strictly more accurate — a function with callers that are themselves dead is still dead. Entry-point reachability catches this; simple caller counting does not | High |
| R7 defines 6 FP categories; V2 defines 8 | V2 adds Reflection and DecoratorTarget based on real-world false positive analysis. R7's 6 categories are a subset | High |
| 05-CALL-GRAPH-V2-PREP uses `Spur` for interned strings; impact engine uses `String` | Impact engine receives resolved strings from the call graph. Interning is internal to the call graph; impact operates on resolved `String` values | High |
| Sensitivity classifier in 14-REACHABILITY has 4 categories; this doc has 6 | V2 adds Infrastructure and Compliance categories for enterprise use cases. The original 4 (PII, Credentials, Financial, Health) are preserved | High |

### 23.2 Open Decisions

| Decision | Options | Recommendation | Confidence |
|----------|---------|---------------|------------|
| Blast radius depth limit | Fixed (20) / Configurable / Unlimited | Configurable with default 20 — prevents runaway BFS on deeply nested graphs | High |
| PageRank iterations | 10 / 20 / 50 | 20 iterations — converges for most graphs, <5s for 10K nodes | High |
| Dead code confidence threshold | 0.3 / 0.5 / 0.7 | 0.5 default — balances recall and precision. User-configurable | Medium |
| Risk score weights | Fixed / Configurable | Fixed for v2 launch, configurable in v2.1 — prevents user confusion | High |
| Overlap zone risk multiplier | Linear (1.3 per overlap) / Exponential | Linear — simpler, predictable. Exponential may over-penalize | Medium |
| Coverage gap risk threshold | 50 / 60 / 70 | 50 — flags all functions in blast radius without coverage | Medium |
| Impact result TTL in cache | None (invalidation only) / 5min / 30min | None — rely on incremental invalidation, not time-based expiry | High |
| Git diff granularity | Function-level / Line-level | Function-level — if any line in a function changes, the whole function is considered changed | High |

### 23.3 Architectural Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Separate engine (not part of reachability) | Yes | Independent caching, testing, and evolution. Reachability is a primitive; impact is a consumer | 
| petgraph for all graph operations | Yes | Consistent with call graph builder. StableGraph handles incremental updates |
| LRU cache for impact results | Yes | Impact queries are expensive (O(V+E) BFS). Cache hit rate expected >80% for IDE use |
| Batch persistence to drift.db | Yes | Consistent with storage V2 prep. Batch writer amortizes SQLite overhead |
| 5-factor risk model | Yes | Covers structural, security (taint), data, entry point, and test dimensions. Extensible |
| PageRank for importance scoring | Yes | Captures transitive importance that simple caller counting misses |
| 8 false positive categories | Yes | Covers all known false positive sources from v1 experience + research |

---

## 24. Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Blast radius BFS too slow on large graphs | Low | High | Depth limit (default 20), early termination, LRU cache |
| Dead code false positives from dynamic dispatch | High | Medium | 8 FP categories, confidence scoring, user-configurable threshold |
| Risk score weights produce unintuitive results | Medium | Medium | Extensive testing on real codebases, user feedback loop, configurable in v2.1 |
| PageRank computation too slow | Low | Low | 20 iterations is O(20 × edges), <5s for 10K nodes. Can reduce iterations |
| Taint summaries unavailable (taint engine not run) | Medium | Low | Graceful degradation — taint factor defaults to 0, other 4 factors still work |
| Test topology unavailable | Medium | Low | Graceful degradation — coverage factor defaults to 50 (unknown) |
| Incremental invalidation misses stale entries | Low | Medium | Periodic full recompute (configurable), cache TTL as fallback |
| Git diff integration misses renamed functions | Medium | Low | Fall back to full analysis if diff parsing fails |
| Coverage gap detection overwhelms users | Medium | Low | Limit output, sort by risk, sensitive-only filter |
| Overlap zone detection is too aggressive | Low | Low | Linear multiplier (1.3) is conservative. Configurable |
| Storage bloat from impact results | Low | Low | Prune old results on scan, keep only latest per function |
| NAPI serialization overhead for large results | Low | Medium | Paginate large result sets, limit blast radius detail in NAPI response |
