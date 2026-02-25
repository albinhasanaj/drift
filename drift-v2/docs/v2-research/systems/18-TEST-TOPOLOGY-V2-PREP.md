# Test Topology — V2 Implementation Prep

> Comprehensive build specification for Drift v2's Test Topology subsystem (System 18).
> Synthesized from: 17-test-topology/overview.md, 17-test-topology/types.md,
> 17-test-topology/extractors.md, 17-test-topology/analyzer.md,
> 01-rust-core/test-topology.md (Rust types, NAPI exposure, framework detection),
> DRIFT-V2-FULL-SYSTEM-AUDIT.md (Cat 17, A14 — 12 recommendations from
> .research/17-test-topology/RECOMMENDATIONS.md),
> DRIFT-V2-STACK-HIERARCHY.md (Level 2B — Graph-Derived Analysis),
> DRIFT-V2-SYSTEMS-REFERENCE.md (§15 — full feature reference),
> PLANNING-DRIFT.md (D1-D7),
> 05-CALL-GRAPH-V2-PREP.md (petgraph StableGraph, Resolution, CallEdge, BFS traversal),
> 16-IMPACT-ANALYSIS-V2-PREP.md (§9 Coverage Analysis Engine, §14 Test Topology Integration),
> 17-IMPACT-ANALYSIS-V2-PREP.md (§11 Coverage Gap Analysis),
> 14-REACHABILITY-ANALYSIS-V2-PREP.md (§12 Coverage Analysis Engine),
> 02-STORAGE-V2-PREP.md (test_files, test_cases, test_coverage, mock_statements,
> test_smells, uncovered_functions tables; batch writer; keyset pagination),
> 03-NAPI-BRIDGE-V2-PREP.md (§10.8 Test Topology Functions — 4 NAPI functions;
> §9 Batch API — AnalysisType::TestTopology; command/query pattern),
> 04-INFRASTRUCTURE-V2-PREP.md (thiserror, tracing, DriftEventHandler, FxHashMap,
> SmallVec, lasso string interning),
> 07-BOUNDARY-DETECTION-V2-PREP.md (DataAccessPoint, SensitiveField — for risk scoring),
> testsmells.org (19 canonical test smells),
> internet research on test impact analysis, mutation testing integration,
> and greedy set cover algorithms.
>
> Purpose: Everything needed to build the Test Topology subsystem from scratch.
> Decisions resolved, inconsistencies flagged, interface contracts defined,
> build order specified. Every v1 feature accounted for. Zero feature loss.
> Every algorithm specified. Every A14 recommendation integrated.
> Generated: 2026-02-08

---

## Table of Contents

1. Architectural Position
2. V1 Complete Feature Inventory
3. V2 Architecture — Unified Test Topology Engine
4. Core Data Model
5. Per-Language Test Extraction Engine
6. Framework Detection & Registry
7. Test-to-Source Mapping Engine
8. Coverage Mapping Engine (Call Graph × Test Topology)
9. Minimum Test Set Selection (Greedy Set Cover)
10. Uncovered Function Detection & Risk Scoring
11. Mock Analysis Engine
12. Test Quality Scoring Engine (7-Dimensional)
13. Test Smell Detection Engine (24 Smells)
14. Fixture & Setup Analysis (Cross-Language)
15. Incremental Analysis & Caching
16. Integration with Impact Analysis
17. Integration with Quality Gates
18. Integration with Constraint Detection
19. Storage Schema (drift.db)
20. NAPI Interface
21. MCP Tool Interface
22. CLI Interface
23. Tracing & Observability
24. Performance Targets & Benchmarks
25. Build Order & Dependencies
26. V1 → V2 Feature Cross-Reference
27. Inconsistencies & Decisions
28. Risk Register

---

## 1. Architectural Position

Test Topology is **Level 2B — Graph-Derived Analysis** in the Drift v2 stack hierarchy.
It answers the three questions every developer asks about their test suite: "Which tests
cover this function?", "What's untested?", and "Which tests should I run after changing
this file?" It understands test frameworks across 9+ languages (45+ frameworks in v2),
tracks mock usage, measures test quality across 7 dimensions, detects 24 test smells,
and integrates with the call graph for transitive coverage analysis.

Per DRIFT-V2-STACK-HIERARCHY.md:

> Test Topology: 35+ frameworks, coverage mapping via call graph BFS, minimum test set,
> mock analysis. Feeds quality gates (test coverage), simulation (test coverage scorer),
> CI agent.

### What Lives Here

- Per-language test extraction (9+ languages, 45+ frameworks, tree-sitter + regex fallback)
- Framework detection via declarative TOML registry (extensible without code changes)
- Test-to-source mapping (5 strategies: import, naming, directory, call graph, annotation)
- Coverage mapping (direct + transitive via call graph BFS + mocked-only tracking)
- Minimum test set selection (greedy weighted set cover for changed files)
- Uncovered function detection with risk scoring (0-100, 6 risk factors)
- Mock analysis (external vs internal, mock ratio, deep mock detection, mock categories)
- Test quality scoring (7 dimensions, A-F grade system, configurable weights)
- Test smell detection (19 canonical + 5 flakiness smells, auto-fixable flags)
- Fixture & setup analysis (cross-language: Python, Java, C#, Go, Rust)
- Incremental analysis (content-hash invalidation, dependency-aware propagation)
- Test extraction caching (SQLite + MessagePack serialization)
- Parameterized test detection (is_parameterized, parameter_count)
- Test type classification (Unit, Integration, E2E, Performance, Snapshot, Property)

### What Does NOT Live Here

- Call graph construction → Call Graph Builder (Level 1)
- Reachability BFS engine → Reachability Analysis (Level 2B)
- Impact analysis → Impact Analysis (Level 2B, consumes TestCoverageMap)
- Data access detection → Boundary Detection (Level 1)
- Quality gate evaluation → Quality Gates (Level 3)
- Constraint mining from test patterns → Constraint Detection (Level 2C)
- MCP tool routing → MCP Server (Level 5)
- Simulation scoring → Simulation Engine (Level 4)

### Critical Path Position

```
Scanner (Level 0)
  → Parsers (Level 0)
    → Call Graph Builder (Level 1)
      → Boundary Detection (Level 1)
        → Test Topology (Level 2B) ← YOU ARE HERE
          → Impact Analysis (Level 2B) — coverage factor in risk scoring
            → Quality Gates (Level 3) — test coverage gate
              → Constraint Detection (Level 2C) — test category constraints
                → Simulation Engine (Level 4) — test coverage scorer
                  → MCP Tools (Level 5) — drift_test_topology
                    → CLI (Level 5) — drift test-topology
```

### Consumer Count: 7+ Downstream Systems

| Consumer | What It Reads | Why |
|----------|--------------|-----|
| Impact Analysis | TestCoverageMap (function → covering tests) | Coverage factor in risk scoring (0.15 weight) |
| Quality Gates | Test coverage gate assessment | Block merges below coverage threshold |
| Constraint Detection | Test category constraints (test patterns) | Mine test-related invariants |
| Simulation Engine | Test coverage scorer | "What if I change this?" test impact |
| CI Agent | Minimum test set for changed files | Run only affected tests in PR |
| MCP Tools | drift_test_topology tool | AI-assisted test analysis |
| CLI | drift test-topology commands | Developer test analysis |
| Context Generation | Test coverage context for AI | AI-ready test summaries |

### Upstream Dependencies (Must Exist Before Test Topology)

| Dependency | What It Provides | Why Needed |
|-----------|-----------------|------------|
| Parsers (Level 0) | ParseResult with tree-sitter ASTs | Test file parsing, AST-based extraction |
| Scanner (Level 0) | ScanDiff (added/modified/removed files) | Incremental analysis input |
| Storage (Level 0) | DatabaseManager with batch writer | Persistence to drift.db |
| Call Graph (Level 1) | petgraph StableGraph, function registry | Transitive coverage via BFS |
| Boundary Detection (Level 1) | DataAccessPoint, SensitiveField | Risk scoring for uncovered functions |
| Infrastructure (Level 0) | thiserror, tracing, DriftEventHandler, config | Error handling, observability, events |
| String Interning (Level 1) | ThreadedRodeo / RodeoReader | Memory-efficient function/file IDs |

---

## 2. V1 Complete Feature Inventory

### 2.1 V1 TypeScript Implementation (Primary — Rich Analysis)

**Location**: `packages/core/src/test-topology/` (~15 source files)

#### TestTopologyAnalyzer (Main API)

```typescript
class TestTopologyAnalyzer {
    extractFromFile(content: string, filePath: string): TestExtraction | null;
    buildMappings(): void;
    getCoverage(sourceFile: string): TestCoverage;
    getUncoveredFunctions(options?: UncoveredOptions): UncoveredFunction[];
    getMinimumTestSet(changedFiles: string[]): MinimumTestSet;
    analyzeMocks(): MockAnalysis;
    getSummary(): TestTopologySummary;
    setCallGraph(callGraph: CallGraph): void;
}
```

#### HybridTestTopologyAnalyzer

```typescript
class HybridTestTopologyAnalyzer {
    // Combines tree-sitter primary with regex fallback
    // Uses tree-sitter as primary, falls back to regex when parsing fails
}
```

#### Per-Language Extractors (8 Languages)

| File | Language | Frameworks |
|------|----------|-----------|
| `typescript-test-extractor.ts` | TypeScript/JS | Jest, Vitest, Mocha, Ava, Tape |
| `python-test-extractor.ts` | Python | Pytest, Unittest, Nose |
| `java-test-extractor.ts` | Java | JUnit4, JUnit5, TestNG |
| `csharp-test-extractor.ts` | C# | xUnit, NUnit, MSTest |
| `php-test-extractor.ts` | PHP | PHPUnit, Pest, Codeception |
| `go-test-extractor.ts` | Go | go-testing, Testify, Ginkgo, Gomega |
| `rust-test-extractor.ts` | Rust | rust-test, tokio-test, proptest, criterion, rstest |
| `cpp-test-extractor.ts` | C++ | GTest, Catch2, Boost.Test, doctest, CppUnit |

Each extractor inherits from `BaseTestExtractor` (abstract base class) and produces
`TestExtraction` results containing test cases, mock statements, setup blocks, and fixtures.

Regex fallback extractors in `extractors/regex/` for when tree-sitter parsing fails.

#### Coverage Mapping Algorithm (V1)

```
1. For each test case:
   a. Resolve direct function calls → function IDs
   b. If call graph available: find transitive calls (BFS through call graph)
   c. Record: test → function mapping with reach type (direct/transitive/mocked)
2. For each source file:
   a. Collect all functions in the file
   b. For each function, find covering tests
   c. Calculate coverage percentage
   d. Flag mock-only coverage separately
```

#### Reach Types (V1)
- `direct` — Test directly calls the function
- `transitive` — Test reaches the function through call chain
- `mocked` — Function is only reached via mocked paths

Confidence: direct=high, transitive-shallow=medium-high, transitive-deep=lower, mocked=lowest.

#### Uncovered Function Detection (V1)

Risk score (0-100) based on:
- Entry point status (+30)
- Sensitive data access (+25)
- Call graph centrality (number of callers)

Inferred reasons for non-coverage:
- `dead-code` — no callers
- `framework-hook` — lifecycle method
- `generated` — in generated file
- `trivial` — getter/setter/constructor
- `test-only` — only called from tests
- `deprecated` — marked deprecated

#### Minimum Test Set (V1)

Given changed files → find all functions → find covering tests → deduplicate →
calculate coverage → estimate time savings. Returns: selected tests with reasons,
total vs selected count, estimated time savings, changed code coverage percentage.

#### Mock Analysis (V1)

Aggregate all mocks → classify external (good) vs internal (suspicious) →
per-test mock ratio → identify high-mock-ratio tests (>0.7) → rank most-mocked modules.

Output: totalMocks, externalMocks, internalMocks, avgMockRatio, highMockRatioTests[],
topMockedModules[].

#### Test Quality Signals (V1)

Per-test quality score (0-100) based on:
- assertionCount
- hasErrorCases
- hasEdgeCases (null, empty, boundary)
- mockRatio (high = potentially brittle)
- setupRatio (setup lines vs test lines)
- score (0-100 composite)

### 2.2 V1 Rust Implementation (Basic — Framework Detection)

**Location**: `crates/drift-core/src/test_topology/` (3 files)

```rust
// types.rs
TestFile { file, framework, test_cases, mocks, imports, covers }
TestCase { name, test_type, line, is_async, is_skipped }
TestFramework { Jest, Vitest, Mocha, Pytest, JUnit, NUnit, XUnit, GoTest,
                PHPUnit, RustTest, Unknown }
TestType { Unit, Integration, E2E, Performance, Snapshot }
MockUsage { target, mock_type, line }
MockType { Full, Partial, Spy }
TestCoverage { source_file, test_files, test_count, risk_level }
RiskLevel { Low, Medium, High, Critical }
TestTopologyResult { test_files, coverage, stats }
```

**NAPI Exposure**: `analyze_test_topology(files: Vec<String>) -> JsTestTopologyResult`

**Limitations**:
- No quality scoring
- No transitive analysis
- No minimum test set
- No mock analysis depth
- No fixture detection beyond Python
- No test smell detection
- No incremental analysis
- Framework detection for only 13 frameworks (vs 35+ in TS)

### 2.3 V1 MCP Integration

- `drift_test_topology` MCP tool for AI-assisted test analysis

### 2.4 V1 CLI Integration

- `drift test-topology` command group: analyze, coverage, minimum-set, mocks

### 2.5 V1 Quality Gate Integration

- Test Coverage gate: minimum thresholds per module, function-level via test topology

### 2.6 V1 Feature Inventory (Exhaustive)

| # | Feature | V1 Behavior | V2 Status |
|---|---------|-------------|-----------|
| T1 | Per-language extractors (8 langs) | TS extractors, BaseTestExtractor | Ported → Rust TestExtractor trait (§5) |
| T2 | Framework detection (35+ frameworks) | TS pattern matching | Upgraded → TOML registry, 45+ frameworks (§6) |
| T3 | Tree-sitter primary extraction | TS tree-sitter bindings | Ported → Rust tree-sitter-* crates (§5) |
| T4 | Regex fallback extraction | TS regex extractors | Preserved → Rust regex fallback (§5) |
| T5 | Test case extraction | name, parent, qualified, line, calls | Upgraded → +is_parameterized, +parameter_count (§5) |
| T6 | Mock statement extraction | target, type, line, isExternal | Upgraded → +mock_category (5 types), +is_deep_mock (§11) |
| T7 | Setup block extraction | beforeEach, setUp, etc. | Preserved → Rust (§14) |
| T8 | Fixture extraction (Python) | Pytest fixtures with scope | Upgraded → cross-language fixtures (§14) |
| T9 | Coverage mapping (direct) | Direct function calls | Preserved → Rust (§8) |
| T10 | Coverage mapping (transitive) | BFS through call graph | Preserved → Rust petgraph BFS (§8) |
| T11 | Coverage mapping (mocked) | Mock-only coverage tracked | Preserved → Rust (§8) |
| T12 | Confidence scoring | Reach type based | Upgraded → depth + resolution confidence (§8) |
| T13 | Uncovered function detection | Risk score 0-100, 6 reasons | Upgraded → 8 reasons, 6 risk factors (§10) |
| T14 | Minimum test set | Set cover, time savings | Upgraded → weighted greedy set cover (§9) |
| T15 | Mock analysis | External vs internal, ratio | Upgraded → 5 categories, deep mock detection (§11) |
| T16 | Test quality scoring | 5 signals, 0-100 score | Upgraded → 7 dimensions, A-F grades (§12) |
| T17 | Summary statistics | Counts, percentages, breakdowns | Preserved → Rust (§4) |
| T18 | Hybrid analyzer | Tree-sitter + regex | Preserved → Rust (§5) |
| T19 | MCP: drift_test_topology | AI-assisted test analysis | Preserved → Rust-native via NAPI (§21) |
| T20 | CLI: test-topology commands | analyze, coverage, minimum-set, mocks | Preserved + expanded (§22) |
| T21 | Quality gate: test coverage | Minimum thresholds | Preserved → Rust evaluation (§17) |
| T22 | Call graph integration | setCallGraph() for transitive | Preserved → direct petgraph access (§8) |
| T23 | NAPI: analyze_test_topology | Basic Rust analysis | Upgraded → 4 NAPI functions (§20) |
| T24 | No test smell detection | Not in v1 | Added → 24 smells (§13) |
| T25 | No incremental analysis | Full recompute | Added → content-hash invalidation (§15) |
| T26 | No parameterized test detection | Not in v1 | Added → is_parameterized, parameter_count (§5) |
| T27 | No mock categories | Only external/internal | Added → 5 categories (§11) |
| T28 | No deep mock detection | Not in v1 | Added → mock returning mock (§11) |
| T29 | No cross-language fixtures | Python only | Added → Java, C#, Go, Rust (§14) |
| T30 | No test-to-source bidirectional maps | One-way only | Added → 5 mapping strategies (§7) |
| T31 | No A-F grade system | Only 0-100 score | Added → grade system (§12) |
| T32 | No TOML framework registry | Hardcoded patterns | Added → extensible registry (§6) |
| T33 | No Kotlin/Swift support | 8 languages | Added → 10+ languages (§6) |
| T34 | No mutation score integration | Not in v1 | Added → optional external data (§12) |
| T35 | No test-to-source naming convention | Not in v1 | Added → mapping strategy (§7) |

**Coverage**: 35/35 features accounted for. 0 features lost. 12 features upgraded. 12 features added.

---

## 3. V2 Architecture — Unified Test Topology Engine

### 3.1 Design Philosophy

V1's test topology is split: rich analysis in TypeScript (~15 files), basic detection in
Rust (3 files). V2 unifies everything in Rust for 10x performance and direct petgraph
access. The TS layer becomes a thin presentation wrapper.

Key design principles:
1. **Rust-native** — Direct petgraph traversal for transitive coverage, no NAPI round-trips
2. **Trait-based extraction** — Single `TestExtractor` trait for all languages (A14 recommendation)
3. **Declarative framework registry** — TOML-based, extensible without code changes
4. **Incremental** — Content-hash invalidation with dependency-aware propagation
5. **Multi-dimensional quality** — 7 scoring dimensions, not just assertion count
6. **Smell-aware** — 24 test smells detected during extraction (zero additional AST traversal)
7. **Call-graph-integrated** — Direct petgraph BFS for transitive coverage mapping

### 3.2 Engine Architecture

```rust
use std::sync::Arc;
use rustc_hash::{FxHashMap, FxHashSet};
use petgraph::stable_graph::NodeIndex;
use lasso::{ThreadedRodeo, Spur};

/// The unified test topology engine. Operates on parsed test files and the call graph.
pub struct TestTopologyEngine {
    /// Call graph (petgraph StableGraph) for transitive coverage.
    graph: Option<Arc<CallGraph>>,

    /// Database for persistence and boundary/sensitivity queries.
    db: Arc<DatabaseManager>,

    /// Per-language extractors (registered at initialization).
    extractors: Vec<Box<dyn TestExtractor>>,

    /// Framework registry (loaded from TOML).
    framework_registry: FrameworkRegistry,

    /// String interner for function IDs and file paths.
    interner: Arc<ThreadedRodeo>,

    /// Configuration.
    config: TestTopologyConfig,

    /// Extraction cache (file_hash → TestExtraction).
    extraction_cache: Mutex<FxHashMap<u64, TestExtraction>>,

    /// Coverage map (function_id → FunctionTestCoverage).
    /// Built by build_coverage_map(), consumed by impact analysis.
    coverage_map: RwLock<FxHashMap<Spur, FunctionTestCoverage>>,

    /// Test-to-source bidirectional maps.
    test_to_source: RwLock<FxHashMap<Spur, Vec<Spur>>>,
    source_to_tests: RwLock<FxHashMap<Spur, Vec<Spur>>>,
}
```

### 3.3 Engine Lifecycle

```
Initialize → Extract → Map → Score → Persist → Query
```

1. **Initialize**: Load framework registry from TOML, register per-language extractors,
   optionally attach call graph
2. **Extract**: Parse test files via per-language extractors (tree-sitter primary, regex fallback).
   Detect framework, extract test cases, mocks, setup blocks, fixtures, smells.
   Cache extractions by content hash.
3. **Map**: Build test-to-source mappings using 5 strategies (import, naming, directory,
   call graph, annotation). Build coverage map via call graph BFS.
4. **Score**: Compute per-test quality scores (7 dimensions), per-file coverage metrics,
   uncovered function risk scores.
5. **Persist**: Write all results to drift.db via batch writer.
6. **Query**: Serve coverage queries, minimum test set, mock analysis, uncovered functions
   via NAPI query functions.

### 3.4 Data Flow Diagram

```
                    ┌─────────────────────────────────────────────────────────┐
                    │              TestTopologyEngine                          │
                    ├──────────┬──────────┬──────────┬────────────────────────┤
                    │ Extract  │ Map      │ Score    │   Query                │
                    │ (§5-6)   │ (§7-8)   │ (§10-13) │   (§20-22)            │
                    ├──────────┴──────────┴──────────┴────────────────────────┤
                    │              Per-Language Extractors (§5)                │
                    │  TS │ Python │ Java │ C# │ PHP │ Go │ Rust │ C++       │
                    │  Kotlin │ Swift (v2 additions)                          │
                    ├─────────────────────────────────────────────────────────┤
                    │              Framework Registry (§6)                     │
                    │  TOML-based │ 45+ frameworks │ Extensible               │
                    ├─────────────────────────────────────────────────────────┤
                    │              Call Graph Integration (§8)                 │
                    │  Direct calls │ Transitive BFS │ petgraph StableGraph   │
                    ├─────────────────────────────────────────────────────────┤
Inputs:             │              Storage (§19)                              │
  ParseResult[]     │  test_files │ test_cases │ test_coverage │ test_smells  │
  ScanDiff          │  mock_statements │ uncovered_functions                  │
  CallGraph         └─────────────────────────────────────────────────────────┘
  DataAccessPoint[]
  SensitiveField[]  Outputs:
                      TestCoverageMap → Impact Analysis (§16)
                      CoverageAssessment → Quality Gates (§17)
                      TestConstraints → Constraint Detection (§18)
                      MinimumTestSet → CI Agent
                      TestTopologySummary → MCP / CLI / Context Gen
```


---

## 4. Core Data Model

### 4.1 TestExtraction — Per-File Extraction Result

```rust
/// Result of extracting test information from a single file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestExtraction {
    /// File path (interned).
    pub file: String,
    /// Detected test framework.
    pub framework: TestFramework,
    /// Source language.
    pub language: Language,
    /// Content hash (xxh3) for incremental invalidation.
    pub content_hash: u64,
    /// Extracted test cases.
    pub test_cases: Vec<TestCase>,
    /// Mock statements found in this file.
    pub mocks: Vec<MockStatement>,
    /// Setup/teardown blocks.
    pub setup_blocks: Vec<SetupBlock>,
    /// Fixtures (cross-language).
    pub fixtures: Vec<FixtureInfo>,
    /// Test smells detected during extraction.
    pub smells: Vec<TestSmell>,
    /// Imports (for test-to-source mapping).
    pub imports: Vec<String>,
    /// Source files this test file covers (resolved during mapping phase).
    pub covers: Vec<String>,
}
```

### 4.2 TestCase — Individual Test

```rust
/// A single test case extracted from a test file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCase {
    /// Unique ID: "file:name:line".
    pub id: String,
    /// Test name/description.
    pub name: String,
    /// Parent describe/context block (if any).
    pub parent_block: Option<String>,
    /// Qualified name: "describe > it" or "ClassName.testMethod".
    pub qualified_name: String,
    /// File path.
    pub file: String,
    /// Line number.
    pub line: u32,
    /// End line of test body.
    pub end_line: u32,
    /// Test type classification.
    pub test_type: TestType,
    /// Functions directly called within the test body.
    pub direct_calls: Vec<String>,
    /// Assertion details.
    pub assertions: Vec<AssertionInfo>,
    /// Quality signals for this test.
    pub quality: TestQualitySignals,
    /// Whether this test is async.
    pub is_async: bool,
    /// Whether this test is skipped (xit, @Disabled, skip, etc.).
    pub is_skipped: bool,
    /// Whether this test is parameterized (A14 recommendation).
    pub is_parameterized: bool,
    /// Number of parameter sets (A14 recommendation).
    pub parameter_count: u32,
    /// Test smells detected in this specific test.
    pub smells: Vec<TestSmellRef>,
}
```

### 4.3 TestType — Classification

```rust
/// Test type classification. Expanded from v1 (added Property).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TestType {
    /// Isolated unit test (single function/class).
    Unit,
    /// Integration test (multiple components).
    Integration,
    /// End-to-end test (full user workflow).
    E2E,
    /// Performance/benchmark test.
    Performance,
    /// Snapshot/regression test.
    Snapshot,
    /// Property-based test (proptest, Hypothesis, QuickCheck).
    Property,
    /// Unknown classification.
    Unknown,
}
```

### 4.4 TestFramework — Expanded Enum

```rust
/// Test framework detection. V2 expands from 13 to 45+ via TOML registry.
/// This enum covers the built-in frameworks; TOML registry adds custom ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TestFramework {
    // TypeScript/JavaScript
    Jest,
    Vitest,
    Mocha,
    Ava,
    Tape,
    Playwright,        // v2 addition (A14)
    Cypress,           // v2 addition (A14)
    TestingLibrary,    // v2 addition (A14)

    // Python
    Pytest,
    Unittest,
    Nose,
    Hypothesis,        // v2 addition (A14)
    Behave,            // v2 addition (A14)

    // Java
    JUnit4,
    JUnit5,
    TestNG,
    Cucumber,          // v2 addition (A14)
    Spock,             // v2 addition (A14)
    Arquillian,        // v2 addition (A14)

    // C#
    XUnit,
    NUnit,
    MSTest,
    SpecFlow,          // v2 addition (A14)
    FluentAssertions,  // v2 addition (A14)

    // PHP
    PHPUnit,
    Pest,
    Codeception,
    Behat,             // v2 addition (A14)

    // Go
    GoTest,
    Testify,
    Ginkgo,
    Gomega,
    GoConvey,          // v2 addition (A14)
    Rapid,             // v2 addition (A14)

    // Rust
    RustTest,
    TokioTest,
    Proptest,
    Criterion,
    Rstest,
    Nextest,           // v2 addition (A14) — runner, not framework, but detected

    // C++
    GTest,
    Catch2,
    BoostTest,
    Doctest,
    CppUnit,
    GoogleMock,        // v2 addition (A14)

    // Kotlin (v2 new language — A14)
    Kotest,
    MockK,

    // Swift (v2 new language — A14)
    Quick,
    Nimble,

    /// Custom framework defined in TOML registry.
    Custom(u32),       // Index into framework registry

    /// Unknown framework.
    Unknown,
}
```

### 4.5 MockStatement — Enhanced Mock Tracking

```rust
/// A mock/stub/spy statement found in a test file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MockStatement {
    /// What's being mocked (module path, function name, class name).
    pub target: String,
    /// Framework-specific mock type (jest.mock, sinon.stub, @patch, etc.).
    pub mock_type: String,
    /// Line number.
    pub line: u32,
    /// Whether the mock targets external dependencies (good) or internal code (suspicious).
    pub is_external: bool,
    /// Whether the mock has an inline implementation.
    pub has_implementation: bool,
    /// Mock category (A14 recommendation — expanded from boolean to 5 categories).
    pub category: MockCategory,
    /// Whether this mock returns another mock (A14 — deep mock detection).
    pub is_deep_mock: bool,
}

/// Mock category classification (A14 recommendation).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MockCategory {
    /// External dependency mock (HTTP clients, databases, file system).
    External,
    /// Internal code mock (application modules, services).
    Internal,
    /// HTTP/API mock (nock, msw, responses, WireMock).
    Http,
    /// Database mock (in-memory DB, query mock).
    Database,
    /// File system mock (memfs, mock-fs, tmpdir).
    FileSystem,
}
```

### 4.6 TestQualitySignals — Per-Test Quality

```rust
/// Quality signals for a single test case.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestQualitySignals {
    /// Number of assertions in the test.
    pub assertion_count: u32,
    /// Whether the test covers error/exception cases.
    pub has_error_cases: bool,
    /// Whether the test covers edge cases (null, empty, boundary).
    pub has_edge_cases: bool,
    /// Mock-to-assertion ratio (high = potentially brittle).
    pub mock_ratio: f64,
    /// Setup-to-test ratio (setup lines vs test lines).
    pub setup_ratio: f64,
    /// Overall quality score (0-100). V1 composite.
    pub score: f64,
}
```

### 4.7 AssertionInfo — Assertion Details

```rust
/// Details about an assertion within a test.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssertionInfo {
    /// Assertion type (equality, truthiness, throws, contains, etc.).
    pub assertion_type: AssertionType,
    /// Line number.
    pub line: u32,
    /// Whether this is a negative assertion (not, never, rejects).
    pub is_negative: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AssertionType {
    Equality,       // assertEquals, toBe, toEqual
    Truthiness,     // assertTrue, toBeTruthy
    Throws,         // assertThrows, toThrow, pytest.raises
    Contains,       // assertContains, toContain
    TypeCheck,      // assertInstanceOf, toBeInstanceOf
    Comparison,     // assertGreaterThan, toBeGreaterThan
    Null,           // assertNull, toBeNull, assertNone
    Snapshot,       // toMatchSnapshot, toMatchInlineSnapshot
    Custom,         // Framework-specific or custom matchers
}
```

### 4.8 SetupBlock — Setup/Teardown

```rust
/// A setup or teardown block in a test file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupBlock {
    /// Block type.
    pub block_type: SetupBlockType,
    /// Line number.
    pub line: u32,
    /// End line.
    pub end_line: u32,
    /// Functions called during setup.
    pub calls: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SetupBlockType {
    BeforeAll,      // beforeAll, @BeforeClass, setUpClass
    BeforeEach,     // beforeEach, @Before, setUp
    AfterEach,      // afterEach, @After, tearDown
    AfterAll,       // afterAll, @AfterClass, tearDownClass
}
```

### 4.9 FixtureInfo — Cross-Language Fixtures (A14 Expansion)

```rust
/// Fixture information. V1 was Python-only; V2 expands to all languages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixtureInfo {
    /// Fixture name.
    pub name: String,
    /// Fixture scope (A14 — expanded beyond Python).
    pub scope: FixtureScope,
    /// Line number.
    pub line: u32,
    /// What the fixture provides (type or description).
    pub provides: Option<String>,
    /// Language-specific fixture type.
    pub fixture_type: FixtureType,
}

/// Fixture scope (A14 — expanded from Python-only to cross-language).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FixtureScope {
    /// Per-test function (default).
    Function,
    /// Per-test class.
    Class,
    /// Per-module/file.
    Module,
    /// Per-session/suite.
    Session,
}

/// Language-specific fixture type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FixtureType {
    PytestFixture,      // @pytest.fixture
    JUnitRule,          // @Rule, @ClassRule (v2 addition)
    JUnitExtension,     // @ExtendWith (JUnit5, v2 addition)
    CSharpSetUp,        // [SetUp], [OneTimeSetUp] (v2 addition)
    GoTestMain,         // TestMain (v2 addition)
    RustTestFixture,    // rstest #[fixture] (v2 addition)
    Custom,
}
```

### 4.10 FunctionTestCoverage — Coverage Map Entry

```rust
/// Coverage information for a single production function.
/// This is the primary output consumed by Impact Analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionTestCoverage {
    /// Function ID (interned).
    pub function_id: String,
    /// Tests that cover this function.
    pub covering_tests: Vec<CoveringTest>,
    /// Overall coverage ratio (0.0 = no coverage, 1.0 = fully covered).
    pub coverage_ratio: f64,
    /// Whether any test directly calls this function.
    pub is_directly_tested: bool,
    /// Whether coverage is mock-only (no real execution path).
    pub is_mock_only: bool,
    /// Number of distinct test files covering this function.
    pub covering_file_count: usize,
}

/// A test that covers a production function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoveringTest {
    /// Test case ID.
    pub test_id: String,
    /// Test file path.
    pub test_file: String,
    /// How the test reaches this function.
    pub reach_type: ReachType,
    /// Call depth (1 = direct, 2+ = transitive).
    pub depth: u32,
    /// Confidence in the coverage mapping (0.0 - 1.0).
    pub confidence: f64,
}

/// How a test reaches a production function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReachType {
    /// Test directly calls the function.
    Direct,
    /// Test reaches the function through a call chain.
    Transitive,
    /// Function is only reached via mocked paths (not real coverage).
    Mocked,
}
```

### 4.11 TestTopologySummary — Aggregate Statistics

```rust
/// Summary statistics for the entire test topology.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestTopologySummary {
    /// Total test files analyzed.
    pub test_file_count: usize,
    /// Total test cases found.
    pub test_case_count: usize,
    /// Total source files with coverage data.
    pub source_file_count: usize,
    /// Source files with at least one covering test.
    pub covered_source_files: usize,
    /// Total production functions.
    pub total_functions: usize,
    /// Functions with at least one covering test.
    pub covered_functions: usize,
    /// File-level coverage percentage.
    pub file_coverage_percent: f64,
    /// Function-level coverage percentage.
    pub function_coverage_percent: f64,
    /// Average mock ratio across all tests.
    pub avg_mock_ratio: f64,
    /// Average quality score across all tests.
    pub avg_quality_score: f64,
    /// Average quality grade.
    pub avg_quality_grade: QualityGrade,
    /// Breakdown by framework.
    pub framework_breakdown: Vec<FrameworkBreakdown>,
    /// Total test smells detected.
    pub total_smells: usize,
    /// Smells by severity.
    pub smells_by_severity: FxHashMap<SmellSeverity, usize>,
    /// Skipped test count.
    pub skipped_test_count: usize,
    /// Parameterized test count.
    pub parameterized_test_count: usize,
    /// Analysis duration in milliseconds.
    pub duration_ms: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameworkBreakdown {
    pub framework: TestFramework,
    pub test_file_count: usize,
    pub test_case_count: usize,
    pub avg_quality_score: f64,
}
```


---

## 5. Per-Language Test Extraction Engine

### 5.1 TestExtractor Trait (A14 — Unified Extraction Interface)

From A14: "Single `TestExtractor` trait for all 9 languages." This replaces v1's
`BaseTestExtractor` abstract class in TypeScript.

```rust
/// Trait implemented by each per-language test extractor.
/// Tree-sitter primary, regex fallback.
pub trait TestExtractor: Send + Sync {
    /// Languages this extractor handles.
    fn supported_languages(&self) -> &[Language];

    /// Detect which test framework is used in this file.
    /// Returns None if the file is not a test file.
    fn detect_framework(
        &self,
        content: &str,
        file_path: &str,
    ) -> Option<TestFramework>;

    /// Extract test information from a file using tree-sitter AST.
    /// This is the primary extraction path.
    fn extract_from_ast(
        &self,
        tree: &tree_sitter::Tree,
        content: &str,
        file_path: &str,
        framework: TestFramework,
    ) -> Result<TestExtraction, TestTopologyError>;

    /// Extract test information using regex patterns (fallback).
    /// Used when tree-sitter parsing fails or is unavailable.
    fn extract_from_regex(
        &self,
        content: &str,
        file_path: &str,
        framework: TestFramework,
    ) -> Result<TestExtraction, TestTopologyError>;

    /// Whether this extractor supports tree-sitter for the given language.
    fn supports_tree_sitter(&self, language: Language) -> bool;
}
```

### 5.2 Extraction Pipeline

```rust
impl TestTopologyEngine {
    /// Extract test information from a single file.
    /// Uses tree-sitter as primary, falls back to regex.
    pub fn extract_file(
        &self,
        content: &str,
        file_path: &str,
        language: Language,
    ) -> Result<Option<TestExtraction>, TestTopologyError> {
        // Step 1: Find the appropriate extractor
        let extractor = self.find_extractor(language)
            .ok_or(TestTopologyError::UnsupportedLanguage(language))?;

        // Step 2: Detect framework (returns None if not a test file)
        let framework = match extractor.detect_framework(content, file_path) {
            Some(fw) => fw,
            None => return Ok(None), // Not a test file
        };

        // Step 3: Check extraction cache
        let content_hash = xxh3_64(content.as_bytes());
        if let Some(cached) = self.extraction_cache.lock().unwrap().get(&content_hash) {
            return Ok(Some(cached.clone()));
        }

        // Step 4: Try tree-sitter extraction
        let extraction = if extractor.supports_tree_sitter(language) {
            match self.parse_with_tree_sitter(content, language) {
                Ok(tree) => {
                    match extractor.extract_from_ast(&tree, content, file_path, framework) {
                        Ok(ext) => ext,
                        Err(_) => {
                            // Fallback to regex on AST extraction failure
                            tracing::warn!(
                                file = file_path,
                                "Tree-sitter extraction failed, falling back to regex"
                            );
                            extractor.extract_from_regex(content, file_path, framework)?
                        }
                    }
                }
                Err(_) => {
                    // Fallback to regex on parse failure
                    tracing::warn!(
                        file = file_path,
                        "Tree-sitter parse failed, falling back to regex"
                    );
                    extractor.extract_from_regex(content, file_path, framework)?
                }
            }
        } else {
            // No tree-sitter support for this language — regex only
            extractor.extract_from_regex(content, file_path, framework)?
        };

        // Step 5: Detect test smells (during extraction, zero additional traversal — A14)
        let extraction = self.detect_smells(extraction)?;

        // Step 6: Cache the extraction
        self.extraction_cache.lock().unwrap()
            .insert(content_hash, extraction.clone());

        Ok(Some(extraction))
    }
}
```

### 5.3 Per-Language Extractor Implementations

Each language extractor is a separate struct implementing `TestExtractor`.
All extractors live in `crates/drift-core/src/test_topology/extractors/`.

```
crates/drift-core/src/test_topology/extractors/
├── mod.rs                      # TestExtractor trait, registry
├── typescript_extractor.rs     # TS/JS: Jest, Vitest, Mocha, Ava, Tape, Playwright, Cypress, TestingLibrary
├── python_extractor.rs         # Python: Pytest, Unittest, Nose, Hypothesis, Behave
├── java_extractor.rs           # Java: JUnit4, JUnit5, TestNG, Cucumber, Spock, Arquillian
├── csharp_extractor.rs         # C#: xUnit, NUnit, MSTest, SpecFlow, FluentAssertions
├── php_extractor.rs            # PHP: PHPUnit, Pest, Codeception, Behat
├── go_extractor.rs             # Go: go-testing, Testify, Ginkgo, Gomega, GoConvey, Rapid
├── rust_extractor.rs           # Rust: rust-test, tokio-test, proptest, criterion, rstest, nextest
├── cpp_extractor.rs            # C++: GTest, Catch2, Boost.Test, doctest, CppUnit, GoogleMock
├── kotlin_extractor.rs         # Kotlin: Kotest, MockK (v2 new language — A14)
├── swift_extractor.rs          # Swift: Quick, Nimble (v2 new language — A14)
└── regex/                      # Regex fallback extractors (one per language)
    ├── mod.rs
    ├── typescript_regex.rs
    ├── python_regex.rs
    ├── java_regex.rs
    ├── csharp_regex.rs
    ├── php_regex.rs
    ├── go_regex.rs
    ├── rust_regex.rs
    ├── cpp_regex.rs
    ├── kotlin_regex.rs
    └── swift_regex.rs
```

### 5.4 What Each Extractor Detects

All extractors detect the same categories of information, adapted to language idioms:

#### Test Cases
- Test function/method declarations (it, test, def test_, @Test, func Test*, #[test], etc.)
- Parent describe/context blocks for qualified naming
- Direct function calls within test body
- Assertions (expect, assert, assertEquals, etc.)
- Error case assertions and edge case assertions
- Parameterized tests (A14: is_parameterized, parameter_count)
  - TS: `it.each`, `test.each`, `describe.each`
  - Python: `@pytest.mark.parametrize`
  - Java: `@ParameterizedTest`, `@DataProvider`
  - C#: `[Theory]`, `[TestCase]`
  - Go: table-driven tests (subtests with `t.Run`)
  - Rust: `#[rstest]` with `#[case]`

#### Mock Statements
- Module mocks (jest.mock, @patch, sinon.stub)
- Function mocks/spies
- HTTP mocks (nock, msw, responses, WireMock)
- Mock category classification (A14: External/Internal/Http/Database/FileSystem)
- Deep mock detection (A14: mock returning mock)
- Whether mock has inline implementation

#### Setup Blocks
- beforeEach / afterEach / beforeAll / afterAll (JS/TS)
- setUp / tearDown / setUpClass / tearDownClass (Python, Java)
- [SetUp] / [TearDown] / [OneTimeSetUp] / [OneTimeTearDown] (C#)
- TestMain (Go)
- Functions called during setup

#### Fixtures (A14 — Cross-Language Expansion)
- Python: @pytest.fixture (scope, provides)
- Java: @Rule, @ClassRule, @ExtendWith (JUnit5)
- C#: [SetUp], [OneTimeSetUp], IClassFixture<T>
- Go: TestMain, test helper functions
- Rust: rstest #[fixture]

### 5.5 Parallel Extraction

Test extraction is embarrassingly parallel — each file is independent.
Uses rayon for parallel extraction across all test files.

```rust
impl TestTopologyEngine {
    /// Extract test information from all test files in parallel.
    pub fn extract_all(
        &self,
        files: &[(String, String, Language)], // (path, content, language)
    ) -> Result<Vec<TestExtraction>, TestTopologyError> {
        let span = tracing::info_span!("test_topology_extract_all", file_count = files.len());
        let _guard = span.enter();

        let extractions: Vec<TestExtraction> = files
            .par_iter()
            .filter_map(|(path, content, lang)| {
                match self.extract_file(content, path, *lang) {
                    Ok(Some(ext)) => Some(ext),
                    Ok(None) => None, // Not a test file
                    Err(e) => {
                        tracing::warn!(file = path.as_str(), error = %e, "Extraction failed");
                        None
                    }
                }
            })
            .collect();

        tracing::info!(
            extracted = extractions.len(),
            total_files = files.len(),
            "Test extraction complete"
        );

        Ok(extractions)
    }
}
```

---

## 6. Framework Detection & Registry

### 6.1 TOML-Based Framework Registry (A14 — Extensible)

V1 hardcodes framework detection patterns in each extractor. V2 uses a declarative
TOML registry that can be extended without code changes.

```toml
# drift-frameworks.toml — Test framework registry
# Users can add custom frameworks in drift.toml [test_topology.custom_frameworks]

[[frameworks]]
id = "jest"
name = "Jest"
language = "typescript"
test_type = "unit"
# File patterns that indicate this framework
file_patterns = ["**/*.test.ts", "**/*.test.js", "**/*.spec.ts", "**/*.spec.js"]
# Import patterns that confirm framework usage
import_patterns = ["@jest/globals", "jest"]
# Test function patterns (tree-sitter query or regex)
test_patterns = ["describe\\(", "it\\(", "test\\(", "expect\\("]
# Mock patterns
mock_patterns = ["jest\\.mock\\(", "jest\\.spyOn\\(", "jest\\.fn\\("]
# Setup patterns
setup_patterns = ["beforeEach\\(", "afterEach\\(", "beforeAll\\(", "afterAll\\("]
# Assertion patterns
assertion_patterns = ["expect\\(.*\\)\\.to", "expect\\(.*\\)\\.not\\.to"]

[[frameworks]]
id = "pytest"
name = "Pytest"
language = "python"
test_type = "unit"
file_patterns = ["**/test_*.py", "**/*_test.py"]
import_patterns = ["pytest", "conftest"]
test_patterns = ["def test_", "@pytest\\.mark"]
mock_patterns = ["@patch", "mock\\.patch", "MagicMock", "mocker\\."]
setup_patterns = ["@pytest\\.fixture", "def setup_method", "def setup_class"]
assertion_patterns = ["assert ", "pytest\\.raises"]

# ... 43 more framework definitions
```

### 6.2 Framework Registry Implementation

```rust
/// Framework registry loaded from TOML.
pub struct FrameworkRegistry {
    /// Built-in frameworks (compiled into binary).
    builtin: Vec<FrameworkDefinition>,
    /// Custom frameworks (loaded from drift.toml).
    custom: Vec<FrameworkDefinition>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FrameworkDefinition {
    pub id: String,
    pub name: String,
    pub language: String,
    pub test_type: String,
    pub file_patterns: Vec<String>,
    pub import_patterns: Vec<String>,
    pub test_patterns: Vec<String>,
    pub mock_patterns: Vec<String>,
    pub setup_patterns: Vec<String>,
    pub assertion_patterns: Vec<String>,
}

impl FrameworkRegistry {
    /// Detect framework for a file. Checks custom frameworks first (user overrides).
    pub fn detect(
        &self,
        content: &str,
        file_path: &str,
        language: Language,
    ) -> Option<TestFramework> {
        let lang_str = language.as_str();

        // Custom frameworks take precedence
        for (idx, fw) in self.custom.iter().enumerate() {
            if fw.language == lang_str && self.matches_framework(fw, content, file_path) {
                return Some(TestFramework::Custom(idx as u32));
            }
        }

        // Then built-in frameworks
        for fw in &self.builtin {
            if fw.language == lang_str && self.matches_framework(fw, content, file_path) {
                return Some(TestFramework::from_id(&fw.id));
            }
        }

        None
    }

    fn matches_framework(
        &self,
        fw: &FrameworkDefinition,
        content: &str,
        file_path: &str,
    ) -> bool {
        // Check file pattern match
        let file_matches = fw.file_patterns.iter()
            .any(|p| glob_match(p, file_path));

        // Check import pattern match
        let import_matches = fw.import_patterns.iter()
            .any(|p| content.contains(p));

        // Check test pattern match
        let test_matches = fw.test_patterns.iter()
            .any(|p| regex_matches(p, content));

        // File pattern OR (import + test pattern)
        file_matches || (import_matches && test_matches)
    }
}
```

### 6.3 V2 Framework Coverage (45+ Frameworks, 10+ Languages)

| Language | V1 Frameworks | V2 Additions (A14) | Total |
|----------|--------------|-------------------|-------|
| TypeScript/JS | Jest, Vitest, Mocha, Ava, Tape | Playwright, Cypress, Testing Library | 8 |
| Python | Pytest, Unittest, Nose | Hypothesis, Behave | 5 |
| Java | JUnit4, JUnit5, TestNG | Cucumber, Spock, Arquillian | 6 |
| C# | xUnit, NUnit, MSTest | SpecFlow, FluentAssertions | 5 |
| PHP | PHPUnit, Pest, Codeception | Behat | 4 |
| Go | go-testing, Testify, Ginkgo, Gomega | GoConvey, Rapid | 6 |
| Rust | rust-test, tokio-test, proptest, criterion, rstest | nextest, GoogleMock | 6 |
| C++ | GTest, Catch2, Boost.Test, doctest, CppUnit | GoogleMock | 6 |
| Kotlin (NEW) | — | Kotest, MockK | 2 |
| Swift (NEW) | — | Quick, Nimble | 2 |
| **Total** | **35** | **~15** | **~50** |


---

## 7. Test-to-Source Mapping Engine

### 7.1 Architecture (A14 — Bidirectional Maps, 5 Strategies)

From A14: "Bidirectional maps (source→tests, test→sources). Mapping strategies: import
analysis, naming convention, directory convention, call graph, explicit annotations."

V1 only used import analysis. V2 uses 5 strategies with confidence-weighted merging.

```rust
/// Test-to-source mapping engine.
/// Builds bidirectional maps using 5 strategies.
pub struct TestSourceMapper {
    /// Mapping strategies in priority order.
    strategies: Vec<Box<dyn MappingStrategy>>,
    /// String interner.
    interner: Arc<ThreadedRodeo>,
}

/// A mapping strategy that links test files to source files.
pub trait MappingStrategy: Send + Sync {
    /// Strategy name for tracing.
    fn name(&self) -> &str;

    /// Confidence of this strategy (0.0 - 1.0).
    fn confidence(&self) -> f64;

    /// Find source files that a test file covers.
    fn map_test_to_source(
        &self,
        test_extraction: &TestExtraction,
        source_files: &[String],
        context: &MappingContext,
    ) -> Vec<MappingResult>;
}

#[derive(Debug, Clone)]
pub struct MappingResult {
    pub source_file: String,
    pub confidence: f64,
    pub strategy: String,
}

pub struct MappingContext<'a> {
    pub call_graph: Option<&'a CallGraph>,
    pub project_root: &'a str,
    pub all_test_files: &'a [String],
    pub all_source_files: &'a [String],
}
```

### 7.2 Strategy 1: Import Analysis (Confidence: 0.90)

The highest-confidence strategy. Analyzes import statements in test files to determine
which source modules they test.

```rust
pub struct ImportMappingStrategy;

impl MappingStrategy for ImportMappingStrategy {
    fn name(&self) -> &str { "import" }
    fn confidence(&self) -> f64 { 0.90 }

    fn map_test_to_source(
        &self,
        extraction: &TestExtraction,
        source_files: &[String],
        _context: &MappingContext,
    ) -> Vec<MappingResult> {
        extraction.imports.iter()
            .filter_map(|import| {
                // Resolve import path to source file
                resolve_import_to_file(import, source_files)
                    .map(|source| MappingResult {
                        source_file: source,
                        confidence: 0.90,
                        strategy: "import".to_string(),
                    })
            })
            .collect()
    }
}
```

### 7.3 Strategy 2: Naming Convention (Confidence: 0.80)

Maps test files to source files by naming convention:
- `user.test.ts` → `user.ts`
- `test_user.py` → `user.py`
- `UserTest.java` → `User.java`
- `UserTests.cs` → `User.cs`

```rust
pub struct NamingConventionStrategy;

impl MappingStrategy for NamingConventionStrategy {
    fn name(&self) -> &str { "naming" }
    fn confidence(&self) -> f64 { 0.80 }

    fn map_test_to_source(
        &self,
        extraction: &TestExtraction,
        source_files: &[String],
        _context: &MappingContext,
    ) -> Vec<MappingResult> {
        let test_file = &extraction.file;
        let stem = extract_source_stem(test_file);

        source_files.iter()
            .filter(|sf| {
                let source_stem = Path::new(sf).file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("");
                source_stem == stem
            })
            .map(|sf| MappingResult {
                source_file: sf.clone(),
                confidence: 0.80,
                strategy: "naming".to_string(),
            })
            .collect()
    }
}

/// Extract the source file stem from a test file name.
/// "user.test.ts" → "user", "test_user.py" → "user", "UserTest.java" → "User"
fn extract_source_stem(test_file: &str) -> &str {
    // Language-specific stripping of test prefixes/suffixes
    // ...
}
```

### 7.4 Strategy 3: Directory Convention (Confidence: 0.70)

Maps test files to source files by directory structure:
- `tests/user.test.ts` → `src/user.ts`
- `__tests__/user.test.ts` → `user.ts`
- `test/test_user.py` → `src/user.py`

```rust
pub struct DirectoryConventionStrategy;

impl MappingStrategy for DirectoryConventionStrategy {
    fn name(&self) -> &str { "directory" }
    fn confidence(&self) -> f64 { 0.70 }

    fn map_test_to_source(
        &self,
        extraction: &TestExtraction,
        source_files: &[String],
        context: &MappingContext,
    ) -> Vec<MappingResult> {
        let test_dir = Path::new(&extraction.file).parent().unwrap_or(Path::new(""));
        let source_dir = infer_source_directory(test_dir, context.project_root);

        source_files.iter()
            .filter(|sf| Path::new(sf).starts_with(&source_dir))
            .filter(|sf| {
                // Additional name similarity check
                let test_stem = extract_source_stem(&extraction.file);
                let source_stem = Path::new(sf).file_stem()
                    .and_then(|s| s.to_str()).unwrap_or("");
                source_stem == test_stem
            })
            .map(|sf| MappingResult {
                source_file: sf.clone(),
                confidence: 0.70,
                strategy: "directory".to_string(),
            })
            .collect()
    }
}
```

### 7.5 Strategy 4: Call Graph (Confidence: 0.85)

Uses the call graph to find which source functions a test calls (directly or transitively).
Maps back to source files.

```rust
pub struct CallGraphMappingStrategy;

impl MappingStrategy for CallGraphMappingStrategy {
    fn name(&self) -> &str { "call_graph" }
    fn confidence(&self) -> f64 { 0.85 }

    fn map_test_to_source(
        &self,
        extraction: &TestExtraction,
        source_files: &[String],
        context: &MappingContext,
    ) -> Vec<MappingResult> {
        let graph = match context.call_graph {
            Some(g) => g,
            None => return Vec::new(),
        };

        let mut covered_files = FxHashSet::default();

        for test_case in &extraction.test_cases {
            for call in &test_case.direct_calls {
                if let Some(node_idx) = graph.find_node(call) {
                    let node = &graph.graph[node_idx];
                    let file = graph.interner.resolve(&node.file).to_string();
                    if source_files.contains(&file) {
                        covered_files.insert(file);
                    }
                }
            }
        }

        covered_files.into_iter()
            .map(|sf| MappingResult {
                source_file: sf,
                confidence: 0.85,
                strategy: "call_graph".to_string(),
            })
            .collect()
    }
}
```

### 7.6 Strategy 5: Explicit Annotations (Confidence: 0.95)

Some frameworks support explicit test-to-source annotations:
- `@covers UserService` (PHPUnit)
- `# covers: user_service.py` (custom comment convention)
- `@see UserService` (JSDoc/JavaDoc)

```rust
pub struct AnnotationMappingStrategy;

impl MappingStrategy for AnnotationMappingStrategy {
    fn name(&self) -> &str { "annotation" }
    fn confidence(&self) -> f64 { 0.95 }

    fn map_test_to_source(
        &self,
        extraction: &TestExtraction,
        source_files: &[String],
        _context: &MappingContext,
    ) -> Vec<MappingResult> {
        // Parse @covers, @see, # covers: annotations from test file
        // ...
        Vec::new() // Placeholder — implemented per-language
    }
}
```

### 7.7 Confidence-Weighted Merging

When multiple strategies map the same test to the same source file, take the highest
confidence. When strategies disagree, include all mappings above a minimum threshold.

```rust
impl TestSourceMapper {
    pub fn build_mappings(
        &self,
        extractions: &[TestExtraction],
        source_files: &[String],
        context: &MappingContext,
    ) -> (FxHashMap<String, Vec<String>>, FxHashMap<String, Vec<String>>) {
        let mut test_to_source: FxHashMap<String, Vec<String>> = FxHashMap::default();
        let mut source_to_tests: FxHashMap<String, Vec<String>> = FxHashMap::default();

        for extraction in extractions {
            let mut file_mappings: FxHashMap<String, f64> = FxHashMap::default();

            for strategy in &self.strategies {
                let results = strategy.map_test_to_source(extraction, source_files, context);
                for result in results {
                    let entry = file_mappings.entry(result.source_file.clone()).or_insert(0.0);
                    *entry = entry.max(result.confidence);
                }
            }

            // Filter by minimum confidence threshold (0.50)
            let mapped_sources: Vec<String> = file_mappings.into_iter()
                .filter(|(_, conf)| *conf >= 0.50)
                .map(|(file, _)| file)
                .collect();

            // Build bidirectional maps
            for source in &mapped_sources {
                source_to_tests.entry(source.clone())
                    .or_default()
                    .push(extraction.file.clone());
            }
            test_to_source.insert(extraction.file.clone(), mapped_sources);
        }

        (test_to_source, source_to_tests)
    }
}
```

---

## 8. Coverage Mapping Engine (Call Graph × Test Topology)

### 8.1 Architecture

Coverage mapping is the core value of test topology. It answers "which tests cover this
function?" by combining direct call extraction with transitive BFS through the call graph.

V1 did this in TypeScript with optional call graph integration. V2 does it in Rust with
direct petgraph access for 10x performance on large codebases.

```rust
impl TestTopologyEngine {
    /// Build the coverage map: function_id → FunctionTestCoverage.
    /// This is the primary output consumed by Impact Analysis.
    pub fn build_coverage_map(
        &self,
        extractions: &[TestExtraction],
    ) -> Result<(), TestTopologyError> {
        let span = tracing::info_span!("build_coverage_map",
            test_files = extractions.len());
        let _guard = span.enter();

        let mut coverage: FxHashMap<Spur, FunctionTestCoverage> = FxHashMap::default();

        for extraction in extractions {
            for test_case in &extraction.test_cases {
                // Step 1: Map direct calls to function IDs
                let direct_functions = self.resolve_direct_calls(
                    &test_case.direct_calls,
                    &extraction.file,
                );

                // Step 2: If call graph available, find transitive calls via BFS
                let transitive_functions = if let Some(ref graph) = self.graph {
                    self.find_transitive_calls(graph, &direct_functions)
                } else {
                    FxHashMap::default()
                };

                // Step 3: Identify mocked-only functions
                let mocked_functions = self.identify_mocked_functions(
                    &extraction.mocks,
                    &direct_functions,
                );

                // Step 4: Record coverage for each function
                for (func_id, _) in &direct_functions {
                    let entry = coverage.entry(*func_id)
                        .or_insert_with(|| FunctionTestCoverage::new(func_id));
                    entry.add_covering_test(CoveringTest {
                        test_id: test_case.id.clone(),
                        test_file: extraction.file.clone(),
                        reach_type: ReachType::Direct,
                        depth: 1,
                        confidence: 0.95,
                    });
                    entry.is_directly_tested = true;
                }

                for (func_id, depth) in &transitive_functions {
                    if direct_functions.contains_key(func_id) {
                        continue; // Already recorded as direct
                    }
                    let entry = coverage.entry(*func_id)
                        .or_insert_with(|| FunctionTestCoverage::new(func_id));

                    // Confidence decreases with depth
                    let confidence = self.compute_transitive_confidence(*depth);

                    entry.add_covering_test(CoveringTest {
                        test_id: test_case.id.clone(),
                        test_file: extraction.file.clone(),
                        reach_type: ReachType::Transitive,
                        depth: *depth,
                        confidence,
                    });
                }

                for func_id in &mocked_functions {
                    let entry = coverage.entry(*func_id)
                        .or_insert_with(|| FunctionTestCoverage::new(func_id));
                    if !entry.is_directly_tested && entry.covering_tests.is_empty() {
                        entry.is_mock_only = true;
                    }
                    entry.add_covering_test(CoveringTest {
                        test_id: test_case.id.clone(),
                        test_file: extraction.file.clone(),
                        reach_type: ReachType::Mocked,
                        depth: 1,
                        confidence: 0.30, // Mocked coverage is low confidence
                    });
                }
            }
        }

        // Compute coverage ratios
        for entry in coverage.values_mut() {
            entry.compute_coverage_ratio();
        }

        // Store in engine
        *self.coverage_map.write().unwrap() = coverage;

        Ok(())
    }
}
```

### 8.2 Transitive Coverage via BFS

```rust
impl TestTopologyEngine {
    /// Find all functions transitively reachable from a set of directly-called functions.
    /// Uses BFS through the call graph (petgraph).
    fn find_transitive_calls(
        &self,
        graph: &CallGraph,
        direct_calls: &FxHashMap<Spur, NodeIndex>,
    ) -> FxHashMap<Spur, u32> {
        let max_depth = self.config.max_transitive_depth; // Default: 10
        let mut visited: FxHashMap<Spur, u32> = FxHashMap::default();
        let mut queue: VecDeque<(NodeIndex, u32)> = VecDeque::new();

        // Seed BFS with direct calls at depth 1
        for (func_id, node_idx) in direct_calls {
            queue.push_back((*node_idx, 1));
            visited.insert(*func_id, 1);
        }

        // BFS through callees
        while let Some((node_idx, depth)) = queue.pop_front() {
            if depth >= max_depth {
                continue;
            }

            for edge in graph.graph.edges(node_idx) {
                let callee_idx = edge.target();
                let callee_node = &graph.graph[callee_idx];
                let callee_id = callee_node.id;

                if !visited.contains_key(&callee_id) {
                    let new_depth = depth + 1;
                    visited.insert(callee_id, new_depth);
                    queue.push_back((callee_idx, new_depth));
                }
            }
        }

        // Remove direct calls (they're tracked separately)
        for func_id in direct_calls.keys() {
            visited.remove(func_id);
        }

        visited
    }

    /// Compute confidence for transitive coverage based on depth.
    /// Deeper = lower confidence.
    fn compute_transitive_confidence(&self, depth: u32) -> f64 {
        match depth {
            1 => 0.95,     // Direct call (shouldn't reach here, but safety)
            2 => 0.85,     // One hop
            3 => 0.75,     // Two hops
            4 => 0.65,     // Three hops
            5..=7 => 0.50, // Medium depth
            _ => 0.35,     // Deep transitive
        }
    }
}
```

### 8.3 Mock-Only Coverage Detection

```rust
impl TestTopologyEngine {
    /// Identify functions that are only reached via mocked paths.
    fn identify_mocked_functions(
        &self,
        mocks: &[MockStatement],
        direct_calls: &FxHashMap<Spur, NodeIndex>,
    ) -> FxHashSet<Spur> {
        let mut mocked = FxHashSet::default();

        for mock in mocks {
            // Resolve mock target to function ID
            if let Some(func_id) = self.resolve_mock_target(&mock.target) {
                // If the function is mocked and NOT directly called, it's mock-only
                if !direct_calls.contains_key(&func_id) {
                    mocked.insert(func_id);
                }
            }
        }

        mocked
    }
}
```


---

## 9. Minimum Test Set Selection (Greedy Set Cover)

### 9.1 Problem Definition

Given a set of changed files, compute the smallest set of tests that covers all changed
functions. This is a weighted set cover problem — NP-hard in general, but the greedy
algorithm provides a ln(n)+1 approximation that's excellent in practice.

V1 used simple deduplication. V2 uses a weighted greedy algorithm that considers test
execution time, coverage breadth, and test quality.

### 9.2 Algorithm

```rust
/// Minimum test set selection result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinimumTestSet {
    /// Selected tests with reasons for selection.
    pub tests: Vec<SelectedTest>,
    /// Total tests that could cover the changes.
    pub total_candidate_tests: usize,
    /// Number of tests selected.
    pub selected_count: usize,
    /// Estimated time saved vs running all candidates.
    pub time_saved_estimate: String,
    /// Percentage of changed code covered by selected tests.
    pub changed_code_coverage: f64,
    /// Functions not covered by any test.
    pub uncovered_changed_functions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectedTest {
    /// Test file path.
    pub file: String,
    /// Test case name.
    pub name: String,
    /// Why this test was selected.
    pub reason: String,
    /// Functions this test covers among the changed set.
    pub covers_functions: Vec<String>,
    /// Estimated execution time (if available).
    pub estimated_time_ms: Option<u64>,
}

impl TestTopologyEngine {
    /// Compute the minimum test set for a set of changed files.
    /// Uses greedy weighted set cover.
    pub fn compute_minimum_test_set(
        &self,
        changed_files: &[String],
    ) -> Result<MinimumTestSet, TestTopologyError> {
        let span = tracing::info_span!("minimum_test_set",
            changed_files = changed_files.len());
        let _guard = span.enter();

        // Step 1: Find all functions in changed files
        let changed_functions = self.find_functions_in_files(changed_files)?;

        if changed_functions.is_empty() {
            return Ok(MinimumTestSet::empty());
        }

        // Step 2: Find all candidate tests (tests covering any changed function)
        let coverage_map = self.coverage_map.read().unwrap();
        let mut candidate_tests: FxHashMap<String, FxHashSet<String>> = FxHashMap::default();

        for func_id in &changed_functions {
            if let Some(cov) = coverage_map.get(func_id) {
                for covering_test in &cov.covering_tests {
                    candidate_tests
                        .entry(covering_test.test_id.clone())
                        .or_default()
                        .insert(self.interner.resolve(func_id).to_string());
                }
            }
        }

        let total_candidates = candidate_tests.len();

        if candidate_tests.is_empty() {
            return Ok(MinimumTestSet {
                tests: Vec::new(),
                total_candidate_tests: 0,
                selected_count: 0,
                time_saved_estimate: "0s".to_string(),
                changed_code_coverage: 0.0,
                uncovered_changed_functions: changed_functions.iter()
                    .map(|f| self.interner.resolve(f).to_string())
                    .collect(),
            });
        }

        // Step 3: Greedy weighted set cover
        let mut uncovered: FxHashSet<String> = changed_functions.iter()
            .map(|f| self.interner.resolve(f).to_string())
            .collect();
        let mut selected: Vec<SelectedTest> = Vec::new();

        while !uncovered.is_empty() && !candidate_tests.is_empty() {
            // Find the test that covers the most uncovered functions
            // weighted by test quality (prefer higher quality tests)
            let best_test = candidate_tests.iter()
                .max_by_key(|(test_id, covers)| {
                    let uncovered_coverage = covers.intersection(&uncovered).count();
                    let quality_bonus = self.get_test_quality_bonus(test_id);
                    // Score: coverage count * 100 + quality bonus
                    uncovered_coverage * 100 + quality_bonus
                })
                .map(|(id, covers)| (id.clone(), covers.clone()));

            match best_test {
                Some((test_id, covers)) => {
                    let newly_covered: Vec<String> = covers.intersection(&uncovered)
                        .cloned()
                        .collect();

                    if newly_covered.is_empty() {
                        break; // No more progress possible
                    }

                    for func in &newly_covered {
                        uncovered.remove(func);
                    }

                    let (file, name) = self.parse_test_id(&test_id);
                    selected.push(SelectedTest {
                        file,
                        name,
                        reason: format!("Covers {} changed functions", newly_covered.len()),
                        covers_functions: newly_covered,
                        estimated_time_ms: self.estimate_test_time(&test_id),
                    });

                    candidate_tests.remove(&test_id);
                }
                None => break,
            }
        }

        // Step 4: Calculate statistics
        let total_changed = changed_functions.len();
        let covered_count = total_changed - uncovered.len();
        let coverage = if total_changed > 0 {
            covered_count as f64 / total_changed as f64 * 100.0
        } else {
            100.0
        };

        let total_time: u64 = selected.iter()
            .filter_map(|t| t.estimated_time_ms)
            .sum();
        let all_time: u64 = total_candidates as u64 * 500; // Rough estimate: 500ms per test
        let saved = all_time.saturating_sub(total_time);

        Ok(MinimumTestSet {
            tests: selected.clone(),
            total_candidate_tests: total_candidates,
            selected_count: selected.len(),
            time_saved_estimate: format_duration(saved),
            changed_code_coverage: coverage,
            uncovered_changed_functions: uncovered.into_iter().collect(),
        })
    }
}
```

---

## 10. Uncovered Function Detection & Risk Scoring

### 10.1 Architecture

Identifies functions with no test coverage and assigns risk scores based on 6 factors.
V1 used 3 factors and 6 non-coverage reasons. V2 uses 6 factors and 8 reasons.

```rust
/// An uncovered function with risk assessment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UncoveredFunction {
    /// Function ID.
    pub function_id: String,
    /// Function name.
    pub name: String,
    /// Qualified name (ClassName.methodName).
    pub qualified_name: String,
    /// File path.
    pub file: String,
    /// Line number.
    pub line: u32,
    /// Risk score (0-100).
    pub risk_score: f64,
    /// Risk level (derived from score).
    pub risk_level: RiskLevel,
    /// Possible reasons for non-coverage.
    pub possible_reasons: Vec<UncoveredReason>,
    /// Whether this function is an entry point.
    pub is_entry_point: bool,
    /// Whether this function accesses sensitive data.
    pub accesses_sensitive_data: bool,
    /// Number of callers (call graph centrality).
    pub caller_count: usize,
    /// Whether this function is on a taint path.
    pub on_taint_path: bool,
}

/// Reasons why a function might intentionally lack test coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UncoveredReason {
    /// No callers in the call graph (likely dead code).
    DeadCode,
    /// Framework lifecycle method (componentDidMount, ngOnInit, etc.).
    FrameworkHook,
    /// In a generated file (*.generated.*, *.g.cs, etc.).
    Generated,
    /// Trivial function (getter, setter, constructor with no logic).
    Trivial,
    /// Only called from test code (test utility).
    TestOnly,
    /// Marked as deprecated.
    Deprecated,
    /// Main/entry function (tested via integration/E2E).
    EntryPoint,       // v2 addition
    /// Configuration/initialization function (tested via integration).
    Configuration,    // v2 addition
}
```

### 10.2 Risk Scoring Algorithm (6 Factors)

```rust
impl TestTopologyEngine {
    /// Compute risk score for an uncovered function.
    /// Score: 0-100, higher = more risky to leave untested.
    fn compute_uncovered_risk(
        &self,
        func_id: &str,
        node_idx: NodeIndex,
        graph: &CallGraph,
    ) -> f64 {
        let mut score = 0.0f64;
        let node = &graph.graph[node_idx];

        // Factor 1: Entry point status (+30)
        // Entry points are the most critical — they're the public API.
        if node.is_entry_point {
            score += 30.0;
        }

        // Factor 2: Sensitive data access (+25)
        // Functions that touch credentials, PII, financial data.
        if self.accesses_sensitive_data(func_id) {
            score += 25.0;
        }

        // Factor 3: Call graph centrality (+20)
        // Functions with many callers affect more code when they break.
        let caller_count = graph.graph.neighbors_directed(
            node_idx, petgraph::Direction::Incoming
        ).count();
        let centrality_score = (caller_count as f64).min(20.0);
        score += centrality_score;

        // Factor 4: Taint path presence (+15)
        // Functions on taint paths (source → sink) are security-critical.
        if self.is_on_taint_path(func_id) {
            score += 15.0;
        }

        // Factor 5: Exported status (+5)
        // Exported functions are part of the public API.
        if node.is_exported {
            score += 5.0;
        }

        // Factor 6: Complexity proxy (+5)
        // Functions with many outgoing calls are more complex.
        let callee_count = graph.graph.neighbors_directed(
            node_idx, petgraph::Direction::Outgoing
        ).count();
        if callee_count > 5 {
            score += 5.0;
        }

        score.min(100.0)
    }

    /// Infer reasons why a function might intentionally lack coverage.
    fn infer_uncovered_reasons(
        &self,
        func_id: &str,
        node_idx: NodeIndex,
        graph: &CallGraph,
    ) -> Vec<UncoveredReason> {
        let mut reasons = Vec::new();
        let node = &graph.graph[node_idx];
        let name = self.interner.resolve(&node.id);

        // Dead code: no incoming edges (no callers)
        let caller_count = graph.graph.neighbors_directed(
            node_idx, petgraph::Direction::Incoming
        ).count();
        if caller_count == 0 && !node.is_entry_point && !node.is_exported {
            reasons.push(UncoveredReason::DeadCode);
        }

        // Framework hook: lifecycle method names
        if is_framework_hook(name) {
            reasons.push(UncoveredReason::FrameworkHook);
        }

        // Generated: file path patterns
        let file = self.interner.resolve(&node.file);
        if is_generated_file(file) {
            reasons.push(UncoveredReason::Generated);
        }

        // Trivial: getter/setter/constructor patterns
        if is_trivial_function(name) {
            reasons.push(UncoveredReason::Trivial);
        }

        // Test-only: only called from test files
        if self.is_test_only_caller(node_idx, graph) {
            reasons.push(UncoveredReason::TestOnly);
        }

        // Deprecated: marked with @deprecated, #[deprecated], etc.
        if is_deprecated(name, file) {
            reasons.push(UncoveredReason::Deprecated);
        }

        // Entry point: main, handler, CLI command
        if node.is_entry_point {
            reasons.push(UncoveredReason::EntryPoint);
        }

        // Configuration: init, configure, setup patterns
        if is_configuration_function(name) {
            reasons.push(UncoveredReason::Configuration);
        }

        reasons
    }
}
```

### 10.3 Risk Level Classification

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,       // 0-25
    Medium,    // 26-50
    High,      // 51-75
    Critical,  // 76-100
}

impl RiskLevel {
    pub fn from_score(score: f64) -> Self {
        match score as u32 {
            0..=25 => RiskLevel::Low,
            26..=50 => RiskLevel::Medium,
            51..=75 => RiskLevel::High,
            _ => RiskLevel::Critical,
        }
    }
}
```


---

## 11. Mock Analysis Engine

### 11.1 Architecture (A14 — Enhanced Mock Categories)

V1 classified mocks as external vs internal. V2 adds 5 mock categories, deep mock
detection, and per-module mock frequency analysis.

```rust
/// Mock analysis result for the entire test suite.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MockAnalysis {
    /// Total mock statements across all tests.
    pub total_mocks: usize,
    /// External dependency mocks (generally good practice).
    pub external_mocks: usize,
    /// Internal code mocks (potentially suspicious).
    pub internal_mocks: usize,
    /// Percentage of mocks that are external.
    pub external_percent: f64,
    /// Percentage of mocks that are internal.
    pub internal_percent: f64,
    /// Average mock-to-assertion ratio across all tests.
    pub avg_mock_ratio: f64,
    /// Tests with high mock ratio (>0.7).
    pub high_mock_ratio_tests: Vec<HighMockTest>,
    /// Most-mocked modules (ranked by mock count).
    pub top_mocked_modules: Vec<MockedModule>,
    /// Mock category breakdown (A14).
    pub category_breakdown: FxHashMap<MockCategory, usize>,
    /// Deep mock count (A14 — mocks returning mocks).
    pub deep_mock_count: usize,
    /// Tests with deep mocks.
    pub deep_mock_tests: Vec<DeepMockTest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HighMockTest {
    pub file: String,
    pub test_name: String,
    pub mock_ratio: f64,
    pub mock_count: usize,
    pub assertion_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MockedModule {
    pub module: String,
    pub mock_count: usize,
    pub mock_category: MockCategory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeepMockTest {
    pub file: String,
    pub test_name: String,
    pub deep_mock_targets: Vec<String>,
    pub line: u32,
}

impl TestTopologyEngine {
    /// Analyze mock usage across all test extractions.
    pub fn analyze_mocks(
        &self,
        extractions: &[TestExtraction],
    ) -> Result<MockAnalysis, TestTopologyError> {
        let span = tracing::info_span!("analyze_mocks",
            test_files = extractions.len());
        let _guard = span.enter();

        let mut total_mocks = 0usize;
        let mut external_mocks = 0usize;
        let mut internal_mocks = 0usize;
        let mut category_counts: FxHashMap<MockCategory, usize> = FxHashMap::default();
        let mut deep_mock_count = 0usize;
        let mut module_mock_counts: FxHashMap<String, (usize, MockCategory)> = FxHashMap::default();
        let mut high_mock_tests = Vec::new();
        let mut deep_mock_tests = Vec::new();
        let mut total_mock_ratio = 0.0f64;
        let mut test_count = 0usize;

        for extraction in extractions {
            for mock in &extraction.mocks {
                total_mocks += 1;

                if mock.is_external {
                    external_mocks += 1;
                } else {
                    internal_mocks += 1;
                }

                *category_counts.entry(mock.category).or_insert(0) += 1;

                if mock.is_deep_mock {
                    deep_mock_count += 1;
                }

                // Track per-module mock counts
                let module = extract_module_from_target(&mock.target);
                let entry = module_mock_counts.entry(module).or_insert((0, mock.category));
                entry.0 += 1;
            }

            // Per-test mock ratio analysis
            for test_case in &extraction.test_cases {
                test_count += 1;
                let mock_ratio = test_case.quality.mock_ratio;
                total_mock_ratio += mock_ratio;

                if mock_ratio > 0.7 {
                    high_mock_tests.push(HighMockTest {
                        file: extraction.file.clone(),
                        test_name: test_case.qualified_name.clone(),
                        mock_ratio,
                        mock_count: extraction.mocks.len(),
                        assertion_count: test_case.quality.assertion_count as usize,
                    });
                }
            }

            // Deep mock detection
            let file_deep_mocks: Vec<_> = extraction.mocks.iter()
                .filter(|m| m.is_deep_mock)
                .collect();
            if !file_deep_mocks.is_empty() {
                for test_case in &extraction.test_cases {
                    deep_mock_tests.push(DeepMockTest {
                        file: extraction.file.clone(),
                        test_name: test_case.qualified_name.clone(),
                        deep_mock_targets: file_deep_mocks.iter()
                            .map(|m| m.target.clone())
                            .collect(),
                        line: test_case.line,
                    });
                }
            }
        }

        // Sort top mocked modules by count
        let mut top_mocked: Vec<MockedModule> = module_mock_counts.into_iter()
            .map(|(module, (count, category))| MockedModule {
                module,
                mock_count: count,
                mock_category: category,
            })
            .collect();
        top_mocked.sort_by(|a, b| b.mock_count.cmp(&a.mock_count));
        top_mocked.truncate(20); // Top 20

        let avg_mock_ratio = if test_count > 0 {
            total_mock_ratio / test_count as f64
        } else {
            0.0
        };

        Ok(MockAnalysis {
            total_mocks,
            external_mocks,
            internal_mocks,
            external_percent: if total_mocks > 0 {
                external_mocks as f64 / total_mocks as f64 * 100.0
            } else { 0.0 },
            internal_percent: if total_mocks > 0 {
                internal_mocks as f64 / total_mocks as f64 * 100.0
            } else { 0.0 },
            avg_mock_ratio,
            high_mock_ratio_tests: high_mock_tests,
            top_mocked_modules: top_mocked,
            category_breakdown: category_counts,
            deep_mock_count,
            deep_mock_tests,
        })
    }
}
```

---

## 12. Test Quality Scoring Engine (7-Dimensional)

### 12.1 Architecture (A14 — Multi-Dimensional Quality)

From A14: "7 dimensions — assertion_quality, error_coverage, edge_coverage, mock_health,
smell_penalty, isolation, mutation_score (optional from external tools). Configurable
weights. Grade system: A/B/C/D/F."

V1 used 5 signals and a single 0-100 score. V2 uses 7 dimensions with configurable
weights and an A-F grade system.

```rust
/// Multi-dimensional test quality assessment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestQualityAssessment {
    /// Per-dimension scores (0.0 - 1.0 each).
    pub dimensions: QualityDimensions,
    /// Weighted composite score (0-100).
    pub composite_score: f64,
    /// Letter grade (A-F).
    pub grade: QualityGrade,
    /// Dimension-level breakdown for reporting.
    pub breakdown: Vec<DimensionScore>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityDimensions {
    /// Assertion quality: count, variety, specificity.
    pub assertion_quality: f64,
    /// Error case coverage: tests for error/exception paths.
    pub error_coverage: f64,
    /// Edge case coverage: null, empty, boundary values.
    pub edge_coverage: f64,
    /// Mock health: external ratio, no deep mocks, reasonable count.
    pub mock_health: f64,
    /// Smell penalty: deduction for detected test smells.
    pub smell_penalty: f64,
    /// Isolation: test independence (no shared state, no order dependency).
    pub isolation: f64,
    /// Mutation score: from external mutation testing tools (optional).
    pub mutation_score: Option<f64>,
}

/// Quality grade (A-F).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum QualityGrade {
    A,  // 90-100
    B,  // 80-89
    C,  // 70-79
    D,  // 60-69
    F,  // 0-59
}

impl QualityGrade {
    pub fn from_score(score: f64) -> Self {
        match score as u32 {
            90..=100 => QualityGrade::A,
            80..=89 => QualityGrade::B,
            70..=79 => QualityGrade::C,
            60..=69 => QualityGrade::D,
            _ => QualityGrade::F,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DimensionScore {
    pub name: String,
    pub score: f64,
    pub weight: f64,
    pub weighted_score: f64,
}
```

### 12.2 Scoring Algorithm

```rust
/// Default quality dimension weights.
/// From A14: "Default weights shift when mutation data is available."
pub struct QualityWeights {
    pub assertion_quality: f64,   // 0.25
    pub error_coverage: f64,      // 0.20
    pub edge_coverage: f64,       // 0.15
    pub mock_health: f64,         // 0.15
    pub smell_penalty: f64,       // 0.10
    pub isolation: f64,           // 0.10
    pub mutation_score: f64,      // 0.05 (0.20 when mutation data available)
}

impl Default for QualityWeights {
    fn default() -> Self {
        Self {
            assertion_quality: 0.25,
            error_coverage: 0.20,
            edge_coverage: 0.15,
            mock_health: 0.15,
            smell_penalty: 0.10,
            isolation: 0.10,
            mutation_score: 0.05,
        }
    }
}

impl QualityWeights {
    /// Adjusted weights when mutation data is available (A14).
    pub fn with_mutation_data() -> Self {
        Self {
            assertion_quality: 0.20,
            error_coverage: 0.15,
            edge_coverage: 0.10,
            mock_health: 0.15,
            smell_penalty: 0.10,
            isolation: 0.10,
            mutation_score: 0.20,
        }
    }
}

impl TestTopologyEngine {
    /// Compute quality assessment for a single test case.
    pub fn assess_test_quality(
        &self,
        test_case: &TestCase,
        smells: &[TestSmell],
        mutation_score: Option<f64>,
    ) -> TestQualityAssessment {
        let weights = if mutation_score.is_some() {
            QualityWeights::with_mutation_data()
        } else {
            QualityWeights::default()
        };

        // Dimension 1: Assertion quality (0.0 - 1.0)
        let assertion_quality = self.score_assertion_quality(test_case);

        // Dimension 2: Error coverage (0.0 - 1.0)
        let error_coverage = if test_case.quality.has_error_cases { 1.0 } else { 0.0 };

        // Dimension 3: Edge case coverage (0.0 - 1.0)
        let edge_coverage = if test_case.quality.has_edge_cases { 1.0 } else { 0.0 };

        // Dimension 4: Mock health (0.0 - 1.0)
        let mock_health = self.score_mock_health(test_case);

        // Dimension 5: Smell penalty (0.0 - 1.0, where 1.0 = no smells)
        let smell_penalty = self.score_smell_penalty(smells);

        // Dimension 6: Isolation (0.0 - 1.0)
        let isolation = self.score_isolation(test_case);

        // Dimension 7: Mutation score (optional, 0.0 - 1.0)
        let mutation = mutation_score.unwrap_or(0.5); // Default to 0.5 when unavailable

        let dimensions = QualityDimensions {
            assertion_quality,
            error_coverage,
            edge_coverage,
            mock_health,
            smell_penalty,
            isolation,
            mutation_score,
        };

        // Compute weighted composite
        let composite = assertion_quality * weights.assertion_quality
            + error_coverage * weights.error_coverage
            + edge_coverage * weights.edge_coverage
            + mock_health * weights.mock_health
            + smell_penalty * weights.smell_penalty
            + isolation * weights.isolation
            + mutation * weights.mutation_score;

        let composite_score = (composite * 100.0).min(100.0);
        let grade = QualityGrade::from_score(composite_score);

        TestQualityAssessment {
            dimensions,
            composite_score,
            grade,
            breakdown: vec![
                DimensionScore { name: "assertion_quality".into(), score: assertion_quality, weight: weights.assertion_quality, weighted_score: assertion_quality * weights.assertion_quality },
                DimensionScore { name: "error_coverage".into(), score: error_coverage, weight: weights.error_coverage, weighted_score: error_coverage * weights.error_coverage },
                DimensionScore { name: "edge_coverage".into(), score: edge_coverage, weight: weights.edge_coverage, weighted_score: edge_coverage * weights.edge_coverage },
                DimensionScore { name: "mock_health".into(), score: mock_health, weight: weights.mock_health, weighted_score: mock_health * weights.mock_health },
                DimensionScore { name: "smell_penalty".into(), score: smell_penalty, weight: weights.smell_penalty, weighted_score: smell_penalty * weights.smell_penalty },
                DimensionScore { name: "isolation".into(), score: isolation, weight: weights.isolation, weighted_score: isolation * weights.isolation },
                DimensionScore { name: "mutation_score".into(), score: mutation, weight: weights.mutation_score, weighted_score: mutation * weights.mutation_score },
            ],
        }
    }

    fn score_assertion_quality(&self, test_case: &TestCase) -> f64 {
        let count = test_case.quality.assertion_count;
        let variety = test_case.assertions.iter()
            .map(|a| a.assertion_type)
            .collect::<FxHashSet<_>>()
            .len();

        // Score based on count (diminishing returns) and variety
        let count_score = (count as f64 / 5.0).min(1.0); // 5+ assertions = max
        let variety_score = (variety as f64 / 3.0).min(1.0); // 3+ types = max

        count_score * 0.6 + variety_score * 0.4
    }

    fn score_mock_health(&self, test_case: &TestCase) -> f64 {
        let mock_ratio = test_case.quality.mock_ratio;
        // Lower mock ratio = healthier test
        // 0.0 ratio = 1.0 score, 1.0 ratio = 0.0 score
        (1.0 - mock_ratio).max(0.0)
    }

    fn score_smell_penalty(&self, smells: &[TestSmell]) -> f64 {
        if smells.is_empty() {
            return 1.0;
        }
        // Each smell reduces score. Critical smells reduce more.
        let penalty: f64 = smells.iter()
            .map(|s| match s.severity {
                SmellSeverity::Critical => 0.25,
                SmellSeverity::Major => 0.15,
                SmellSeverity::Minor => 0.05,
                SmellSeverity::Info => 0.02,
            })
            .sum();
        (1.0 - penalty).max(0.0)
    }

    fn score_isolation(&self, test_case: &TestCase) -> f64 {
        // Heuristic: tests with low setup ratio and no shared state indicators
        let setup_penalty = test_case.quality.setup_ratio.min(1.0);
        (1.0 - setup_penalty * 0.5).max(0.0)
    }
}
```


---

## 13. Test Smell Detection Engine (24 Smells)

### 13.1 Architecture (A14 — 19 Canonical + 5 Flakiness Smells)

From A14: "19 canonical smells (from testsmells.org) + 5 flakiness-inducing smells.
Detected during extraction (zero additional AST traversal). Each smell has severity,
line, suggestion, auto_fixable flag."

Test smells are detected during the extraction phase — the same AST traversal that
extracts test cases also identifies smells. This is zero-cost additional analysis.

```rust
/// A test smell detected in a test file or test case.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestSmell {
    /// Smell identifier.
    pub smell_type: TestSmellType,
    /// Human-readable name.
    pub name: String,
    /// Severity level.
    pub severity: SmellSeverity,
    /// File path.
    pub file: String,
    /// Line number where the smell occurs.
    pub line: u32,
    /// Test case name (if smell is within a specific test).
    pub test_name: Option<String>,
    /// Description of the issue.
    pub description: String,
    /// Suggested fix.
    pub suggestion: String,
    /// Whether this smell can be auto-fixed.
    pub auto_fixable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SmellSeverity {
    Critical,  // Likely causes test failures or false passes
    Major,     // Significantly reduces test value
    Minor,     // Reduces test clarity or maintainability
    Info,      // Style/convention issue
}
```

### 13.2 Canonical Test Smells (19 — from testsmells.org)

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TestSmellType {
    // === 19 Canonical Smells (testsmells.org) ===

    /// Multiple unrelated assertions without clear grouping.
    /// Detection: >5 assertions of different types in one test.
    AssertionRoulette,          // Severity: Major

    /// Test logic contains if/else/switch/match.
    /// Detection: conditional statements in test body.
    ConditionalTestLogic,       // Severity: Major

    /// Test with no assertions.
    /// Detection: assertion_count == 0.
    EmptyTest,                  // Severity: Critical

    /// Hardcoded magic numbers in assertions.
    /// Detection: numeric literals in assert comparisons.
    MagicNumberTest,            // Severity: Minor

    /// Test depends on external resources (files, network, DB).
    /// Detection: file I/O, HTTP calls, DB queries in test body.
    MysteryGuest,               // Severity: Major

    /// Test uses sleep/delay for synchronization.
    /// Detection: sleep(), setTimeout(), time.sleep() calls.
    SleepyTest,                 // Severity: Critical (flakiness)

    /// Test with no assertions (alias for EmptyTest in some taxonomies).
    /// Detection: test body has calls but no assertions.
    UnknownTest,                // Severity: Critical

    /// Test verifies behavior through side effects, not direct calls.
    /// Detection: test asserts on objects not directly returned by SUT.
    IndirectTesting,            // Severity: Minor

    /// Tests that interfere with each other via shared state.
    /// Detection: global variable mutation, shared fixtures without isolation.
    TestRunWar,                 // Severity: Critical (flakiness)

    /// Async test without await/assertion on result.
    /// Detection: async call without await or .then() assertion.
    FireAndForget,              // Severity: Critical

    /// Test constructor does work (should be in setUp).
    /// Detection: non-trivial constructor in test class.
    ConstructorInitialization,  // Severity: Minor

    /// Default test case (auto-generated, never customized).
    /// Detection: test name matches default patterns.
    DefaultTest,                // Severity: Minor

    /// Test depends on execution order.
    /// Detection: shared mutable state between tests without reset.
    DependentTest,              // Severity: Major

    /// Duplicate assertion logic across tests.
    /// Detection: identical assertion sequences in multiple tests.
    DuplicateAssert,            // Severity: Minor

    /// Test is too eager — tests too many things.
    /// Detection: >10 assertions or >5 distinct function calls.
    EagerTest,                  // Severity: Minor

    /// Test ignores exceptions (empty catch blocks).
    /// Detection: try/catch with empty catch in test body.
    ExceptionHandling,          // Severity: Major

    /// Test has too much setup relative to actual testing.
    /// Detection: setup_ratio > 0.7.
    GeneralFixture,             // Severity: Minor

    /// Assertion message is missing or unhelpful.
    /// Detection: assert without message parameter.
    LazyTest,                   // Severity: Info

    /// Test is overly sensitive to implementation details.
    /// Detection: mocks internal methods, asserts on call order.
    SensitiveEquality,          // Severity: Minor

    // === 5 Flakiness-Inducing Smells (A14) ===

    /// Test depends on system time (Date.now(), time.time()).
    /// Detection: time-dependent calls without mocking.
    TimeDependency,             // Severity: Critical (flakiness)

    /// Test depends on random values without seeding.
    /// Detection: Math.random(), random.random() without seed.
    RandomDependency,           // Severity: Major (flakiness)

    /// Test depends on network availability.
    /// Detection: HTTP/TCP calls without mocking.
    NetworkDependency,          // Severity: Critical (flakiness)

    /// Test depends on file system state.
    /// Detection: file reads/writes without tmpdir/cleanup.
    FileSystemDependency,       // Severity: Major (flakiness)

    /// Test has race conditions (async without proper sync).
    /// Detection: parallel async operations without barriers.
    RaceCondition,              // Severity: Critical (flakiness)
}
```

### 13.3 Smell Detection During Extraction

Smells are detected during the same AST traversal that extracts test cases.
Each extractor calls `detect_smells_in_test()` for each test case it extracts.

```rust
impl TestTopologyEngine {
    /// Detect test smells in a test extraction.
    /// Called after extraction, operates on the extraction result.
    fn detect_smells(
        &self,
        mut extraction: TestExtraction,
    ) -> Result<TestExtraction, TestTopologyError> {
        let mut file_smells = Vec::new();

        for test_case in &extraction.test_cases {
            // EmptyTest / UnknownTest: no assertions
            if test_case.quality.assertion_count == 0 {
                file_smells.push(TestSmell {
                    smell_type: TestSmellType::EmptyTest,
                    name: "Empty Test".to_string(),
                    severity: SmellSeverity::Critical,
                    file: extraction.file.clone(),
                    line: test_case.line,
                    test_name: Some(test_case.qualified_name.clone()),
                    description: "Test has no assertions — it can never fail.".to_string(),
                    suggestion: "Add assertions to verify expected behavior.".to_string(),
                    auto_fixable: false,
                });
            }

            // AssertionRoulette: >5 assertions of different types
            if test_case.quality.assertion_count > 5 {
                let types: FxHashSet<_> = test_case.assertions.iter()
                    .map(|a| a.assertion_type)
                    .collect();
                if types.len() > 3 {
                    file_smells.push(TestSmell {
                        smell_type: TestSmellType::AssertionRoulette,
                        name: "Assertion Roulette".to_string(),
                        severity: SmellSeverity::Major,
                        file: extraction.file.clone(),
                        line: test_case.line,
                        test_name: Some(test_case.qualified_name.clone()),
                        description: format!(
                            "Test has {} assertions of {} different types — hard to diagnose failures.",
                            test_case.quality.assertion_count, types.len()
                        ),
                        suggestion: "Split into focused tests with fewer, related assertions.".to_string(),
                        auto_fixable: false,
                    });
                }
            }

            // GeneralFixture: setup_ratio > 0.7
            if test_case.quality.setup_ratio > 0.7 {
                file_smells.push(TestSmell {
                    smell_type: TestSmellType::GeneralFixture,
                    name: "General Fixture".to_string(),
                    severity: SmellSeverity::Minor,
                    file: extraction.file.clone(),
                    line: test_case.line,
                    test_name: Some(test_case.qualified_name.clone()),
                    description: format!(
                        "Setup is {:.0}% of the test — most setup may be unused.",
                        test_case.quality.setup_ratio * 100.0
                    ),
                    suggestion: "Move unused setup to specific tests or use targeted fixtures.".to_string(),
                    auto_fixable: false,
                });
            }

            // EagerTest: >10 assertions or >5 distinct function calls
            if test_case.quality.assertion_count > 10 || test_case.direct_calls.len() > 5 {
                file_smells.push(TestSmell {
                    smell_type: TestSmellType::EagerTest,
                    name: "Eager Test".to_string(),
                    severity: SmellSeverity::Minor,
                    file: extraction.file.clone(),
                    line: test_case.line,
                    test_name: Some(test_case.qualified_name.clone()),
                    description: "Test verifies too many things — split into focused tests.".to_string(),
                    suggestion: "Extract separate test cases for each behavior.".to_string(),
                    auto_fixable: false,
                });
            }

            // SleepyTest: sleep/delay calls
            // TimeDependency, NetworkDependency, FileSystemDependency, RandomDependency
            // These are detected by checking direct_calls against known patterns
            self.detect_flakiness_smells(test_case, &extraction.file, &mut file_smells);
        }

        // FireAndForget: async tests without await
        self.detect_fire_and_forget(&extraction, &mut file_smells);

        extraction.smells = file_smells;
        Ok(extraction)
    }
}
```

---

## 14. Fixture & Setup Analysis (Cross-Language)

### 14.1 Architecture (A14 — Expanded Beyond Python)

V1 only detected Python pytest fixtures. V2 detects fixtures and setup patterns across
all supported languages.

| Language | Fixture/Setup Patterns | V1 | V2 |
|----------|----------------------|----|----|
| Python | @pytest.fixture (scope, provides) | ✓ | ✓ |
| Java | @Rule, @ClassRule, @ExtendWith (JUnit5) | ✗ | ✓ |
| C# | [SetUp], [OneTimeSetUp], IClassFixture<T> | ✗ | ✓ |
| Go | TestMain, test helper functions | ✗ | ✓ |
| Rust | rstest #[fixture] | ✗ | ✓ |
| TypeScript | beforeEach/afterEach (already as SetupBlock) | ✓ | ✓ |
| PHP | setUp/tearDown (already as SetupBlock) | ✓ | ✓ |
| C++ | SetUp/TearDown (GTest), SECTION (Catch2) | ✗ | ✓ |

### 14.2 Fixture Scope Analysis

```rust
impl TestTopologyEngine {
    /// Analyze fixture usage across all test files.
    /// Returns fixture dependency graph and scope analysis.
    pub fn analyze_fixtures(
        &self,
        extractions: &[TestExtraction],
    ) -> FixtureAnalysis {
        let mut fixtures_by_scope: FxHashMap<FixtureScope, Vec<&FixtureInfo>> =
            FxHashMap::default();
        let mut fixture_usage: FxHashMap<String, usize> = FxHashMap::default();

        for extraction in extractions {
            for fixture in &extraction.fixtures {
                fixtures_by_scope.entry(fixture.scope)
                    .or_default()
                    .push(fixture);
                *fixture_usage.entry(fixture.name.clone()).or_insert(0) += 1;
            }
        }

        FixtureAnalysis {
            total_fixtures: extractions.iter()
                .map(|e| e.fixtures.len())
                .sum(),
            by_scope: fixtures_by_scope.into_iter()
                .map(|(scope, fixtures)| (scope, fixtures.len()))
                .collect(),
            most_used: fixture_usage.into_iter()
                .sorted_by(|a, b| b.1.cmp(&a.1))
                .take(10)
                .collect(),
        }
    }
}
```

---

## 15. Incremental Analysis & Caching

### 15.1 Architecture (A14 — Content-Hash Invalidation)

From A14: "Content-hash-based invalidation with dependency-aware propagation. When source
file changes, re-map all tests covering it. When test file changes, re-extract. Cache in
SQLite `test_extraction_cache` table with MessagePack-serialized extraction results.
Target: <500ms incremental for 10 changed files."

```rust
impl TestTopologyEngine {
    /// Incremental analysis: only re-analyze changed files.
    pub fn analyze_incremental(
        &self,
        scan_diff: &ScanDiff,
    ) -> Result<TestTopologySummary, TestTopologyError> {
        let span = tracing::info_span!("test_topology_incremental",
            added = scan_diff.added.len(),
            modified = scan_diff.modified.len(),
            removed = scan_diff.removed.len());
        let _guard = span.enter();

        // Step 1: Remove data for deleted files
        for file in &scan_diff.removed {
            self.remove_file_data(file)?;
        }

        // Step 2: Re-extract changed test files
        let changed_test_files: Vec<_> = scan_diff.added.iter()
            .chain(scan_diff.modified.iter())
            .filter(|f| self.is_test_file(f))
            .collect();

        for file in &changed_test_files {
            let content = std::fs::read_to_string(file)
                .map_err(|e| TestTopologyError::Io(file.clone(), e))?;
            let language = detect_language(file);
            if let Some(extraction) = self.extract_file(&content, file, language)? {
                self.persist_extraction(&extraction)?;
            }
        }

        // Step 3: Re-map tests covering changed source files
        let changed_source_files: Vec<_> = scan_diff.added.iter()
            .chain(scan_diff.modified.iter())
            .filter(|f| !self.is_test_file(f))
            .collect();

        if !changed_source_files.is_empty() {
            // Find all tests that cover changed source files
            let source_to_tests = self.source_to_tests.read().unwrap();
            let mut affected_tests = FxHashSet::default();
            for source in &changed_source_files {
                if let Some(tests) = source_to_tests.get(source.as_str()) {
                    for test in tests {
                        affected_tests.insert(test.clone());
                    }
                }
            }

            // Re-build coverage map for affected tests
            if !affected_tests.is_empty() {
                self.rebuild_coverage_for_tests(&affected_tests)?;
            }
        }

        // Step 4: Return updated summary
        self.compute_summary()
    }

    /// Check extraction cache before re-extracting.
    fn check_extraction_cache(
        &self,
        content_hash: u64,
    ) -> Option<TestExtraction> {
        // Check in-memory cache first
        if let Some(cached) = self.extraction_cache.lock().unwrap().get(&content_hash) {
            return Some(cached.clone());
        }

        // Check SQLite cache (MessagePack-serialized)
        self.db.query_extraction_cache(content_hash).ok().flatten()
    }

    /// Persist extraction to SQLite cache.
    fn persist_extraction_cache(
        &self,
        content_hash: u64,
        extraction: &TestExtraction,
    ) -> Result<(), TestTopologyError> {
        let serialized = rmp_serde::to_vec(extraction)
            .map_err(|e| TestTopologyError::Serialization(e.to_string()))?;
        self.db.insert_extraction_cache(content_hash, &serialized)
            .map_err(TestTopologyError::Storage)
    }
}
```

### 15.2 Performance Target

From A14: "<500ms incremental for 10 changed files."

This is achievable because:
1. Extraction cache avoids re-parsing unchanged test files
2. Only affected coverage mappings are rebuilt (not the entire map)
3. Rayon parallelizes extraction of changed files
4. SQLite batch writer minimizes I/O overhead


---

## 16. Integration with Impact Analysis

### 16.1 TestCoverageMap — The Primary Integration Point

The impact analysis engine (16-IMPACT-ANALYSIS-V2-PREP.md §9, §14) consumes a
`TestCoverageMap` from the test topology engine. This map provides the coverage factor
in the impact risk scoring formula (0.15 weight).

```rust
/// The coverage map exposed to impact analysis.
/// Type alias for the coverage map stored in TestTopologyEngine.
pub type TestCoverageMap = FxHashMap<String, FunctionTestCoverage>;

impl TestTopologyEngine {
    /// Get the coverage map for consumption by impact analysis.
    /// Returns a snapshot (cloned) to avoid holding the read lock.
    pub fn get_coverage_map(&self) -> TestCoverageMap {
        self.coverage_map.read().unwrap()
            .iter()
            .map(|(k, v)| (self.interner.resolve(k).to_string(), v.clone()))
            .collect()
    }

    /// Check if a specific function has test coverage.
    /// Used by impact analysis for per-function coverage factor.
    pub fn has_coverage(&self, function_id: &str) -> bool {
        let map = self.coverage_map.read().unwrap();
        if let Some(spur) = self.interner.get(function_id) {
            map.get(&spur).map_or(false, |c| c.coverage_ratio > 0.0)
        } else {
            false
        }
    }

    /// Get covering test count for a function.
    /// Used by impact analysis blast radius computation.
    pub fn covering_test_count(&self, function_id: &str) -> usize {
        let map = self.coverage_map.read().unwrap();
        if let Some(spur) = self.interner.get(function_id) {
            map.get(&spur).map_or(0, |c| c.covering_tests.len())
        } else {
            0
        }
    }

    /// Recommend tests for a set of affected functions.
    /// Used by impact analysis change impact results.
    pub fn recommend_tests_for_functions(
        &self,
        affected_functions: &[String],
    ) -> Vec<String> {
        let map = self.coverage_map.read().unwrap();
        let mut recommended = FxHashSet::default();

        for func_id in affected_functions {
            if let Some(spur) = self.interner.get(func_id) {
                if let Some(cov) = map.get(&spur) {
                    for test in &cov.covering_tests {
                        recommended.insert(test.test_id.clone());
                    }
                }
            }
        }

        recommended.into_iter().collect()
    }
}
```

### 16.2 Impact Risk Scoring Integration

From 16-IMPACT-ANALYSIS-V2-PREP.md §7:

| Factor | Weight | Source |
|--------|--------|--------|
| Callers | 0.20 | Call graph |
| Entry Points | 0.20 | Call graph |
| Data | 0.20 | Boundary detection |
| Taint | 0.20 | Taint analysis |
| **Coverage** | **0.15** | **Test topology** |
| Depth | 0.05 | Call graph |

The coverage factor: functions with no test coverage get +15 to their risk score.
Functions with mock-only coverage get +10. Functions with direct test coverage get +0.

---

## 17. Integration with Quality Gates

### 17.1 Test Coverage Gate

The quality gate system (Level 3) includes a test coverage gate that consumes
test topology data. The gate evaluates:

1. **Function-level coverage threshold**: Minimum percentage of functions with tests
2. **File-level coverage threshold**: Minimum percentage of files with tests
3. **Critical function coverage**: All entry points and sensitive-data functions must have tests
4. **Mock-only coverage warning**: Flag functions with only mock coverage
5. **Quality grade threshold**: Minimum average quality grade (e.g., C or above)

```rust
/// Test coverage gate assessment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCoverageAssessment {
    /// Whether the gate passes.
    pub passed: bool,
    /// Function-level coverage percentage.
    pub function_coverage: f64,
    /// File-level coverage percentage.
    pub file_coverage: f64,
    /// Critical functions without coverage.
    pub uncovered_critical: Vec<UncoveredFunction>,
    /// Functions with mock-only coverage.
    pub mock_only_functions: Vec<String>,
    /// Average quality grade.
    pub avg_quality_grade: QualityGrade,
    /// Total test smells (critical + major).
    pub critical_smells: usize,
    /// Gate failure reasons (if any).
    pub failure_reasons: Vec<String>,
}

impl TestTopologyEngine {
    /// Assess test coverage for quality gate evaluation.
    pub fn assess_for_quality_gate(
        &self,
        policy: &TestCoveragePolicy,
    ) -> Result<TestCoverageAssessment, TestTopologyError> {
        let summary = self.compute_summary()?;
        let coverage_map = self.coverage_map.read().unwrap();

        let mut failure_reasons = Vec::new();

        // Check function coverage threshold
        if summary.function_coverage_percent < policy.min_function_coverage {
            failure_reasons.push(format!(
                "Function coverage {:.1}% below threshold {:.1}%",
                summary.function_coverage_percent, policy.min_function_coverage
            ));
        }

        // Check file coverage threshold
        if summary.file_coverage_percent < policy.min_file_coverage {
            failure_reasons.push(format!(
                "File coverage {:.1}% below threshold {:.1}%",
                summary.file_coverage_percent, policy.min_file_coverage
            ));
        }

        // Check critical function coverage
        let uncovered_critical = self.find_uncovered_critical_functions()?;
        if !uncovered_critical.is_empty() && policy.require_critical_coverage {
            failure_reasons.push(format!(
                "{} critical functions without test coverage",
                uncovered_critical.len()
            ));
        }

        // Check quality grade
        if (summary.avg_quality_grade as u8) > (policy.min_quality_grade as u8) {
            failure_reasons.push(format!(
                "Average quality grade {:?} below minimum {:?}",
                summary.avg_quality_grade, policy.min_quality_grade
            ));
        }

        Ok(TestCoverageAssessment {
            passed: failure_reasons.is_empty(),
            function_coverage: summary.function_coverage_percent,
            file_coverage: summary.file_coverage_percent,
            uncovered_critical,
            mock_only_functions: self.find_mock_only_functions(),
            avg_quality_grade: summary.avg_quality_grade,
            critical_smells: summary.smells_by_severity
                .get(&SmellSeverity::Critical).copied().unwrap_or(0),
            failure_reasons,
        })
    }
}

/// Quality gate policy for test coverage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCoveragePolicy {
    pub min_function_coverage: f64,     // Default: 60.0
    pub min_file_coverage: f64,         // Default: 70.0
    pub require_critical_coverage: bool, // Default: true
    pub min_quality_grade: QualityGrade, // Default: C
    pub max_critical_smells: usize,     // Default: 0
}
```

---

## 18. Integration with Constraint Detection

### 18.1 Test Category Constraints

The constraint detection system (Level 2C) mines test-related invariants from the
test topology data. These become enforceable constraints.

From DRIFT-V2-SYSTEMS-REFERENCE.md: "Test Topology: Coverage requirements, test patterns"
feeds into constraint categories: `test`.

Examples of mined constraints:
- `must_have_test(UserService.createUser)` — critical function must have a test
- `test_coverage_min(auth/, 80%)` — auth module must maintain 80% coverage
- `no_internal_mocks(PaymentService)` — payment service tests must not mock internals
- `max_mock_ratio(0.5)` — no test should have >50% mock ratio

```rust
impl TestTopologyEngine {
    /// Generate constraint candidates from test topology data.
    /// Consumed by the constraint detection system.
    pub fn generate_constraint_candidates(&self) -> Vec<ConstraintCandidate> {
        let mut candidates = Vec::new();
        let coverage_map = self.coverage_map.read().unwrap();

        // Constraint: critical functions must have tests
        for (func_id, cov) in coverage_map.iter() {
            let func_str = self.interner.resolve(func_id);
            if cov.is_directly_tested && self.is_critical_function(func_id) {
                candidates.push(ConstraintCandidate {
                    constraint_type: "must_have_test".to_string(),
                    target: func_str.to_string(),
                    category: "test".to_string(),
                    confidence: 0.85,
                    evidence: format!("Function {} is critical and currently tested", func_str),
                });
            }
        }

        candidates
    }
}
```

---

## 19. Storage Schema (drift.db)

### 19.1 Tables

From 02-STORAGE-V2-PREP.md: Test Topology tables are `test_files`, `test_cases`,
`test_coverage`, `mock_statements`, `test_smells`, `uncovered_functions`.

Migration file: `004_test_topology.sql`

```sql
-- Test Topology tables for drift.db
-- Migration: 004_test_topology.sql

-- Test files: one row per test file
CREATE TABLE test_files (
    id INTEGER PRIMARY KEY,
    file TEXT NOT NULL UNIQUE,
    framework TEXT NOT NULL,
    language TEXT NOT NULL,
    content_hash INTEGER NOT NULL,
    test_case_count INTEGER NOT NULL DEFAULT 0,
    mock_count INTEGER NOT NULL DEFAULT 0,
    smell_count INTEGER NOT NULL DEFAULT 0,
    avg_quality_score REAL NOT NULL DEFAULT 0.0,
    quality_grade TEXT NOT NULL DEFAULT 'F',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

CREATE INDEX idx_test_files_framework ON test_files(framework);
CREATE INDEX idx_test_files_language ON test_files(language);
CREATE INDEX idx_test_files_content_hash ON test_files(content_hash);

-- Test cases: one row per test case
CREATE TABLE test_cases (
    id INTEGER PRIMARY KEY,
    test_file_id INTEGER NOT NULL REFERENCES test_files(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    qualified_name TEXT NOT NULL,
    parent_block TEXT,
    line INTEGER NOT NULL,
    end_line INTEGER NOT NULL,
    test_type TEXT NOT NULL DEFAULT 'unknown',
    is_async INTEGER NOT NULL DEFAULT 0,
    is_skipped INTEGER NOT NULL DEFAULT 0,
    is_parameterized INTEGER NOT NULL DEFAULT 0,
    parameter_count INTEGER NOT NULL DEFAULT 0,
    assertion_count INTEGER NOT NULL DEFAULT 0,
    has_error_cases INTEGER NOT NULL DEFAULT 0,
    has_edge_cases INTEGER NOT NULL DEFAULT 0,
    mock_ratio REAL NOT NULL DEFAULT 0.0,
    setup_ratio REAL NOT NULL DEFAULT 0.0,
    quality_score REAL NOT NULL DEFAULT 0.0,
    quality_grade TEXT NOT NULL DEFAULT 'F',
    direct_calls TEXT,  -- JSON array of function IDs
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

CREATE INDEX idx_test_cases_file ON test_cases(test_file_id);
CREATE INDEX idx_test_cases_type ON test_cases(test_type);
CREATE INDEX idx_test_cases_quality ON test_cases(quality_score);
CREATE INDEX idx_test_cases_skipped ON test_cases(is_skipped);

-- Test coverage: maps test cases to production functions
CREATE TABLE test_coverage (
    id INTEGER PRIMARY KEY,
    test_case_id INTEGER NOT NULL REFERENCES test_cases(id) ON DELETE CASCADE,
    function_id TEXT NOT NULL,
    source_file TEXT NOT NULL,
    reach_type TEXT NOT NULL,  -- 'direct', 'transitive', 'mocked'
    depth INTEGER NOT NULL DEFAULT 1,
    confidence REAL NOT NULL DEFAULT 0.0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

CREATE INDEX idx_test_coverage_function ON test_coverage(function_id);
CREATE INDEX idx_test_coverage_source ON test_coverage(source_file);
CREATE INDEX idx_test_coverage_reach ON test_coverage(reach_type);
CREATE INDEX idx_test_coverage_test ON test_coverage(test_case_id);

-- Mock statements: one row per mock in a test file
CREATE TABLE mock_statements (
    id INTEGER PRIMARY KEY,
    test_file_id INTEGER NOT NULL REFERENCES test_files(id) ON DELETE CASCADE,
    target TEXT NOT NULL,
    mock_type TEXT NOT NULL,
    line INTEGER NOT NULL,
    is_external INTEGER NOT NULL DEFAULT 0,
    has_implementation INTEGER NOT NULL DEFAULT 0,
    category TEXT NOT NULL DEFAULT 'external',
    is_deep_mock INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

CREATE INDEX idx_mock_statements_file ON mock_statements(test_file_id);
CREATE INDEX idx_mock_statements_target ON mock_statements(target);
CREATE INDEX idx_mock_statements_category ON mock_statements(category);

-- Test smells: one row per detected smell
CREATE TABLE test_smells (
    id INTEGER PRIMARY KEY,
    test_file_id INTEGER NOT NULL REFERENCES test_files(id) ON DELETE CASCADE,
    test_case_id INTEGER REFERENCES test_cases(id) ON DELETE CASCADE,
    smell_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    line INTEGER NOT NULL,
    description TEXT NOT NULL,
    suggestion TEXT NOT NULL,
    auto_fixable INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

CREATE INDEX idx_test_smells_file ON test_smells(test_file_id);
CREATE INDEX idx_test_smells_type ON test_smells(smell_type);
CREATE INDEX idx_test_smells_severity ON test_smells(severity);

-- Uncovered functions: high-risk functions without test coverage
CREATE TABLE uncovered_functions (
    id INTEGER PRIMARY KEY,
    function_id TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    qualified_name TEXT NOT NULL,
    file TEXT NOT NULL,
    line INTEGER NOT NULL,
    risk_score REAL NOT NULL DEFAULT 0.0,
    risk_level TEXT NOT NULL DEFAULT 'low',
    is_entry_point INTEGER NOT NULL DEFAULT 0,
    accesses_sensitive_data INTEGER NOT NULL DEFAULT 0,
    caller_count INTEGER NOT NULL DEFAULT 0,
    on_taint_path INTEGER NOT NULL DEFAULT 0,
    possible_reasons TEXT,  -- JSON array of UncoveredReason strings
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

CREATE INDEX idx_uncovered_risk ON uncovered_functions(risk_score DESC);
CREATE INDEX idx_uncovered_level ON uncovered_functions(risk_level);
CREATE INDEX idx_uncovered_file ON uncovered_functions(file);

-- Extraction cache: MessagePack-serialized extraction results
CREATE TABLE test_extraction_cache (
    content_hash INTEGER PRIMARY KEY,
    extraction_data BLOB NOT NULL,  -- MessagePack-serialized TestExtraction
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;
```

### 19.2 Batch Writer Integration

All writes use the batch writer from 02-STORAGE-V2-PREP.md for optimal performance.
Test topology writes are batched per-file: one transaction per test file extraction.

```rust
impl TestTopologyEngine {
    /// Persist all extraction results to drift.db via batch writer.
    fn persist_all(
        &self,
        extractions: &[TestExtraction],
    ) -> Result<(), TestTopologyError> {
        let writer = self.db.writer();
        let mut conn = writer.lock().unwrap();

        let tx = conn.transaction()
            .map_err(TestTopologyError::Storage)?;

        // Clear existing data (full rebuild)
        tx.execute_batch("
            DELETE FROM test_smells;
            DELETE FROM mock_statements;
            DELETE FROM test_coverage;
            DELETE FROM test_cases;
            DELETE FROM test_files;
            DELETE FROM uncovered_functions;
        ").map_err(TestTopologyError::Storage)?;

        for extraction in extractions {
            self.persist_extraction_tx(&tx, extraction)?;
        }

        tx.commit().map_err(TestTopologyError::Storage)?;
        Ok(())
    }
}
```


---

## 20. NAPI Interface

### 20.1 NAPI Functions (4 — from 03-NAPI-BRIDGE-V2-PREP.md §10.8)

From the NAPI bridge spec, test topology exposes 4 functions following the
command/query pattern: one async command function (analyze) and three sync query functions.

| Function | Sync/Async | Returns | Description |
|----------|-----------|---------|-------------|
| `analyze_test_topology(root)` | Async | `TestTopologySummary` | Full test analysis: extract, map, score, persist |
| `query_test_coverage(file?)` | Sync | `CoverageResult` | Coverage per file or function |
| `query_minimum_test_set(changed_files)` | Sync | `MinTestSetResult` | Tests to run for changes |
| `query_uncovered_functions()` | Sync | `UncoveredFunction[]` | High-risk untested functions |

### 20.2 Command Function: analyze_test_topology

```rust
use napi::bindgen_prelude::*;

#[napi(object)]
pub struct NapiTestTopologySummary {
    pub test_file_count: u32,
    pub test_case_count: u32,
    pub source_file_count: u32,
    pub covered_source_files: u32,
    pub total_functions: u32,
    pub covered_functions: u32,
    pub file_coverage_percent: f64,
    pub function_coverage_percent: f64,
    pub avg_mock_ratio: f64,
    pub avg_quality_score: f64,
    pub avg_quality_grade: String,
    pub total_smells: u32,
    pub skipped_test_count: u32,
    pub parameterized_test_count: u32,
    pub duration_ms: u32,
    pub status: String,
}

pub struct AnalyzeTestTopologyTask {
    root: String,
}

#[napi]
impl Task for AnalyzeTestTopologyTask {
    type Output = NapiTestTopologySummary;
    type JsValue = NapiTestTopologySummary;

    fn compute(&mut self) -> napi::Result<Self::Output> {
        let rt = crate::runtime::get()?;
        let start = std::time::Instant::now();

        // Run full test topology analysis
        let summary = drift_core::test_topology::analyze(
            &PathBuf::from(&self.root),
            &rt.db,
            rt.call_graph.as_ref(),
            &rt.config.test_topology,
        ).map_err(to_napi_error)?;

        Ok(NapiTestTopologySummary::from(summary))
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> napi::Result<Self::JsValue> {
        Ok(output)
    }
}

#[napi]
pub fn analyze_test_topology(root: String) -> AsyncTask<AnalyzeTestTopologyTask> {
    AsyncTask::new(AnalyzeTestTopologyTask { root })
}
```

### 20.3 Query Functions

```rust
/// Query test coverage for a specific file or all files.
#[napi]
pub fn query_test_coverage(file: Option<String>) -> napi::Result<serde_json::Value> {
    let rt = crate::runtime::get()?;

    let result = match file {
        Some(f) => drift_core::test_topology::query_file_coverage(&rt.db, &f),
        None => drift_core::test_topology::query_all_coverage(&rt.db),
    }.map_err(to_napi_error)?;

    serde_json::to_value(&result)
        .map_err(|e| napi::Error::from_reason(format!("[INTERNAL_ERROR] {e}")))
}

/// Query minimum test set for changed files.
#[napi]
pub fn query_minimum_test_set(changed_files: Vec<String>) -> napi::Result<serde_json::Value> {
    let rt = crate::runtime::get()?;

    let result = drift_core::test_topology::query_minimum_test_set(
        &rt.db,
        &changed_files,
    ).map_err(to_napi_error)?;

    serde_json::to_value(&result)
        .map_err(|e| napi::Error::from_reason(format!("[INTERNAL_ERROR] {e}")))
}

/// Query uncovered functions with risk scores.
#[napi]
pub fn query_uncovered_functions() -> napi::Result<serde_json::Value> {
    let rt = crate::runtime::get()?;

    let result = drift_core::test_topology::query_uncovered_functions(&rt.db)
        .map_err(to_napi_error)?;

    serde_json::to_value(&result)
        .map_err(|e| napi::Error::from_reason(format!("[INTERNAL_ERROR] {e}")))
}
```

### 20.4 Error Codes

```rust
pub mod test_topology_codes {
    pub const TEST_TOPOLOGY_ERROR: &str = "TEST_TOPOLOGY_ERROR";
    pub const EXTRACTION_FAILED: &str = "EXTRACTION_FAILED";
    pub const UNSUPPORTED_FRAMEWORK: &str = "UNSUPPORTED_FRAMEWORK";
    pub const COVERAGE_MAP_ERROR: &str = "COVERAGE_MAP_ERROR";
    pub const CALL_GRAPH_REQUIRED: &str = "CALL_GRAPH_REQUIRED";
}

impl DriftErrorCode for TestTopologyError {
    fn error_code(&self) -> &'static str {
        match self {
            TestTopologyError::UnsupportedLanguage(_) => "UNSUPPORTED_LANGUAGE",
            TestTopologyError::ExtractionFailed { .. } => "EXTRACTION_FAILED",
            TestTopologyError::UnsupportedFramework(_) => "UNSUPPORTED_FRAMEWORK",
            TestTopologyError::CoverageMapError(_) => "COVERAGE_MAP_ERROR",
            TestTopologyError::CallGraphRequired => "CALL_GRAPH_REQUIRED",
            TestTopologyError::Storage(_) => "STORAGE_ERROR",
            TestTopologyError::Io(_, _) => "SCAN_ERROR",
            TestTopologyError::Serialization(_) => "INTERNAL_ERROR",
        }
    }
}
```

---

## 21. MCP Tool Interface

### 21.1 drift_test_topology Tool

From DRIFT-V2-FULL-SYSTEM-AUDIT.md Cat 07: `drift_test_topology` is in the Analysis
tool category of the drift-analysis MCP server.

```typescript
// MCP tool definition (TS — routing layer)
const drift_test_topology = {
    name: "drift_test_topology",
    description: "Analyze test topology: coverage mapping, uncovered functions, " +
        "minimum test set, mock analysis, test quality, and test smells.",
    inputSchema: {
        type: "object",
        properties: {
            action: {
                type: "string",
                enum: ["summary", "coverage", "uncovered", "minimum_set",
                       "mocks", "quality", "smells"],
                description: "Analysis action to perform",
            },
            file: {
                type: "string",
                description: "File path for file-specific queries (coverage, quality)",
            },
            changed_files: {
                type: "array",
                items: { type: "string" },
                description: "Changed files for minimum test set calculation",
            },
            severity: {
                type: "string",
                enum: ["critical", "major", "minor", "info"],
                description: "Minimum severity filter for smells",
            },
            limit: {
                type: "number",
                description: "Maximum results to return (default: 20)",
            },
        },
        required: ["action"],
    },
};
```

### 21.2 MCP Tool Actions

| Action | Description | Returns |
|--------|-------------|---------|
| `summary` | Full test topology summary | TestTopologySummary |
| `coverage` | Coverage for a file or all files | CoverageResult |
| `uncovered` | High-risk uncovered functions | UncoveredFunction[] |
| `minimum_set` | Minimum tests for changed files | MinimumTestSet |
| `mocks` | Mock analysis across all tests | MockAnalysis |
| `quality` | Quality scores and grades | QualityAssessment[] |
| `smells` | Test smells with severity filter | TestSmell[] |

### 21.3 MCP Response Format

```json
{
    "summary": {
        "test_files": 245,
        "test_cases": 1832,
        "function_coverage": "73.2%",
        "avg_quality_grade": "B",
        "total_smells": 47,
        "critical_smells": 3
    },
    "details": { ... },
    "stats": {
        "frameworks": { "jest": 120, "vitest": 85, "pytest": 40 },
        "coverage_by_module": { ... }
    }
}
```

---

## 22. CLI Interface

### 22.1 Command Group: drift test-topology

From DRIFT-V2-FULL-SYSTEM-AUDIT.md Cat 10:
`test-topology` → analyze, coverage, minimum-set, mocks

V2 expands with quality and smells subcommands.

```
drift test-topology analyze              # Full test topology analysis
drift test-topology coverage [file]      # Coverage report (file or project)
drift test-topology coverage --uncovered # Show uncovered functions
drift test-topology minimum-set <files>  # Minimum tests for changed files
drift test-topology mocks                # Mock analysis report
drift test-topology mocks --deep         # Show deep mock details
drift test-topology quality              # Quality scores and grades
drift test-topology quality --grade C    # Filter by minimum grade
drift test-topology smells               # Test smell report
drift test-topology smells --severity critical  # Filter by severity
drift test-topology smells --fixable     # Show only auto-fixable smells
```

### 22.2 CLI Output Examples

```
$ drift test-topology analyze

Test Topology Analysis
═══════════════════════════════════════════════════════════
  Test Files:     245 across 8 frameworks
  Test Cases:     1,832 (47 skipped, 89 parameterized)
  Coverage:       73.2% functions, 81.5% files
  Quality:        Grade B (avg 82.4/100)
  Smells:         47 total (3 critical, 12 major)
  Duration:       1.2s

  Framework Breakdown:
    Jest:          120 files, 892 tests, avg B+
    Vitest:         85 files, 634 tests, avg B
    Pytest:         40 files, 306 tests, avg A-

  Top Uncovered (Critical Risk):
    ⚠ PaymentService.processRefund  (risk: 92, entry point + sensitive data)
    ⚠ AuthController.resetPassword  (risk: 87, entry point + sensitive data)
    ⚠ DataMigrator.migrate          (risk: 78, 12 callers, no tests)
```

```
$ drift test-topology minimum-set src/auth/login.ts src/auth/session.ts

Minimum Test Set for 2 Changed Files
═══════════════════════════════════════════════════════════
  Changed Functions:  8
  Candidate Tests:    34
  Selected Tests:     7 (79% reduction)
  Coverage:           87.5% of changed code
  Est. Time Saved:    ~45s

  Selected:
    1. auth/login.test.ts > "should authenticate valid credentials"
       Covers: login(), validateCredentials(), createSession()
    2. auth/session.test.ts > "should refresh expired token"
       Covers: refreshToken(), validateSession()
    ...

  Uncovered:
    ⚠ revokeAllSessions() — no covering tests found
```

---

## 23. Tracing & Observability

### 23.1 Span Structure

Following 04-INFRASTRUCTURE-V2-PREP.md patterns, test topology uses structured
tracing spans for all operations.

```rust
// Top-level analysis span
#[tracing::instrument(skip(self), fields(
    test_files = %file_count,
    frameworks = %framework_count,
))]
pub fn analyze(&self, ...) -> Result<TestTopologySummary, TestTopologyError> { ... }

// Per-phase spans
tracing::info_span!("test_topology_extract", files = file_count);
tracing::info_span!("test_topology_map", strategies = 5);
tracing::info_span!("test_topology_score", tests = test_count);
tracing::info_span!("test_topology_persist", tables = 6);

// Per-file extraction span (debug level — high volume)
tracing::debug_span!("extract_file", file = %path, language = %lang);
```

### 23.2 Events

```rust
// DriftEventHandler events (per D5)
pub trait DriftEventHandler {
    fn on_test_topology_complete(&self, summary: &TestTopologySummary) {}
    fn on_test_coverage_changed(&self, file: &str, old_coverage: f64, new_coverage: f64) {}
    fn on_critical_uncovered_found(&self, function: &UncoveredFunction) {}
    fn on_test_smell_detected(&self, smell: &TestSmell) {}
}
```

---

## 24. Performance Targets & Benchmarks

### 24.1 Targets

| Operation | Target | Measurement |
|-----------|--------|-------------|
| Full analysis (10K files) | <3s | End-to-end: extract + map + score + persist |
| Full analysis (100K files) | <30s | Same pipeline, larger codebase |
| Incremental (10 changed files) | <500ms | A14 target |
| Single file extraction | <5ms | Tree-sitter parse + extraction |
| Coverage map build | <1s (10K functions) | BFS traversal + map construction |
| Minimum test set | <100ms | Greedy set cover |
| Query: coverage per file | <5ms | SQLite indexed query |
| Query: uncovered functions | <10ms | SQLite indexed query |
| Memory: coverage map | <50MB (100K functions) | FxHashMap in-memory |

### 24.2 Benchmark Suite

```rust
// crates/drift-core/benches/test_topology_bench.rs
use criterion::{criterion_group, criterion_main, Criterion};

fn bench_extraction(c: &mut Criterion) {
    c.bench_function("extract_jest_file", |b| {
        let content = include_str!("fixtures/large_jest_file.ts");
        b.iter(|| engine.extract_file(content, "test.ts", Language::TypeScript))
    });
}

fn bench_coverage_map(c: &mut Criterion) {
    c.bench_function("build_coverage_map_10k", |b| {
        b.iter(|| engine.build_coverage_map(&extractions_10k))
    });
}

fn bench_minimum_test_set(c: &mut Criterion) {
    c.bench_function("minimum_test_set_100_changed", |b| {
        b.iter(|| engine.compute_minimum_test_set(&changed_100))
    });
}

criterion_group!(benches, bench_extraction, bench_coverage_map, bench_minimum_test_set);
criterion_main!(benches);
```

---

## 25. Build Order & Dependencies

### Phase 1: Core Types & Error Handling (Week 1)
1. `test_topology/error.rs` — TestTopologyError enum (thiserror)
2. `test_topology/types.rs` — All core types (TestCase, TestFramework, MockStatement, etc.)
3. `test_topology/config.rs` — TestTopologyConfig
4. `test_topology/mod.rs` — Module structure
5. Verify: types compile, error codes registered

### Phase 2: Framework Registry & Detection (Week 1-2)
6. `test_topology/registry.rs` — FrameworkRegistry, TOML loading
7. `drift-frameworks.toml` — Built-in framework definitions (45+)
8. Framework detection tests for all supported frameworks
9. Verify: framework detection works for all 45+ frameworks

### Phase 3: Per-Language Extractors (Week 2-3)
10. `test_topology/extractors/mod.rs` — TestExtractor trait
11. TypeScript extractor (highest priority — most common)
12. Python extractor
13. Java extractor
14. Remaining extractors (C#, PHP, Go, Rust, C++, Kotlin, Swift)
15. Regex fallback extractors for all languages
16. Verify: extraction works for all frameworks with tree-sitter and regex

### Phase 4: Test-to-Source Mapping (Week 3)
17. `test_topology/mapping.rs` — TestSourceMapper, 5 strategies
18. Import analysis strategy
19. Naming convention strategy
20. Directory convention strategy
21. Call graph strategy
22. Annotation strategy
23. Confidence-weighted merging
24. Verify: bidirectional maps built correctly

### Phase 5: Coverage Mapping (Week 4)
25. `test_topology/coverage.rs` — Coverage map builder
26. Direct call resolution
27. Transitive BFS through call graph
28. Mock-only coverage detection
29. Confidence scoring
30. Verify: coverage map matches expected output for test fixtures

### Phase 6: Analysis Engines (Week 4-5)
31. `test_topology/minimum_set.rs` — Greedy weighted set cover
32. `test_topology/uncovered.rs` — Uncovered function detection + risk scoring
33. `test_topology/mock_analysis.rs` — Mock analysis engine
34. `test_topology/quality.rs` — 7-dimensional quality scoring
35. `test_topology/smells.rs` — 24 test smell detectors
36. `test_topology/fixtures.rs` — Cross-language fixture analysis
37. Verify: all analysis engines produce correct output

### Phase 7: Storage & Persistence (Week 5)
38. `004_test_topology.sql` — Migration file
39. Storage read/write functions for all 6 tables
40. Batch writer integration
41. Extraction cache (MessagePack serialization)
42. Verify: round-trip persistence works

### Phase 8: Incremental Analysis (Week 5-6)
43. Content-hash invalidation logic
44. Dependency-aware propagation
45. Incremental extraction + mapping
46. Verify: <500ms for 10 changed files

### Phase 9: Integration & NAPI (Week 6)
47. NAPI binding functions (4 functions)
48. Integration with impact analysis (TestCoverageMap)
49. Integration with quality gates (TestCoverageAssessment)
50. Integration with constraint detection (constraint candidates)
51. Verify: full pipeline works end-to-end via NAPI

### Phase 10: MCP & CLI (Week 7)
52. MCP tool definition and routing
53. CLI subcommands (7 commands)
54. Output formatting
55. Verify: MCP and CLI produce correct output

### Dependency Graph

```
Infrastructure (Level 0) ──→ thiserror, tracing, config
Parsers (Level 0) ──→ tree-sitter ASTs for extraction
Scanner (Level 0) ──→ ScanDiff for incremental analysis
Storage (Level 0) ──→ drift.db for persistence
String Interning (Level 1) ──→ lasso for function/file IDs
Call Graph (Level 1) ──→ petgraph for transitive coverage BFS
Boundary Detection (Level 1) ──→ DataAccessPoint for risk scoring
Test Topology (Level 2B) ──→ THIS SYSTEM
  → Impact Analysis (Level 2B) ──→ TestCoverageMap (§16)
  → Quality Gates (Level 3) ──→ TestCoverageAssessment (§17)
  → Constraint Detection (Level 2C) ──→ test category constraints (§18)
  → Simulation Engine (Level 4) ──→ test coverage scorer
  → MCP Tools (Level 5) ──→ drift_test_topology (§21)
  → CLI (Level 5) ──→ drift test-topology (§22)
```


---

## 26. V1 → V2 Feature Cross-Reference

Complete mapping of every v1 feature to its v2 location. Zero features lost.

| # | V1 Feature | V1 Location | V2 Location | Status |
|---|-----------|-------------|-------------|--------|
| T1 | Per-language extractors (8 langs) | `packages/core/src/test-topology/extractors/` | `crates/drift-core/src/test_topology/extractors/` | Ported → Rust |
| T2 | Framework detection (35 frameworks) | TS pattern matching in extractors | TOML registry + Rust detection (§6) | Upgraded → 45+ frameworks |
| T3 | Tree-sitter primary extraction | TS tree-sitter bindings | Rust tree-sitter-* crates (§5) | Ported → Rust |
| T4 | Regex fallback extraction | `extractors/regex/` (TS) | `extractors/regex/` (Rust) (§5) | Ported → Rust |
| T5 | Test case extraction | TestCase with name, parent, qualified, line, calls | Same + is_parameterized, parameter_count (§4.2) | Upgraded |
| T6 | Mock statement extraction | MockStatement with target, type, line, isExternal | Same + category (5 types), is_deep_mock (§4.5) | Upgraded |
| T7 | Setup block extraction | SetupBlock with type, line, calls | Same (§4.8) | Preserved |
| T8 | Fixture extraction (Python) | FixtureInfo with name, scope, line | Cross-language: Python, Java, C#, Go, Rust (§4.9, §14) | Upgraded |
| T9 | Coverage mapping (direct) | Direct function call resolution | Same (§8) | Preserved |
| T10 | Coverage mapping (transitive) | BFS through call graph (TS) | BFS through petgraph (Rust) (§8.2) | Ported → Rust |
| T11 | Coverage mapping (mocked) | Mock-only coverage tracked separately | Same (§8.3) | Preserved |
| T12 | Confidence scoring | Reach type based (high/medium/low) | Depth + resolution confidence (§8.2) | Upgraded |
| T13 | Uncovered function detection | Risk score 0-100, 6 reasons | 6 risk factors, 8 reasons (§10) | Upgraded |
| T14 | Minimum test set | Simple deduplication | Weighted greedy set cover (§9) | Upgraded |
| T15 | Mock analysis | External vs internal, ratio, top modules | 5 categories, deep mock, per-module (§11) | Upgraded |
| T16 | Test quality scoring | 5 signals, 0-100 score | 7 dimensions, A-F grades (§12) | Upgraded |
| T17 | Summary statistics | Counts, percentages, framework breakdown | Same + smells, grades, parameterized (§4.11) | Upgraded |
| T18 | Hybrid analyzer | Tree-sitter + regex fallback | Same pattern in Rust (§5.2) | Preserved |
| T19 | MCP: drift_test_topology | AI-assisted test analysis | 7 actions, richer data (§21) | Upgraded |
| T20 | CLI: test-topology commands | analyze, coverage, minimum-set, mocks | Same + quality, smells (§22) | Upgraded |
| T21 | Quality gate: test coverage | Minimum thresholds | Multi-factor assessment (§17) | Upgraded |
| T22 | Call graph integration | setCallGraph() for transitive | Direct petgraph access (§8) | Upgraded |
| T23 | NAPI: analyze_test_topology | Basic Rust analysis | 4 NAPI functions (§20) | Upgraded |
| T24 | TestFile Rust type | Basic: file, framework, test_cases, mocks | Full: + smells, fixtures, content_hash (§4.1) | Upgraded |
| T25 | TestCase Rust type | Basic: name, test_type, line, is_async, is_skipped | Full: + parameterized, quality, assertions (§4.2) | Upgraded |
| T26 | TestFramework Rust enum | 13 variants | 45+ variants + Custom (§4.4) | Upgraded |
| T27 | TestType Rust enum | Unit, Integration, E2E, Performance, Snapshot | Same + Property (§4.3) | Upgraded |
| T28 | MockUsage Rust type | target, mock_type, line | Full MockStatement (§4.5) | Upgraded |
| T29 | MockType Rust enum | Full, Partial, Spy | MockCategory: External, Internal, Http, Database, FileSystem (§4.5) | Upgraded |
| T30 | TestCoverage Rust type | source_file, test_files, test_count, risk_level | FunctionTestCoverage with reach types, confidence (§4.10) | Upgraded |
| T31 | RiskLevel Rust enum | Low, Medium, High, Critical | Same (§10.3) | Preserved |
| T32 | TestTopologyResult Rust type | test_files, coverage, stats | TestTopologySummary with full metrics (§4.11) | Upgraded |

**Total: 32 v1 features mapped. 0 lost. 20 upgraded. 12 preserved.**

---

## 27. Inconsistencies & Decisions

### 27.1 Resolved Inconsistencies

**I1: Framework count discrepancy**
- 17-test-topology/overview.md says "35+ frameworks"
- 01-rust-core/test-topology.md says "13 frameworks" (Rust enum)
- DRIFT-V2-FULL-SYSTEM-AUDIT.md Cat 17 lists 35 specific frameworks
- **Resolution**: V1 TS has 35+, V1 Rust has 13. V2 unifies at 45+ via TOML registry.
  The Rust enum covers built-in frameworks; TOML registry adds custom ones.

**I2: Quality scoring dimensions**
- 17-test-topology/types.md defines 5 signals (assertionCount, hasErrorCases, hasEdgeCases, mockRatio, setupRatio)
- A14 recommends 7 dimensions (assertion_quality, error_coverage, edge_coverage, mock_health, smell_penalty, isolation, mutation_score)
- **Resolution**: V2 uses 7 dimensions (A14). V1's 5 signals map to the first 4 dimensions.
  smell_penalty and isolation are new. mutation_score is optional external data.

**I3: Mock classification**
- 17-test-topology/types.md: MockStatement has `isExternal: boolean`
- 01-rust-core/test-topology.md: MockType enum has Full, Partial, Spy
- A14: MockCategory has External, Internal, Http, Database, FileSystem
- **Resolution**: V2 uses MockCategory (A14) for classification AND preserves the
  isExternal boolean for backward compatibility. MockType (Full/Partial/Spy) is
  orthogonal — it describes the mock technique, not the target category.

**I4: Test-to-source mapping strategies**
- 17-test-topology/analyzer.md: Only mentions import analysis
- A14: 5 strategies (import, naming, directory, call graph, annotation)
- **Resolution**: V2 implements all 5 strategies (A14). Import analysis is highest
  confidence (0.90), annotation is highest when available (0.95).

**I5: Fixture scope**
- 17-test-topology/types.md: Python-only (Pytest fixtures)
- A14: FixtureScope expanded to Function/Class/Module/Session for all languages
- **Resolution**: V2 uses cross-language FixtureScope (A14). Python fixtures map
  directly. Java @Rule/@ClassRule map to Class scope. C# [SetUp] maps to Function.

**I6: Incremental analysis**
- 17-test-topology/overview.md: No mention of incremental
- A14: Content-hash invalidation, <500ms for 10 changed files
- **Resolution**: V2 implements incremental analysis (A14). Uses content_hash from
  scanner for invalidation. Dependency-aware: when source file changes, re-map
  all tests covering it.

### 27.2 Design Decisions

| Decision | Choice | Confidence | Source |
|----------|--------|------------|--------|
| Extraction engine | Rust with TestExtractor trait | Very High | A14, performance requirements |
| Framework registry | TOML-based, extensible | High | A14, extensibility requirement |
| Tree-sitter + regex | Hybrid: tree-sitter primary, regex fallback | Very High | V1 pattern, proven robustness |
| Coverage mapping | Direct petgraph BFS in Rust | Very High | Performance, direct graph access |
| Minimum test set | Greedy weighted set cover | High | NP-hard problem, greedy is standard |
| Quality scoring | 7 dimensions, A-F grades | High | A14, multi-dimensional assessment |
| Test smells | 24 smells during extraction | High | A14, testsmells.org, zero-cost |
| Fixture detection | Cross-language (Python, Java, C#, Go, Rust) | High | A14, expanded beyond Python |
| Incremental analysis | Content-hash + dependency propagation | High | A14, <500ms target |
| Storage | 6 tables in drift.db | Very High | 02-STORAGE-V2-PREP.md |
| NAPI interface | 4 functions (1 async + 3 sync) | Very High | 03-NAPI-BRIDGE-V2-PREP.md §10.8 |
| Mock categories | 5 categories (External, Internal, Http, Database, FileSystem) | High | A14 |
| Deep mock detection | Mock returning mock | High | A14, test quality signal |
| Parameterized tests | is_parameterized + parameter_count | High | A14 |
| New languages | Kotlin (Kotest, MockK), Swift (Quick, Nimble) | Medium | A14, market demand |
| Mutation score | Optional external data integration | Medium | A14, not self-computed |
| Extraction cache | SQLite + MessagePack | High | A14, performance |
| Mapping strategies | 5 strategies with confidence merging | High | A14, accuracy improvement |
| Risk scoring | 6 factors (entry, sensitive, centrality, taint, exported, complexity) | High | V1 + taint integration |
| Uncovered reasons | 8 reasons (V1's 6 + EntryPoint + Configuration) | High | Completeness |

---

## 28. Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Tree-sitter grammar unavailable for Kotlin/Swift | Medium | Low | Regex fallback extractors handle this; tree-sitter grammars can be added later |
| Framework detection false positives | Medium | Medium | TOML registry allows tuning; file pattern + import + test pattern triple-check |
| Transitive coverage BFS too slow on large graphs | Low | High | Max depth limit (default 10); BFS is O(V+E) which is fast for petgraph |
| Mock category misclassification | Medium | Low | Conservative default (External); user can override via config |
| Test smell false positives | Medium | Medium | Severity levels allow filtering; auto_fixable flag prevents bad auto-fixes |
| Quality grade too harsh/lenient | Medium | Medium | Configurable weights; grade thresholds adjustable in config |
| Incremental analysis misses dependencies | Low | High | Content-hash is reliable; dependency propagation covers source→test links |
| MessagePack cache corruption | Low | Medium | Cache is advisory — full re-extraction on cache miss |
| Kotlin/Swift extractors incomplete | High | Low | New languages; start with regex-only, add tree-sitter incrementally |
| Mutation score integration complexity | Medium | Low | Optional field; defaults to 0.5 when unavailable |

---

## File Module Structure

```
crates/drift-core/src/test_topology/
├── mod.rs                      # Module exports, TestTopologyEngine
├── types.rs                    # All core types (§4)
├── error.rs                    # TestTopologyError enum (thiserror)
├── config.rs                   # TestTopologyConfig
├── registry.rs                 # FrameworkRegistry, TOML loading (§6)
├── mapping.rs                  # TestSourceMapper, 5 strategies (§7)
├── coverage.rs                 # Coverage map builder, BFS (§8)
├── minimum_set.rs              # Greedy weighted set cover (§9)
├── uncovered.rs                # Uncovered function detection + risk (§10)
├── mock_analysis.rs            # Mock analysis engine (§11)
├── quality.rs                  # 7-dimensional quality scoring (§12)
├── smells.rs                   # 24 test smell detectors (§13)
├── fixtures.rs                 # Cross-language fixture analysis (§14)
├── incremental.rs              # Incremental analysis + caching (§15)
├── persistence.rs              # drift.db read/write functions (§19)
├── extractors/
│   ├── mod.rs                  # TestExtractor trait, registry
│   ├── typescript_extractor.rs # TS/JS (8 frameworks)
│   ├── python_extractor.rs     # Python (5 frameworks)
│   ├── java_extractor.rs       # Java (6 frameworks)
│   ├── csharp_extractor.rs     # C# (5 frameworks)
│   ├── php_extractor.rs        # PHP (4 frameworks)
│   ├── go_extractor.rs         # Go (6 frameworks)
│   ├── rust_extractor.rs       # Rust (6 frameworks)
│   ├── cpp_extractor.rs        # C++ (6 frameworks)
│   ├── kotlin_extractor.rs     # Kotlin (2 frameworks)
│   ├── swift_extractor.rs      # Swift (2 frameworks)
│   └── regex/                  # Regex fallback extractors
│       ├── mod.rs
│       ├── typescript_regex.rs
│       ├── python_regex.rs
│       ├── java_regex.rs
│       ├── csharp_regex.rs
│       ├── php_regex.rs
│       ├── go_regex.rs
│       ├── rust_regex.rs
│       ├── cpp_regex.rs
│       ├── kotlin_regex.rs
│       └── swift_regex.rs
└── drift-frameworks.toml       # Built-in framework definitions

crates/drift-napi/src/bindings/
└── test_topology.rs            # 4 NAPI functions (§20)

crates/drift-napi/src/conversions/
└── test_types.rs               # NAPI type conversions (§20)

sql/
└── 004_test_topology.sql       # Migration (§19)
```

---

## Summary of All Decisions

| Decision | Choice | Confidence | Source |
|----------|--------|------------|--------|
| All extraction in Rust | TestExtractor trait, 10 language extractors | Very High | A14, performance |
| TOML framework registry | Extensible, 45+ built-in frameworks | High | A14, extensibility |
| Hybrid extraction | Tree-sitter primary + regex fallback | Very High | V1 proven pattern |
| 5 mapping strategies | Import, naming, directory, call graph, annotation | High | A14 |
| petgraph BFS for transitive | Direct graph access, max depth 10 | Very High | Performance |
| Greedy set cover | Weighted by quality + coverage breadth | High | Standard algorithm |
| 7-dimension quality | A-F grades, configurable weights | High | A14 |
| 24 test smells | 19 canonical + 5 flakiness, during extraction | High | A14, testsmells.org |
| Cross-language fixtures | Python, Java, C#, Go, Rust, C++, TS, PHP | High | A14 |
| Content-hash incremental | <500ms for 10 files, SQLite + MessagePack cache | High | A14 |
| 6 drift.db tables | test_files, test_cases, test_coverage, mock_statements, test_smells, uncovered_functions | Very High | 02-STORAGE-V2-PREP.md |
| 4 NAPI functions | 1 async command + 3 sync queries | Very High | 03-NAPI-BRIDGE-V2-PREP.md |
| 7 MCP actions | summary, coverage, uncovered, minimum_set, mocks, quality, smells | High | Cat 07 |
| 7 CLI commands | analyze, coverage, minimum-set, mocks, quality, smells + flags | High | Cat 10 |
| 5 mock categories | External, Internal, Http, Database, FileSystem | High | A14 |
| 8 uncovered reasons | V1's 6 + EntryPoint + Configuration | High | Completeness |
| 6 risk factors | Entry point, sensitive data, centrality, taint, exported, complexity | High | V1 + taint |
| 10+ languages | V1's 8 + Kotlin + Swift | Medium-High | A14, market demand |
| Optional mutation score | External tool integration, shifts quality weights | Medium | A14 |
| Total NAPI functions | 4 (analyze_test_topology, query_test_coverage, query_minimum_test_set, query_uncovered_functions) | Very High | 03-NAPI-BRIDGE-V2-PREP.md §10.8 |
