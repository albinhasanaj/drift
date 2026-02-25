# 17 Test Topology — Master Recap

## Executive Summary

Test Topology is Drift's test intelligence layer — a dual-implementation system (TypeScript analysis engine + Rust extraction core) that maps tests to the production code they exercise, scores test quality, computes minimum test sets for CI optimization, and performs deep mock analysis. The system spans ~15 TypeScript source files in `packages/core/src/test-topology/` and 3 Rust files in `crates/drift-core/src/test_topology/`, supporting 9 languages, 35+ test frameworks, and 8 dedicated per-language extractors with regex fallback. It integrates with the call graph for transitive coverage analysis, feeds into quality gates for test-aware enforcement, and is exposed via MCP for AI-assisted test guidance. This category is the bridge between code analysis and test confidence — answering "which tests cover this function?", "what's untested?", and "which tests should I run after this change?"

---

## System Architecture

### Layer Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         CONSUMERS                                           │
│  MCP (drift_test_topology) │ CLI (test-topology) │ Quality Gates            │
│  Context Generation │ Refactor Planning │ CI Optimization                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                    TestTopologyAnalyzer (TS)                                 │
│  Coverage Mapping │ Minimum Test Set │ Mock Analysis │ Quality Scoring      │
│  Uncovered Function Detection │ Summary Statistics                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                    HybridTestTopologyAnalyzer (TS)                           │
│  Tree-sitter primary extraction │ Regex fallback extraction                 │
├──────────┬──────────┬──────────┬──────────┬──────────┬──────────┬──────────┤
│    TS    │  Python  │   Java   │    C#    │   PHP    │    Go    │   Rust   │
│Extractor │Extractor │Extractor │Extractor │Extractor │Extractor │Extractor │
├──────────┴──────────┴──────────┴──────────┴──────────┴──────────┴──────────┤
│                         C++ Extractor                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                    Regex Fallback Extractors (all languages)                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                    Call Graph Integration                                    │
│  Direct calls │ Transitive reachability (BFS) │ Native SQLite queries       │
├─────────────────────────────────────────────────────────────────────────────┤
│                    Rust Core (crates/drift-core/src/test_topology/)          │
│  analyzer.rs │ types.rs │ mod.rs                                            │
│  Framework detection (13) │ Test case extraction │ Mock detection            │
│  NAPI: analyze_test_topology()                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Component Inventory

| Component | Location | Purpose |
|-----------|----------|---------|
| `test-topology-analyzer.ts` | Main analyzer | Coverage mapping, minimum test set, mock analysis, quality scoring, uncovered function detection |
| `hybrid-test-topology-analyzer.ts` | Hybrid analyzer | Tree-sitter + regex fallback orchestration |
| `types.ts` | Type definitions | ~15 interfaces: TestCase, TestCoverage, MockStatement, MinimumTestSet, etc. |
| `extractors/base-test-extractor.ts` | Base class | Abstract extractor with framework detection, test case/mock/setup extraction interfaces |
| `extractors/typescript-test-extractor.ts` | TS/JS | Jest, Vitest, Mocha, Ava, Tape |
| `extractors/python-test-extractor.ts` | Python | Pytest, Unittest, Nose |
| `extractors/java-test-extractor.ts` | Java | JUnit4, JUnit5, TestNG |
| `extractors/csharp-test-extractor.ts` | C# | xUnit, NUnit, MSTest |
| `extractors/php-test-extractor.ts` | PHP | PHPUnit, Pest, Codeception |
| `extractors/go-test-extractor.ts` | Go | go-testing, Testify, Ginkgo, Gomega |
| `extractors/rust-test-extractor.ts` | Rust | rust-test, tokio-test, proptest, criterion, rstest |
| `extractors/cpp-test-extractor.ts` | C++ | GTest, Catch2, Boost.Test, doctest, CppUnit |
| `extractors/regex/` | Regex fallback | Degraded extraction when tree-sitter unavailable |
| `crates/.../analyzer.rs` | Rust analyzer | Native test file analysis, framework detection |
| `crates/.../types.rs` | Rust types | TestFile, TestCase, TestFramework, MockUsage, TestCoverage, RiskLevel |
| `crates/.../mod.rs` | Rust module | Module exports |

---

## Supported Frameworks (35+)

| Language | Frameworks | Rust Support |
|----------|-----------|--------------|
| TypeScript/JavaScript | Jest, Vitest, Mocha, Ava, Tape | Jest, Vitest, Mocha |
| Python | Pytest, Unittest, Nose | Pytest |
| Java | JUnit4, JUnit5, TestNG | JUnit |
| C# | xUnit, NUnit, MSTest | NUnit, XUnit |
| PHP | PHPUnit, Pest, Codeception | PHPUnit |
| Go | go-testing, Testify, Ginkgo, Gomega | GoTest |
| Rust | rust-test, tokio-test, proptest, criterion, rstest | RustTest |
| C++ | GTest, Catch2, Boost.Test, doctest, CppUnit | Catch2, GoogleTest |

**Rust detects 13 frameworks** (basic detection). **TypeScript detects 35+** (deep extraction with assertions, mocks, setup blocks, fixtures).

---

## Core Algorithms

### 1. Coverage Mapping Algorithm

The central algorithm that maps tests to the production code they exercise:

```
1. For each test case:
   a. Resolve direct function calls from test body → function IDs
   b. If call graph available:
      - BFS through call graph from each direct call
      - Collect transitive calls with depth tracking
   c. Record: test → function mapping with reach type and depth

2. For each source file:
   a. Collect all functions defined in the file
   b. For each function, find all covering tests
   c. Calculate coverage percentage
   d. Flag mock-only coverage separately (not real coverage)
```

**Reach Types**:
- `direct` — Test directly calls the function (high confidence)
- `transitive` — Test reaches function through call chain (confidence decreases with depth)
- `mocked` — Function only reached via mocked paths (lowest confidence)

**Confidence Scoring for Coverage**:
- Direct calls: high confidence
- Transitive (shallow depth, ≤2 hops): medium-high confidence
- Transitive (deep, >2 hops): lower confidence
- Mocked: lowest confidence — tracked separately from real coverage

### 2. Minimum Test Set Selection (Set Cover Problem)

Given changed files, computes the smallest set of tests that covers the changes:

```
1. For each changed file:
   a. Find all functions defined in the file
   b. Find all tests covering those functions (direct + transitive)
2. Deduplicate test set across all changed files
3. Calculate coverage of changed code by selected tests
4. Estimate time saved vs running full test suite
```

**Output**: Selected tests with reasons, total vs selected count, estimated time savings, changed code coverage percentage.

### 3. Uncovered Function Detection

Identifies functions with no test coverage and assigns risk scores:

```
1. Iterate all functions in call graph
2. Filter out test files themselves
3. For each function without covering tests:
   a. Calculate risk score (0-100):
      - Is it an entry point? (+30 risk)
      - Does it access sensitive data? (+25 risk)
      - How many callers does it have? (centrality-based)
   b. Infer possible reasons for non-coverage:
      - dead-code: no callers in call graph
      - framework-hook: lifecycle method (componentDidMount, ngOnInit, etc.)
      - generated: in generated file path
      - trivial: getter/setter/constructor
      - test-only: only called from test files
      - deprecated: marked with @deprecated or similar
```

### 4. Mock Analysis

Deep analysis of mock usage patterns across the test suite:

```
1. Aggregate all mock statements across all tests
2. Classify each mock:
   - External (good): mocking third-party dependencies, HTTP, databases
   - Internal (suspicious): mocking own application code
3. Calculate per-test mock ratio: mocks / (mocks + real calls)
4. Identify high-mock-ratio tests (ratio > 0.7) — potentially brittle
5. Rank most-mocked modules by mock count
```

### 5. Test Quality Scoring

Per-test quality score (0-100) based on multiple signals:

```
TestQualitySignals {
  assertionCount: number      — More assertions = higher quality
  hasErrorCases: boolean      — Tests error paths
  hasEdgeCases: boolean       — Tests null, empty, boundary values
  mockRatio: number           — High mock ratio = potentially brittle
  setupRatio: number          — Setup lines vs test lines (high = complex)
  score: number               — Composite 0-100
}
```

### 6. Summary Statistics

Topology-wide aggregation:
- Test files / test cases count
- Covered vs total source files and functions
- Coverage percentages (file-level and function-level)
- Average mock ratio and quality score
- Breakdown by framework

---

## Data Models

### TypeScript Types (Full Feature Set)

```typescript
// Core extraction output
interface TestExtraction {
  file: string;
  framework: TestFramework;
  language: string;
  testCases: TestCase[];
  mocks: MockStatement[];
  setupBlocks: SetupBlock[];
  fixtures?: FixtureInfo[];        // Pytest fixtures, etc.
}

// Individual test case with full metadata
interface TestCase {
  id: string;                       // "file:name:line"
  name: string;
  parentBlock?: string;             // Parent describe/context
  qualifiedName: string;            // "describe > it"
  file: string;
  line: number;
  directCalls: string[];            // Functions directly called
  transitiveCalls: string[];        // Functions transitively reachable
  assertions: AssertionInfo[];
  quality: TestQualitySignals;
}

// Quality signals per test
interface TestQualitySignals {
  assertionCount: number;
  hasErrorCases: boolean;
  hasEdgeCases: boolean;
  mockRatio: number;
  setupRatio: number;
  score: number;                    // 0-100
}

// Coverage per source file
interface TestCoverage {
  sourceFile: string;
  tests: TestCoverageInfo[];
  functions: FunctionCoverageInfo[];
  coveragePercent: number;
}

// Uncovered function with risk assessment
interface UncoveredFunction {
  functionId: string;
  name: string;
  qualifiedName: string;
  file: string;
  line: number;
  possibleReasons: UncoveredReason[];
  riskScore: number;                // 0-100
  isEntryPoint: boolean;
  accessesSensitiveData: boolean;
}

// Minimum test set result
interface MinimumTestSet {
  tests: Array<{ file: string; name: string; reason: string }>;
  totalTests: number;
  selectedTests: number;
  timeSaved: string;
  changedCodeCoverage: number;
}

// Mock statement
interface MockStatement {
  target: string;
  mockType: string;                 // jest.mock, sinon.stub, @patch, etc.
  line: number;
  isExternal: boolean;
  hasImplementation?: boolean;
}

// Mock analysis result
interface MockAnalysis {
  totalMocks: number;
  externalMocks: number;
  internalMocks: number;
  externalPercent: number;
  internalPercent: number;
  avgMockRatio: number;
  highMockRatioTests: Array<{ file: string; testName: string; mockRatio: number }>;
  topMockedModules: Array<{ module: string; count: number }>;
}
```

### Rust Types (Basic Extraction)

```rust
struct TestFile {
    file: String,
    framework: TestFramework,
    test_cases: Vec<TestCase>,
    mocks: Vec<MockUsage>,
    imports: Vec<String>,
    covers: Vec<String>,
}

struct TestCase {
    name: String,
    test_type: TestType,            // Unit, Integration, E2E, Performance, Snapshot
    line: u32,
    is_async: bool,
    is_skipped: bool,
}

enum TestFramework {
    Jest, Vitest, Mocha, Pytest, JUnit, NUnit, XUnit,
    GoTest, PHPUnit, RustTest, Catch2, GoogleTest, Unknown
}

enum TestType { Unit, Integration, E2E, Performance, Snapshot, Unknown }

struct MockUsage {
    target: String,
    mock_type: MockType,            // Full, Partial, Spy
    line: u32,
}

enum MockType { Full, Partial, Spy, Function, Module, Class, Http }

struct TestCoverage {
    source_file: String,
    test_files: Vec<String>,
    test_count: usize,
    risk_level: RiskLevel,          // Low, Medium, High, Critical
}

struct TestTopologyResult {
    test_files: Vec<TestFile>,
    coverage: Vec<TestCoverage>,
    stats: TestTopologyStats,
}
```

---

## Per-Language Extractor Details

### What Each Extractor Detects

**Test Cases**:
- Test function/method declarations (it, test, def test_, @Test, TEST_F, etc.)
- Parent describe/context blocks for qualified naming
- Direct function calls within test body
- Assertions (expect, assert, assertEquals, Assert.Equal, etc.)
- Error case assertions and edge case assertions

**Mock Statements**:
- Module mocks (jest.mock, vi.mock, @patch, sinon.stub)
- Function mocks/spies
- HTTP mocks
- Whether mock targets external or internal code
- Whether mock has inline implementation

**Setup Blocks**:
- beforeEach / afterEach / beforeAll / afterAll (JS/TS)
- setUp / tearDown (Python, Java)
- SetUp / TearDown attributes (C#)
- Functions called during setup

**Fixtures** (Python-specific currently):
- Pytest fixture name, scope, line number
- What the fixture provides

### Extractor Architecture

All extractors inherit from `BaseTestExtractor` which provides:
- Framework detection interface
- Test case extraction interface
- Mock statement extraction interface
- Setup block extraction interface
- Common utilities (line counting, pattern matching)

**Hybrid Strategy**: `HybridTestTopologyAnalyzer` uses tree-sitter as primary parser, falls back to regex extractors when tree-sitter parsing fails or is unavailable for a language.

---

## Integration Points

### Upstream Dependencies

| Dependency | What It Provides | How Used |
|------------|-----------------|----------|
| **02-parsers** | Tree-sitter AST per language | Primary extraction via tree-sitter queries |
| **04-call-graph** | Function relationships, BFS traversal | Transitive coverage mapping, reachability |
| **01-rust-core** | Native NAPI bridge | `analyze_test_topology()` for basic extraction |

### Downstream Consumers

| Consumer | What It Uses | Purpose |
|----------|-------------|---------|
| **07-mcp** | `drift_test_topology` tool | AI-assisted test analysis and guidance |
| **09-quality-gates** | Coverage data, uncovered functions | Test coverage enforcement in CI |
| **10-cli** | `test-topology` command, `TestTopologyRunner` | CLI analysis output |
| **05-analyzers** | Test coverage for refactor impact | Affected tests calculation |
| **13-advanced** | Test file mapping for 6D scoring | Coverage scoring in advanced analysis |
| **22-context-generation** | Test topology data | AI context enrichment |
| **25-services-layer** | Scan pipeline integration | Orchestrated execution |

### MCP Integration

Exposed as `drift_test_topology` MCP tool — one of 18 analysis tools in the "heavy analysis" category. Pre-loaded by the startup warmer alongside patterns, call graph, boundaries, env vars, DNA, contracts, history, coupling, and error handling.

### CLI Integration

`TestTopologyRunner` extends `BaseRunner` — one of 13 runners in the setup pipeline. Positioned in Phase 5 (Deep Analysis) of the CLI setup flow, after boundaries, contracts, environment, constants, and call graph.

### Quality Gates Integration

Test topology feeds into:
- **Impact Simulation Gate**: Affected tests calculation for blast radius
- **Pattern Compliance Gate**: Test convention enforcement
- **Regression Detection Gate**: Test coverage regression tracking

---

## Rust vs TypeScript Feature Parity

| Feature | Rust | TypeScript | Gap |
|---------|------|-----------|-----|
| Framework detection | 13 frameworks | 35+ frameworks | TS has 2.7× more |
| Test case extraction | Basic (name, type, line) | Rich (calls, assertions, quality) | Major gap |
| Mock detection | Basic (target, type, line) | Rich (external/internal, implementation) | Major gap |
| Quality scoring | ❌ | ✅ (0-100 composite) | Missing in Rust |
| Transitive coverage | ❌ | ✅ (via call graph BFS) | Missing in Rust |
| Minimum test set | ❌ | ✅ (set cover algorithm) | Missing in Rust |
| Uncovered function detection | ❌ | ✅ (with risk scoring) | Missing in Rust |
| Mock analysis | ❌ | ✅ (external/internal classification) | Missing in Rust |
| Setup block extraction | ❌ | ✅ (per-language) | Missing in Rust |
| Fixture detection | ❌ | ✅ (Python pytest) | Missing in Rust |
| Async test detection | ✅ | ✅ | Parity |
| Skipped test detection | ✅ | ✅ | Parity |
| Test type classification | ✅ (5 types) | ✅ (5 types) | Parity |
| Import analysis | ✅ | ✅ | Parity |
| Source file mapping | ✅ (import-based) | ✅ (import + call graph) | TS richer |

**Summary**: Rust handles basic test detection and framework identification. TypeScript owns all the intelligence — quality scoring, transitive coverage, minimum test set, mock analysis, and uncovered function detection. The gap is substantial.

---

## Known Gaps and Limitations

### Architectural Gaps

1. **No incremental analysis**: Full re-extraction on every scan. No caching of test topology results.
2. **No file-change-aware updates**: Cannot update topology for just changed test files.
3. **Fixture detection Python-only**: JUnit @Rule, C# [SetUp], Go TestMain, Rust test fixtures not detected.
4. **No test dependency tracking**: Cannot detect test ordering dependencies or shared state.
5. **No flaky test detection**: No integration with test execution results to identify flaky tests.
6. **No test execution time estimation**: Minimum test set reports "time saved" but has no actual execution time data.
7. **No parameterized test expansion**: Parameterized tests (pytest.mark.parametrize, @ParameterizedTest, [Theory]) counted as single test.
8. **No test suite hierarchy**: Flat test list — no modeling of test suite → test class → test method hierarchy.

### Coverage Gaps

9. **No property-based test detection**: Hypothesis (Python), fast-check (JS), QuickCheck patterns not recognized.
10. **No contract test detection**: Pact, Spring Cloud Contract not recognized.
11. **No mutation testing integration**: No connection to mutation testing frameworks (Stryker, mutmut, pitest).
12. **No visual regression test detection**: Playwright visual comparisons, Percy, Chromatic not recognized.
13. **No load/stress test detection**: k6, Locust, Gatling, JMeter test files not recognized.
14. **No API test detection**: Postman collections, REST-assured, Karate not recognized.
15. **No BDD/Gherkin detection**: Cucumber, SpecFlow, Behave feature files not parsed.

### Quality Gaps

16. **Quality scoring is simplistic**: No weighting by code complexity or risk level of covered code.
17. **No assertion quality analysis**: All assertions weighted equally — `expect(true).toBe(true)` scores same as meaningful assertions.
18. **No test isolation analysis**: Cannot detect tests that depend on execution order or shared mutable state.
19. **No test smell detection**: Long tests, conditional logic in tests, multiple assertions without clear intent not flagged.

### Integration Gaps

20. **No CI execution data integration**: Cannot consume JUnit XML, pytest JSON, or other test result formats.
21. **No code coverage tool integration**: Cannot consume Istanbul/NYC, coverage.py, JaCoCo reports.
22. **No test impact analysis feedback loop**: Minimum test set recommendations not validated against actual test results.
23. **Call graph integration is optional**: Without call graph, coverage mapping falls back to import-only analysis (much less accurate).

### Performance Gaps

24. **All extraction in TypeScript**: 8 per-language extractors are pure TypeScript — slow for large codebases.
25. **Sequential extraction**: No parallel extraction across files.
26. **No AST caching**: Re-parses test files on every analysis.
27. **Regex fallback is expensive**: Regex extractors run full-file scans when tree-sitter fails.

---

## Cross-System Impact Analysis

### How Test Topology Affects the Pipeline

```
Test Topology Data Flow:
                                                    
  Parsers ──→ Extractors ──→ TestTopologyAnalyzer ──→ Coverage Map
                                    │                      │
                                    ├──→ Quality Scores     ├──→ MCP (drift_test_topology)
                                    ├──→ Mock Analysis      ├──→ Quality Gates (enforcement)
                                    ├──→ Minimum Test Set   ├──→ CLI (reporting)
                                    └──→ Uncovered Funcs    ├──→ Context Generation
                                                           ├──→ Refactor Impact
                                                           └──→ CI Optimization
```

### Security Considerations

- Test topology reveals which security-critical code lacks test coverage
- Uncovered function detection with `accessesSensitiveData` flag identifies security testing gaps
- Mock analysis identifies where security boundaries are mocked away (false sense of security)
- Integration with security boundary gate: tests that mock auth checks don't count as real coverage

### Convention Enforcement

- Test naming conventions can be enforced via pattern compliance
- Test file placement conventions (co-located vs separate `__tests__/` directory)
- Minimum coverage thresholds per module via quality gates
- Framework consistency enforcement (don't mix Jest and Vitest in same project)

---

## V2 Migration Notes

### What Must Move to Rust

Per the migration strategy (Phase 7: Advanced Analysis), test topology is scheduled for Rust migration with "richer than current Rust version" as the target.

**Priority components for Rust migration**:
1. All 8 per-language extractors (hot path — called per test file)
2. Coverage mapping with call graph traversal (BFS is algorithmic, benefits from Rust speed)
3. Quality scoring (pure computation)
4. Minimum test set selection (set cover problem — benefits from Rust performance at scale)
5. Framework detection (already partially in Rust, needs full parity)

**What can stay in TypeScript**:
- Mock analysis presentation (formatting, reporting)
- MCP tool orchestration
- CLI output formatting

### NAPI Bridge Evolution

Current: Single `analyze_test_topology(files: Vec<String>) -> JsTestTopologyResult`

V2 should expose:
- `extract_tests(file: String, content: String) -> JsTestExtraction`
- `build_coverage_map(extractions: Vec, call_graph: &CallGraph) -> JsCoverageMap`
- `compute_minimum_test_set(changed_files: Vec, coverage: &CoverageMap) -> JsMinimumTestSet`
- `score_test_quality(extraction: &TestExtraction) -> JsQualityScore`
- `detect_uncovered_functions(coverage: &CoverageMap, call_graph: &CallGraph) -> Vec<JsUncoveredFunction>`
- `analyze_mocks(extractions: Vec) -> JsMockAnalysis`

---

## Quality Checklist

- [x] All source files inventoried with locations and purposes
- [x] All 35+ supported frameworks documented by language
- [x] All 6 core algorithms documented with pseudocode
- [x] All TypeScript and Rust data models captured
- [x] All 8 per-language extractors documented
- [x] Complete integration map (upstream + downstream)
- [x] Rust vs TypeScript feature parity gap analysis
- [x] 27 known gaps categorized (architectural, coverage, quality, integration, performance)
- [x] Cross-system impact analysis (security, conventions, pipeline)
- [x] V2 migration plan with NAPI bridge evolution
- [x] Extractor architecture and hybrid strategy documented
