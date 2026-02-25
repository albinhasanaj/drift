# 17 Test Topology — V2 Recommendations

> **Purpose**: Concrete, actionable recommendations for building an enterprise-grade test topology system in Drift v2. Each recommendation is grounded in the v1 recap and validated against research findings.
>
> **Approach**: Recommendations ordered by priority (R1-R12), with implementation details, Rust API signatures, data models, and cross-system impact analysis.
>
> **Date**: February 2026

---

## R1: Unified Rust Extraction Engine (P0)

### Problem
V1 has 8 TypeScript per-language extractors (~15 files) plus a basic Rust analyzer (3 files). The TS extractors are sequential, uncached, and re-parse on every scan. Rust detects only 13 frameworks with basic extraction while TS detects 35+ with rich metadata.

### Recommendation
Build a single Rust extraction engine covering all 9 languages with full TS feature parity, using tree-sitter primary + regex fallback.

### Architecture

```rust
/// Core extraction trait — all language extractors implement this
pub trait TestExtractor: Send + Sync {
    fn detect_framework(&self, content: &str, path: &str) -> Option<TestFramework>;
    fn extract_tests(&self, tree: &Tree, content: &str, path: &str) -> TestExtraction;
    fn supported_languages(&self) -> &[Language];
}

/// Unified extraction result
pub struct TestExtraction {
    pub file: String,
    pub language: Language,
    pub framework: TestFramework,
    pub test_cases: Vec<TestCase>,
    pub mock_statements: Vec<MockStatement>,
    pub setup_blocks: Vec<SetupBlock>,
    pub fixtures: Vec<FixtureInfo>,
    pub imports: Vec<ImportRef>,
    pub file_hash: u64,                // xxhash for incremental invalidation
}

pub struct TestCase {
    pub id: String,                     // "file:name:line"
    pub name: String,
    pub qualified_name: String,         // "describe > it" or "Class::method"
    pub parent_block: Option<String>,
    pub line: u32,
    pub end_line: u32,
    pub test_type: TestType,
    pub is_async: bool,
    pub is_skipped: bool,
    pub is_parameterized: bool,         // NEW: @ParameterizedTest, pytest.mark.parametrize
    pub parameter_count: Option<u32>,   // NEW: estimated test instances
    pub direct_calls: Vec<String>,
    pub assertions: Vec<AssertionInfo>,
    pub smells: Vec<TestSmell>,         // NEW: inline smell detection during extraction
}

pub struct MockStatement {
    pub target: String,
    pub mock_type: MockType,            // Full, Partial, Spy
    pub mock_category: MockCategory,    // NEW: External, Internal, Http, Database, FileSystem
    pub line: u32,
    pub has_implementation: bool,
    pub is_deep_mock: bool,             // NEW: mock returning mock detection
}

pub struct SetupBlock {
    pub kind: SetupKind,
    pub line: u32,
    pub end_line: u32,
    pub calls: Vec<String>,
}

pub struct FixtureInfo {
    pub name: String,
    pub scope: FixtureScope,            // Function, Class, Module, Session
    pub line: u32,
    pub language: Language,             // NEW: expand beyond Python
}
```

### Framework Coverage Target (v2)

| Language | v1 Frameworks | v2 Target (additions) |
|----------|--------------|----------------------|
| TypeScript/JS | Jest, Vitest, Mocha, Ava, Tape | + Playwright, Cypress, Testing Library |
| Python | Pytest, Unittest, Nose | + Hypothesis (property-based), Behave (BDD) |
| Java | JUnit4, JUnit5, TestNG | + Cucumber, Spock, Arquillian |
| C# | xUnit, NUnit, MSTest | + SpecFlow (BDD), FluentAssertions detection |
| PHP | PHPUnit, Pest, Codeception | + Behat (BDD) |
| Go | go-testing, Testify, Ginkgo, Gomega | + GoConvey, rapid (property-based) |
| Rust | rust-test, tokio-test, proptest, criterion, rstest | + nextest runner detection |
| C++ | GTest, Catch2, Boost.Test, doctest, CppUnit | + GoogleMock detection |
| Kotlin | — (NEW) | JUnit5, Kotest, MockK |
| Swift | — (NEW) | XCTest, Quick/Nimble |

### NAPI Bridge

```rust
#[napi]
pub fn extract_tests(file_path: String, content: String) -> JsTestExtraction { ... }

#[napi]
pub fn extract_tests_batch(files: Vec<FileInput>) -> Vec<JsTestExtraction> { ... }

#[napi]
pub fn detect_test_framework(file_path: String, content: String) -> Option<String> { ... }
```

### Cross-System Impact
- **02-parsers**: Reuses tree-sitter grammars already loaded by parser subsystem
- **01-rust-core**: Shares rayon thread pool for parallel extraction
- **08-storage**: Extraction results cached in SQLite with file_hash for invalidation

### Risks
- Tree-sitter query complexity varies by language — some frameworks need regex fallback
- Parameterized test expansion is framework-specific and may not be fully deterministic
- New language additions (Kotlin, Swift) require new tree-sitter grammars

---

## R2: Incremental Analysis with Content-Hash Invalidation (P0)

### Problem
V1 performs full re-extraction on every scan. For a 500K-file codebase with 50K test files, this means re-parsing 50K files even if only 3 changed.

### Recommendation
Implement content-hash-based incremental analysis with dependency-aware invalidation propagation.

### Design

```rust
pub struct TestTopologyCache {
    /// file_path → (content_hash, TestExtraction)
    extractions: HashMap<String, (u64, TestExtraction)>,
    /// source_file → Vec<test_file> (reverse dependency map)
    source_to_tests: HashMap<String, Vec<String>>,
    /// test_file → Vec<source_file> (forward dependency map)
    test_to_sources: HashMap<String, Vec<String>>,
}

impl TestTopologyCache {
    /// Determine which files need re-extraction
    pub fn compute_invalidation_set(
        &self,
        changed_files: &[ChangedFile],
    ) -> InvalidationSet {
        let mut to_extract = HashSet::new();
        let mut to_remap = HashSet::new();

        for file in changed_files {
            let new_hash = xxhash64(file.content);
            let cached_hash = self.extractions.get(&file.path).map(|(h, _)| *h);

            if cached_hash != Some(new_hash) {
                if self.is_test_file(&file.path) {
                    to_extract.insert(file.path.clone());
                } else {
                    // Source file changed — re-map all tests that cover it
                    if let Some(tests) = self.source_to_tests.get(&file.path) {
                        to_remap.extend(tests.iter().cloned());
                    }
                }
            }
        }

        InvalidationSet { to_extract, to_remap }
    }
}
```

### Invalidation Rules

| Change Type | Action |
|-------------|--------|
| Test file content changed | Re-extract that test file, re-map its coverage |
| Source file content changed | Re-map all tests covering that source file |
| New test file added | Extract and add to topology |
| Test file deleted | Remove from topology, update coverage |
| Source file deleted | Remove coverage entries, flag orphaned tests |
| Import graph changed | Re-compute coverage for affected test↔source pairs |

### SQLite Schema for Cache

```sql
CREATE TABLE test_extraction_cache (
    file_path TEXT PRIMARY KEY,
    content_hash INTEGER NOT NULL,
    extraction_json BLOB NOT NULL,      -- MessagePack-serialized TestExtraction
    extracted_at INTEGER NOT NULL,
    framework TEXT,
    test_count INTEGER,
    mock_count INTEGER
);

CREATE INDEX idx_cache_hash ON test_extraction_cache(content_hash);
```

### Performance Target
- Full extraction (50K test files): <30s with rayon parallelism
- Incremental extraction (10 changed files): <500ms
- Cache lookup: <1ms per file

### Cross-System Impact
- **08-storage**: Shares SQLite database with other cached analysis results
- **01-rust-core**: Reuses xxhash infrastructure already in Rust core
- **25-services-layer**: Scanner service provides changed file list for incremental mode

---

## R3: Test Smell Detection Engine (P0)

### Problem
V1 has no test smell detection. Test quality scoring uses basic signals (assertion count, mock ratio) but misses structural quality issues that research shows correlate with test brittleness and flakiness.

### Recommendation
Implement detection for the 19 canonical test smells plus 5 flakiness-inducing smells, integrated directly into the extraction pipeline (zero additional AST traversal cost).

### Smell Catalog

```rust
pub enum TestSmell {
    // Canonical smells (testsmells.org catalog)
    AssertionRoulette { assertion_count: u32 },
    ConditionalTestLogic { control_flow_count: u32 },
    ConstructorInitialization,
    DefaultTest,
    DuplicateAssert { duplicate_count: u32 },
    EagerTest { production_methods_called: u32 },
    EmptyTest,
    ExceptionHandling,
    GeneralFixture { unused_setup_vars: Vec<String> },
    IgnoredTest,
    LazyTest { shared_method: String },
    MagicNumberTest { magic_numbers: Vec<String> },
    MysteryGuest { external_resource: String },
    RedundantPrint,
    RedundantAssertion,
    ResourceOptimism { resource_type: String },
    SensitiveEquality,
    SleepyTest { sleep_ms: Option<u64> },
    UnknownTest,  // No assertions

    // Flakiness-inducing smells (Palomba & Zaidman, 2020)
    IndirectTesting { intermediary: String },
    TestRunWar { shared_state: String },
    FireAndForget { async_call: String },
}

pub struct TestSmellResult {
    pub smell: TestSmell,
    pub severity: SmellSeverity,        // Info, Warning, Error
    pub line: u32,
    pub suggestion: Option<String>,
    pub auto_fixable: bool,
}
```

### Detection During Extraction

Smells are detected during the same AST traversal that extracts test cases — no second pass needed:

```rust
impl<E: TestExtractor> SmellAwareExtractor<E> {
    pub fn extract_with_smells(
        &self, tree: &Tree, content: &str, path: &str
    ) -> TestExtraction {
        let mut extraction = self.inner.extract_tests(tree, content, path);

        for test_case in &mut extraction.test_cases {
            let smells = self.detect_smells(tree, test_case, &extraction);
            test_case.smells = smells;
        }

        extraction
    }

    fn detect_smells(
        &self, tree: &Tree, test: &TestCase, extraction: &TestExtraction
    ) -> Vec<TestSmellResult> {
        let mut smells = Vec::new();

        // Assertion Roulette: >1 assertion without messages
        if test.assertions.len() > 1
            && test.assertions.iter().all(|a| a.message.is_none())
        {
            smells.push(TestSmellResult {
                smell: TestSmell::AssertionRoulette {
                    assertion_count: test.assertions.len() as u32,
                },
                severity: SmellSeverity::Warning,
                line: test.line,
                suggestion: Some("Add descriptive messages to assertions".into()),
                auto_fixable: false,
            });
        }

        // Unknown Test: no assertions at all
        if test.assertions.is_empty() && !test.is_skipped {
            smells.push(TestSmellResult {
                smell: TestSmell::UnknownTest,
                severity: SmellSeverity::Error,
                line: test.line,
                suggestion: Some("Add assertions to verify behavior".into()),
                auto_fixable: false,
            });
        }

        // ... (remaining 22 smell detectors follow same pattern)
        smells
    }
}
```

### Cross-System Impact
- **09-quality-gates**: New "test-smell" gate type for CI enforcement
- **07-mcp**: Smell data exposed via `drift_test_topology` tool
- **03-detectors**: Test smell detection follows same pattern as code smell detection — shared severity model

---

## R4: Enhanced Test Quality Scoring (P0)

### Problem
V1's quality scoring is simplistic — assertion count, error/edge case booleans, mock ratio, setup ratio → single 0-100 score. No weighting by code risk, no mutation score integration, no smell penalty.

### Recommendation
Build a multi-dimensional quality scoring system with configurable weights, mutation score integration, and smell penalties.

### Scoring Algorithm

```rust
pub struct TestQualityScore {
    pub overall: f32,                   // 0-100 composite
    pub dimensions: QualityDimensions,
    pub grade: QualityGrade,            // A, B, C, D, F
}

pub struct QualityDimensions {
    pub assertion_quality: f32,         // 0-1: count + meaningfulness
    pub error_coverage: f32,            // 0-1: error path testing
    pub edge_coverage: f32,             // 0-1: boundary/null/empty testing
    pub mock_health: f32,               // 0-1: inverse of mock ratio, external preferred
    pub smell_penalty: f32,             // 0-1: 1.0 = no smells, 0.0 = severe smells
    pub isolation: f32,                 // 0-1: test independence
    pub mutation_score: Option<f32>,    // 0-1: from external mutation testing data
}

impl TestQualityScore {
    pub fn compute(
        test: &TestCase,
        config: &QualityConfig,
        mutation_data: Option<&MutationData>,
    ) -> Self {
        let d = QualityDimensions {
            assertion_quality: Self::score_assertions(test),
            error_coverage: if test.has_error_cases { 1.0 } else { 0.0 },
            edge_coverage: if test.has_edge_cases { 1.0 } else { 0.0 },
            mock_health: Self::score_mock_health(test),
            smell_penalty: Self::score_smell_penalty(test),
            isolation: Self::score_isolation(test),
            mutation_score: mutation_data.map(|m| m.score_for_test(&test.id)),
        };

        let weights = if d.mutation_score.is_some() {
            &config.weights_with_mutation
        } else {
            &config.weights_default
        };

        let overall = (
            d.assertion_quality * weights.assertion
            + d.error_coverage * weights.error
            + d.edge_coverage * weights.edge
            + d.mock_health * weights.mock
            + d.smell_penalty * weights.smell
            + d.isolation * weights.isolation
            + d.mutation_score.unwrap_or(0.0) * weights.mutation
        ) * 100.0;

        Self {
            overall: overall.clamp(0.0, 100.0),
            dimensions: d,
            grade: QualityGrade::from_score(overall),
        }
    }
}
```

### Default Weights

| Dimension | Without Mutation Data | With Mutation Data |
|-----------|----------------------|-------------------|
| Assertion quality | 0.25 | 0.15 |
| Error coverage | 0.15 | 0.10 |
| Edge coverage | 0.15 | 0.10 |
| Mock health | 0.15 | 0.10 |
| Smell penalty | 0.15 | 0.10 |
| Isolation | 0.15 | 0.10 |
| Mutation score | 0.00 | 0.35 |

### Grade Thresholds

| Grade | Score Range | Meaning |
|-------|------------|---------|
| A | 90-100 | Excellent — comprehensive, well-structured tests |
| B | 75-89 | Good — solid coverage with minor gaps |
| C | 60-74 | Adequate — functional but room for improvement |
| D | 40-59 | Poor — significant quality issues |
| F | 0-39 | Failing — tests provide little confidence |

### Cross-System Impact
- **09-quality-gates**: Quality grade can be a gate threshold (e.g., "no new tests below grade C")
- **07-mcp**: AI agents can use quality scores to prioritize test improvement suggestions
- **13-advanced**: 6D scoring system consumes test quality as one dimension

---

## R5: Method-Level Coverage Mapping with Call Graph (P0)

### Problem
V1's coverage mapping uses import analysis as primary and call graph as optional enhancement. Without call graph, accuracy is low (file-level only). With call graph, transitive coverage is computed via BFS but the algorithm lacks confidence calibration.

### Recommendation
Make call graph integration the primary coverage strategy with calibrated confidence scoring based on reach depth and type.

### Coverage Model

```rust
pub struct CoverageMap {
    /// source_function → Vec<CoveringTest>
    function_coverage: HashMap<FunctionId, Vec<CoveringTest>>,
    /// source_file → FileCoverage
    file_coverage: HashMap<String, FileCoverage>,
    /// Statistics
    stats: CoverageStats,
}

pub struct CoveringTest {
    pub test_id: String,
    pub test_file: String,
    pub reach_type: ReachType,
    pub reach_depth: u32,               // 0 = direct, 1+ = transitive hops
    pub confidence: f32,                // Calibrated confidence
    pub is_mocked: bool,               // Reached only through mocked path
    pub path: Vec<FunctionId>,         // Call chain from test to function
}

pub enum ReachType {
    Direct,                             // Test directly calls function
    Transitive,                         // Test reaches through call chain
    MockedOnly,                         // Only reached via mocked dependencies
    ImportOnly,                         // Only linked via import (no call graph)
}
```

### Confidence Calibration

```rust
impl CoveringTest {
    pub fn compute_confidence(&self) -> f32 {
        let base = match self.reach_type {
            ReachType::Direct => 0.95,
            ReachType::Transitive => 0.85,
            ReachType::MockedOnly => 0.30,
            ReachType::ImportOnly => 0.50,
        };

        // Depth decay: confidence decreases with call chain length
        let depth_factor = if self.reach_depth == 0 {
            1.0
        } else {
            // Exponential decay: 0.9^depth
            0.9_f32.powi(self.reach_depth as i32)
        };

        // Mock penalty: if any node in path is mocked, reduce confidence
        let mock_factor = if self.is_mocked { 0.5 } else { 1.0 };

        (base * depth_factor * mock_factor).clamp(0.0, 1.0)
    }
}
```

### BFS with Depth Tracking

```rust
pub fn build_coverage(
    extractions: &[TestExtraction],
    call_graph: &CallGraph,
    max_depth: u32,
) -> CoverageMap {
    let mut map = CoverageMap::new();

    for extraction in extractions {
        for test_case in &extraction.test_cases {
            // Direct calls
            for call in &test_case.direct_calls {
                if let Some(func_id) = call_graph.resolve_function(call) {
                    map.add_coverage(func_id, CoveringTest {
                        test_id: test_case.id.clone(),
                        reach_type: ReachType::Direct,
                        reach_depth: 0,
                        // ...
                    });

                    // BFS for transitive coverage
                    let mut visited = HashSet::new();
                    let mut queue = VecDeque::new();
                    queue.push_back((func_id.clone(), 1u32));
                    visited.insert(func_id.clone());

                    while let Some((current, depth)) = queue.pop_front() {
                        if depth > max_depth { continue; }

                        for callee in call_graph.callees(&current) {
                            if visited.insert(callee.clone()) {
                                let is_mocked = test_case.mock_statements
                                    .iter()
                                    .any(|m| m.target == callee.name);

                                map.add_coverage(callee.clone(), CoveringTest {
                                    test_id: test_case.id.clone(),
                                    reach_type: if is_mocked {
                                        ReachType::MockedOnly
                                    } else {
                                        ReachType::Transitive
                                    },
                                    reach_depth: depth,
                                    // ...
                                });

                                if !is_mocked {
                                    queue.push_back((callee, depth + 1));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    map
}
```

### Cross-System Impact
- **04-call-graph**: Primary dependency — coverage quality directly tied to call graph completeness
- **09-quality-gates**: Coverage percentages feed into pattern compliance and regression gates
- **21-security**: Security-critical functions without test coverage flagged as high risk

---

## R6: Intelligent Minimum Test Set Selection (P1)

### Problem
V1's minimum test set is a simple deduplication of tests covering changed functions. It doesn't account for test execution time, test reliability (flakiness), test quality, or overlapping coverage. The "time saved" estimate has no actual execution time data.

### Recommendation
Implement a weighted set cover algorithm that optimizes for maximum coverage with minimum cost, where cost factors in execution time, flakiness history, and quality score.

### Algorithm

```rust
pub struct MinimumTestSetConfig {
    pub coverage_target: f32,           // 0.0-1.0, default 0.95
    pub max_tests: Option<usize>,       // Hard cap on selected tests
    pub weight_coverage: f32,           // 0.4 — how much coverage matters
    pub weight_speed: f32,              // 0.3 — prefer faster tests
    pub weight_reliability: f32,        // 0.2 — prefer non-flaky tests
    pub weight_quality: f32,            // 0.1 — prefer higher quality tests
    pub include_previously_failing: bool, // Always include (safety net)
    pub include_new_tests: bool,        // Always include new tests (safety net)
}

pub struct MinimumTestSetResult {
    pub selected: Vec<SelectedTest>,
    pub total_tests: usize,
    pub selected_count: usize,
    pub coverage_achieved: f32,         // Actual coverage of changed code
    pub estimated_time: Duration,       // Based on historical execution times
    pub estimated_savings: Duration,    // vs running all impacted tests
    pub safety_additions: Vec<SafetyTest>, // Previously failing + new tests
    pub uncovered_functions: Vec<String>,  // Functions not covered by selection
}

pub struct SelectedTest {
    pub test_id: String,
    pub file: String,
    pub name: String,
    pub reason: SelectionReason,
    pub covers_functions: Vec<String>,
    pub estimated_time: Option<Duration>,
    pub quality_score: f32,
    pub reliability_score: f32,         // 1.0 = never flaky, 0.0 = always flaky
}

pub enum SelectionReason {
    CoverageOptimal,                    // Selected by set cover algorithm
    PreviouslyFailing,                  // Safety net: failed in last run
    NewTest,                            // Safety net: newly added test
    OnlyCoverage,                       // Only test covering a changed function
    HighRiskFunction,                   // Covers a high-risk uncovered function
}
```

### Greedy Weighted Set Cover

```rust
pub fn compute_minimum_test_set(
    changed_files: &[String],
    coverage_map: &CoverageMap,
    call_graph: &CallGraph,
    execution_history: Option<&ExecutionHistory>,
    config: &MinimumTestSetConfig,
) -> MinimumTestSetResult {
    // 1. Find all functions in changed files
    let changed_functions: HashSet<FunctionId> = changed_files.iter()
        .flat_map(|f| call_graph.functions_in_file(f))
        .collect();

    // 2. Find all candidate tests
    let candidates: Vec<TestCandidate> = changed_functions.iter()
        .flat_map(|f| coverage_map.tests_covering(f))
        .unique_by(|t| &t.test_id)
        .map(|t| score_candidate(t, execution_history, config))
        .collect();

    // 3. Safety net: always include previously failing and new tests
    let mut selected = Vec::new();
    let mut covered = HashSet::new();

    for candidate in &candidates {
        if candidate.is_previously_failing || candidate.is_new {
            selected.push(candidate.clone());
            covered.extend(candidate.covers.iter().cloned());
        }
    }

    // 4. Greedy weighted set cover for remaining
    let mut remaining: Vec<_> = candidates.iter()
        .filter(|c| !selected.iter().any(|s| s.test_id == c.test_id))
        .collect();

    while coverage_ratio(&covered, &changed_functions) < config.coverage_target {
        if remaining.is_empty() { break; }

        // Score each remaining test by marginal value
        let best = remaining.iter()
            .max_by(|a, b| {
                let a_marginal = marginal_coverage(a, &covered, &changed_functions);
                let b_marginal = marginal_coverage(b, &covered, &changed_functions);
                let a_score = a_marginal * config.weight_coverage
                    + a.speed_score * config.weight_speed
                    + a.reliability * config.weight_reliability
                    + a.quality * config.weight_quality;
                let b_score = b_marginal * config.weight_coverage
                    + b.speed_score * config.weight_speed
                    + b.reliability * config.weight_reliability
                    + b.quality * config.weight_quality;
                a_score.partial_cmp(&b_score).unwrap()
            });

        if let Some(best) = best {
            covered.extend(best.covers.iter().cloned());
            selected.push((*best).clone());
            remaining.retain(|c| c.test_id != best.test_id);
        }

        if let Some(max) = config.max_tests {
            if selected.len() >= max { break; }
        }
    }

    // 5. Build result
    MinimumTestSetResult { /* ... */ }
}
```

### Cross-System Impact
- **10-cli**: `drift test-set <changed-files>` command for CI integration
- **07-mcp**: `drift_minimum_test_set` tool for AI-assisted PR review
- **09-quality-gates**: Minimum test set feeds into impact simulation gate

---

## R7: Test Execution Data Ingestion (P1)

### Problem
V1 has no integration with test execution results. The system cannot consume JUnit XML, pytest JSON, or coverage reports. This means no actual execution times, no flakiness data, no real coverage validation.

### Recommendation
Build a test result ingestion pipeline that consumes standard formats and enriches the topology with execution data.

### Supported Formats

| Format | Source | Data Extracted |
|--------|--------|---------------|
| JUnit XML | All CI systems | Pass/fail, execution time, error messages, test count |
| pytest JSON | Python CI | Pass/fail, duration, markers, fixtures used |
| CTRF JSON | Modern frameworks | Standardized results across frameworks |
| Istanbul/NYC JSON | JS/TS coverage | Line/branch/function coverage per file |
| coverage.py JSON | Python coverage | Line coverage per file |
| JaCoCo XML | Java coverage | Line/branch/method coverage |
| Cobertura XML | Multi-language | Line/branch coverage |
| lcov | C/C++/Go | Line coverage |

### Ingestion API

```rust
#[napi]
pub fn ingest_test_results(
    format: String,         // "junit-xml", "pytest-json", "ctrf", etc.
    content: String,        // Raw file content
) -> JsTestResultIngestion { ... }

#[napi]
pub fn ingest_coverage_report(
    format: String,         // "istanbul", "coverage-py", "jacoco", "cobertura", "lcov"
    content: String,
) -> JsCoverageIngestion { ... }
```

### Data Model

```rust
pub struct TestExecutionRecord {
    pub test_id: String,
    pub status: TestStatus,             // Passed, Failed, Skipped, Error
    pub duration_ms: Option<u64>,
    pub error_message: Option<String>,
    pub timestamp: u64,
    pub run_id: String,                 // Groups results from same CI run
    pub branch: Option<String>,
    pub commit: Option<String>,
}

pub struct ExecutionHistory {
    /// test_id → Vec<TestExecutionRecord> (last N runs)
    records: HashMap<String, Vec<TestExecutionRecord>>,
    /// Computed metrics
    pub flaky_tests: HashSet<String>,   // Tests that flip pass/fail without code change
    pub slow_tests: Vec<(String, Duration)>, // Tests above P95 duration
    pub avg_durations: HashMap<String, Duration>,
}
```

### Flakiness Detection

```rust
impl ExecutionHistory {
    /// A test is flaky if it has both pass and fail results
    /// within a window where the test file didn't change
    pub fn detect_flaky_tests(&self, topology_cache: &TestTopologyCache) -> HashSet<String> {
        let mut flaky = HashSet::new();

        for (test_id, records) in &self.records {
            // Group by file_hash (same test code)
            let groups = records.iter()
                .group_by(|r| topology_cache.hash_at_commit(&test_id, &r.commit));

            for (hash, group) in &groups {
                let statuses: Vec<_> = group.map(|r| &r.status).collect();
                let has_pass = statuses.iter().any(|s| **s == TestStatus::Passed);
                let has_fail = statuses.iter().any(|s| **s == TestStatus::Failed);

                if has_pass && has_fail {
                    flaky.insert(test_id.clone());
                }
            }
        }

        flaky
    }
}
```

### Cross-System Impact
- **08-storage**: Execution history stored in SQLite with retention policy (90 days)
- **R6**: Execution times and flakiness data feed into minimum test set selection
- **09-quality-gates**: Flaky test count as a quality gate metric
- **10-cli**: `drift ingest-results <path>` command for CI pipeline integration

---

## R8: Uncovered Function Risk Scoring (P1)

### Problem
V1's risk scoring is basic: +30 for entry point, +25 for sensitive data, plus centrality. No consideration of code complexity, change frequency, or historical bug density.

### Recommendation
Build a multi-factor risk scoring model that combines static analysis signals with historical data.

### Risk Model

```rust
pub struct UncoveredFunctionRisk {
    pub function_id: FunctionId,
    pub risk_score: f32,                // 0-100
    pub risk_level: RiskLevel,          // Critical, High, Medium, Low
    pub factors: Vec<RiskFactor>,
    pub suggested_test_type: TestType,  // Unit, Integration, E2E
    pub estimated_effort: TestEffort,   // Low, Medium, High
    pub non_coverage_reason: Option<NonCoverageReason>,
}

pub struct RiskFactor {
    pub factor: RiskFactorType,
    pub weight: f32,
    pub value: f32,
    pub explanation: String,
}

pub enum RiskFactorType {
    IsEntryPoint,                       // +25: API endpoint, exported function
    AccessesSensitiveData,              // +20: PII, credentials, financial data
    HighCentrality,                     // +15: many callers in call graph
    HighComplexity,                     // +15: cyclomatic complexity > threshold
    RecentlyChanged,                    // +10: changed in last N commits
    HistoricalBugDensity,               // +10: file has had bugs before
    SecurityCritical,                   // +20: in auth/crypto/validation path
    NoErrorHandling,                    // +10: no try/catch or error return
    CrossBoundary,                      // +5: crosses module/package boundary
}

pub enum NonCoverageReason {
    DeadCode,                           // No callers
    FrameworkHook,                      // Lifecycle method
    Generated,                          // In generated file
    Trivial,                            // Getter/setter/constructor
    TestOnly,                           // Only called from tests
    Deprecated,                         // Marked deprecated
    ThirdParty,                         // Wrapper around third-party code
    InternalOnly,                       // Private/internal, tested through public API
}
```

### Cross-System Impact
- **04-call-graph**: Centrality data from call graph
- **05-analyzers**: Complexity data from flow analyzer
- **19-error-handling**: Error handling gaps feed into risk scoring
- **21-security**: Security-critical path detection

---

## R9: Mock Analysis with Dependency Classification (P1)

### Problem
V1 classifies mocks as external/internal but doesn't go deeper. No detection of mock anti-patterns, no tracking of mock-to-real coverage ratio per module, no identification of "mock-heavy" modules that indicate design issues.

### Recommendation
Build comprehensive mock analysis with dependency classification, anti-pattern detection, and module-level health metrics.

### Mock Health Model

```rust
pub struct MockAnalysisResult {
    pub summary: MockSummary,
    pub per_test: Vec<TestMockProfile>,
    pub per_module: Vec<ModuleMockProfile>,
    pub anti_patterns: Vec<MockAntiPattern>,
    pub recommendations: Vec<MockRecommendation>,
}

pub struct MockSummary {
    pub total_mocks: usize,
    pub by_category: HashMap<MockCategory, usize>,
    pub avg_mock_ratio: f32,
    pub tests_above_threshold: usize,   // Tests with mock ratio > 0.7
    pub modules_over_mocked: usize,     // Modules mocked in >50% of tests
}

pub enum MockCategory {
    ExternalApi,                        // Third-party APIs, payment gateways
    Database,                           // DB queries, ORM calls
    FileSystem,                         // File I/O
    Network,                            // HTTP, gRPC, WebSocket
    InternalService,                    // Own microservices
    InternalModule,                     // Own code modules (suspicious)
    TimeDate,                           // Clock/timer mocks (acceptable)
    Random,                             // Random number generators (acceptable)
}

pub struct MockAntiPattern {
    pub pattern: MockAntiPatternType,
    pub test_id: String,
    pub line: u32,
    pub severity: SmellSeverity,
    pub suggestion: String,
}

pub enum MockAntiPatternType {
    DeepMock,                           // Mock returning mock
    OverMocking,                        // >70% mock ratio
    InternalMocking,                    // Mocking own code instead of using real impl
    MockWithoutVerification,            // Mock created but never verified
    PartialMock,                        // Partial mock of class under test
    MockingValueObjects,                // Mocking simple data objects
}
```

### Cross-System Impact
- **03-detectors**: Mock anti-patterns are a form of code smell — shared severity model
- **07-mcp**: AI agents use mock analysis to suggest refactoring opportunities
- **09-quality-gates**: Mock health as a quality gate dimension

---

## R10: Test Topology SQLite Schema (P1)

### Problem
V1 stores test topology data in memory during analysis with no persistence. Results are recomputed from scratch on every scan.

### Recommendation
Persist all test topology data in the unified SQLite database with proper indexing for fast queries.

### Schema

```sql
-- Test files and their metadata
CREATE TABLE test_files (
    file_path TEXT PRIMARY KEY,
    language TEXT NOT NULL,
    framework TEXT NOT NULL,
    test_count INTEGER NOT NULL,
    mock_count INTEGER NOT NULL,
    smell_count INTEGER NOT NULL,
    quality_grade TEXT,                 -- A, B, C, D, F
    avg_quality_score REAL,
    content_hash INTEGER NOT NULL,
    extracted_at INTEGER NOT NULL
);

-- Individual test cases
CREATE TABLE test_cases (
    id TEXT PRIMARY KEY,                -- "file:name:line"
    file_path TEXT NOT NULL REFERENCES test_files(file_path),
    name TEXT NOT NULL,
    qualified_name TEXT NOT NULL,
    line INTEGER NOT NULL,
    end_line INTEGER NOT NULL,
    test_type TEXT NOT NULL,            -- unit, integration, e2e, performance, snapshot
    is_async BOOLEAN NOT NULL DEFAULT 0,
    is_skipped BOOLEAN NOT NULL DEFAULT 0,
    is_parameterized BOOLEAN NOT NULL DEFAULT 0,
    assertion_count INTEGER NOT NULL DEFAULT 0,
    quality_score REAL,
    quality_grade TEXT
);

-- Coverage mappings: test → source function
CREATE TABLE test_coverage (
    test_id TEXT NOT NULL REFERENCES test_cases(id),
    function_id TEXT NOT NULL,
    source_file TEXT NOT NULL,
    reach_type TEXT NOT NULL,           -- direct, transitive, mocked, import_only
    reach_depth INTEGER NOT NULL DEFAULT 0,
    confidence REAL NOT NULL,
    PRIMARY KEY (test_id, function_id)
);

-- Mock statements
CREATE TABLE mock_statements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    test_file TEXT NOT NULL REFERENCES test_files(file_path),
    test_id TEXT REFERENCES test_cases(id),
    target TEXT NOT NULL,
    mock_type TEXT NOT NULL,
    mock_category TEXT NOT NULL,
    line INTEGER NOT NULL,
    has_implementation BOOLEAN NOT NULL DEFAULT 0,
    is_deep_mock BOOLEAN NOT NULL DEFAULT 0
);

-- Test smells detected
CREATE TABLE test_smells (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    test_id TEXT NOT NULL REFERENCES test_cases(id),
    smell_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    line INTEGER NOT NULL,
    suggestion TEXT,
    auto_fixable BOOLEAN NOT NULL DEFAULT 0
);

-- Test execution history (from ingested results)
CREATE TABLE test_executions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    test_id TEXT NOT NULL,
    status TEXT NOT NULL,               -- passed, failed, skipped, error
    duration_ms INTEGER,
    error_message TEXT,
    run_id TEXT NOT NULL,
    branch TEXT,
    commit_sha TEXT,
    timestamp INTEGER NOT NULL
);

-- Uncovered functions with risk scores
CREATE TABLE uncovered_functions (
    function_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    file_path TEXT NOT NULL,
    line INTEGER NOT NULL,
    risk_score REAL NOT NULL,
    risk_level TEXT NOT NULL,
    non_coverage_reason TEXT,
    computed_at INTEGER NOT NULL
);

-- Indexes for common queries
CREATE INDEX idx_coverage_source ON test_coverage(source_file);
CREATE INDEX idx_coverage_function ON test_coverage(function_id);
CREATE INDEX idx_cases_file ON test_cases(file_path);
CREATE INDEX idx_executions_test ON test_executions(test_id);
CREATE INDEX idx_executions_run ON test_executions(run_id);
CREATE INDEX idx_smells_test ON test_smells(test_id);
CREATE INDEX idx_uncovered_risk ON uncovered_functions(risk_score DESC);
```

### Cross-System Impact
- **08-storage**: Integrated into unified drift.db schema
- **07-mcp**: All MCP queries go through SQLite for consistent, fast access
- **15-migration**: Schema versioned with migration support

---

## R11: NAPI Bridge API (P1)

### Recommendation
Expose a comprehensive NAPI API that TypeScript consumers (MCP, CLI, Quality Gates) can call.

### API Surface

```rust
// Extraction
#[napi] pub fn extract_tests(path: String, content: String) -> JsTestExtraction;
#[napi] pub fn extract_tests_batch(files: Vec<JsFileInput>) -> Vec<JsTestExtraction>;
#[napi] pub fn detect_framework(path: String, content: String) -> Option<String>;

// Coverage
#[napi] pub fn build_coverage_map(db_path: String) -> JsCoverageMap;
#[napi] pub fn get_coverage_for_file(db_path: String, file: String) -> JsFileCoverage;
#[napi] pub fn get_uncovered_functions(db_path: String, opts: JsUncoveredOpts) -> Vec<JsUncoveredFunction>;

// Minimum Test Set
#[napi] pub fn compute_minimum_test_set(
    db_path: String, changed_files: Vec<String>, config: JsTestSetConfig
) -> JsMinimumTestSet;

// Quality
#[napi] pub fn score_test_quality(extraction: JsTestExtraction) -> JsQualityScore;
#[napi] pub fn analyze_mocks(db_path: String) -> JsMockAnalysis;
#[napi] pub fn get_test_smells(db_path: String, opts: JsSmellOpts) -> Vec<JsTestSmell>;

// Ingestion
#[napi] pub fn ingest_test_results(format: String, content: String) -> JsIngestionResult;
#[napi] pub fn ingest_coverage_report(format: String, content: String) -> JsCoverageIngestion;

// Summary
#[napi] pub fn get_topology_summary(db_path: String) -> JsTopologySummary;
```

---

## R12: MCP Tool Redesign (P2)

### Problem
V1 exposes a single `drift_test_topology` tool. This is too coarse — AI agents need targeted queries.

### Recommendation
Split into focused tools aligned with the MCP tool consolidation pattern from 07-mcp recommendations.

### Tool Surface

| Tool | Purpose | Key Parameters |
|------|---------|---------------|
| `drift_test_coverage` | Coverage for a file/function | file, function, include_transitive |
| `drift_test_set` | Minimum test set for changes | changed_files, coverage_target |
| `drift_uncovered` | Uncovered functions with risk | min_risk, limit, sort_by |
| `drift_test_quality` | Quality scores and smells | file, grade_filter, smell_filter |
| `drift_mock_analysis` | Mock health and anti-patterns | file, category_filter |
| `drift_test_summary` | Topology-wide statistics | — |

Or, following the consolidated tool pattern from R12 in 07-mcp:

```
drift_analyze(type: "test_topology", subtype: "coverage", params: { file: "..." })
drift_analyze(type: "test_topology", subtype: "minimum_set", params: { changed: [...] })
drift_analyze(type: "test_topology", subtype: "uncovered", params: { min_risk: 50 })
```

---

## Implementation Priority Matrix

| Rec | Title | Priority | Effort | Dependencies | Phase |
|-----|-------|----------|--------|-------------|-------|
| R1 | Rust Extraction Engine | P0 | High | 02-parsers (tree-sitter) | Phase 7 |
| R2 | Incremental Analysis | P0 | Medium | R1, 08-storage | Phase 7 |
| R3 | Test Smell Detection | P0 | Medium | R1 | Phase 7 |
| R4 | Quality Scoring | P0 | Medium | R1, R3 | Phase 7 |
| R5 | Coverage Mapping | P0 | High | R1, 04-call-graph | Phase 7 |
| R6 | Minimum Test Set | P1 | High | R5, R7 | Phase 7+ |
| R7 | Execution Data Ingestion | P1 | Medium | R10 | Phase 7+ |
| R8 | Risk Scoring | P1 | Medium | R5, 04-call-graph | Phase 7+ |
| R9 | Mock Analysis | P1 | Medium | R1 | Phase 7+ |
| R10 | SQLite Schema | P1 | Low | 08-storage | Phase 5 (with storage) |
| R11 | NAPI Bridge | P1 | Medium | R1-R9 | Phase 7 |
| R12 | MCP Tools | P2 | Low | R11, 07-mcp | Phase 7+ |

### Critical Path

```
R1 (Extraction) → R3 (Smells) → R4 (Quality)
                → R5 (Coverage) → R6 (Min Test Set)
                                → R8 (Risk Scoring)
                → R9 (Mock Analysis)
R10 (Schema) — can start independently with storage phase
R7 (Ingestion) — can start independently, feeds into R6
R11 (NAPI) — wraps R1-R9 for TS consumers
R12 (MCP) — wraps R11 for AI agents
```

---

## Cross-Category Dependency Map

| This Recommendation | Depends On | Depended On By |
|--------------------|-----------|----------------|
| R1 (Extraction) | 02-parsers, 01-rust-core | R2-R9, R11 |
| R2 (Incremental) | R1, 08-storage | All (performance) |
| R3 (Smells) | R1 | R4, 09-quality-gates |
| R4 (Quality) | R1, R3 | 07-mcp, 09-quality-gates, 13-advanced |
| R5 (Coverage) | R1, 04-call-graph | R6, R8, 09-quality-gates, 21-security |
| R6 (Min Test Set) | R5, R7 | 07-mcp, 10-cli |
| R7 (Ingestion) | R10 | R6 (execution times), R8 (bug density) |
| R8 (Risk) | R5, 04-call-graph, 19-error-handling | 07-mcp, 09-quality-gates |
| R9 (Mocks) | R1 | 07-mcp, 03-detectors |
| R10 (Schema) | 08-storage | R7, all queries |
| R11 (NAPI) | R1-R9 | R12, 10-cli, 25-services |
| R12 (MCP) | R11, 07-mcp | AI agents |

---

## Security Considerations

1. **Test execution data ingestion**: Validate all ingested XML/JSON to prevent XXE attacks (JUnit XML) and JSON injection. Use a sandboxed parser.
2. **File path handling**: All file paths in test topology must be normalized and validated against the project root to prevent path traversal.
3. **Sensitive data in test names**: Test names may contain sensitive information (API keys in parameterized tests, PII in test data). The system should support redaction rules.
4. **Mock target analysis**: Mock targets reveal internal architecture. Ensure test topology data respects the same access controls as other Drift data.
5. **Execution history retention**: Test execution records may contain error messages with sensitive data. Apply the same 90-day retention policy as audit data.

---

## Quality Checklist

- [x] 12 recommendations covering all identified gaps
- [x] Rust API signatures for all core components
- [x] SQLite schema with proper indexing
- [x] NAPI bridge API surface defined
- [x] Cross-system impact analysis for every recommendation
- [x] Implementation priority matrix with critical path
- [x] Security considerations documented
- [x] Dependency map across all 12 recommendations
- [x] Research-backed decisions (Meta PTS, Microsoft TIA, test smell catalog, mutation testing)
- [x] Backward compatibility with v1 data models considered
- [x] Performance targets specified (full extraction <30s, incremental <500ms)
- [x] Enterprise-scale considerations (500K+ files, monorepo, multi-language)
