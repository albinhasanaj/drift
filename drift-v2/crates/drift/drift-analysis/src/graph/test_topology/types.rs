//! Test topology types — quality scores, smells, coverage.

use drift_core::types::collections::{FxHashMap, FxHashSet};
use petgraph::graph::NodeIndex;
use serde::{Deserialize, Serialize};

/// 7-dimension quality score for a test suite or function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestQualityScore {
    /// % of source functions covered by at least 1 test.
    pub coverage_breadth: f32,
    /// Average number of tests per source function.
    pub coverage_depth: f32,
    /// Assertions per test function.
    pub assertion_density: f32,
    /// % of dependencies mocked.
    pub mock_ratio: f32,
    /// Test independence (shared state detection).
    pub isolation: f32,
    /// Time since last test update relative to source update.
    pub freshness: f32,
    /// Test pass/fail consistency.
    pub stability: f32,
    /// Weighted aggregate score.
    pub overall: f32,
    /// Detected test smells.
    pub smells: Vec<TestSmell>,
}

impl TestQualityScore {
    /// Compute overall score from dimensions.
    pub fn compute_overall(&mut self) {
        // Weights: breadth=0.25, depth=0.15, assertion=0.15, mock=0.10,
        //          isolation=0.15, freshness=0.10, stability=0.10
        self.overall = self.coverage_breadth * 0.25
            + self.coverage_depth * 0.15
            + self.assertion_density * 0.15
            + self.mock_ratio * 0.10
            + self.isolation * 0.15
            + self.freshness * 0.10
            + self.stability * 0.10;
        self.overall = self.overall.clamp(0.0, 1.0);
    }
}

impl Default for TestQualityScore {
    fn default() -> Self {
        Self {
            coverage_breadth: 0.0,
            coverage_depth: 0.0,
            assertion_density: 0.0,
            mock_ratio: 0.0,
            isolation: 1.0, // Assume isolated by default
            freshness: 1.0, // Assume fresh by default
            stability: 1.0, // Assume stable by default
            overall: 0.0,
            smells: Vec::new(),
        }
    }
}

/// 24 test smell variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TestSmell {
    /// Test uses external resources without mocking.
    MysteryGuest,
    /// Test verifies too many things.
    EagerTest,
    /// Test doesn't verify enough.
    LazyTest,
    /// Multiple assertions without clear purpose.
    AssertionRoulette,
    /// Test body is empty.
    EmptyTest,
    /// Test uses sleep/delay.
    SleepInTest,
    /// Test has conditional logic.
    ConditionalTest,
    /// Test depends on execution order.
    OrderDependent,
    /// Test uses hardcoded values.
    HardcodedValues,
    /// Test duplicates production logic.
    DuplicateLogic,
    /// Test is too long.
    LongTest,
    /// Test has no assertions.
    AssertionFree,
    /// Test uses global state.
    GlobalState,
    /// Test has complex setup.
    ComplexSetup,
    /// Test ignores return values.
    IgnoredReturnValue,
    /// Test uses magic numbers.
    MagicNumbers,
    /// Test has dead code.
    DeadTestCode,
    /// Test catches and ignores exceptions.
    ExceptionSwallowing,
    /// Test uses deprecated APIs.
    DeprecatedApi,
    /// Test has flaky behavior.
    FlakyTest,
    /// Test mocks too many dependencies.
    ExcessiveMocking,
    /// Test has unclear naming.
    UnclearNaming,
    /// Test lacks cleanup/teardown.
    MissingCleanup,
    /// Test has redundant assertions.
    RedundantAssertion,
}

impl TestSmell {
    pub fn name(&self) -> &'static str {
        match self {
            Self::MysteryGuest => "mystery_guest",
            Self::EagerTest => "eager_test",
            Self::LazyTest => "lazy_test",
            Self::AssertionRoulette => "assertion_roulette",
            Self::EmptyTest => "empty_test",
            Self::SleepInTest => "sleep_in_test",
            Self::ConditionalTest => "conditional_test",
            Self::OrderDependent => "order_dependent",
            Self::HardcodedValues => "hardcoded_values",
            Self::DuplicateLogic => "duplicate_logic",
            Self::LongTest => "long_test",
            Self::AssertionFree => "assertion_free",
            Self::GlobalState => "global_state",
            Self::ComplexSetup => "complex_setup",
            Self::IgnoredReturnValue => "ignored_return_value",
            Self::MagicNumbers => "magic_numbers",
            Self::DeadTestCode => "dead_test_code",
            Self::ExceptionSwallowing => "exception_swallowing",
            Self::DeprecatedApi => "deprecated_api",
            Self::FlakyTest => "flaky_test",
            Self::ExcessiveMocking => "excessive_mocking",
            Self::UnclearNaming => "unclear_naming",
            Self::MissingCleanup => "missing_cleanup",
            Self::RedundantAssertion => "redundant_assertion",
        }
    }

    /// All 24 smell variants.
    pub fn all() -> &'static [TestSmell] {
        &[
            Self::MysteryGuest, Self::EagerTest, Self::LazyTest,
            Self::AssertionRoulette, Self::EmptyTest, Self::SleepInTest,
            Self::ConditionalTest, Self::OrderDependent, Self::HardcodedValues,
            Self::DuplicateLogic, Self::LongTest, Self::AssertionFree,
            Self::GlobalState, Self::ComplexSetup, Self::IgnoredReturnValue,
            Self::MagicNumbers, Self::DeadTestCode, Self::ExceptionSwallowing,
            Self::DeprecatedApi, Self::FlakyTest, Self::ExcessiveMocking,
            Self::UnclearNaming, Self::MissingCleanup, Self::RedundantAssertion,
        ]
    }
}

/// Coverage mapping: test function → set of covered source functions.
#[derive(Debug, Clone, Default)]
pub struct CoverageMapping {
    /// test_function → set of source functions it covers.
    pub test_to_source: FxHashMap<NodeIndex, FxHashSet<NodeIndex>>,
    /// source_function → set of tests that cover it.
    pub source_to_test: FxHashMap<NodeIndex, FxHashSet<NodeIndex>>,
    /// Total source functions.
    pub total_source_functions: usize,
    /// Total test functions.
    pub total_test_functions: usize,
}

/// Result of minimum test set computation.
#[derive(Debug, Clone)]
pub struct MinimumTestSet {
    /// The minimum set of tests that covers all source functions.
    pub tests: Vec<NodeIndex>,
    /// Number of source functions covered.
    pub covered_functions: usize,
    /// Total source functions.
    pub total_functions: usize,
    /// Coverage percentage.
    pub coverage_percent: f32,
}

/// Detected test framework.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TestFrameworkKind {
    // JavaScript/TypeScript
    Jest, Mocha, Vitest, Jasmine, Ava, Tape, QUnit, Cypress, Playwright, TestingLibrary,
    // Python
    Pytest, Unittest, Nose, Doctest, Hypothesis, Robot,
    // Java
    JUnit, TestNG, Mockito, Spock,
    // C#
    NUnit, XUnit, MSTest,
    // Go
    GoTest, Testify, Ginkgo,
    // Rust
    RustTest, Proptest, Criterion,
    // Ruby
    RSpec, Minitest, Cucumber,
    // PHP
    PHPUnit, Pest, Codeception,
    // Kotlin
    KotlinTest, Kotest, JUnit5,
    // Generic
    Unknown,
}

impl TestFrameworkKind {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Jest => "jest", Self::Mocha => "mocha", Self::Vitest => "vitest",
            Self::Jasmine => "jasmine", Self::Ava => "ava", Self::Tape => "tape",
            Self::QUnit => "qunit", Self::Cypress => "cypress", Self::Playwright => "playwright",
            Self::TestingLibrary => "testing_library",
            Self::Pytest => "pytest", Self::Unittest => "unittest", Self::Nose => "nose",
            Self::Doctest => "doctest", Self::Hypothesis => "hypothesis", Self::Robot => "robot",
            Self::JUnit => "junit", Self::TestNG => "testng", Self::Mockito => "mockito",
            Self::Spock => "spock",
            Self::NUnit => "nunit", Self::XUnit => "xunit", Self::MSTest => "mstest",
            Self::GoTest => "go_test", Self::Testify => "testify", Self::Ginkgo => "ginkgo",
            Self::RustTest => "rust_test", Self::Proptest => "proptest", Self::Criterion => "criterion",
            Self::RSpec => "rspec", Self::Minitest => "minitest", Self::Cucumber => "cucumber",
            Self::PHPUnit => "phpunit", Self::Pest => "pest", Self::Codeception => "codeception",
            Self::KotlinTest => "kotlin_test", Self::Kotest => "kotest", Self::JUnit5 => "junit5",
            Self::Unknown => "unknown",
        }
    }
}
