//! Testing detector — test patterns, assertion styles, mock usage.

use smallvec::SmallVec;

use crate::detectors::traits::{Detector, DetectorCategory, DetectorVariant};
use crate::engine::types::{DetectionMethod, PatternCategory, PatternMatch};
use crate::engine::visitor::DetectionContext;

pub struct TestingDetector;

impl Detector for TestingDetector {
    fn id(&self) -> &str { "testing-base" }
    fn category(&self) -> DetectorCategory { DetectorCategory::Testing }
    fn variant(&self) -> DetectorVariant { DetectorVariant::Base }

    fn detect(&self, ctx: &DetectionContext) -> Vec<PatternMatch> {
        let mut matches = Vec::new();

        let test_frameworks = [
            // JS/TS
            "describe", "it", "test", "expect", "assert",
            "beforeEach", "afterEach", "beforeAll", "afterAll",
            "jest", "mocha",
            // Python
            "pytest", "unittest",
            // Java/Kotlin
            "@Test", "@BeforeEach", "@AfterEach", "@ParameterizedTest",
            // Go
            "testing.T", "testing.B",
            // Rust
            "#[test]", "#[cfg(test)]",
            // Ruby
            "RSpec", "Minitest",
            // PHP
            "PHPUnit", "TestCase",
            // C#
            "[Test]", "[Fact]", "[Theory]", "TestMethod",
        ];
        let mock_patterns = [
            // JS/TS
            "mock", "stub", "spy", "jest.fn", "sinon",
            // Python
            "Mock", "patch", "MagicMock", "mocker",
            // Java/Kotlin
            "Mockito", "when", "verify", "MockBean",
            // Go
            "gomock", "testify",
            // Rust
            "mockall",
            // Ruby
            "double", "allow", "receive",
            // PHP
            "createMock", "getMockBuilder", "Prophecy",
            // C#
            "Moq", "Substitute", "FakeItEasy",
        ];
        let assertion_patterns = [
            // JS/TS
            "toBe", "toEqual", "toHaveBeenCalled", "toMatchSnapshot", "toThrow",
            // Python
            "assertEqual", "assertTrue", "assertFalse", "assertRaises", "assert_called",
            // Java/Kotlin
            "assertEquals", "assertThat", "assertThrows", "assertNotNull",
            // Go (testing.T methods)
            "Equal", "NoError", "Nil", "True", "False",
            // Rust
            "assert_eq", "assert_ne", "assert!",
            // Ruby
            "assert_equal", "refute", "expect_to",
            // PHP
            "assertSame", "assertInstanceOf", "assertCount",
            // C#
            "Assert.Equal", "Assert.True", "Assert.Throws",
        ];

        for call in ctx.call_sites {
            // Detect test framework usage
            if test_frameworks.contains(&call.callee_name.as_str()) {
                matches.push(PatternMatch {
                    file: ctx.file.to_string(),
                    line: call.line,
                    column: call.column,
                    pattern_id: "TEST-FRAMEWORK-001".to_string(),
                    confidence: 0.90,
                    cwe_ids: SmallVec::new(),
                    owasp: None,
                    detection_method: DetectionMethod::AstVisitor,
                    category: PatternCategory::Testing,
                    matched_text: format!("test framework: {}", call.callee_name),
                });
            }

            // Detect mock usage
            if mock_patterns.iter().any(|p| call.callee_name.contains(p)) {
                matches.push(PatternMatch {
                    file: ctx.file.to_string(),
                    line: call.line,
                    column: call.column,
                    pattern_id: "TEST-MOCK-001".to_string(),
                    confidence: 0.85,
                    cwe_ids: SmallVec::new(),
                    owasp: None,
                    detection_method: DetectionMethod::AstVisitor,
                    category: PatternCategory::Testing,
                    matched_text: format!("mock pattern: {}", call.callee_name),
                });
            }

            // Detect assertion patterns
            if assertion_patterns.iter().any(|p| call.callee_name.contains(p)) {
                matches.push(PatternMatch {
                    file: ctx.file.to_string(),
                    line: call.line,
                    column: call.column,
                    pattern_id: "TEST-ASSERT-001".to_string(),
                    confidence: 0.90,
                    cwe_ids: SmallVec::new(),
                    owasp: None,
                    detection_method: DetectionMethod::AstVisitor,
                    category: PatternCategory::Testing,
                    matched_text: format!("assertion: {}", call.callee_name),
                });
            }
        }

        // Detect test functions by naming convention
        for func in ctx.functions {
            let lower = func.name.to_lowercase();
            if lower.starts_with("test_") || lower.starts_with("test") || lower.ends_with("_test")
                || lower.starts_with("should_") || lower.starts_with("it_")
            {
                matches.push(PatternMatch {
                    file: ctx.file.to_string(),
                    line: func.line,
                    column: func.column,
                    pattern_id: "TEST-FUNC-001".to_string(),
                    confidence: 0.85,
                    cwe_ids: SmallVec::new(),
                    owasp: None,
                    detection_method: DetectionMethod::AstVisitor,
                    category: PatternCategory::Testing,
                    matched_text: format!("test function: {}", func.name),
                });
            }
        }

        matches
    }
}
