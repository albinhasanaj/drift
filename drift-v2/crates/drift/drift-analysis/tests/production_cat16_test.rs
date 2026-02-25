//! Category 16: Detection Engine (Flow 3) — Production Tests
//!
//! 16 detector categories, 3 detector variants, panic-safe execution via `catch_unwind`.
//!
//! T16-01 through T16-07.

use std::collections::HashSet;

use drift_analysis::detectors::registry::{create_default_registry, DetectorRegistry};
use drift_analysis::detectors::traits::{Detector, DetectorCategory, DetectorVariant};
use drift_analysis::engine::types::{DetectionMethod, PatternCategory, PatternMatch};
use drift_analysis::engine::visitor::{
    DetectionContext, DetectionEngine, LearningDetectorHandler, VisitorRegistry,
};
use drift_analysis::parsers::types::{
    CallSite, ClassInfo, ClassKind, DocCommentInfo, DocCommentStyle,
    ErrorHandlingInfo, ErrorHandlingKind, ExportInfo, FunctionInfo, ImportInfo, ParseResult,
    Position, Range, StringLiteralInfo, StringContext,
};
use drift_analysis::scanner::language_detect::Language;
use smallvec::{smallvec, SmallVec};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn default_range() -> Range {
    Range {
        start: Position { line: 0, column: 0 },
        end: Position { line: 0, column: 0 },
    }
}

fn make_call(name: &str, line: u32, receiver: Option<&str>) -> CallSite {
    CallSite {
        callee_name: name.to_string(),
        receiver: receiver.map(|s| s.to_string()),
        file: "test.ts".to_string(),
        line,
        column: 0,
        argument_count: 0,
        is_await: false,
    }
}

fn make_function(name: &str, line: u32) -> FunctionInfo {
    FunctionInfo {
        name: name.to_string(),
        qualified_name: None,
        file: "test.ts".to_string(),
        line,
        column: 0,
        end_line: line + 10,
        parameters: smallvec![],
        return_type: None,
        generic_params: smallvec![],
        visibility: drift_analysis::parsers::types::Visibility::Public,
        is_exported: false,
        is_async: false,
        is_generator: false,
        is_abstract: false,
        range: Range {
            start: Position { line, column: 0 },
            end: Position {
                line: line + 10,
                column: 0,
            },
        },
        decorators: Vec::new(),
        doc_comment: None,
        body_hash: 0,
        signature_hash: 0,
    }
}

fn make_import(source: &str, line: u32) -> ImportInfo {
    ImportInfo {
        source: source.to_string(),
        specifiers: smallvec![],
        is_type_only: false,
        file: "test.ts".to_string(),
        line,
    }
}

fn make_export(name: &str, line: u32) -> ExportInfo {
    ExportInfo {
        name: Some(name.to_string()),
        is_default: false,
        is_type_only: false,
        source: None,
        file: "test.ts".to_string(),
        line,
    }
}

fn make_class(name: &str, line: u32) -> ClassInfo {
    ClassInfo {
        name: name.to_string(),
        namespace: None,
        extends: None,
        implements: smallvec![],
        generic_params: smallvec![],
        is_exported: false,
        is_abstract: false,
        class_kind: ClassKind::Class,
        methods: Vec::new(),
        properties: Vec::new(),
        range: Range {
            start: Position { line, column: 0 },
            end: Position {
                line: line + 20,
                column: 0,
            },
        },
        decorators: Vec::new(),
    }
}

fn make_string_literal(value: &str, line: u32) -> StringLiteralInfo {
    StringLiteralInfo {
        value: value.to_string(),
        context: StringContext::Unknown,
        file: "test.ts".to_string(),
        line,
        column: 0,
        range: default_range(),
    }
}

fn make_doc_comment(text: &str, line: u32) -> DocCommentInfo {
    DocCommentInfo {
        text: text.to_string(),
        style: DocCommentStyle::JsDoc,
        file: "test.ts".to_string(),
        line,
        range: default_range(),
    }
}

fn make_error_handling(kind: ErrorHandlingKind, line: u32, has_body: bool) -> ErrorHandlingInfo {
    ErrorHandlingInfo {
        kind,
        file: "test.ts".to_string(),
        line,
        end_line: line + 5,
        range: default_range(),
        caught_type: None,
        has_body,
        function_scope: None,
    }
}

/// Build a ParseResult that triggers at least one match from every detector category.
/// This is the "kitchen sink" file that all 16 detectors can find patterns in.
fn build_all_category_parse_result() -> (ParseResult, Vec<u8>) {
    let source = b"// kitchen sink file for all 16 detector categories".to_vec();

    let mut pr = ParseResult {
        file: "test.ts".to_string(),
        language: Language::TypeScript,
        ..Default::default()
    };

    // Security: eval() call
    pr.call_sites.push(make_call("eval", 1, None));

    // DataAccess: ORM method
    pr.call_sites.push(make_call("findOne", 2, None));

    // Errors: empty catch block (TryCatch with no body)
    pr.error_handling
        .push(make_error_handling(ErrorHandlingKind::TryCatch, 3, false));

    // Testing: test framework usage
    pr.call_sites.push(make_call("describe", 4, None));
    // Also add a mock call for testing detector
    pr.call_sites.push(make_call("jest.fn", 5, None));

    // Structural: function with naming convention
    pr.functions.push(make_function("myFunction", 6));

    // Api: REST route handler on known router receiver
    pr.call_sites.push(make_call("get", 7, Some("app")));
    // Also add an API route string literal
    pr.string_literals
        .push(make_string_literal("/api/v1/users", 8));

    // Auth: auth-related function
    let mut auth_func = make_function("authenticateUser", 9);
    auth_func.name = "authenticateUser".to_string();
    pr.functions.push(auth_func);
    // Auth: JWT import
    pr.imports.push(make_import("jsonwebtoken", 10));

    // Components: React import
    pr.imports.push(make_import("react", 11));

    // Config: env access call
    pr.call_sites
        .push(make_call("getenv", 12, None));

    // Contracts: interface definition
    let mut iface = make_class("IUserService", 13);
    iface.class_kind = ClassKind::Interface;
    pr.classes.push(iface);

    // Documentation: doc comment
    pr.doc_comments
        .push(make_doc_comment("/** This is a doc comment */", 14));

    // Logging: console.log call
    pr.call_sites
        .push(make_call("log", 15, Some("console")));

    // Performance: async function without await
    let mut async_func = make_function("fetchData", 16);
    async_func.is_async = true;
    pr.functions.push(async_func);

    // Styling: styled-components import
    pr.imports.push(make_import("styled-components", 17));

    // Types: function with return type
    let mut typed_func = make_function("getUser", 18);
    typed_func.return_type = Some("User".to_string());
    pr.functions.push(typed_func);

    // Accessibility: a11y import
    pr.imports.push(make_import("@testing-library/jest-dom", 19));

    // Add an export so structural detector can find export patterns
    pr.exports.push(make_export("myFunction", 20));

    (pr, source)
}

// ---------------------------------------------------------------------------
// T16-01: All 16 Detectors Fire
// ---------------------------------------------------------------------------

#[test]
fn t16_01_all_16_detectors_fire() {
    let registry = create_default_registry();

    // Verify we have at least 16 detectors registered
    assert!(
        registry.count() >= 16,
        "Expected at least 16 detectors, got {}",
        registry.count()
    );

    let (pr, source) = build_all_category_parse_result();
    let ctx = DetectionContext::from_parse_result(&pr, &source);

    let matches = registry.run_all(&ctx);

    // Collect all unique categories from matches
    let categories: HashSet<String> = matches.iter().map(|m| m.category.name().to_string()).collect();

    // We expect matches from all 16 categories
    let expected_categories = [
        "security",
        "data_access",
        "errors",
        "testing",
        "structural",
        "api",
        "auth",
        "components",
        "config",
        "contracts",
        "documentation",
        "logging",
        "performance",
        "styling",
        "types",
        "accessibility",
    ];

    let mut missing: Vec<&str> = Vec::new();
    for cat in &expected_categories {
        if !categories.contains(*cat) {
            missing.push(cat);
        }
    }

    assert!(
        missing.is_empty(),
        "Missing categories: {:?}\nGot categories: {:?}\nTotal matches: {}",
        missing,
        categories,
        matches.len()
    );

    // Every match must have detection_method set
    for m in &matches {
        // DetectionMethod is always set by construction (it's not Option), but verify non-default
        // by checking it's one of the known variants
        assert!(
            matches!(
                m.detection_method,
                DetectionMethod::AstVisitor
                    | DetectionMethod::StringRegex
                    | DetectionMethod::TomlPattern
                    | DetectionMethod::LearningDeviation
                    | DetectionMethod::Semantic
            ),
            "detection_method must be a known variant for match: {:?}",
            m.pattern_id
        );
    }

    assert!(
        matches.len() >= 16,
        "Expected at least 16 matches (1 per category), got {}",
        matches.len()
    );
}

// ---------------------------------------------------------------------------
// T16-02: Detector Panic Safety
// ---------------------------------------------------------------------------

/// A detector that panics inside detect().
struct PanickingDetector;

impl Detector for PanickingDetector {
    fn id(&self) -> &str {
        "panicking-detector"
    }
    fn category(&self) -> DetectorCategory {
        DetectorCategory::Security
    }
    fn variant(&self) -> DetectorVariant {
        DetectorVariant::Base
    }
    fn detect(&self, _ctx: &DetectionContext) -> Vec<PatternMatch> {
        panic!("intentional panic inside detector");
    }
}

/// A detector that always produces a result (canary).
struct CanaryDetector;

impl Detector for CanaryDetector {
    fn id(&self) -> &str {
        "canary-detector"
    }
    fn category(&self) -> DetectorCategory {
        DetectorCategory::Structural
    }
    fn variant(&self) -> DetectorVariant {
        DetectorVariant::Base
    }
    fn detect(&self, ctx: &DetectionContext) -> Vec<PatternMatch> {
        vec![PatternMatch {
            file: ctx.file.to_string(),
            line: 0,
            column: 0,
            pattern_id: "CANARY-001".to_string(),
            confidence: 1.0,
            cwe_ids: SmallVec::new(),
            owasp: None,
            detection_method: DetectionMethod::AstVisitor,
            category: PatternCategory::Structural,
            matched_text: "canary".to_string(),
        }]
    }
}

#[test]
fn t16_02_detector_panic_safety() {
    let mut registry = DetectorRegistry::new();

    // Register panicking detector first, then canary after
    registry.register(Box::new(PanickingDetector));
    registry.register(Box::new(CanaryDetector));

    let pr = ParseResult {
        file: "test.ts".to_string(),
        language: Language::TypeScript,
        ..Default::default()
    };
    let source = b"test content";
    let ctx = DetectionContext::from_parse_result(&pr, source);

    // Must NOT panic — catch_unwind must prevent crash
    let matches = registry.run_all(&ctx);

    // Canary detector must still have run and produced a result
    assert!(
        matches.iter().any(|m| m.pattern_id == "CANARY-001"),
        "Canary detector should still produce results after panicking detector"
    );

    // The panicking detector should NOT produce any matches
    assert!(
        !matches
            .iter()
            .any(|m| m.pattern_id.contains("PANIC")),
        "Panicking detector should not produce matches"
    );
}

// ---------------------------------------------------------------------------
// T16-03: Learning Detector 2-Pass
// ---------------------------------------------------------------------------

/// A test LearningDetectorHandler that learns naming conventions, then detects deviations.
struct NamingConventionLearner {
    snake_case_count: usize,
    camel_case_count: usize,
    learned_dominant: Option<String>,
    results: Vec<PatternMatch>,
}

impl NamingConventionLearner {
    fn new() -> Self {
        Self {
            snake_case_count: 0,
            camel_case_count: 0,
            learned_dominant: None,
            results: Vec::new(),
        }
    }

    fn classify(name: &str) -> Option<&'static str> {
        if name.contains('_') && name == name.to_lowercase() {
            Some("snake_case")
        } else if name.chars().any(|c| c.is_uppercase())
            && name.chars().next().is_some_and(|c| c.is_lowercase())
        {
            Some("camelCase")
        } else {
            None
        }
    }
}

impl LearningDetectorHandler for NamingConventionLearner {
    fn id(&self) -> &str {
        "naming-convention-learner"
    }

    fn languages(&self) -> &[Language] {
        &[]
    }

    fn learn(&mut self, ctx: &DetectionContext) {
        for func in ctx.functions {
            match Self::classify(&func.name) {
                Some("snake_case") => self.snake_case_count += 1,
                Some("camelCase") => self.camel_case_count += 1,
                _ => {}
            }
        }
        // After learning, determine dominant convention
        if self.snake_case_count > self.camel_case_count {
            self.learned_dominant = Some("snake_case".to_string());
        } else if self.camel_case_count > self.snake_case_count {
            self.learned_dominant = Some("camelCase".to_string());
        }
    }

    fn detect(&mut self, ctx: &DetectionContext) {
        let dominant = match &self.learned_dominant {
            Some(d) => d.clone(),
            None => return,
        };
        for func in ctx.functions {
            if let Some(convention) = Self::classify(&func.name) {
                if convention != dominant {
                    self.results.push(PatternMatch {
                        file: ctx.file.to_string(),
                        line: func.line,
                        column: func.column,
                        pattern_id: "LEARN-NAMING-001".to_string(),
                        confidence: 0.80,
                        cwe_ids: SmallVec::new(),
                        owasp: None,
                        detection_method: DetectionMethod::LearningDeviation,
                        category: PatternCategory::Structural,
                        matched_text: format!(
                            "{} uses {} but dominant is {}",
                            func.name, convention, dominant
                        ),
                    });
                }
            }
        }
    }

    fn results(&self) -> Vec<PatternMatch> {
        self.results.clone()
    }

    fn reset(&mut self) {
        self.snake_case_count = 0;
        self.camel_case_count = 0;
        self.learned_dominant = None;
        self.results.clear();
    }
}

#[test]
fn t16_03_learning_detector_two_pass() {
    let mut visitor_registry = VisitorRegistry::new();
    visitor_registry.register_learning_handler(Box::new(NamingConventionLearner::new()));

    let mut engine = DetectionEngine::new(visitor_registry);

    // Build 100 "files" — 80 with snake_case, 20 with camelCase
    let mut contexts_data: Vec<(ParseResult, Vec<u8>)> = Vec::new();
    for i in 0..100u32 {
        let mut pr = ParseResult {
            file: format!("file_{}.ts", i),
            language: Language::TypeScript,
            ..Default::default()
        };
        if i < 80 {
            pr.functions.push(make_function(&format!("my_func_{}", i), 1));
        } else {
            pr.functions
                .push(make_function(&format!("myFunc{}", i), 1));
        }
        let source = format!("// file {}", i).into_bytes();
        contexts_data.push((pr, source));
    }

    let contexts: Vec<DetectionContext> = contexts_data
        .iter()
        .map(|(pr, src)| DetectionContext::from_parse_result(pr, src))
        .collect();

    // Run learning pass
    let learning_matches = engine.run_learning_pass(&contexts);

    // Learning detector should find deviations: camelCase functions when dominant is snake_case
    assert!(
        !learning_matches.is_empty(),
        "Learning detector should produce deviation matches"
    );

    // All matches should be LearningDeviation method
    for m in &learning_matches {
        assert_eq!(
            m.detection_method,
            DetectionMethod::LearningDeviation,
            "Learning detector should use LearningDeviation method"
        );
    }

    // Should detect the 20 camelCase deviations
    assert_eq!(
        learning_matches.len(),
        20,
        "Should detect 20 camelCase deviations (files 80-99)"
    );

    // Compare with a base detector (single pass) — the base structural detector doesn't
    // detect convention deviations, it just classifies what it sees.
    // So the learning detector must produce DIFFERENT results than a single-pass approach.
    let base_registry = create_default_registry();
    let (pr, source) = build_all_category_parse_result();
    let ctx = DetectionContext::from_parse_result(&pr, &source);
    let base_matches = base_registry.run_all(&ctx);
    let base_has_learning = base_matches
        .iter()
        .any(|m| m.detection_method == DetectionMethod::LearningDeviation);
    assert!(
        !base_has_learning,
        "Base detectors should NOT produce LearningDeviation matches"
    );
}

// ---------------------------------------------------------------------------
// T16-04: DetectionContext Construction with Empty ParseResult
// ---------------------------------------------------------------------------

#[test]
fn t16_04_detection_context_from_empty_parse_result() {
    let pr = ParseResult {
        file: "empty.ts".to_string(),
        language: Language::TypeScript,
        ..Default::default()
    };
    let source = b"";

    // Must not panic
    let ctx = DetectionContext::from_parse_result(&pr, source);

    // All borrowed slices must be valid (empty but not null)
    assert_eq!(ctx.file, "empty.ts");
    assert_eq!(ctx.language, Language::TypeScript);
    assert!(ctx.source.is_empty());
    assert!(ctx.imports.is_empty());
    assert!(ctx.exports.is_empty());
    assert!(ctx.functions.is_empty());
    assert!(ctx.classes.is_empty());
    assert!(ctx.call_sites.is_empty());

    // Run all detectors on this empty context — must not panic
    let registry = create_default_registry();
    let matches = registry.run_all(&ctx);

    // Should produce zero matches since there's nothing to detect
    // (Some detectors might still produce matches for structural analysis of empty files,
    // but none should crash)
    // Just verify no panic occurred — matches count doesn't matter for this test
    let _ = matches;
}

// ---------------------------------------------------------------------------
// T16-05: PatternMatch Output Completeness
// ---------------------------------------------------------------------------

#[test]
fn t16_05_pattern_match_output_completeness() {
    let registry = create_default_registry();

    // Build a context with an eval() call so the security detector fires
    let mut pr = ParseResult {
        file: "insecure.ts".to_string(),
        language: Language::TypeScript,
        ..Default::default()
    };
    pr.call_sites.push(make_call("eval", 10, None));
    let source = b"eval(userInput)";
    let ctx = DetectionContext::from_parse_result(&pr, source);

    let matches = registry.run_all(&ctx);

    // Find the eval detection match
    let eval_match = matches
        .iter()
        .find(|m| m.pattern_id == "SEC-EVAL-001")
        .expect("Security detector should find eval() usage");

    // PatternMatch must have all 10 fields populated correctly:
    // 1. file
    assert_eq!(eval_match.file, "insecure.ts");
    // 2. line
    assert_eq!(eval_match.line, 10);
    // 3. column
    // column is set (may be 0)
    let _ = eval_match.column;
    // 4. pattern_id
    assert_eq!(eval_match.pattern_id, "SEC-EVAL-001");
    // 5. confidence
    assert!(
        eval_match.confidence > 0.0 && eval_match.confidence <= 1.0,
        "confidence must be in (0,1], got {}",
        eval_match.confidence
    );
    // 6. category
    assert_eq!(eval_match.category, PatternCategory::Security);
    // 7. detection_method
    assert_eq!(eval_match.detection_method, DetectionMethod::AstVisitor);
    // 8. matched_text
    assert!(
        !eval_match.matched_text.is_empty(),
        "matched_text must not be empty"
    );
    // 9. cwe_ids
    assert!(
        !eval_match.cwe_ids.is_empty(),
        "cwe_ids must be populated for security findings"
    );
    assert!(
        eval_match.cwe_ids.contains(&95),
        "cwe_ids must contain CWE-95 for eval injection, got {:?}",
        eval_match.cwe_ids
    );
    // 10. owasp
    assert!(
        eval_match.owasp.is_some(),
        "owasp must be populated for security findings"
    );
}

// ---------------------------------------------------------------------------
// T16-06: Category Filtering — critical_only
// ---------------------------------------------------------------------------

#[test]
fn t16_06_category_filtering_critical_only() {
    let mut registry = create_default_registry();

    // First, run without filtering to get a baseline
    let (pr, source) = build_all_category_parse_result();
    let ctx = DetectionContext::from_parse_result(&pr, &source);

    let all_matches = registry.run_all(&ctx);
    let all_categories: HashSet<String> = all_matches
        .iter()
        .map(|m| m.category.name().to_string())
        .collect();

    // Should have multiple categories
    assert!(
        all_categories.len() > 1,
        "Without filtering, should have matches from multiple categories"
    );

    // Enable critical-only mode
    registry.set_critical_only(true);

    let critical_matches = registry.run_all(&ctx);

    // Critical matches should be fewer (or equal) to all matches
    assert!(
        critical_matches.len() <= all_matches.len(),
        "Critical-only should produce fewer or equal matches"
    );

    // All critical matches should be from detectors where is_critical() = true
    // Only SecurityDetector has is_critical() = true
    let critical_categories: HashSet<String> = critical_matches
        .iter()
        .map(|m| m.category.name().to_string())
        .collect();

    // SecurityDetector is the only one with is_critical() = true
    // So critical_matches should only contain security category
    if !critical_matches.is_empty() {
        assert!(
            critical_categories.contains("security"),
            "Critical-only should include security category"
        );
        // Non-critical categories should be filtered out
        let non_critical_in_critical: Vec<_> = critical_categories
            .iter()
            .filter(|c| *c != "security")
            .collect();
        assert!(
            non_critical_in_critical.is_empty(),
            "Critical-only should NOT include non-critical categories: {:?}",
            non_critical_in_critical
        );
    }

    // Verify that enabled_count changed
    assert!(
        registry.enabled_count() < registry.count(),
        "With critical_only, enabled_count ({}) should be less than total count ({})",
        registry.enabled_count(),
        registry.count()
    );
}

// ---------------------------------------------------------------------------
// T16-07: Security Detector CWE Mapping
// ---------------------------------------------------------------------------

#[test]
fn t16_07_security_detector_cwe_mapping() {
    let registry = create_default_registry();

    // Build a context with eval(userInput) call
    let mut pr = ParseResult {
        file: "vulnerable.ts".to_string(),
        language: Language::TypeScript,
        ..Default::default()
    };
    pr.call_sites.push(CallSite {
        callee_name: "eval".to_string(),
        receiver: None,
        file: "vulnerable.ts".to_string(),
        line: 5,
        column: 4,
        argument_count: 1,
        is_await: false,
    });
    let source = b"const result = eval(userInput);";
    let ctx = DetectionContext::from_parse_result(&pr, source);

    let matches = registry.run_all(&ctx);

    // Find the eval match
    let eval_match = matches
        .iter()
        .find(|m| m.pattern_id == "SEC-EVAL-001")
        .expect("Must detect eval() call");

    // CWE-95: Eval injection
    assert!(
        eval_match.cwe_ids.contains(&95),
        "cwe_ids must contain CWE-95 (eval injection), got {:?}",
        eval_match.cwe_ids
    );

    // OWASP must be non-empty
    assert!(
        eval_match.owasp.is_some(),
        "owasp must be populated for eval injection"
    );
    let owasp = eval_match.owasp.as_ref().unwrap();
    assert!(
        !owasp.is_empty(),
        "owasp string must not be empty"
    );
    // Should be A03:2021 (Injection) based on the source code
    assert!(
        owasp.contains("A03"),
        "owasp should reference A03 (Injection), got {}",
        owasp
    );
}
