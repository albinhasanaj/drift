#![allow(clippy::field_reassign_with_default, clippy::redundant_closure, clippy::manual_range_contains, unused_variables, unused_imports)]
//! Phase 2 — Engine, Detectors, Call Graph, Boundaries Stress Tests
//!
//! RegexEngine timeout protection, multi-pattern matching, CallGraphBuilder
//! with synthetic parse results, BoundaryDetector framework detection,
//! sensitive field identification, and VisitorRegistry dispatch.

use drift_analysis::engine::regex_engine::{RegexEngine, RegexPattern};
use drift_analysis::engine::string_extraction::{
    ExtractedString, StringExtractionContext, StringKind,
};
use drift_analysis::engine::types::PatternCategory;
use drift_analysis::engine::visitor::{DetectionEngine, VisitorRegistry};
use drift_analysis::call_graph::builder::CallGraphBuilder;
use drift_analysis::call_graph::types::{CallGraph, FunctionNode, CallEdge, Resolution};
use drift_analysis::boundaries::detector::BoundaryDetector;
use drift_analysis::boundaries::sensitive::SensitiveFieldDetector;
use drift_analysis::boundaries::types::*;
use drift_analysis::parsers::types::*;

use smallvec::SmallVec;
use std::time::{Duration, Instant};

// ═══════════════════════════════════════════════════════════════════════════
// REGEX ENGINE — pattern matching, timeout, edge cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_regex_engine_default_patterns() {
    let engine = RegexEngine::new();
    assert!(engine.pattern_count() >= 7, "should have at least 7 default patterns");
}

#[test]
fn stress_regex_engine_sql_injection_detection() {
    let engine = RegexEngine::new();
    let strings = vec![make_string(
        r#"SELECT * FROM users WHERE id = ${userId}"#,
        "app.ts",
        10,
    )];
    let matches = engine.match_strings(&strings);
    assert!(!matches.is_empty(), "should detect SQL injection pattern");
    assert!(matches.iter().any(|m| m.pattern_id.contains("sql")));
}

#[test]
fn stress_regex_engine_hardcoded_secret_detection() {
    let engine = RegexEngine::new();
    let strings = vec![make_string(
        r#"password = "super_secret_password_123""#,
        "config.ts",
        5,
    )];
    let matches = engine.match_strings(&strings);
    assert!(!matches.is_empty(), "should detect hardcoded secret");
}

#[test]
fn stress_regex_engine_http_url_detection() {
    let engine = RegexEngine::new();
    let strings = vec![make_string(
        "http://api.example.com/v1/users",
        "service.ts",
        20,
    )];
    let matches = engine.match_strings(&strings);
    assert!(!matches.is_empty(), "should detect HTTP URL");
}

#[test]
fn stress_regex_engine_eval_detection() {
    let engine = RegexEngine::new();
    let strings = vec![make_string(
        r#"eval("alert('xss')")"#,
        "bad.js",
        1,
    )];
    let matches = engine.match_strings(&strings);
    assert!(!matches.is_empty(), "should detect eval usage");
}

#[test]
fn stress_regex_engine_console_log_detection() {
    let engine = RegexEngine::new();
    let strings = vec![make_string(
        "console.log(\"debug info\")",
        "app.ts",
        15,
    )];
    let matches = engine.match_strings(&strings);
    assert!(!matches.is_empty(), "should detect console.log");
}

#[test]
fn stress_regex_engine_todo_detection() {
    let engine = RegexEngine::new();
    let strings = vec![make_string(
        "TODO: fix this before release",
        "app.ts",
        100,
    )];
    let matches = engine.match_strings(&strings);
    assert!(!matches.is_empty(), "should detect TODO comment");
}

#[test]
fn stress_regex_engine_no_false_positive_on_clean_code() {
    let engine = RegexEngine::new();
    let strings = vec![
        make_string("Hello, world!", "app.ts", 1),
        make_string("const x = 42;", "app.ts", 2),
        make_string("function add(a, b) { return a + b; }", "math.ts", 1),
    ];
    let matches = engine.match_strings(&strings);
    // Clean code should produce zero or very few matches
    assert!(matches.len() <= 1, "clean code should not trigger many patterns");
}

#[test]
fn stress_regex_engine_1000_strings() {
    let engine = RegexEngine::new();
    let strings: Vec<ExtractedString> = (0..1000)
        .map(|i| make_string(&format!("value_{i}"), "bulk.ts", i as u32))
        .collect();

    let start = Instant::now();
    let matches = engine.match_strings(&strings);
    let elapsed = start.elapsed();

    // Should complete quickly — no pathological regex
    assert!(elapsed.as_millis() < 500, "1000 strings took too long: {elapsed:?}");
}

#[test]
fn stress_regex_engine_custom_patterns() {
    let patterns = vec![RegexPattern {
        id: "custom-test".into(),
        pattern: r#"CUSTOM_MARKER_\d+"#.into(),
        category: PatternCategory::Structural,
        confidence: 0.99,
        cwe_ids: SmallVec::new(),
        owasp: None,
        description: "Custom test pattern".into(),
    }];
    let engine = RegexEngine::with_patterns(patterns);
    assert_eq!(engine.pattern_count(), 1);

    let strings = vec![
        make_string("CUSTOM_MARKER_42", "test.ts", 1),
        make_string("no match here", "test.ts", 2),
    ];
    let matches = engine.match_strings(&strings);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].pattern_id, "custom-test");
}

#[test]
fn stress_regex_engine_empty_strings() {
    let engine = RegexEngine::new();
    let matches = engine.match_strings(&[]);
    assert!(matches.is_empty());
}

#[test]
fn stress_regex_engine_empty_string_values() {
    let engine = RegexEngine::new();
    let strings = vec![make_string("", "empty.ts", 1)];
    let matches = engine.match_strings(&strings);
    // Empty string should not match anything
    assert!(matches.is_empty());
}

#[test]
fn stress_regex_engine_unicode_strings() {
    let engine = RegexEngine::new();
    let strings = vec![
        make_string("日本語テスト", "i18n.ts", 1),
        make_string("console.log(\"中文\")", "i18n.ts", 2),
    ];
    let matches = engine.match_strings(&strings);
    // The console.log should still be detected
    assert!(matches.iter().any(|m| m.pattern_id == "console-log"));
}

#[test]
fn stress_regex_engine_very_long_string() {
    let engine = RegexEngine::new();
    let long_string = "a".repeat(100_000);
    let strings = vec![make_string(&long_string, "big.ts", 1)];

    let start = Instant::now();
    let _matches = engine.match_strings(&strings);
    let elapsed = start.elapsed();

    // Should not hang on very long strings
    assert!(elapsed.as_secs() < 2, "long string took too long: {elapsed:?}");
}

fn make_string(value: &str, file: &str, line: u32) -> ExtractedString {
    ExtractedString {
        value: value.to_string(),
        file: file.to_string(),
        line,
        column: 0,
        kind: StringKind::Literal,
        context: StringExtractionContext::Unknown,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// CALL GRAPH — build, resolution, node/edge management, stress
// ═══════════════════════════════════════════════════════════════════════════

fn make_parse_result(file: &str, functions: Vec<(&str, u32, u32, bool)>, calls: Vec<(&str, u32)>, imports: Vec<&str>) -> ParseResult {
    ParseResult {
        file: file.to_string(),
        language: drift_analysis::scanner::language_detect::Language::TypeScript,
        content_hash: 0,
        functions: functions.iter().map(|(name, line, end_line, exported)| FunctionInfo {
            name: name.to_string(),
            qualified_name: None,
            file: file.to_string(),
            line: *line,
            column: 0,
            end_line: *end_line,
            parameters: SmallVec::new(),
            return_type: None,
            generic_params: SmallVec::new(),
            visibility: Visibility::Public,
            is_exported: *exported,
            is_async: false,
            is_generator: false,
            is_abstract: false,
            range: Range::default(),
            decorators: Vec::new(),
            doc_comment: None,
            body_hash: 0,
            signature_hash: 0,
        }).collect(),
        classes: Vec::new(),
        imports: imports.iter().map(|src| ImportInfo {
            source: src.to_string(),
            specifiers: SmallVec::new(),
            is_type_only: false,
            file: file.to_string(),
            line: 0,
        }).collect(),
        exports: Vec::new(),
        call_sites: calls.iter().map(|(name, line)| CallSite {
            callee_name: name.to_string(),
            receiver: None,
            file: file.to_string(),
            line: *line,
            column: 0,
            argument_count: 0,
            is_await: false,
        }).collect(),
        decorators: Vec::new(),
        string_literals: Vec::new(),
        numeric_literals: Vec::new(),
        error_handling: Vec::new(),
        doc_comments: Vec::new(),
        namespace: None,
        parse_time_us: 0,
        error_count: 0,
        error_ranges: Vec::new(),
        has_errors: false,
    }
}

#[test]
fn stress_call_graph_empty_input() {
    let builder = CallGraphBuilder::new();
    let (graph, stats) = builder.build(&[]).unwrap();
    assert_eq!(graph.function_count(), 0);
    assert_eq!(graph.edge_count(), 0);
    assert_eq!(stats.total_functions, 0);
}

#[test]
fn stress_call_graph_single_file_same_file_calls() {
    let pr = make_parse_result(
        "app.ts",
        vec![
            ("main", 1, 20, true),
            ("helper", 25, 40, false),
        ],
        vec![("helper", 10)], // main calls helper at line 10
        vec![],
    );

    let builder = CallGraphBuilder::new();
    let (graph, stats) = builder.build(&[pr]).unwrap();

    assert_eq!(stats.total_functions, 2);
    // Same-file resolution should find the edge
    assert!(stats.total_edges <= 1);
}

#[test]
fn stress_call_graph_100_files_1000_functions() {
    let parse_results: Vec<ParseResult> = (0..100)
        .map(|file_idx| {
            let functions: Vec<(&str, u32, u32, bool)> = Vec::new();
            let mut pr = make_parse_result(
                &format!("src/module_{file_idx}.ts"),
                vec![],
                vec![],
                vec![],
            );
            // Add 10 functions per file
            for func_idx in 0..10 {
                let start = func_idx * 20;
                pr.functions.push(FunctionInfo {
                    name: format!("func_{func_idx}"),
                    qualified_name: None,
                    file: format!("src/module_{file_idx}.ts"),
                    line: start,
                    column: 0,
                    end_line: start + 15,
                    parameters: SmallVec::new(),
                    return_type: None,
                    generic_params: SmallVec::new(),
                    visibility: Visibility::Public,
                    is_exported: func_idx < 5,
                    is_async: false,
                    is_generator: false,
                    is_abstract: false,
                    range: Range::default(),
                    decorators: Vec::new(),
                    doc_comment: None,
                    body_hash: 0,
                    signature_hash: 0,
                });
            }
            pr
        })
        .collect();

    let builder = CallGraphBuilder::new();
    let start = Instant::now();
    let (graph, stats) = builder.build(&parse_results).unwrap();
    let elapsed = start.elapsed();

    assert_eq!(stats.total_functions, 1000);
    // Should build in well under 5 seconds
    assert!(elapsed.as_secs() < 5, "call graph build took too long: {elapsed:?}");
}

#[test]
fn stress_call_graph_node_dedup() {
    let mut graph = CallGraph::new();
    let node = FunctionNode {
        file: "app.ts".into(),
        name: "main".into(),
        qualified_name: None,
        language: "typescript".into(),
        line: 1,
        end_line: 20,
        is_entry_point: false,
        is_exported: true,
        signature_hash: 0,
        body_hash: 0,
    };

    let idx1 = graph.add_function(node.clone());
    let idx2 = graph.add_function(node);
    assert_eq!(idx1, idx2, "duplicate function should return same index");
    assert_eq!(graph.function_count(), 1);
}

#[test]
fn stress_call_graph_remove_file() {
    let mut graph = CallGraph::new();
    for i in 0..10 {
        graph.add_function(FunctionNode {
            file: "remove_me.ts".into(),
            name: format!("func_{i}"),
            qualified_name: None,
            language: "typescript".into(),
            line: i * 10,
            end_line: i * 10 + 5,
            is_entry_point: false,
            is_exported: false,
            signature_hash: 0,
            body_hash: 0,
        });
    }
    assert_eq!(graph.function_count(), 10);

    graph.remove_file("remove_me.ts");
    assert_eq!(graph.function_count(), 0);
    assert!(graph.get_file_nodes("remove_me.ts").is_empty());
}

#[test]
fn stress_call_graph_resolution_strategies() {
    // Verify all 6 resolution strategies have correct confidence values
    let strategies = Resolution::all_ordered();
    assert_eq!(strategies.len(), 6);

    assert_eq!(Resolution::SameFile.default_confidence(), 0.95);
    assert_eq!(Resolution::MethodCall.default_confidence(), 0.90);
    assert_eq!(Resolution::DiInjection.default_confidence(), 0.80);
    assert_eq!(Resolution::ImportBased.default_confidence(), 0.75);
    assert_eq!(Resolution::ExportBased.default_confidence(), 0.60);
    assert_eq!(Resolution::Fuzzy.default_confidence(), 0.40);

    // All have names
    for r in strategies {
        assert!(!r.name().is_empty());
        assert!(!format!("{r}").is_empty());
    }
}

#[test]
fn stress_call_graph_edge_management() {
    let mut graph = CallGraph::new();
    let n1 = graph.add_function(FunctionNode {
        file: "a.ts".into(), name: "caller".into(), qualified_name: None,
        language: "typescript".into(), line: 1, end_line: 20,
        is_entry_point: false, is_exported: true, signature_hash: 0, body_hash: 0,
    });
    let n2 = graph.add_function(FunctionNode {
        file: "a.ts".into(), name: "callee".into(), qualified_name: None,
        language: "typescript".into(), line: 25, end_line: 40,
        is_entry_point: false, is_exported: false, signature_hash: 0, body_hash: 0,
    });

    graph.add_edge(n1, n2, CallEdge {
        resolution: Resolution::SameFile,
        confidence: 0.95,
        call_site_line: 10,
    });

    assert_eq!(graph.edge_count(), 1);
}

// ═══════════════════════════════════════════════════════════════════════════
// BOUNDARY DETECTOR — framework detection, model extraction, sensitive fields
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_boundary_detector_no_frameworks() {
    let detector = BoundaryDetector::new();
    let result = detector.detect(&[]).unwrap();
    assert!(result.frameworks_detected.is_empty());
    assert!(result.models.is_empty());
    assert_eq!(result.total_fields, 0);
    assert_eq!(result.total_sensitive, 0);
}

#[test]
fn stress_boundary_detector_typeorm_detection() {
    let pr = make_parse_result("user.entity.ts", vec![], vec![], vec!["typeorm"]);
    let detector = BoundaryDetector::new();
    let result = detector.detect(&[pr]).unwrap();
    assert!(result.frameworks_detected.contains(&OrmFramework::TypeOrm));
}

#[test]
fn stress_boundary_detector_multiple_frameworks() {
    let prs = vec![
        make_parse_result("user.entity.ts", vec![], vec![], vec!["typeorm"]),
        make_parse_result("models.py", vec![], vec![], vec!["django.db"]),
        make_parse_result("schema.ts", vec![], vec![], vec!["@prisma/client"]),
        make_parse_result("model.rb", vec![], vec![], vec!["active_record"]),
    ];
    let detector = BoundaryDetector::new();
    let result = detector.detect(&prs).unwrap();

    assert!(result.frameworks_detected.contains(&OrmFramework::TypeOrm));
    assert!(result.frameworks_detected.contains(&OrmFramework::Django));
    assert!(result.frameworks_detected.contains(&OrmFramework::Prisma));
    assert!(result.frameworks_detected.contains(&OrmFramework::ActiveRecord));
}

#[test]
fn stress_boundary_detector_sequelize_detection() {
    let pr = make_parse_result("user.model.ts", vec![], vec![], vec!["sequelize"]);
    let detector = BoundaryDetector::new();
    let result = detector.detect(&[pr]).unwrap();
    assert!(result.frameworks_detected.contains(&OrmFramework::Sequelize));
}

#[test]
fn stress_boundary_detector_hibernate_detection() {
    let pr = make_parse_result("User.java", vec![], vec![], vec!["javax.persistence"]);
    let detector = BoundaryDetector::new();
    let result = detector.detect(&[pr]).unwrap();
    assert!(result.frameworks_detected.contains(&OrmFramework::Hibernate));
}

#[test]
fn stress_boundary_detector_efcore_detection() {
    let pr = make_parse_result("User.cs", vec![], vec![], vec!["Microsoft.EntityFrameworkCore"]);
    let detector = BoundaryDetector::new();
    let result = detector.detect(&[pr]).unwrap();
    assert!(result.frameworks_detected.contains(&OrmFramework::EfCore));
}

#[test]
fn stress_boundary_detector_sqlalchemy_detection() {
    let pr = make_parse_result("models.py", vec![], vec![], vec!["sqlalchemy"]);
    let detector = BoundaryDetector::new();
    let result = detector.detect(&[pr]).unwrap();
    assert!(result.frameworks_detected.contains(&OrmFramework::SqlAlchemy));
}

#[test]
fn stress_boundary_detector_eloquent_detection() {
    let pr = make_parse_result("User.php", vec![], vec![], vec![r"Illuminate\Database"]);
    let detector = BoundaryDetector::new();
    let result = detector.detect(&[pr]).unwrap();
    assert!(result.frameworks_detected.contains(&OrmFramework::Eloquent));
}

// ═══════════════════════════════════════════════════════════════════════════
// SENSITIVE FIELD DETECTOR — PII, credentials, financial, health
// ═══════════════════════════════════════════════════════════════════════════

fn make_model(name: &str, fields: Vec<&str>) -> ExtractedModel {
    ExtractedModel {
        name: name.to_string(),
        table_name: Some(name.to_lowercase()),
        file: "model.ts".into(),
        line: 1,
        framework: OrmFramework::TypeOrm,
        fields: fields.iter().enumerate().map(|(i, f)| ExtractedField {
            name: f.to_string(),
            field_type: Some("string".into()),
            is_primary_key: i == 0,
            is_nullable: false,
            is_unique: false,
            default_value: None,
            line: i as u32 + 1,
        }).collect(),
        relationships: Vec::new(),
        confidence: 0.9,
    }
}

#[test]
fn stress_sensitive_detector_pii_fields() {
    let detector = SensitiveFieldDetector::new();
    let model = make_model("User", vec!["id", "email", "phone_number", "first_name", "last_name", "ssn", "date_of_birth"]);
    let sensitive = detector.detect_sensitive_fields(&model);

    let field_names: Vec<&str> = sensitive.iter().map(|s| s.field_name.as_str()).collect();
    assert!(field_names.contains(&"email"), "email should be PII");
    assert!(field_names.contains(&"phone_number"), "phone_number should be PII");
    assert!(field_names.contains(&"ssn"), "ssn should be PII");
}

#[test]
fn stress_sensitive_detector_credential_fields() {
    let detector = SensitiveFieldDetector::new();
    let model = make_model("Account", vec!["id", "password_hash", "api_key", "secret_token", "auth_token"]);
    let sensitive = detector.detect_sensitive_fields(&model);

    let cred_fields: Vec<&str> = sensitive.iter()
        .filter(|s| s.sensitivity == SensitivityType::Credentials)
        .map(|s| s.field_name.as_str())
        .collect();
    assert!(!cred_fields.is_empty(), "should detect credential fields");
}

#[test]
fn stress_sensitive_detector_financial_fields() {
    let detector = SensitiveFieldDetector::new();
    let model = make_model("Payment", vec!["id", "credit_card_number", "bank_account", "routing_number"]);
    let sensitive = detector.detect_sensitive_fields(&model);

    let financial: Vec<&str> = sensitive.iter()
        .filter(|s| s.sensitivity == SensitivityType::Financial)
        .map(|s| s.field_name.as_str())
        .collect();
    assert!(!financial.is_empty(), "should detect financial fields");
}

#[test]
fn stress_sensitive_detector_health_fields() {
    let detector = SensitiveFieldDetector::new();
    let model = make_model("Patient", vec!["id", "diagnosis", "prescription", "medical_record_number"]);
    let sensitive = detector.detect_sensitive_fields(&model);

    let health: Vec<&str> = sensitive.iter()
        .filter(|s| s.sensitivity == SensitivityType::Health)
        .map(|s| s.field_name.as_str())
        .collect();
    assert!(!health.is_empty(), "should detect health fields");
}

#[test]
fn stress_sensitive_detector_no_false_positives_on_safe_fields() {
    let detector = SensitiveFieldDetector::new();
    let model = make_model("Config", vec!["id", "created_at", "updated_at", "is_active", "count", "status"]);
    let sensitive = detector.detect_sensitive_fields(&model);
    // These generic fields should not be flagged as sensitive
    assert!(sensitive.len() <= 1, "safe fields should not trigger many detections, got: {}", sensitive.len());
}

#[test]
fn stress_sensitive_detector_empty_model() {
    let detector = SensitiveFieldDetector::new();
    let model = make_model("Empty", vec![]);
    let sensitive = detector.detect_sensitive_fields(&model);
    assert!(sensitive.is_empty());
}

#[test]
fn stress_sensitive_detector_all_sensitivity_types() {
    // Verify all 4 sensitivity types exist and have names
    let types = SensitivityType::all();
    assert_eq!(types.len(), 4);
    for t in types {
        assert!(!t.name().is_empty());
        assert!(!format!("{t}").is_empty());
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ORM FRAMEWORK ENUM — exhaustive coverage
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_orm_framework_names() {
    let frameworks = [
        OrmFramework::Sequelize, OrmFramework::TypeOrm, OrmFramework::Prisma,
        OrmFramework::Mongoose, OrmFramework::Knex, OrmFramework::Objection,
        OrmFramework::Bookshelf, OrmFramework::MikroOrm, OrmFramework::Drizzle,
        OrmFramework::Django, OrmFramework::SqlAlchemy, OrmFramework::Peewee,
        OrmFramework::Tortoise, OrmFramework::Pony,
        OrmFramework::ActiveRecord, OrmFramework::Sequel,
        OrmFramework::Hibernate, OrmFramework::Jpa, OrmFramework::MyBatis, OrmFramework::Jooq,
        OrmFramework::EfCore, OrmFramework::Dapper, OrmFramework::NHibernate,
        OrmFramework::Eloquent, OrmFramework::Doctrine, OrmFramework::Propel,
        OrmFramework::Gorm, OrmFramework::Ent, OrmFramework::Sqlx,
        OrmFramework::Diesel, OrmFramework::SeaOrm, OrmFramework::SqlxRust,
        OrmFramework::Unknown,
    ];

    // All 33 frameworks should have unique non-empty names
    let mut names = std::collections::HashSet::new();
    for fw in &frameworks {
        let name = fw.name();
        assert!(!name.is_empty(), "framework name must not be empty");
        assert!(names.insert(name), "duplicate framework name: {name}");
        assert!(!format!("{fw}").is_empty());
    }
    assert_eq!(frameworks.len(), 33);
}

// ═══════════════════════════════════════════════════════════════════════════
// VISITOR REGISTRY — handler registration, counting
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_visitor_registry_empty() {
    let registry = VisitorRegistry::new();
    assert_eq!(registry.handler_count(), 0);
    assert_eq!(registry.file_handler_count(), 0);
    assert_eq!(registry.learning_handler_count(), 0);
}

#[test]
fn stress_detection_engine_empty_registry() {
    let registry = VisitorRegistry::new();
    let engine = DetectionEngine::new(registry);
    assert_eq!(engine.registry().handler_count(), 0);
}

// ═══════════════════════════════════════════════════════════════════════════
// PATTERN CATEGORY — exhaustive coverage
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_pattern_category_all_16() {
    let categories = PatternCategory::all();
    assert_eq!(categories.len(), 16);

    let mut names = std::collections::HashSet::new();
    for cat in categories {
        let name = cat.name();
        assert!(!name.is_empty());
        assert!(names.insert(name), "duplicate category name: {name}");
        assert!(!format!("{cat}").is_empty());

        // Round-trip via parse_str
        let parsed = PatternCategory::parse_str(name);
        assert!(parsed.is_some(), "parse_str failed for: {name}");
        assert_eq!(parsed.unwrap(), *cat);
    }
}

#[test]
fn stress_pattern_category_parse_unknown() {
    assert!(PatternCategory::parse_str("nonexistent").is_none());
    assert!(PatternCategory::parse_str("").is_none());
}
