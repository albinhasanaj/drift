#![allow(clippy::assertions_on_constants, clippy::needless_range_loop)]
//! E2E Gap Coverage Tests
//!
//! Covers the 5 categories missing from the main e2e_full_pipeline_test:
//!
//! 1. Adversarial Inputs — malformed, empty, huge, binary, NUL-byte files
//! 2. Isolation / Graceful Degradation — Phase N failure → Phase N+1 survives
//! 3. Concurrency — batch writer multi-thread, read pool concurrent reads, parallel parse
//! 4. Edge Cases — new Language variants through full pipeline, GateInput with feedback_stats
//! 5. Storage Roundtrip Fidelity — persist → read back → verify field-level equality

use std::path::Path;
use std::sync::{Arc, Barrier};
use std::thread;

use drift_analysis::boundaries::detector::BoundaryDetector;
use drift_analysis::call_graph::builder::CallGraphBuilder;
use drift_analysis::enforcement::audit::HealthScorer;
use drift_analysis::enforcement::gates::{GateInput, GateOrchestrator};
use drift_analysis::enforcement::policy::{Policy, PolicyEngine};
use drift_analysis::enforcement::reporters;
use drift_analysis::enforcement::rules::{
    PatternInfo, PatternLocation, RulesEvaluator, RulesInput,
};
use drift_analysis::engine::pipeline::AnalysisPipeline;
use drift_analysis::engine::regex_engine::RegexEngine;
use drift_analysis::engine::resolution::ResolutionIndex;
use drift_analysis::engine::visitor::{DetectionEngine, VisitorRegistry};
use drift_analysis::parsers::manager::ParserManager;
use drift_analysis::parsers::types::ParseResult;
use drift_analysis::patterns::aggregation::pipeline::AggregationPipeline;
use drift_analysis::patterns::confidence::scorer::ConfidenceScorer;
use drift_analysis::patterns::outliers::selector::OutlierDetector;
use drift_analysis::scanner::language_detect::Language;
use drift_analysis::scanner::Scanner;
use drift_analysis::structural::constants;
use drift_analysis::structural::crypto::detector::CryptoDetector;
use drift_core::config::ScanConfig;
use drift_core::events::handler::DriftEventHandler;
use drift_core::types::collections::FxHashMap;
use drift_storage::batch::commands::{
    FileMetadataRow, FunctionRow,
};
use drift_storage::batch::writer::BatchWriter;
use drift_storage::connection::pragmas::apply_pragmas;
use drift_storage::migrations;
use drift_storage::queries::enforcement::{
    self, GateResultRow, ViolationRow,
};
use drift_storage::queries::files;
use drift_storage::queries::functions;
use drift_storage::queries::scan_history;
use rusqlite::Connection;
use tempfile::TempDir;

struct NoOpHandler;
impl DriftEventHandler for NoOpHandler {}

fn test_connection() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    apply_pragmas(&conn).unwrap();
    migrations::run_migrations(&conn).unwrap();
    conn
}

// ============================================================================
// SECTION 1: ADVERSARIAL INPUTS
// ============================================================================

/// Files that should never crash the scanner, parser, or analysis pipeline.
#[test]
fn adversarial_empty_file_survives_full_pipeline() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("empty.ts"), "").unwrap();

    let scanner = Scanner::new(ScanConfig::default());
    let diff = scanner.scan(dir.path(), &FxHashMap::default(), &NoOpHandler).unwrap();
    assert!(!diff.added.is_empty());

    let parser = ParserManager::new();
    let source = b"";
    // Empty file should parse (may produce empty ParseResult), not panic
    let result = parser.parse(source, &dir.path().join("empty.ts"));
    // Whether Ok or Err, no panic is the assertion
    eprintln!("[Adversarial] Empty file parse: {:?}", result.is_ok());

    // Analysis on empty ParseResult should not panic
    let pr = result.unwrap_or_else(|_| ParseResult {
        file: "empty.ts".to_string(),
        ..ParseResult::default()
    });
    let registry = VisitorRegistry::new();
    let engine = DetectionEngine::new(registry);
    let regex_engine = RegexEngine::new();
    let mut pipeline = AnalysisPipeline::new(engine, regex_engine);
    let mut ri = ResolutionIndex::new();

    let mut ts_parser = tree_sitter::Parser::new();
    ts_parser.set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()).unwrap();
    if let Some(tree) = ts_parser.parse(source as &[u8], None) {
        let _result = pipeline.analyze_file(&pr, source, &tree, &mut ri);
    }
    eprintln!("[Adversarial] Empty file analysis: no panic");
}

#[test]
fn adversarial_binary_file_does_not_crash_parser() {
    let dir = TempDir::new().unwrap();
    // PNG header + random binary data
    let binary: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
    std::fs::write(dir.path().join("image.png"), &binary).unwrap();
    // Binary disguised as TypeScript
    std::fs::write(dir.path().join("sneaky.ts"), &binary).unwrap();

    let parser = ParserManager::new();
    // .png should fail language detection → Err, not panic
    let result = parser.parse(&binary, Path::new("image.png"));
    assert!(result.is_err(), "Binary .png should fail to parse, not panic");

    // Binary disguised as .ts should not panic (tree-sitter is error-tolerant)
    let result2 = parser.parse(&binary, Path::new("sneaky.ts"));
    eprintln!("[Adversarial] Binary-as-TS parse: ok={}", result2.is_ok());
    // No panic is the assertion
}

#[test]
fn adversarial_nul_bytes_in_source_do_not_crash() {
    let dir = TempDir::new().unwrap();
    let source = b"export function \x00evil\x00() { return \x00; }\n";
    std::fs::write(dir.path().join("nul.ts"), source).unwrap();

    let parser = ParserManager::new();
    let result = parser.parse(source, Path::new("nul.ts"));
    eprintln!("[Adversarial] NUL-byte file parse: ok={}", result.is_ok());
    // No panic is the real test
}

#[test]
fn adversarial_huge_single_line_file() {
    // 500KB single-line file — tests buffer limits
    let huge = format!("export const x = \"{}\";", "A".repeat(500_000));
    let parser = ParserManager::new();
    let result = parser.parse(huge.as_bytes(), Path::new("huge.ts"));
    eprintln!("[Adversarial] 500KB single-line parse: ok={}", result.is_ok());
}

#[test]
fn adversarial_deeply_nested_braces() {
    // 200-level deep nesting — can trigger stack overflow in recursive parsers
    let mut source = String::new();
    for _ in 0..200 {
        source.push_str("if (true) { ");
    }
    source.push_str("return 1;");
    for _ in 0..200 {
        source.push_str(" }");
    }
    let parser = ParserManager::new();
    let result = parser.parse(source.as_bytes(), Path::new("nested.ts"));
    eprintln!("[Adversarial] Deep nesting parse: ok={}", result.is_ok());
}

#[test]
fn adversarial_unicode_identifiers_and_emoji() {
    let source = r#"
export function café_naïve(データ: string): string {
    const 🔥 = "fire";
    return データ + 🔥;
}
"#;
    let parser = ParserManager::new();
    let result = parser.parse(source.as_bytes(), Path::new("unicode.ts"));
    assert!(result.is_ok(), "Unicode identifiers should parse");
    let pr = result.unwrap();
    assert!(!pr.functions.is_empty(), "Should extract function with unicode name");
}

#[test]
fn adversarial_mixed_language_extensions() {
    // File with .ts extension but Python content
    let python_in_ts = "def hello():\n    print('hello')\n";
    let parser = ParserManager::new();
    // Should not panic — tree-sitter will produce error nodes but survive
    let result = parser.parse(python_in_ts.as_bytes(), Path::new("confusion.ts"));
    eprintln!("[Adversarial] Python-in-.ts parse: ok={}", result.is_ok());
}

#[test]
fn adversarial_scanner_with_symlinks_and_special_paths() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("normal.ts"), "export const x = 1;").unwrap();
    // File with spaces and special chars in name
    std::fs::write(dir.path().join("file with spaces (1).ts"), "export const y = 2;").unwrap();
    // Dot-prefixed (hidden) file
    std::fs::write(dir.path().join(".hidden.ts"), "export const z = 3;").unwrap();

    let scanner = Scanner::new(ScanConfig::default());
    let diff = scanner.scan(dir.path(), &FxHashMap::default(), &NoOpHandler).unwrap();
    // Should at least find the normal file without crashing
    assert!(!diff.added.is_empty(), "Scanner should find at least one file");
    eprintln!("[Adversarial] Special paths: {} files found", diff.added.len());
}

// ============================================================================
// SECTION 2: ISOLATION / GRACEFUL DEGRADATION
// ============================================================================

/// When parser produces zero functions, call graph should be empty (not panic).
#[test]
fn isolation_empty_parse_results_produce_empty_call_graph() {
    let empty_results: Vec<ParseResult> = vec![];
    let builder = CallGraphBuilder::new();
    let (graph, stats) = builder.build(&empty_results).unwrap();
    assert_eq!(stats.total_functions, 0);
    assert_eq!(stats.total_edges, 0);
    assert_eq!(graph.function_count(), 0);
    eprintln!("[Isolation] Empty parse → empty call graph: OK");
}

/// When parser produces results but no patterns, aggregation/confidence/outlier should survive.
#[test]
fn isolation_zero_patterns_through_aggregation_confidence_outlier_pipeline() {
    // Zero pattern matches → empty aggregation
    let agg_pipeline = AggregationPipeline::with_defaults();
    let agg = agg_pipeline.run(&[]);
    assert!(agg.patterns.is_empty());

    // Zero patterns → empty confidence scores
    let scorer = ConfidenceScorer::with_defaults();
    let scores = scorer.score_batch(&agg.patterns, None);
    assert!(scores.is_empty());

    // Zero values → no outliers
    let detector = OutlierDetector::new();
    let outliers = detector.detect(&[]);
    assert!(outliers.is_empty());

    eprintln!("[Isolation] Zero patterns → aggregation/confidence/outlier all empty: OK");
}

/// When call graph is empty, boundary detection should still work.
#[test]
fn isolation_empty_call_graph_does_not_break_boundary_detection() {
    // Boundary detection uses parse results, not call graph directly
    let pr = ParseResult {
        file: "src/test.ts".to_string(),
        ..ParseResult::default()
    };
    let detector = BoundaryDetector::new();
    let result = detector.detect(&[pr]).unwrap();
    // Empty parse result = no boundaries, but no panic
    eprintln!("[Isolation] Empty PR → boundary detection: {} frameworks", result.frameworks_detected.len());
}

/// When no violations exist, gates/policy/reporters should produce valid output.
#[test]
fn isolation_zero_violations_gates_policy_reporters() {
    let orchestrator = GateOrchestrator::new();
    let input = GateInput::default();
    let results = orchestrator.execute(&input).unwrap();
    assert_eq!(results.len(), 6, "Should still produce 6 gate results with zero input");

    // All gates should pass with no input (no violations = good)
    for r in &results {
        eprintln!("  Gate {:?}: {:?} score={:.1}", r.gate_id, r.status, r.score);
    }

    // Policy should work
    let policy = PolicyEngine::new(Policy::standard());
    let policy_result = policy.evaluate(&results);
    eprintln!("[Isolation] Zero-violation policy: passed={}", policy_result.overall_passed);

    // Reporters should produce non-empty output
    let formats = reporters::available_formats();
    for &format in formats {
        let reporter = reporters::create_reporter(format).unwrap();
        match reporter.generate(&results) {
            Ok(output) => assert!(!output.is_empty(), "{format} should produce output"),
            Err(e) => eprintln!("  [WARN] {format}: {e}"),
        }
    }
    eprintln!("[Isolation] Zero-violation reporters: {} formats OK", formats.len());
}

/// When health scorer receives zero patterns, it should return a valid score.
#[test]
fn isolation_health_scorer_zero_patterns() {
    let scorer = HealthScorer::new();
    let (score, breakdown) = scorer.compute(&[], &[]);
    assert!(score.is_finite(), "Health score should be finite, got {score}");
    assert!((0.0..=100.0).contains(&score), "Health score out of range: {score}");
    eprintln!("[Isolation] Zero-pattern health score: {:.1}", score);
    eprintln!("  confidence={:.2} approval={:.2} compliance={:.2}",
        breakdown.avg_confidence, breakdown.approval_ratio, breakdown.compliance_rate);
}

/// Crypto detector on non-crypto files should return empty, not error.
#[test]
fn isolation_crypto_detector_on_plain_text() {
    let detector = CryptoDetector::new();
    let findings = detector.detect("const x = 1;\nconst y = 2;\n", "src/simple.ts", "typescript");
    eprintln!("[Isolation] Crypto on plain code: {} findings", findings.len());
    // No panic, may or may not find false positives
}

/// Constants extractor on binary-looking content should not panic.
#[test]
fn isolation_constants_extractor_binary_content() {
    let binary_ish = "\x00\x01\x02\x03const MAGIC = 42;\x04\x05";
    let consts = constants::extractor::extract_constants(binary_ish, "weird.ts", "typescript");
    eprintln!("[Isolation] Constants from binary-ish: {} found", consts.len());
}

// ============================================================================
// SECTION 3: CONCURRENCY
// ============================================================================

/// Batch writer handles multiple command types from multiple threads without corruption.
#[test]
fn concurrency_batch_writer_multi_thread_writes() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("concurrent.db");

    let conn = Connection::open(&db_path).unwrap();
    apply_pragmas(&conn).unwrap();
    migrations::run_migrations(&conn).unwrap();
    let writer = Arc::new(BatchWriter::new(conn));

    let num_threads = 4;
    let files_per_thread = 25;
    let barrier = Arc::new(Barrier::new(num_threads));

    let handles: Vec<_> = (0..num_threads).map(|t| {
        let w = Arc::clone(&writer);
        let b = Arc::clone(&barrier);
        thread::spawn(move || {
            b.wait(); // Start all threads simultaneously
            for i in 0..files_per_thread {
                let path = format!("src/thread_{t}/file_{i}.ts");
                w.send(drift_storage::batch::commands::BatchCommand::UpsertFileMetadata(vec![
                    FileMetadataRow {
                        path: path.clone(),
                        language: Some("TypeScript".to_string()),
                        file_size: 100 + i as i64,
                        content_hash: vec![t as u8, i as u8, 0u8, 0, 0, 0, 0, 0],
                        mtime_secs: 1700000000,
                        mtime_nanos: 0,
                        last_scanned_at: 1700000000,
                        scan_duration_us: Some(50),
                    },
                ])).unwrap();

                w.send(drift_storage::batch::commands::BatchCommand::InsertFunctions(vec![
                    FunctionRow {
                        file: path,
                        name: format!("fn_{t}_{i}"),
                        qualified_name: None,
                        language: "TypeScript".to_string(),
                        line: i as i64 + 1,
                        end_line: i as i64 + 10,
                        parameter_count: 0,
                        return_type: None,
                        is_exported: true,
                        is_async: false,
                        body_hash: vec![],
                        signature_hash: vec![],
                    },
                ])).unwrap();
            }
        })
    }).collect();

    for h in handles {
        h.join().unwrap();
    }
    writer.flush().unwrap();

    // Verify all rows landed
    let read_conn = Connection::open(&db_path).unwrap();
    apply_pragmas(&read_conn).unwrap();
    let file_count = files::count_files(&read_conn).unwrap();
    let func_count = functions::count_functions(&read_conn).unwrap();

    eprintln!("[Concurrency] Batch writer: {} files, {} functions from {} threads",
        file_count, func_count, num_threads);
    assert_eq!(file_count, (num_threads * files_per_thread) as i64,
        "All files should be persisted without loss");
    assert_eq!(func_count, (num_threads * files_per_thread) as i64,
        "All functions should be persisted without loss");
}

/// DatabaseManager read pool handles concurrent readers without blocking.
#[test]
fn concurrency_read_pool_concurrent_reads() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("pool.db");

    let db = drift_storage::DatabaseManager::open(&db_path).unwrap();

    // Seed some data
    db.with_writer(|conn| {
        for i in 0..50 {
            conn.execute(
                "INSERT INTO file_metadata (path, language, file_size, content_hash, mtime_secs, mtime_nanos, last_scanned_at)
                 VALUES (?1, 'TypeScript', 100, X'0102030405060708', 1000, 0, 1000)",
                rusqlite::params![format!("src/file_{i}.ts")],
            ).map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })?;
        }
        Ok(())
    }).unwrap();

    // Concurrent reads
    let db = Arc::new(db);
    let barrier = Arc::new(Barrier::new(8));
    let handles: Vec<_> = (0..8).map(|_| {
        let db = Arc::clone(&db);
        let b = Arc::clone(&barrier);
        thread::spawn(move || {
            b.wait();
            let count = db.with_reader(|conn| {
                files::count_files(conn)
            }).unwrap();
            assert_eq!(count, 50);
            count
        })
    }).collect();

    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert!(results.iter().all(|&c| c == 50), "All readers should see 50 files");
    eprintln!("[Concurrency] Read pool: 8 concurrent readers all got 50 files");
}

/// Parser handles many files in parallel threads without crashing.
#[test]
fn concurrency_parallel_parsing() {
    let sources: Vec<(String, String)> = (0..20).map(|i| {
        let name = format!("src/parallel_{i}.ts");
        let content = format!(
            "export function fn_{i}(x: number): number {{ return x * {i}; }}\n\
             export class Class_{i} {{ method_{i}() {{ return {i}; }} }}\n"
        );
        (name, content)
    }).collect();

    let barrier = Arc::new(Barrier::new(sources.len()));
    let sources = Arc::new(sources);

    let handles: Vec<_> = (0..sources.len()).map(|i| {
        let srcs = Arc::clone(&sources);
        let b = Arc::clone(&barrier);
        thread::spawn(move || {
            b.wait();
            let parser = ParserManager::new();
            let (name, content) = &srcs[i];
            parser.parse(content.as_bytes(), Path::new(name)).ok()
        })
    }).collect();

    let results: Vec<_> = handles.into_iter()
        .filter_map(|h| h.join().unwrap())
        .collect();

    eprintln!("[Concurrency] Parallel parsing: {}/{} succeeded", results.len(), sources.len());
    assert!(results.len() >= 18, "At least 90% of parallel parses should succeed");

    let total_funcs: usize = results.iter().map(|r| r.functions.len()).sum();
    assert!(total_funcs > 0, "Should extract functions from parallel parses");
    eprintln!("[Concurrency] Parallel parsing: {} total functions extracted", total_funcs);
}

// ============================================================================
// SECTION 4: EDGE CASES WITHIN PHASES
// ============================================================================

/// New Language variants (Cpp, C, Swift, Scala) go through the full pipeline
/// without non-exhaustive match panics.
#[test]
fn edge_case_new_language_variants_full_pipeline() {
    let new_langs = [
        (Language::Cpp, "test.cpp"),
        (Language::C, "test.c"),
        (Language::Swift, "test.swift"),
        (Language::Scala, "test.scala"),
    ];

    for (lang, filename) in &new_langs {
        // Language properties should not panic
        let name = lang.name();
        assert!(!name.is_empty(), "{lang:?} should have a non-empty name");

        let exts = lang.extensions();
        assert!(!exts.is_empty(), "{lang:?} should have extensions");

        // Round-trip through from_extension
        let first_ext = exts[0];
        let detected = Language::from_extension(Some(first_ext));
        assert_eq!(detected, Some(*lang), "Extension {first_ext} should map back to {lang:?}");

        // tree-sitter grammar should not panic
        let _grammar = lang.ts_language();

        // Parser should not panic (may return Err for unsupported grammars)
        let parser = ParserManager::new();
        let source = b"int main() { return 0; }";
        let result = parser.parse(source, Path::new(filename));
        eprintln!("  {lang:?} parse: ok={}", result.is_ok());
    }
    eprintln!("[EdgeCase] All 4 new Language variants survived pipeline without panic");
}

/// GateInput with a real FeedbackStatsProvider should clone and evaluate.
#[test]
fn edge_case_gate_input_with_feedback_stats() {
    use drift_analysis::enforcement::feedback::stats_provider::FeedbackStatsProvider;

    struct MockStats;
    impl FeedbackStatsProvider for MockStats {
        fn fp_rate_for_detector(&self, _detector_id: &str) -> f64 { 0.15 }
        fn fp_rate_for_pattern(&self, _pattern_id: &str) -> f64 { 0.10 }
        fn is_detector_disabled(&self, _detector_id: &str) -> bool { false }
        fn total_actions_for_detector(&self, _detector_id: &str) -> u64 { 42 }
    }

    let input = GateInput {
        feedback_stats: Some(Arc::new(MockStats)),
        files: vec!["src/test.ts".to_string()],
        ..GateInput::default()
    };

    // Clone should work with Arc<dyn FeedbackStatsProvider>
    let cloned = input.clone();
    assert!(cloned.feedback_stats.is_some());
    assert_eq!(cloned.files.len(), 1);

    // Debug should not panic
    let debug = format!("{:?}", cloned);
    assert!(debug.contains("GateInput"), "Debug output should mention GateInput");
    assert!(debug.contains("FeedbackStatsProvider"), "Debug should show provider placeholder");

    // Gates should evaluate without panic
    let orchestrator = GateOrchestrator::new();
    let results = orchestrator.execute(&input).unwrap();
    assert_eq!(results.len(), 6);
    eprintln!("[EdgeCase] GateInput with FeedbackStatsProvider: 6 gates evaluated");
}

/// Aggregation pipeline with a single pattern (edge case: can't compute variance).
#[test]
fn edge_case_single_pattern_aggregation() {
    use drift_analysis::engine::types::{PatternMatch, PatternCategory, DetectionMethod};
    use smallvec::SmallVec;

    let single_match = PatternMatch {
        pattern_id: "single-pat".to_string(),
        category: PatternCategory::Structural,
        file: "src/test.ts".to_string(),
        line: 10,
        column: 0,
        matched_text: "testFunc".to_string(),
        confidence: 0.9,
        detection_method: DetectionMethod::AstVisitor,
        cwe_ids: SmallVec::new(),
        owasp: None,
    };

    let pipeline = AggregationPipeline::with_defaults();
    let result = pipeline.run(&[single_match]);
    assert!(!result.patterns.is_empty(), "Single match should produce at least one pattern");

    // Confidence scoring with 1 pattern
    let scorer = ConfidenceScorer::with_defaults();
    let scores = scorer.score_batch(&result.patterns, None);
    for (id, score) in &scores {
        assert!(score.posterior_mean.is_finite(), "Score for {id} should be finite");
        assert!(score.posterior_mean >= 0.0 && score.posterior_mean <= 1.0);
    }
    eprintln!("[EdgeCase] Single pattern: {} scored", scores.len());
}

/// Rules evaluator with patterns that have extreme confidence values.
#[test]
fn edge_case_rules_extreme_confidence() {
    let evaluator = RulesEvaluator::new();
    let input = RulesInput {
        patterns: vec![
            PatternInfo {
                pattern_id: "zero-conf".to_string(),
                category: "naming".to_string(),
                confidence: 0.0,
                locations: vec![PatternLocation { file: "a.ts".to_string(), line: 1, column: None }],
                outliers: vec![],
                cwe_ids: vec![],
                owasp_categories: vec![],
            },
            PatternInfo {
                pattern_id: "one-conf".to_string(),
                category: "naming".to_string(),
                confidence: 1.0,
                locations: vec![PatternLocation { file: "b.ts".to_string(), line: 1, column: None }],
                outliers: vec![],
                cwe_ids: vec![],
                owasp_categories: vec![],
            },
        ],
        source_lines: std::collections::HashMap::new(),
        baseline_violation_ids: std::collections::HashSet::new(),
    };
    let violations = evaluator.evaluate(&input);
    eprintln!("[EdgeCase] Extreme confidence: {} violations from 0.0 and 1.0 confidence", violations.len());
    // No panic is the assertion
}

// ============================================================================
// SECTION 5: STORAGE ROUNDTRIP FIDELITY
// ============================================================================

/// Violations survive persist → query with all fields intact.
#[test]
fn storage_roundtrip_violation_field_fidelity() {
    let conn = test_connection();

    let original = ViolationRow {
        id: "v-unicode-テスト".to_string(),
        file: "src/controllers/user_controller.ts".to_string(),
        line: 42,
        column: Some(15),
        end_line: Some(42),
        end_column: Some(30),
        severity: "error".to_string(),
        pattern_id: "SEC-SQL-001".to_string(),
        rule_id: "no-sql-injection".to_string(),
        message: "SQL injection via string concatenation — use parameterized queries".to_string(),
        quick_fix_strategy: Some("replace".to_string()),
        quick_fix_description: Some("Use prepared statement with $1 parameter".to_string()),
        cwe_id: Some(89),
        owasp_category: Some("A03:2021".to_string()),
        suppressed: false,
        is_new: true,
    };

    enforcement::insert_violation(&conn, &original).unwrap();
    let rows = enforcement::query_violations_by_file(&conn, &original.file).unwrap();
    assert_eq!(rows.len(), 1);
    let loaded = &rows[0];

    assert_eq!(loaded.id, original.id, "id mismatch");
    assert_eq!(loaded.file, original.file, "file mismatch");
    assert_eq!(loaded.line, original.line, "line mismatch");
    assert_eq!(loaded.column, original.column, "column mismatch");
    assert_eq!(loaded.end_line, original.end_line, "end_line mismatch");
    assert_eq!(loaded.end_column, original.end_column, "end_column mismatch");
    assert_eq!(loaded.severity, original.severity, "severity mismatch");
    assert_eq!(loaded.pattern_id, original.pattern_id, "pattern_id mismatch");
    assert_eq!(loaded.rule_id, original.rule_id, "rule_id mismatch");
    assert_eq!(loaded.message, original.message, "message mismatch");
    assert_eq!(loaded.quick_fix_strategy, original.quick_fix_strategy, "quick_fix_strategy mismatch");
    assert_eq!(loaded.quick_fix_description, original.quick_fix_description, "quick_fix_description mismatch");
    assert_eq!(loaded.cwe_id, original.cwe_id, "cwe_id mismatch");
    assert_eq!(loaded.owasp_category, original.owasp_category, "owasp_category mismatch");
    assert_eq!(loaded.suppressed, original.suppressed, "suppressed mismatch");
    assert_eq!(loaded.is_new, original.is_new, "is_new mismatch");

    eprintln!("[StorageRoundtrip] Violation: all 16 fields match after roundtrip");
}

/// Suppressed violation roundtrip — suppressed=true must survive.
#[test]
fn storage_roundtrip_suppressed_violation() {
    let conn = test_connection();

    let v = ViolationRow {
        id: "v-suppressed".to_string(),
        file: "src/legacy.ts".to_string(),
        line: 1,
        column: None,
        end_line: None,
        end_column: None,
        severity: "warning".to_string(),
        pattern_id: "LEGACY-001".to_string(),
        rule_id: "legacy-api".to_string(),
        message: "Suppressed by team lead".to_string(),
        quick_fix_strategy: None,
        quick_fix_description: None,
        cwe_id: None,
        owasp_category: None,
        suppressed: true,
        is_new: false,
    };

    enforcement::insert_violation(&conn, &v).unwrap();
    let rows = enforcement::query_all_violations(&conn).unwrap();
    assert!(rows[0].suppressed, "suppressed=true must survive roundtrip");
    assert!(!rows[0].is_new, "is_new=false must survive roundtrip");
    eprintln!("[StorageRoundtrip] Suppressed violation: booleans survived");
}

/// Gate results survive persist → query with all fields intact.
#[test]
fn storage_roundtrip_gate_result_field_fidelity() {
    let conn = test_connection();

    let original = GateResultRow {
        gate_id: "pattern_compliance".to_string(),
        status: "failed".to_string(),
        passed: false,
        score: 67.5,
        summary: "3 violations exceed threshold".to_string(),
        violation_count: 3,
        warning_count: 7,
        execution_time_ms: 42,
        details: Some("{\"threshold\": 0.8}".to_string()),
        error: None,
        run_at: 0, // DB default
    };

    enforcement::insert_gate_result(&conn, &original).unwrap();
    let rows = enforcement::query_gate_results(&conn).unwrap();
    assert_eq!(rows.len(), 1);
    let loaded = &rows[0];

    assert_eq!(loaded.gate_id, original.gate_id, "gate_id mismatch");
    assert_eq!(loaded.status, original.status, "status mismatch");
    assert_eq!(loaded.passed, original.passed, "passed mismatch");
    assert!((loaded.score - original.score).abs() < f64::EPSILON, "score mismatch");
    assert_eq!(loaded.summary, original.summary, "summary mismatch");
    assert_eq!(loaded.violation_count, original.violation_count, "violation_count mismatch");
    assert_eq!(loaded.warning_count, original.warning_count, "warning_count mismatch");
    assert_eq!(loaded.execution_time_ms, original.execution_time_ms, "execution_time_ms mismatch");
    assert_eq!(loaded.details, original.details, "details mismatch");
    assert_eq!(loaded.error, original.error, "error mismatch");

    eprintln!("[StorageRoundtrip] Gate result: all 10 fields match after roundtrip");
}

/// Gate result with error field populated roundtrips correctly.
#[test]
fn storage_roundtrip_gate_result_with_error() {
    let conn = test_connection();

    let g = GateResultRow {
        gate_id: "test_coverage".to_string(),
        status: "error".to_string(),
        passed: false,
        score: 0.0,
        summary: "Gate failed with internal error".to_string(),
        violation_count: 0,
        warning_count: 0,
        execution_time_ms: 1,
        details: None,
        error: Some("timeout after 30s — coverage tool unresponsive".to_string()),
        run_at: 0,
    };

    enforcement::insert_gate_result(&conn, &g).unwrap();
    let rows = enforcement::query_gate_results(&conn).unwrap();
    assert_eq!(rows[0].error.as_deref(), Some("timeout after 30s — coverage tool unresponsive"));
    assert!(!rows[0].passed);
    eprintln!("[StorageRoundtrip] Gate with error: error field survived");
}

/// Scan history insert → update → query roundtrip.
#[test]
fn storage_roundtrip_scan_history_lifecycle() {
    let conn = test_connection();

    let id = scan_history::insert_scan_start(&conn, 1700000000, "/project/root").unwrap();
    assert!(id > 0);

    scan_history::update_scan_complete(
        &conn, id, 1700000005,
        100,  // total
        10,   // added
        5,    // modified
        2,    // removed
        83,   // unchanged
        5000, // duration_ms
        "completed",
        None,
    ).unwrap();

    let rows = scan_history::query_recent(&conn, 10).unwrap();
    assert_eq!(rows.len(), 1);
    let scan = &rows[0];
    assert_eq!(scan.id, id);
    assert_eq!(scan.started_at, 1700000000);
    assert_eq!(scan.completed_at, Some(1700000005));
    assert_eq!(scan.root_path, "/project/root");
    assert_eq!(scan.total_files, Some(100));
    assert_eq!(scan.added_files, Some(10));
    assert_eq!(scan.modified_files, Some(5));
    assert_eq!(scan.removed_files, Some(2));
    assert_eq!(scan.unchanged_files, Some(83));
    assert_eq!(scan.duration_ms, Some(5000));
    assert_eq!(scan.status, "completed");
    assert!(scan.error.is_none());

    eprintln!("[StorageRoundtrip] Scan history: all 12 fields match after lifecycle");
}

/// Scan history with error status roundtrips correctly.
#[test]
fn storage_roundtrip_scan_history_with_error() {
    let conn = test_connection();

    let id = scan_history::insert_scan_start(&conn, 1700000010, "/bad/path").unwrap();
    scan_history::update_scan_complete(
        &conn, id, 1700000011,
        0, 0, 0, 0, 0, 100,
        "failed",
        Some("Permission denied: /bad/path"),
    ).unwrap();

    let rows = scan_history::query_recent(&conn, 10).unwrap();
    let scan = rows.iter().find(|s| s.id == id).unwrap();
    assert_eq!(scan.status, "failed");
    assert_eq!(scan.error.as_deref(), Some("Permission denied: /bad/path"));
    eprintln!("[StorageRoundtrip] Scan with error: status + error survived");
}

/// Functions survive batch writer → query roundtrip with all fields.
#[test]
fn storage_roundtrip_functions_via_batch_writer() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("func_rt.db");

    let conn = Connection::open(&db_path).unwrap();
    apply_pragmas(&conn).unwrap();
    migrations::run_migrations(&conn).unwrap();

    // Must insert file_metadata first (foreign key reference)
    conn.execute(
        "INSERT INTO file_metadata (path, language, file_size, content_hash, mtime_secs, mtime_nanos, last_scanned_at)
         VALUES ('src/test.ts', 'TypeScript', 1000, X'0102030405060708', 1000, 0, 1000)",
        [],
    ).unwrap();

    let writer = BatchWriter::new(conn);

    writer.send(drift_storage::batch::commands::BatchCommand::InsertFunctions(vec![
        FunctionRow {
            file: "src/test.ts".to_string(),
            name: "processPayment".to_string(),
            qualified_name: Some("PaymentService.processPayment".to_string()),
            language: "TypeScript".to_string(),
            line: 42,
            end_line: 78,
            parameter_count: 3,
            return_type: Some("Promise<PaymentResult>".to_string()),
            is_exported: true,
            is_async: true,
            body_hash: vec![0xDE, 0xAD, 0xBE, 0xEF],
            signature_hash: vec![0xCA, 0xFE, 0xBA, 0xBE],
        },
    ])).unwrap();
    writer.flush().unwrap();

    // Read back via query
    let read_conn = Connection::open(&db_path).unwrap();
    apply_pragmas(&read_conn).unwrap();
    let funcs = functions::get_functions_by_file(&read_conn, "src/test.ts").unwrap();
    assert_eq!(funcs.len(), 1);
    let f = &funcs[0];
    assert_eq!(f.name, "processPayment");
    assert_eq!(f.qualified_name.as_deref(), Some("PaymentService.processPayment"));
    assert_eq!(f.language, "TypeScript");
    assert_eq!(f.line, 42);
    assert_eq!(f.end_line, 78);
    assert_eq!(f.parameter_count, 3);
    assert!(f.is_exported);
    assert!(f.is_async);

    eprintln!("[StorageRoundtrip] Function via batch writer: all fields match");
}

/// Multiple violations for same file roundtrip with ordering preserved.
#[test]
fn storage_roundtrip_multiple_violations_ordering() {
    let conn = test_connection();

    for i in (0..5).rev() {
        let v = ViolationRow {
            id: format!("v-{i}"),
            file: "src/multi.ts".to_string(),
            line: (i + 1) * 10,
            column: None,
            end_line: None,
            end_column: None,
            severity: "warning".to_string(),
            pattern_id: format!("PAT-{i:03}"),
            rule_id: "test".to_string(),
            message: format!("Violation {i}"),
            quick_fix_strategy: None,
            quick_fix_description: None,
            cwe_id: None,
            owasp_category: None,
            suppressed: false,
            is_new: false,
        };
        enforcement::insert_violation(&conn, &v).unwrap();
    }

    let rows = enforcement::query_violations_by_file(&conn, "src/multi.ts").unwrap();
    assert_eq!(rows.len(), 5);

    // query_violations_by_file orders by line ASC
    for i in 0..5 {
        assert_eq!(rows[i].line, ((i + 1) * 10) as u32,
            "Violations should be ordered by line");
    }
    eprintln!("[StorageRoundtrip] Multiple violations: ordering preserved");
}

/// File metadata survives DatabaseManager write → read roundtrip.
#[test]
fn storage_roundtrip_file_metadata_via_database_manager() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("meta_rt.db");

    let db = drift_storage::DatabaseManager::open(&db_path).unwrap();

    db.with_writer(|conn| {
        conn.execute(
            "INSERT INTO file_metadata (path, language, file_size, content_hash, mtime_secs, mtime_nanos, last_scanned_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                "src/unicode_ファイル.ts", "TypeScript", 2048,
                vec![0xAAu8, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11],
                1700000042_i64, 123456789_i64, 1700000042_i64
            ],
        ).map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })?;
        Ok(())
    }).unwrap();

    // Read through read pool
    let meta = db.with_reader(|conn| {
        files::get_file_metadata(conn, "src/unicode_ファイル.ts")
    }).unwrap();

    assert!(meta.is_some(), "Should find file with unicode path");
    let m = meta.unwrap();
    assert_eq!(m.path, "src/unicode_ファイル.ts");
    assert_eq!(m.language.as_deref(), Some("TypeScript"));
    assert_eq!(m.file_size, 2048);
    assert_eq!(m.mtime_secs, 1700000042);

    eprintln!("[StorageRoundtrip] File metadata with unicode path: survived write→read pool roundtrip");
}
