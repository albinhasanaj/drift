//! Production Category 26: Idempotency & Determinism
//!
//! Running the same operation twice must produce identical results.
//! Critical for CI reproducibility.
//!
//! T26-01 through T26-05.

use std::collections::HashMap;

use drift_analysis::engine::types::{DetectionMethod, PatternCategory, PatternMatch};
use drift_analysis::enforcement::gates::orchestrator::GateOrchestrator;
use drift_analysis::enforcement::gates::types::GateInput;
use drift_analysis::enforcement::reporters::sarif::SarifReporter;
use drift_analysis::enforcement::reporters::Reporter;
use drift_analysis::enforcement::rules::{PatternInfo, PatternLocation, OutlierLocation, Severity, Violation};
use drift_analysis::patterns::aggregation::pipeline::AggregationPipeline;
use drift_analysis::patterns::confidence::scorer::{ConfidenceScorer, ScorerConfig};
use drift_analysis::patterns::learning::discovery::ConventionDiscoverer;
use drift_analysis::patterns::learning::types::InMemoryConventionStore;
use drift_analysis::patterns::pipeline::PatternIntelligencePipeline;
use drift_analysis::scanner::Scanner;
use drift_core::config::ScanConfig;
use drift_core::events::handler::DriftEventHandler;
use drift_core::types::collections::FxHashMap;
use smallvec::smallvec;
use tempfile::TempDir;

// ── Helpers ────────────────────────────────────────────────────────────────

struct NoOpHandler;
impl DriftEventHandler for NoOpHandler {}

fn make_match(
    file: &str,
    line: u32,
    pattern_id: &str,
    confidence: f32,
    category: PatternCategory,
) -> PatternMatch {
    PatternMatch {
        file: file.to_string(),
        line,
        column: 0,
        pattern_id: pattern_id.to_string(),
        confidence,
        cwe_ids: smallvec![],
        owasp: None,
        detection_method: DetectionMethod::AstVisitor,
        category,
        matched_text: format!("matched_{pattern_id}"),
    }
}

/// Build a realistic set of pattern matches spanning multiple files and categories.
fn build_test_matches() -> Vec<PatternMatch> {
    let mut matches = Vec::new();

    // Structural patterns across 10 files
    for i in 0..10 {
        matches.push(make_match(
            &format!("src/module_{i}.ts"),
            10 + i,
            "singleton-pattern",
            0.92,
            PatternCategory::Structural,
        ));
    }

    // Error handling patterns across 8 files
    for i in 0..8 {
        matches.push(make_match(
            &format!("src/handler_{i}.ts"),
            20 + i,
            "try-catch-all",
            0.85,
            PatternCategory::Errors,
        ));
    }

    // Security patterns across 5 files
    for i in 0..5 {
        matches.push(make_match(
            &format!("src/auth_{i}.ts"),
            30 + i,
            "hardcoded-secret",
            0.95,
            PatternCategory::Security,
        ));
    }

    // API patterns across 6 files
    for i in 0..6 {
        matches.push(make_match(
            &format!("src/api_{i}.ts"),
            40 + i,
            "unvalidated-input",
            0.88,
            PatternCategory::Api,
        ));
    }

    // A low-confidence pattern that should be filtered/handled consistently
    for i in 0..3 {
        matches.push(make_match(
            &format!("src/util_{i}.ts"),
            50 + i,
            "magic-number",
            0.45,
            PatternCategory::Config,
        ));
    }

    matches
}

fn build_gate_input() -> GateInput {
    let patterns = vec![
        PatternInfo {
            pattern_id: "singleton-pattern".to_string(),
            category: "structural".to_string(),
            confidence: 0.92,
            locations: (0..10)
                .map(|i| PatternLocation {
                    file: format!("src/module_{i}.ts"),
                    line: 10 + i,
                    column: Some(0),
                })
                .collect(),
            outliers: vec![OutlierLocation {
                file: "src/module_3.ts".to_string(),
                line: 13,
                column: Some(0),
                end_line: None,
                end_column: None,
                deviation_score: 2.5,
                message: "Unusual singleton variant".to_string(),
            }],
            cwe_ids: vec![],
            owasp_categories: vec![],
        },
        PatternInfo {
            pattern_id: "hardcoded-secret".to_string(),
            category: "security".to_string(),
            confidence: 0.95,
            locations: (0..5)
                .map(|i| PatternLocation {
                    file: format!("src/auth_{i}.ts"),
                    line: 30 + i,
                    column: Some(0),
                })
                .collect(),
            outliers: vec![],
            cwe_ids: vec![798],
            owasp_categories: vec!["A07:2021".to_string()],
        },
    ];

    GateInput {
        files: (0..10)
            .map(|i| format!("src/module_{i}.ts"))
            .collect(),
        all_files: (0..20)
            .map(|i| format!("src/file_{i}.ts"))
            .collect(),
        patterns,
        constraints: vec![],
        security_findings: vec![],
        test_coverage: None,
        error_gaps: vec![],
        previous_health_score: Some(0.85),
        current_health_score: Some(0.82),
        predecessor_results: HashMap::new(),
        baseline_violations: std::collections::HashSet::new(),
        feedback_stats: None,
    }
}

fn build_gate_results_with_violations() -> Vec<drift_analysis::enforcement::gates::GateResult> {
    use drift_analysis::enforcement::gates::types::{GateId, GateResult};
    use drift_analysis::enforcement::rules::QuickFix;

    let violations = vec![
        Violation {
            id: "hardcoded-secret-src/auth_0.ts-30".to_string(),
            file: "src/auth_0.ts".to_string(),
            line: 30,
            column: Some(5),
            end_line: Some(30),
            end_column: Some(40),
            severity: Severity::Error,
            pattern_id: "hardcoded-secret".to_string(),
            rule_id: "SEC-001".to_string(),
            message: "Hardcoded secret detected in source code".to_string(),
            quick_fix: Some(QuickFix {
                strategy: drift_analysis::enforcement::rules::QuickFixStrategy::Rename,
                description: "Move to environment variable".to_string(),
                replacement: Some("process.env.SECRET".to_string()),
            }),
            cwe_id: Some(798),
            owasp_category: Some("A07:2021".to_string()),
            suppressed: false,
            is_new: true,
        },
        Violation {
            id: "singleton-outlier-src/module_3.ts-13".to_string(),
            file: "src/module_3.ts".to_string(),
            line: 13,
            column: Some(0),
            end_line: None,
            end_column: None,
            severity: Severity::Warning,
            pattern_id: "singleton-pattern".to_string(),
            rule_id: "PAT-002".to_string(),
            message: "Unusual singleton variant detected".to_string(),
            quick_fix: None,
            cwe_id: None,
            owasp_category: None,
            suppressed: false,
            is_new: false,
        },
    ];

    vec![
        GateResult::fail(
            GateId::SecurityBoundaries,
            0.60,
            "Security gate failed: 1 hardcoded secret".to_string(),
            violations,
        ),
        GateResult::pass(
            GateId::PatternCompliance,
            0.95,
            "Pattern compliance passed".to_string(),
        ),
    ]
}

// ── T26-01: Analysis Idempotency ───────────────────────────────────────────
// Run the full pattern intelligence pipeline twice on identical input.
// Second run must produce identical aggregation, scores, conventions.
// No ghost deltas.

#[test]
fn t26_01_analysis_idempotency() {
    let matches = build_test_matches();

    // Run 1
    let mut pipeline1 = PatternIntelligencePipeline::new();
    let result1 = pipeline1.run(&matches, 50, 1_700_000_000, None);

    // Run 2 — identical input
    let mut pipeline2 = PatternIntelligencePipeline::new();
    let result2 = pipeline2.run(&matches, 50, 1_700_000_000, None);

    // Aggregation must be identical
    assert_eq!(
        result1.aggregation.patterns.len(),
        result2.aggregation.patterns.len(),
        "pattern count must match"
    );

    for (p1, p2) in result1
        .aggregation
        .patterns
        .iter()
        .zip(result2.aggregation.patterns.iter())
    {
        assert_eq!(p1.pattern_id, p2.pattern_id, "pattern_id mismatch");
        assert_eq!(
            p1.location_count, p2.location_count,
            "location_count mismatch for {}",
            p1.pattern_id
        );
        assert_eq!(
            p1.file_spread, p2.file_spread,
            "file_spread mismatch for {}",
            p1.pattern_id
        );
        assert!(
            (p1.confidence_mean - p2.confidence_mean).abs() < 1e-10,
            "confidence_mean mismatch for {}: {} vs {}",
            p1.pattern_id,
            p1.confidence_mean,
            p2.confidence_mean
        );
    }

    // Confidence scores must be identical
    assert_eq!(
        result1.scores.len(),
        result2.scores.len(),
        "score count mismatch"
    );
    for ((id1, s1), (id2, s2)) in result1.scores.iter().zip(result2.scores.iter()) {
        assert_eq!(id1, id2, "score pattern_id ordering mismatch");
        assert!(
            (s1.posterior_mean - s2.posterior_mean).abs() < 1e-10,
            "posterior_mean mismatch for {id1}: {} vs {}",
            s1.posterior_mean,
            s2.posterior_mean
        );
        assert_eq!(s1.tier, s2.tier, "tier mismatch for {id1}");
    }

    // Conventions must be identical
    assert_eq!(
        result1.conventions.len(),
        result2.conventions.len(),
        "convention count mismatch"
    );
    for (c1, c2) in result1.conventions.iter().zip(result2.conventions.iter()) {
        assert_eq!(c1.pattern_id, c2.pattern_id, "convention pattern_id mismatch");
        assert_eq!(c1.scope, c2.scope, "convention scope mismatch");
        assert!(
            (c1.dominance_ratio - c2.dominance_ratio).abs() < 1e-10,
            "dominance_ratio mismatch for {}",
            c1.pattern_id
        );
        assert!(
            (c1.convergence_score() - c2.convergence_score()).abs() < 1e-10,
            "convergence_score mismatch for {}",
            c1.pattern_id
        );
    }

    // No ghost deltas — promoted_count must be identical
    assert_eq!(
        result1.promoted_count, result2.promoted_count,
        "promoted_count must be identical"
    );
}

// ── T26-02: Scanner Sorted Output ──────────────────────────────────────────
// Scan a repo with files in random filesystem order. Run twice.
// ScanDiff.added must be sorted identically both times.

#[test]
fn t26_02_scanner_sorted_output() {
    let dir = TempDir::new().unwrap();

    // Create files with deliberately non-alphabetical names
    let file_names = [
        "zebra.ts",
        "alpha.ts",
        "middleware.ts",
        "beta.rs",
        "aardvark.py",
        "config.json",
        "utils.ts",
        "index.ts",
        "main.go",
        "setup.py",
    ];
    for name in &file_names {
        std::fs::write(
            dir.path().join(name),
            format!("// content of {name}\nconst x = 1;\n"),
        )
        .unwrap();
    }

    let config = ScanConfig::default();

    // Scan 1
    let scanner1 = Scanner::new(config.clone());
    let diff1 = scanner1
        .scan(dir.path(), &FxHashMap::default(), &NoOpHandler)
        .unwrap();

    // Scan 2 — same directory, no changes
    let scanner2 = Scanner::new(config);
    let diff2 = scanner2
        .scan(dir.path(), &FxHashMap::default(), &NoOpHandler)
        .unwrap();

    // Both scans should find the same files
    assert_eq!(
        diff1.added.len(),
        diff2.added.len(),
        "file count should match"
    );

    // ScanDiff.added must be sorted identically
    assert_eq!(
        diff1.added, diff2.added,
        "added lists must be sorted identically across runs"
    );

    // Verify the lists are actually sorted (not just equal but unsorted)
    let mut sorted_added = diff1.added.clone();
    sorted_added.sort();
    assert_eq!(
        diff1.added, sorted_added,
        "added list must be sorted (incremental.rs sorts all diff vectors)"
    );

    // modified, removed, unchanged must also be deterministic
    assert_eq!(diff1.modified, diff2.modified, "modified must match");
    assert_eq!(diff1.removed, diff2.removed, "removed must match");
    assert_eq!(diff1.unchanged, diff2.unchanged, "unchanged must match");
}

// ── T26-03: Convention Discovery Determinism ───────────────────────────────
// Run pattern intelligence on the same repo twice.
// conventions must be identical: same pattern_id, scope, frequency,
// is_contested, convergence_score.

#[test]
fn t26_03_convention_discovery_determinism() {
    let matches = build_test_matches();
    let total_files = 50u64;
    let now = 1_700_000_000u64;

    // Run aggregation (shared input for both discovery runs)
    let agg_pipeline = AggregationPipeline::with_defaults();
    let agg_result = agg_pipeline.run(&matches);

    let scorer = ConfidenceScorer::new(ScorerConfig {
        total_files,
        default_age_days: 7,
        default_data_quality: None,
    });

    let scores: Vec<(String, _)> = agg_result
        .patterns
        .iter()
        .map(|p| {
            let score = scorer.score(
                p,
                drift_analysis::patterns::confidence::types::MomentumDirection::Stable,
                7,
                None,
                None,
            );
            (p.pattern_id.clone(), score)
        })
        .collect();

    // Discovery run 1
    let discoverer1 = ConventionDiscoverer::new();
    let conventions1 = discoverer1.discover(&agg_result.patterns, &scores, total_files, now);

    // Discovery run 2 — identical input
    let discoverer2 = ConventionDiscoverer::new();
    let conventions2 = discoverer2.discover(&agg_result.patterns, &scores, total_files, now);

    assert_eq!(
        conventions1.len(),
        conventions2.len(),
        "convention count must match"
    );

    for (c1, c2) in conventions1.iter().zip(conventions2.iter()) {
        assert_eq!(c1.pattern_id, c2.pattern_id, "pattern_id mismatch");
        assert_eq!(c1.scope, c2.scope, "scope mismatch for {}", c1.pattern_id);
        assert_eq!(
            c1.category, c2.category,
            "category mismatch for {}",
            c1.pattern_id
        );
        assert!(
            (c1.dominance_ratio - c2.dominance_ratio).abs() < 1e-10,
            "dominance_ratio mismatch for {}",
            c1.pattern_id
        );
        assert!(
            (c1.convergence_score() - c2.convergence_score()).abs() < 1e-10,
            "convergence_score mismatch for {}",
            c1.pattern_id
        );
        assert_eq!(
            c1.observation_count, c2.observation_count,
            "observation_count mismatch for {}",
            c1.pattern_id
        );
        assert_eq!(
            c1.promotion_status, c2.promotion_status,
            "promotion_status mismatch for {}",
            c1.pattern_id
        );
    }

    // Also test with convention store — persistence must be deterministic
    let mut store1 = InMemoryConventionStore::new();
    let discoverer3 = ConventionDiscoverer::new();
    let conventions3 = discoverer3.discover_with_store(
        &agg_result.patterns,
        &scores,
        total_files,
        now,
        Some(&mut store1),
    );

    let mut store2 = InMemoryConventionStore::new();
    let discoverer4 = ConventionDiscoverer::new();
    let conventions4 = discoverer4.discover_with_store(
        &agg_result.patterns,
        &scores,
        total_files,
        now,
        Some(&mut store2),
    );

    assert_eq!(
        conventions3.len(),
        conventions4.len(),
        "store-backed convention count must match"
    );
    assert_eq!(
        store1.len(),
        store2.len(),
        "store sizes must match"
    );
}

// ── T26-04: Enforcement Determinism ────────────────────────────────────────
// Run enforcement on identical input twice.
// Gate results must have identical score, status, violations_count.
// Execution time may differ but status must not.

#[test]
fn t26_04_enforcement_determinism() {
    let input = build_gate_input();

    // Run 1
    let orchestrator1 = GateOrchestrator::new();
    let results1 = orchestrator1.execute(&input).expect("execution should succeed");

    // Run 2 — identical input
    let orchestrator2 = GateOrchestrator::new();
    let results2 = orchestrator2.execute(&input).expect("execution should succeed");

    assert_eq!(
        results1.len(),
        results2.len(),
        "gate result count must match"
    );

    // Compare by gate_id (not position) because topological sort order for
    // independent gates is non-deterministic (HashMap iteration order).
    let map1: HashMap<_, _> = results1.iter().map(|r| (r.gate_id, r)).collect();
    let map2: HashMap<_, _> = results2.iter().map(|r| (r.gate_id, r)).collect();

    assert_eq!(
        map1.keys().collect::<std::collections::HashSet<_>>(),
        map2.keys().collect::<std::collections::HashSet<_>>(),
        "same set of gate_ids must be present"
    );

    for (gate_id, r1) in &map1 {
        let r2 = map2.get(gate_id).expect("gate_id must exist in both runs");
        assert_eq!(
            r1.status, r2.status,
            "status must be identical for {gate_id:?}",
        );
        assert_eq!(
            r1.passed, r2.passed,
            "passed must be identical for {gate_id:?}",
        );
        assert!(
            (r1.score - r2.score).abs() < 1e-10,
            "score must be identical for {gate_id:?}: {} vs {}",
            r1.score,
            r2.score
        );
        assert_eq!(
            r1.violations.len(),
            r2.violations.len(),
            "violations_count must be identical for {gate_id:?}",
        );

        // Violation details must match (not just count)
        for (v1, v2) in r1.violations.iter().zip(r2.violations.iter()) {
            assert_eq!(v1.rule_id, v2.rule_id, "violation rule_id mismatch");
            assert_eq!(v1.file, v2.file, "violation file mismatch");
            assert_eq!(v1.line, v2.line, "violation line mismatch");
            assert_eq!(
                v1.severity, v2.severity,
                "violation severity mismatch for {}",
                v1.id
            );
        }

        // execution_time_ms may differ — that's expected
    }
}

// ── T26-05: Report Format Stability ────────────────────────────────────────
// Generate SARIF for the same analysis results twice.
// Output must be byte-identical. Rule IDs, violation locations, severity
// must match exactly.

#[test]
fn t26_05_report_format_stability() {
    let gate_results = build_gate_results_with_violations();

    let reporter = SarifReporter::new();

    // Generate 1
    let report1 = reporter
        .generate(&gate_results)
        .expect("SARIF generation should succeed");

    // Generate 2 — identical input
    let report2 = reporter
        .generate(&gate_results)
        .expect("SARIF generation should succeed");

    // SARIF has no timestamps in the output, so byte-identical is expected
    assert_eq!(
        report1, report2,
        "SARIF output must be byte-identical for identical input"
    );

    // Parse and verify structural correctness
    let sarif1: serde_json::Value =
        serde_json::from_str(&report1).expect("SARIF must be valid JSON");
    let sarif2: serde_json::Value =
        serde_json::from_str(&report2).expect("SARIF must be valid JSON");

    assert_eq!(sarif1, sarif2, "parsed SARIF JSON must be identical");

    // Verify SARIF structure contains expected elements
    let runs = sarif1["runs"].as_array().expect("runs must be array");
    assert_eq!(runs.len(), 1, "must have exactly 1 run");

    let results = runs[0]["results"].as_array().expect("results must be array");
    // 1 suppressed=false violation from SecurityBoundaries + 1 from PatternCompliance (0 violations)
    // = 2 violations total (both unsuppressed)
    assert_eq!(
        results.len(),
        2,
        "SARIF should have 2 unsuppressed violations"
    );

    // Verify rule IDs are present
    let rules = runs[0]["tool"]["driver"]["rules"]
        .as_array()
        .expect("rules must be array");
    let rule_ids: Vec<&str> = rules.iter().map(|r| r["id"].as_str().unwrap()).collect();
    assert!(
        rule_ids.contains(&"SEC-001"),
        "must contain SEC-001 rule"
    );
    assert!(
        rule_ids.contains(&"PAT-002"),
        "must contain PAT-002 rule"
    );

    // Verify taxonomies are deterministic
    let taxonomies = runs[0]["taxonomies"]
        .as_array()
        .expect("taxonomies must be array");
    assert!(
        !taxonomies.is_empty(),
        "should have CWE/OWASP taxonomies"
    );

    // CWE taxonomy should reference CWE-798
    let cwe_taxonomy = taxonomies
        .iter()
        .find(|t| t["name"].as_str() == Some("CWE"))
        .expect("CWE taxonomy must exist");
    let cwe_taxa = cwe_taxonomy["taxa"].as_array().unwrap();
    assert!(
        cwe_taxa.iter().any(|t| t["id"].as_str() == Some("CWE-798")),
        "CWE-798 must be in taxa"
    );

    // Also test JSON reporter determinism
    let json_reporter = drift_analysis::enforcement::reporters::json::JsonReporter;
    let json1 = json_reporter.generate(&gate_results).unwrap();
    let json2 = json_reporter.generate(&gate_results).unwrap();
    assert_eq!(json1, json2, "JSON reporter output must be byte-identical");
}
