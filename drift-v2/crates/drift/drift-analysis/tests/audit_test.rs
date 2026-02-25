#![allow(clippy::for_kv_map)]
//! Phase 6 tests: Audit System — Health Scoring & Degradation Detection
//! T6-AUD-01 through T6-AUD-08

use drift_analysis::enforcement::audit::*;

fn make_patterns() -> Vec<PatternAuditData> {
    vec![
        PatternAuditData {
            id: "p1".to_string(),
            name: "camelCase".to_string(),
            category: "naming".to_string(),
            status: PatternStatus::Approved,
            confidence: 0.92,
            location_count: 50,
            outlier_count: 5,
            in_call_graph: true,
            constraint_issues: 0,
            has_error_issues: false, locations: vec![],
        },
        PatternAuditData {
            id: "p2".to_string(),
            name: "error-handling".to_string(),
            category: "error_handling".to_string(),
            status: PatternStatus::Approved,
            confidence: 0.85,
            location_count: 30,
            outlier_count: 10,
            in_call_graph: true,
            constraint_issues: 0,
            has_error_issues: false, locations: vec![],
        },
        PatternAuditData {
            id: "p3".to_string(),
            name: "sql-param".to_string(),
            category: "security".to_string(),
            status: PatternStatus::Discovered,
            confidence: 0.70,
            location_count: 20,
            outlier_count: 3,
            in_call_graph: false,
            constraint_issues: 1,
            has_error_issues: false, locations: vec![],
        },
    ]
}

/// T6-AUD-01: Test 5-factor health score with correct weights.
#[test]
fn test_health_score_five_factors() {
    let scorer = HealthScorer::new();
    let patterns = make_patterns();
    let (score, breakdown) = scorer.compute(&patterns, &[]);

    // Verify weights are applied correctly
    // avgConfidence = (0.92 + 0.85 + 0.70) / 3 ≈ 0.823
    let expected_conf = (0.92 + 0.85 + 0.70) / 3.0;
    assert!((breakdown.avg_confidence - expected_conf).abs() < 0.01);

    // approvalRatio = 2/3 ≈ 0.667
    assert!((breakdown.approval_ratio - 2.0 / 3.0).abs() < 0.01);

    // complianceRate = (50+30+20) / (50+30+20+5+10+3) ≈ 0.847
    let total_loc = 50.0 + 30.0 + 20.0;
    let total_out = 5.0 + 10.0 + 3.0;
    let expected_compliance = total_loc / (total_loc + total_out);
    assert!((breakdown.compliance_rate - expected_compliance).abs() < 0.01);

    // crossValidationRate = 2/3 ≈ 0.667
    assert!((breakdown.cross_validation_rate - 2.0 / 3.0).abs() < 0.01);

    // duplicateFreeRate = 1.0 (no duplicates)
    assert!((breakdown.duplicate_free_rate - 1.0).abs() < 0.01);

    // Verify formula: (conf*0.30 + approval*0.20 + compliance*0.20 + crossval*0.15 + dupfree*0.15) * 100
    let expected_raw = expected_conf * 0.30
        + (2.0 / 3.0) * 0.20
        + expected_compliance * 0.20
        + (2.0 / 3.0) * 0.15
        + 1.0 * 0.15;
    let expected_score = expected_raw * 100.0;
    assert!(
        (score - expected_score).abs() < 1.0,
        "Score {score:.1} should be close to {expected_score:.1}"
    );
    assert!(score > 0.0 && score <= 100.0);
}

/// T6-AUD-02: Test degradation detection thresholds.
#[test]
fn test_degradation_detection() {
    let detector = DegradationDetector::new();

    let previous = AuditSnapshot {
        health_score: 85.0,
        avg_confidence: 0.90,
        approval_ratio: 0.80,
        compliance_rate: 0.90,
        cross_validation_rate: 0.70,
        duplicate_free_rate: 1.0,
        pattern_count: 50,
        category_scores: std::collections::HashMap::new(),
        timestamp: 1000,
        root_path: None,
        total_files: None,
    };

    // 5-point drop → warning
    let current_warning = AuditSnapshot {
        health_score: 80.0,
        ..previous.clone()
    };
    let alerts = detector.detect(&current_warning, &previous);
    assert!(alerts.iter().any(|a| a.severity == AlertSeverity::Warning));

    // 15-point drop → critical
    let current_critical = AuditSnapshot {
        health_score: 70.0,
        ..previous.clone()
    };
    let alerts = detector.detect(&current_critical, &previous);
    assert!(alerts.iter().any(|a| a.severity == AlertSeverity::Critical));
}

/// T6-AUD-03: Test trend prediction via linear regression.
#[test]
fn test_trend_prediction() {
    let analyzer = TrendAnalyzer::new();

    // 5 declining data points
    let scores = vec![90.0, 87.0, 84.0, 81.0, 78.0];
    let prediction = analyzer.predict(&scores);
    assert!(prediction.is_some(), "Should produce prediction with 5+ data points");

    let pred = prediction.unwrap();
    assert!(pred.slope < 0.0, "Slope should be negative for declining scores");
    assert_eq!(pred.direction, TrendDirection::Declining);
    assert!(pred.predicted_score_7d < 78.0, "7-day prediction should be below current");
    assert!(pred.predicted_score_30d < pred.predicted_score_7d, "30-day should be lower than 7-day");
    assert!(pred.confidence_interval >= 0.0 && pred.confidence_interval <= 1.0);
}

/// T6-AUD-04: Test auto-approve patterns meeting stability criteria.
#[test]
fn test_auto_approve() {
    let approver = AutoApprover::new();
    let patterns = vec![
        // Should auto-approve: conf≥0.90, outlier≤0.50, locs≥3
        PatternAuditData {
            id: "stable".to_string(),
            name: "stable-pattern".to_string(),
            category: "naming".to_string(),
            status: PatternStatus::Discovered,
            confidence: 0.95,
            location_count: 10,
            outlier_count: 2,
            in_call_graph: true,
            constraint_issues: 0,
            has_error_issues: false, locations: vec![],
        },
        // Should need review: conf 0.75
        PatternAuditData {
            id: "review".to_string(),
            name: "review-pattern".to_string(),
            category: "naming".to_string(),
            status: PatternStatus::Discovered,
            confidence: 0.75,
            location_count: 5,
            outlier_count: 1,
            in_call_graph: false,
            constraint_issues: 0,
            has_error_issues: false, locations: vec![],
        },
        // Should be likely-FP: conf 0.40
        PatternAuditData {
            id: "fp".to_string(),
            name: "fp-pattern".to_string(),
            category: "naming".to_string(),
            status: PatternStatus::Discovered,
            confidence: 0.40,
            location_count: 2,
            outlier_count: 5,
            in_call_graph: false,
            constraint_issues: 0,
            has_error_issues: false, locations: vec![],
        },
    ];

    let (auto_approved, needs_review, likely_fp) = approver.classify(&patterns);
    assert!(auto_approved.contains(&"stable".to_string()));
    assert!(needs_review.contains(&"review".to_string()));
    assert!(likely_fp.contains(&"fp".to_string()));
}

/// T6-AUD-05: Test three-tier Jaccard duplicate detection.
#[test]
fn test_jaccard_duplicate_detection() {
    use std::collections::HashSet;

    // Test exact Jaccard computation
    let set_a: HashSet<String> = (0..10).map(|i| format!("file{i}:10")).collect();
    let mut set_b = set_a.clone();
    set_b.insert("file99:10".to_string()); // One extra

    let sim = DuplicateDetector::jaccard_from_sets(&set_a, &set_b);
    assert!(sim > 0.90, "Nearly identical sets should have high similarity");

    // Completely different sets
    let set_c: HashSet<String> = (100..110).map(|i| format!("file{i}:10")).collect();
    let sim2 = DuplicateDetector::jaccard_from_sets(&set_a, &set_c);
    assert!(sim2 < 0.01, "Completely different sets should have ~0 similarity");
}

/// T6-AUD-06: Test health score with all-zero inputs (new project).
#[test]
fn test_health_score_empty_project() {
    let scorer = HealthScorer::new();
    let (score, breakdown) = scorer.compute(&[], &[]);

    // Should return sensible default, not NaN or 0
    assert!(!score.is_nan(), "Score should not be NaN");
    assert!(score >= 0.0, "Score should be non-negative");
    assert!(score <= 100.0, "Score should be <= 100");
    assert!(!breakdown.raw_score.is_nan());
}

/// T6-AUD-07: Test per-category health breakdown.
#[test]
fn test_per_category_health() {
    let scorer = HealthScorer::new();
    let patterns = make_patterns();
    let category_health = scorer.compute_per_category(&patterns, &[]);

    // Should have 3 categories
    assert_eq!(category_health.len(), 3);
    assert!(category_health.contains_key("naming"));
    assert!(category_health.contains_key("error_handling"));
    assert!(category_health.contains_key("security"));

    // Each category should have a valid score
    for (_, health) in &category_health {
        assert!(health.score >= 0.0 && health.score <= 100.0);
        assert!(health.pattern_count > 0);
    }
}

/// T6-AUD-08: Test anomaly detection via Z-score.
#[test]
fn test_anomaly_detection_zscore() {
    let analyzer = TrendAnalyzer::new();

    // Normal values with one spike
    let values = vec![80.0, 81.0, 79.0, 80.0, 82.0, 80.0, 79.0, 81.0, 80.0, 150.0];
    let anomalies = analyzer.detect_anomalies("violations", &values, 2.0);

    assert!(!anomalies.is_empty(), "Should detect the spike as anomaly");
    assert!(anomalies[0].z_score.abs() > 2.0);
}
