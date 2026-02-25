#![allow(unused_imports, unused_variables)]
//! Phase 3 Outlier Tests — T3-OUT-01 through T3-OUT-11.

use drift_analysis::patterns::outliers::types::{
    DeviationScore, OutlierConfig, OutlierMethod, OutlierResult, SignificanceTier,
};
use drift_analysis::patterns::outliers::selector::OutlierDetector;
use drift_analysis::patterns::outliers::{zscore, grubbs, esd, iqr, mad, rule_based};
use drift_analysis::patterns::outliers::conversion::{
    convert_to_violations, ViolationSeverity,
};

// ---- T3-OUT-01: Auto-selects correct method based on sample size ----

#[test]
fn t3_out_01_auto_select_method() {
    let detector = OutlierDetector::new();

    // Helper: generate approximately normal data of given size
    fn normal_data(n: usize) -> Vec<f64> {
        (0..n).map(|i| 50.0 + (i as f64 * 0.1)).collect()
    }

    // n ≥ 30 + normal → ZScore
    let d30 = normal_data(30);
    let d100 = normal_data(100);
    let d1000 = normal_data(1000);
    assert_eq!(detector.select_primary_method(&d30), OutlierMethod::ZScore);
    assert_eq!(detector.select_primary_method(&d100), OutlierMethod::ZScore);
    assert_eq!(detector.select_primary_method(&d1000), OutlierMethod::ZScore);

    // 25 ≤ n < 30 + normal → GeneralizedEsd
    let d25 = normal_data(25);
    let d29 = normal_data(29);
    assert_eq!(detector.select_primary_method(&d25), OutlierMethod::GeneralizedEsd);
    assert_eq!(detector.select_primary_method(&d29), OutlierMethod::GeneralizedEsd);

    // 10 ≤ n < 25 + normal → Grubbs
    let d10 = normal_data(10);
    let d24 = normal_data(24);
    assert_eq!(detector.select_primary_method(&d10), OutlierMethod::Grubbs);
    assert_eq!(detector.select_primary_method(&d24), OutlierMethod::Grubbs);

    // n < 10 → RuleBased
    let d1 = normal_data(1);
    let d9 = normal_data(9);
    assert_eq!(detector.select_primary_method(&d1), OutlierMethod::RuleBased);
    assert_eq!(detector.select_primary_method(&d9), OutlierMethod::RuleBased);
}

// ---- T3-OUT-02: Statistical methods produce correct classifications ----

#[test]
fn t3_out_02_statistical_correctness() {
    // Ground truth: values 0-49 are normal (mean ~25), values at indices 0,1,2 are outliers
    let mut values: Vec<f64> = (0..50).map(|i| 25.0 + (i as f64 - 25.0) * 0.5).collect();
    // Inject 3 clear outliers
    values[0] = 200.0;
    values[1] = -150.0;
    values[2] = 180.0;

    let ground_truth_outliers: Vec<usize> = vec![0, 1, 2];

    // Z-Score
    let z_results = zscore::detect(&values, 2.5, 3);
    let z_detected: Vec<usize> = z_results.iter().map(|r| r.index).collect();
    let z_tp = z_detected.iter().filter(|i| ground_truth_outliers.contains(i)).count();
    let z_precision = if z_detected.is_empty() { 0.0 } else { z_tp as f64 / z_detected.len() as f64 };
    let z_recall = z_tp as f64 / ground_truth_outliers.len() as f64;
    assert!(z_precision >= 0.90, "Z-Score precision should be ≥90%, got {:.1}%", z_precision * 100.0);
    assert!(z_recall >= 0.80, "Z-Score recall should be ≥80%, got {:.1}%", z_recall * 100.0);

    // IQR
    let iqr_results = iqr::detect(&values, 1.5);
    let iqr_detected: Vec<usize> = iqr_results.iter().map(|r| r.index).collect();
    let iqr_tp = iqr_detected.iter().filter(|i| ground_truth_outliers.contains(i)).count();
    let iqr_precision = if iqr_detected.is_empty() { 0.0 } else { iqr_tp as f64 / iqr_detected.len() as f64 };
    let iqr_recall = iqr_tp as f64 / ground_truth_outliers.len() as f64;
    assert!(iqr_precision >= 0.90, "IQR precision should be ≥90%, got {:.1}%", iqr_precision * 100.0);
    assert!(iqr_recall >= 0.80, "IQR recall should be ≥80%, got {:.1}%", iqr_recall * 100.0);

    // Grubbs (on smaller dataset)
    let mut small_values: Vec<f64> = vec![10.0; 20];
    small_values[0] = 100.0;
    let grubbs_results = grubbs::detect(&small_values, 0.05);
    assert!(!grubbs_results.is_empty(), "Grubbs should detect the outlier");
    assert_eq!(grubbs_results[0].index, 0);
}

// ---- T3-OUT-03: Outlier-to-violation conversion ----

#[test]
fn t3_out_03_violation_conversion() {
    let outliers = vec![
        OutlierResult {
            index: 0,
            value: 200.0,
            test_statistic: 5.0,
            deviation_score: DeviationScore::new(0.95),
            significance: SignificanceTier::Critical,
            method: OutlierMethod::ZScore,
            is_outlier: true,
        },
        OutlierResult {
            index: 1,
            value: 150.0,
            test_statistic: 3.0,
            deviation_score: DeviationScore::new(0.5),
            significance: SignificanceTier::Moderate,
            method: OutlierMethod::ZScore,
            is_outlier: true,
        },
    ];

    let file_line_map = vec![
        ("src/main.ts".to_string(), 42u32),
        ("src/utils.ts".to_string(), 15u32),
    ];

    let violations = convert_to_violations("no-console", &outliers, &file_line_map);
    assert_eq!(violations.len(), 2);

    // Critical → Error
    assert_eq!(violations[0].severity, ViolationSeverity::Error);
    assert_eq!(violations[0].pattern_id, "no-console");
    assert_eq!(violations[0].file, "src/main.ts");
    assert_eq!(violations[0].line, 42);

    // Moderate → Warning
    assert_eq!(violations[1].severity, ViolationSeverity::Warning);
}

// ---- T3-OUT-04: All identical values (variance=0) ----

#[test]
fn t3_out_04_identical_values() {
    let values = vec![5.0; 50];

    let z = zscore::detect(&values, 2.5, 3);
    assert!(z.is_empty(), "Z-Score should find no outliers in identical values");

    let g = grubbs::detect(&values, 0.05);
    assert!(g.is_empty(), "Grubbs should find no outliers in identical values");

    let e = esd::detect(&values, 5, 0.05);
    assert!(e.is_empty(), "ESD should find no outliers in identical values");

    // IQR and MAD handle zero-spread via fallback
    let i = iqr::detect(&values, 1.5);
    assert!(i.is_empty(), "IQR should find no outliers in identical values");

    let m = mad::detect(&values, 3.5);
    assert!(m.is_empty(), "MAD should find no outliers in identical values");
}

// ---- T3-OUT-05: Single value (n=1) ----

#[test]
fn t3_out_05_single_value() {
    let values = vec![42.0];

    let z = zscore::detect(&values, 2.5, 3);
    assert!(z.is_empty());

    let g = grubbs::detect(&values, 0.05);
    assert!(g.is_empty());

    let e = esd::detect(&values, 1, 0.05);
    assert!(e.is_empty());

    let i = iqr::detect(&values, 1.5);
    assert!(i.is_empty());

    let m = mad::detect(&values, 3.5);
    assert!(m.is_empty());

    // Full detector should also handle gracefully
    let detector = OutlierDetector::new();
    let results = detector.detect(&values);
    // May or may not find rule-based outliers, but should not panic
    for r in &results {
        assert!(r.deviation_score.value() >= 0.0);
        assert!(r.deviation_score.value() <= 1.0);
    }
}

// ---- T3-OUT-06: Two values (n=2) ----

#[test]
fn t3_out_06_two_values() {
    let values = vec![10.0, 100.0];

    let g = grubbs::detect(&values, 0.05);
    assert!(g.is_empty(), "Grubbs should handle n=2 gracefully (insufficient data)");

    let z = zscore::detect(&values, 2.5, 3);
    // Z-Score with n=2 may or may not detect — should not panic
    for r in &z {
        assert!(r.deviation_score.value().is_finite());
    }
}

// ---- T3-OUT-07: Z-Score iterative masking finds multiple outliers ----

#[test]
fn t3_out_07_iterative_masking() {
    let mut values: Vec<f64> = vec![10.0; 50];
    values[0] = 100.0;
    values[1] = 95.0;
    values[2] = 90.0;

    let results = zscore::detect(&values, 2.5, 3);
    assert!(results.len() >= 2, "Should find at least 2 outliers via iterative masking, found {}", results.len());

    // All detected should be from the injected outliers
    for r in &results {
        assert!(r.index <= 2, "Detected outlier at index {} should be one of the injected ones", r.index);
    }
}

// ---- T3-OUT-08: MAD robustness with 40% outliers ----

#[test]
fn t3_out_08_mad_robustness() {
    // 60% normal (value=10), 40% outliers (value=100)
    let mut values: Vec<f64> = vec![10.0; 30];
    for i in 0..20 {
        values.push(100.0);
    }

    let results = mad::detect(&values, 3.5);
    // MAD uses median, so the 60% majority (10.0) defines "normal"
    // The 40% at 100.0 should be flagged
    assert!(!results.is_empty(), "MAD should detect outliers even with 40% contamination");

    let outlier_indices: Vec<usize> = results.iter().map(|r| r.index).collect();
    // At least some of the 100.0 values should be detected
    let high_value_detected = outlier_indices.iter().any(|&i| values[i] > 50.0);
    assert!(high_value_detected, "MAD should detect the high-value outliers");
}

// ---- T3-OUT-09: Generalized ESD with known dataset ----

#[test]
fn t3_out_09_esd_reference() {
    // Rosner (1983) style: normal data with injected outliers
    let mut values: Vec<f64> = Vec::new();
    // 25 normal values centered around 50
    for i in 0..25 {
        values.push(50.0 + (i as f64 - 12.5) * 2.0);
    }
    // 3 outliers
    values.push(200.0);
    values.push(195.0);
    values.push(190.0);

    let results = esd::detect(&values, 5, 0.05);
    assert!(results.len() >= 2, "ESD should find at least 2 of the 3 outliers, found {}", results.len());

    // All detected should be from the injected outliers (indices 25, 26, 27)
    for r in &results {
        assert!(r.index >= 25, "Detected outlier at index {} should be one of the injected ones", r.index);
    }
}

// ---- T3-OUT-10: Rule-based fires regardless of sample size ----

#[test]
fn t3_out_10_rule_based_always_active() {
    let rules = vec![rule_based::zero_confidence_rule()];

    // n=1
    let results = rule_based::detect(&[0.0], &rules);
    assert_eq!(results.len(), 1, "Rule should fire for single zero value");

    // n=5
    let results = rule_based::detect(&[0.9, 0.8, 0.0, 0.7, 0.85], &rules);
    assert_eq!(results.len(), 1, "Rule should fire for zero value in small set");
    assert_eq!(results[0].index, 2);

    // n=100
    let mut values: Vec<f64> = vec![0.9; 100];
    values[50] = 0.0;
    values[75] = -0.1;
    let results = rule_based::detect(&values, &rules);
    assert_eq!(results.len(), 2, "Rule should fire for zero/negative values in large set");

    // Custom rule
    let extreme_rule = rule_based::extreme_deviation_rule(5.0);
    let rules2 = vec![extreme_rule];
    let mut vals: Vec<f64> = vec![10.0; 50];
    vals[0] = 1000.0;
    let results = rule_based::detect(&vals, &rules2);
    assert!(!results.is_empty(), "Custom extreme deviation rule should fire");
}

// ---- T3-OUT-11: DeviationScore normalization ----

#[test]
fn t3_out_11_deviation_score_normalization() {
    // Normal range
    let score = DeviationScore::new(0.5);
    assert!((score.value() - 0.5).abs() < 1e-10);

    // Clamped to [0, 1]
    let score = DeviationScore::new(-0.5);
    assert_eq!(score.value(), 0.0, "Negative should clamp to 0.0");

    let score = DeviationScore::new(1.5);
    assert_eq!(score.value(), 1.0, "Above 1.0 should clamp to 1.0");

    // Zero
    let score = DeviationScore::zero();
    assert_eq!(score.value(), 0.0);

    // Boundary values
    let score = DeviationScore::new(0.0);
    assert_eq!(score.value(), 0.0);

    let score = DeviationScore::new(1.0);
    assert_eq!(score.value(), 1.0);

    // All outlier results from detector should have valid scores
    let detector = OutlierDetector::new();
    let mut values: Vec<f64> = vec![0.9; 50];
    values[0] = 0.01;
    values[1] = 200.0;
    let results = detector.detect(&values);
    for r in &results {
        assert!(r.deviation_score.value() >= 0.0, "Score should be ≥0.0, got {}", r.deviation_score.value());
        assert!(r.deviation_score.value() <= 1.0, "Score should be ≤1.0, got {}", r.deviation_score.value());
    }
}
