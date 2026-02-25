//! Phase 3 Learning Tests — T3-LRN-01 through T3-LRN-08.

use drift_analysis::engine::types::PatternCategory;
use drift_analysis::patterns::aggregation::types::{AggregatedPattern, PatternLocation};
use drift_analysis::patterns::confidence::types::{ConfidenceScore, MomentumDirection};
use drift_analysis::patterns::learning::discovery::ConventionDiscoverer;
use drift_analysis::patterns::learning::promotion::{self, PromotionConfig};
use drift_analysis::patterns::learning::relearning;
use drift_analysis::patterns::learning::dirichlet::DirichletMultinomial;
use drift_analysis::patterns::learning::expiry;
use drift_analysis::patterns::learning::types::{
    Convention, ConventionCategory, ConventionScope, PromotionStatus,
};

fn make_pattern(id: &str, locations: u32, files: u32) -> AggregatedPattern {
    let locs: Vec<PatternLocation> = (0..locations)
        .map(|i| PatternLocation {
            file: format!("file_{}.ts", i % files),
            line: i + 1,
            column: 0,
            confidence: 0.9,
            is_outlier: false,
            matched_text: None,
        })
        .collect();
    AggregatedPattern {
        pattern_id: id.to_string(),
        category: PatternCategory::Structural,
        location_count: locations,
        outlier_count: 0,
        file_spread: files,
        hierarchy: None,
        locations: locs,
        aliases: Vec::new(),
        merged_from: Vec::new(),
        confidence_mean: 0.9,
        confidence_stddev: 0.05,
        confidence_values: vec![0.9; locations as usize],
        is_dirty: false,
        location_hash: 0,
    }
}

fn make_convention(pattern_id: &str, last_seen: u64, status: PromotionStatus) -> Convention {
    Convention {
        id: format!("conv_{}", pattern_id),
        pattern_id: pattern_id.to_string(),
        category: ConventionCategory::ProjectSpecific,
        scope: ConventionScope::Project,
        confidence_score: ConfidenceScore::from_params(90.0, 10.0, MomentumDirection::Stable),
        dominance_ratio: 0.8,
        discovery_date: 1000,
        last_seen,
        promotion_status: status,
        observation_count: 10,
        scan_count: 1,
    }
}

// ---- T3-LRN-01: Convention discovery with thresholds ----

#[test]
fn t3_lrn_01_convention_discovery() {
    let discoverer = ConventionDiscoverer::new();

    // Pattern with 80 occurrences across 10 files — should be discovered
    let patterns = vec![make_pattern("dominant", 80, 10)];
    let scores = vec![(
        "dominant".to_string(),
        ConfidenceScore::from_params(90.0, 10.0, MomentumDirection::Stable),
    )];

    let conventions = discoverer.discover(&patterns, &scores, 100, 1000);
    assert_eq!(conventions.len(), 1, "Should discover 1 convention");
    assert_eq!(conventions[0].pattern_id, "dominant");
    assert!(conventions[0].dominance_ratio >= 0.60, "Dominance should be ≥0.60");

    // Pattern below min_occurrences (2 < 3) — should NOT be discovered
    let patterns = vec![make_pattern("rare", 2, 1)];
    let scores = vec![("rare".to_string(), ConfidenceScore::uniform_prior())];
    let conventions = discoverer.discover(&patterns, &scores, 100, 1000);
    assert!(conventions.is_empty(), "Pattern below min_occurrences should not be discovered");

    // Pattern below min_files (1 < 2) — should NOT be discovered
    let patterns = vec![make_pattern("single_file", 10, 1)];
    let scores = vec![("single_file".to_string(), ConfidenceScore::uniform_prior())];
    let conventions = discoverer.discover(&patterns, &scores, 100, 1000);
    assert!(conventions.is_empty(), "Pattern below min_files should not be discovered");
}

// ---- T3-LRN-02: Convention category classification ----

#[test]
fn t3_lrn_02_category_classification() {
    let discoverer = ConventionDiscoverer::new();

    // Universal: high spread (≥80%) + Established confidence
    let patterns = vec![make_pattern("universal_pat", 90, 85)];
    let scores = vec![(
        "universal_pat".to_string(),
        ConfidenceScore::from_params(200.0, 10.0, MomentumDirection::Stable),
    )];
    let conventions = discoverer.discover(&patterns, &scores, 100, 1000);
    assert!(!conventions.is_empty());
    assert_eq!(conventions[0].category, ConventionCategory::Universal,
        "High spread + Established should be Universal");

    // Emerging: rising momentum
    let patterns = vec![make_pattern("emerging_pat", 30, 10)];
    let scores = vec![(
        "emerging_pat".to_string(),
        ConfidenceScore::from_params(10.0, 5.0, MomentumDirection::Rising),
    )];
    let conventions = discoverer.discover(&patterns, &scores, 100, 1000);
    assert!(!conventions.is_empty());
    assert_eq!(conventions[0].category, ConventionCategory::Emerging,
        "Rising momentum should be Emerging");

    // Legacy: falling momentum
    let patterns = vec![make_pattern("legacy_pat", 30, 10)];
    let scores = vec![(
        "legacy_pat".to_string(),
        ConfidenceScore::from_params(10.0, 5.0, MomentumDirection::Falling),
    )];
    let conventions = discoverer.discover(&patterns, &scores, 100, 1000);
    assert!(!conventions.is_empty());
    assert_eq!(conventions[0].category, ConventionCategory::Legacy,
        "Falling momentum should be Legacy");

    // Contested: two patterns within 15% of each other
    let patterns = vec![
        make_pattern("style_a", 45, 10),
        make_pattern("style_b", 55, 12),
    ];
    let scores = vec![
        ("style_a".to_string(), ConfidenceScore::from_params(10.0, 5.0, MomentumDirection::Stable)),
        ("style_b".to_string(), ConfidenceScore::from_params(12.0, 5.0, MomentumDirection::Stable)),
    ];
    let conventions = discoverer.discover(&patterns, &scores, 100, 1000);
    let contested: Vec<_> = conventions.iter().filter(|c| c.category == ConventionCategory::Contested).collect();
    assert!(!contested.is_empty(), "Two patterns within 15% should be Contested");
}

// ---- T3-LRN-03: Auto-promotion from discovered → approved ----

#[test]
fn t3_lrn_03_auto_promotion() {
    let config = PromotionConfig::default();

    // High confidence → should promote
    let mut conv = make_convention("high_conf", 1000, PromotionStatus::Discovered);
    conv.confidence_score = ConfidenceScore::from_params(200.0, 10.0, MomentumDirection::Stable);
    assert!(promotion::check_promotion(&conv, &config, None), "High confidence should qualify for promotion");

    // Low confidence → should NOT promote
    let mut conv_low = make_convention("low_conf", 1000, PromotionStatus::Discovered);
    conv_low.confidence_score = ConfidenceScore::from_params(5.0, 95.0, MomentumDirection::Stable);
    assert!(!promotion::check_promotion(&conv_low, &config, None), "Low confidence should not qualify");

    // Already approved → should NOT re-promote
    let conv_approved = make_convention("approved", 1000, PromotionStatus::Approved);
    assert!(!promotion::check_promotion(&conv_approved, &config, None), "Already approved should not re-promote");

    // Batch promotion
    let mut conventions = vec![
        make_convention("a", 1000, PromotionStatus::Discovered),
        make_convention("b", 1000, PromotionStatus::Discovered),
    ];
    conventions[0].confidence_score = ConfidenceScore::from_params(200.0, 10.0, MomentumDirection::Stable);
    conventions[1].confidence_score = ConfidenceScore::from_params(5.0, 95.0, MomentumDirection::Stable);

    let promoted = promotion::promote_batch(&mut conventions, &config);
    assert_eq!(promoted, 1, "Should promote exactly 1 convention");
    assert_eq!(conventions[0].promotion_status, PromotionStatus::Approved);
    assert_eq!(conventions[1].promotion_status, PromotionStatus::Discovered);
}

// ---- T3-LRN-04: Re-learning trigger ----

#[test]
fn t3_lrn_04_relearning_trigger() {
    // Below threshold → incremental
    assert!(!relearning::should_relearn(5, 100, 0.10));
    assert_eq!(relearning::determine_mode(5, 100, 0.10), relearning::LearningMode::Incremental);

    // Above threshold → full re-learn
    assert!(relearning::should_relearn(15, 100, 0.10));
    assert_eq!(relearning::determine_mode(15, 100, 0.10), relearning::LearningMode::Full);

    // No changes → skip
    assert_eq!(relearning::determine_mode(0, 100, 0.10), relearning::LearningMode::Skip);

    // Edge case: exactly at threshold (10%) → not triggered (> not >=)
    assert!(!relearning::should_relearn(10, 100, 0.10));

    // Edge case: zero total files
    assert!(!relearning::should_relearn(5, 0, 0.10));
}

// ---- T3-LRN-05: Dirichlet-Multinomial for multi-value conventions ----

#[test]
fn t3_lrn_05_dirichlet_multinomial() {
    let mut dist = DirichletMultinomial::new(vec![
        "camelCase".into(),
        "snake_case".into(),
        "PascalCase".into(),
    ]);

    // Observe naming style usage
    dist.observe_n(0, 80); // camelCase dominant
    dist.observe_n(1, 15); // snake_case
    dist.observe_n(2, 5);  // PascalCase

    let (idx, label, mean) = dist.dominant().unwrap();
    assert_eq!(idx, 0);
    assert_eq!(label, "camelCase");
    assert!(mean > 0.5, "Dominant style should have >50% posterior mean, got {}", mean);

    // Verify posterior means sum to ~1.0
    let means = dist.posterior_means();
    let sum: f64 = means.iter().sum();
    assert!((sum - 1.0).abs() < 1e-10, "Posterior means should sum to 1.0, got {}", sum);

    // Not contested (clear dominant)
    assert!(!dist.is_contested(0.15));

    assert_eq!(dist.total_observations(), 100);
    assert_eq!(dist.num_categories(), 3);
}

// ---- T3-LRN-06: Convention expiry after 90 days ----

#[test]
fn t3_lrn_06_convention_expiry() {
    let seconds_per_day = 86400u64;
    let now = 1000 + seconds_per_day * 100;

    // Convention last seen 91 days ago → should expire
    let conv_old = make_convention("old", 1000, PromotionStatus::Discovered);
    assert!(expiry::check_expiry(&conv_old, now, 90), "Convention not seen for 91+ days should expire");

    // Convention last seen 30 days ago → should NOT expire
    let conv_recent = make_convention("recent", now - seconds_per_day * 30, PromotionStatus::Discovered);
    assert!(!expiry::check_expiry(&conv_recent, now, 90), "Recent convention should not expire");

    // Already expired → should NOT re-expire
    let conv_expired = make_convention("expired", 1000, PromotionStatus::Expired);
    assert!(!expiry::check_expiry(&conv_expired, now, 90));

    // Batch expiry
    let mut conventions = vec![
        make_convention("old1", 1000, PromotionStatus::Discovered),
        make_convention("recent1", now - seconds_per_day * 10, PromotionStatus::Discovered),
    ];
    let expired = expiry::process_expiry(&mut conventions, now, 90);
    assert_eq!(expired, 1);
    assert_eq!(conventions[0].promotion_status, PromotionStatus::Expired);
    assert_eq!(conventions[0].category, ConventionCategory::Legacy);
    assert_eq!(conventions[1].promotion_status, PromotionStatus::Discovered);
}

// ---- T3-LRN-07: Contested convention not auto-promoted ----

#[test]
fn t3_lrn_07_contested_not_promoted() {
    let discoverer = ConventionDiscoverer::new();
    let patterns = vec![
        make_pattern("style_a", 45, 10),
        make_pattern("style_b", 55, 12),
    ];
    let scores = vec![
        ("style_a".to_string(), ConfidenceScore::from_params(10.0, 5.0, MomentumDirection::Stable)),
        ("style_b".to_string(), ConfidenceScore::from_params(12.0, 5.0, MomentumDirection::Stable)),
    ];

    let mut conventions = discoverer.discover(&patterns, &scores, 100, 1000);

    // Try to promote
    let config = PromotionConfig::default();
    let _promoted = promotion::promote_batch(&mut conventions, &config);

    // Contested conventions should not be promoted (their confidence is too low)
    let contested_promoted: Vec<_> = conventions.iter()
        .filter(|c| c.category == ConventionCategory::Contested && c.promotion_status == PromotionStatus::Approved)
        .collect();
    assert!(contested_promoted.is_empty(), "Contested conventions should not be auto-promoted");
}

// ---- T3-LRN-08: Directory-scoped convention isolation ----

#[test]
fn t3_lrn_08_directory_scope() {
    // Test that ConventionScope::Directory correctly scopes
    let scope_a = ConventionScope::Directory("src/components".to_string());
    let scope_b = ConventionScope::Directory("src/utils".to_string());

    assert_ne!(scope_a, scope_b, "Different directories should have different scopes");
    assert_eq!(scope_a, ConventionScope::Directory("src/components".to_string()));

    // Display format
    assert_eq!(format!("{}", scope_a), "directory:src/components");
    assert_eq!(format!("{}", scope_b), "directory:src/utils");
    assert_eq!(format!("{}", ConventionScope::Project), "project");
    assert_eq!(format!("{}", ConventionScope::Package("@my/pkg".to_string())), "package:@my/pkg");

    // Convention with directory scope
    let conv = Convention {
        id: "conv_dir".to_string(),
        pattern_id: "pattern_dir".to_string(),
        category: ConventionCategory::ProjectSpecific,
        scope: ConventionScope::Directory("src/components".to_string()),
        confidence_score: ConfidenceScore::uniform_prior(),
        dominance_ratio: 0.8,
        discovery_date: 1000,
        last_seen: 1000,
        promotion_status: PromotionStatus::Discovered,
        observation_count: 5,
        scan_count: 1,
    };

    // Verify scope is directory-specific
    match &conv.scope {
        ConventionScope::Directory(dir) => assert_eq!(dir, "src/components"),
        _ => panic!("Expected Directory scope"),
    }
}
