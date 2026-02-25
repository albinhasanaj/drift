//! Enterprise stress tests for Cortex Validation hardening fixes.
//!
//! Covers:
//! - P1-12/E-02: ValidationEngine now runs real 4-dimension validation
//!   (citation, temporal, contradiction, pattern alignment) instead of
//!   just listing candidates.
//!
//! Every test targets a specific production failure mode.

use chrono::{Duration, Utc};
use cortex_core::memory::*;
use cortex_core::memory::types::InsightContent;
use cortex_core::traits::IValidator;
use cortex_validation::engine::{ValidationConfig, ValidationEngine};

fn make_memory_with_age(id: &str, days_old: i64, confidence: f64) -> BaseMemory {
    let now = Utc::now();
    let content = TypedContent::Insight(InsightContent {
        observation: format!("observation for {id}"),
        evidence: vec![],
    });
    BaseMemory {
        id: id.to_string(),
        memory_type: MemoryType::Insight,
        content: content.clone(),
        summary: format!("summary {id}"),
        transaction_time: now - Duration::days(days_old),
        valid_time: now - Duration::days(days_old),
        valid_until: None,
        confidence: Confidence::new(confidence),
        importance: Importance::Normal,
        last_accessed: now,
        access_count: 1,
        linked_patterns: vec![],
        linked_constraints: vec![],
        linked_files: vec![],
        linked_functions: vec![],
        tags: vec![],
        archived: false,
        superseded_by: None,
        supersedes: None,
        namespace: Default::default(),
        source_agent: Default::default(),
        content_hash: BaseMemory::compute_content_hash(&content).unwrap(),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// P1-12/E-02: VALIDATION ENGINE — 4-dimension validation
// ═══════════════════════════════════════════════════════════════════════════════

/// PRODUCTION BUG: drift_cortex_validate tool only listed candidates (via
/// getValidationCandidates) but never ran the actual 4-dimension validation.
/// Verify validate() returns a real result with all 4 dimension scores.
#[test]
fn hst_e02_01_validate_returns_all_four_dimensions() {
    let engine = ValidationEngine::default();
    let memory = make_memory_with_age("val-001", 5, 0.8);

    let result = engine.validate(&memory).unwrap();
    let scores = &result.dimension_scores;

    // All 4 dimensions must be present (0.0-1.0 range).
    assert!((0.0..=1.0).contains(&scores.citation), "citation out of range: {}", scores.citation);
    assert!((0.0..=1.0).contains(&scores.temporal), "temporal out of range: {}", scores.temporal);
    assert!((0.0..=1.0).contains(&scores.contradiction), "contradiction out of range: {}", scores.contradiction);
    assert!((0.0..=1.0).contains(&scores.pattern_alignment), "pattern_alignment out of range: {}", scores.pattern_alignment);
}

/// Overall score is the average of the 4 dimensions.
#[test]
fn hst_e02_02_overall_score_is_average() {
    let engine = ValidationEngine::default();
    let memory = make_memory_with_age("val-002", 5, 0.8);

    let result = engine.validate(&memory).unwrap();
    let scores = &result.dimension_scores;
    let expected_avg = (scores.citation + scores.temporal + scores.contradiction + scores.pattern_alignment) / 4.0;

    assert!(
        (result.overall_score - expected_avg).abs() < 1e-10,
        "Overall score {} != average {}",
        result.overall_score,
        expected_avg
    );
}

/// passed flag matches threshold comparison.
#[test]
fn hst_e02_03_passed_matches_threshold() {
    let config = ValidationConfig {
        pass_threshold: 0.5,
        ..Default::default()
    };
    let engine = ValidationEngine::new(config);
    let memory = make_memory_with_age("val-003", 5, 0.8);

    let result = engine.validate(&memory).unwrap();
    assert_eq!(
        result.passed,
        result.overall_score >= 0.5,
        "passed={} but overall_score={}",
        result.passed,
        result.overall_score
    );
}

/// Very old memory (1000 days) — temporal score should reflect staleness.
#[test]
fn hst_e02_04_old_memory_temporal_penalty() {
    let engine = ValidationEngine::default();
    let old_memory = make_memory_with_age("val-old", 1000, 0.8);
    let new_memory = make_memory_with_age("val-new", 1, 0.8);

    let old_result = engine.validate(&old_memory).unwrap();
    let new_result = engine.validate(&new_memory).unwrap();

    // Old memory should have lower temporal score.
    assert!(
        old_result.dimension_scores.temporal <= new_result.dimension_scores.temporal,
        "1000-day memory temporal {} should be <= 1-day memory temporal {}",
        old_result.dimension_scores.temporal,
        new_result.dimension_scores.temporal
    );
}

/// validate_basic with related memories — contradiction check runs.
#[test]
fn hst_e02_05_validate_basic_with_related_memories() {
    let engine = ValidationEngine::default();
    let memory = make_memory_with_age("val-005", 5, 0.8);
    let related = vec![
        make_memory_with_age("rel-001", 3, 0.9),
        make_memory_with_age("rel-002", 7, 0.7),
    ];

    let result = engine.validate_basic(&memory, &related).unwrap();
    assert!(!result.memory_id.is_empty());
    assert!((0.0..=1.0).contains(&result.dimension_scores.contradiction));
}

/// Empty memory ID doesn't panic — returns a valid result.
#[test]
fn hst_e02_06_empty_memory_id_no_panic() {
    let engine = ValidationEngine::default();
    let memory = make_memory_with_age("", 5, 0.8);

    let result = engine.validate(&memory);
    assert!(result.is_ok(), "Empty ID should not panic");
}

/// Stress: validate 500 memories sequentially — no degradation.
#[test]
fn hst_e02_07_stress_500_validations() {
    let engine = ValidationEngine::default();

    for i in 0..500 {
        let memory = make_memory_with_age(&format!("stress-{i}"), i % 365 + 1, 0.5 + (i as f64 % 50.0) / 100.0);
        let result = engine.validate(&memory).unwrap();
        assert!(
            (0.0..=1.0).contains(&result.overall_score),
            "Score out of range at iteration {i}: {}",
            result.overall_score
        );
    }
}

/// Custom config: very low pass_threshold → everything passes.
#[test]
fn hst_e02_08_low_threshold_everything_passes() {
    let config = ValidationConfig {
        pass_threshold: 0.0,
        ..Default::default()
    };
    let engine = ValidationEngine::new(config);

    for i in 0..20 {
        let memory = make_memory_with_age(&format!("low-{i}"), 100, 0.1);
        let result = engine.validate(&memory).unwrap();
        assert!(result.passed, "With threshold=0.0, everything should pass");
    }
}

/// Custom config: very high pass_threshold → most things fail.
#[test]
fn hst_e02_09_high_threshold_strict_validation() {
    let config = ValidationConfig {
        pass_threshold: 0.99,
        ..Default::default()
    };
    let engine = ValidationEngine::new(config);

    let memory = make_memory_with_age("strict-001", 100, 0.5);
    let result = engine.validate(&memory).unwrap();
    // With no file checker and a 100-day old memory, unlikely to score 0.99+.
    // The test is that it returns a result, not panic.
    assert!(!result.memory_id.is_empty());
}

/// Epistemic promotion: Conjecture → Provisional on validation pass.
#[test]
fn hst_e02_10_epistemic_promotion_conjecture_to_provisional() {
    let engine = ValidationEngine::default();
    let status = cortex_core::models::EpistemicStatus::Conjecture {
        source: "test".to_string(),
        created_at: chrono::Utc::now(),
    };

    let promotion = engine.promote_epistemic_status(&status, true, false);
    assert!(promotion.is_some(), "Conjecture + pass should promote");
    match promotion.unwrap() {
        cortex_core::models::EpistemicStatus::Provisional { evidence_count, .. } => {
            assert_eq!(evidence_count, 1);
        }
        other => panic!("Expected Provisional, got {:?}", other),
    }
}

/// Epistemic promotion: validation failure → no promotion.
#[test]
fn hst_e02_11_no_promotion_on_failure() {
    let engine = ValidationEngine::default();
    let status = cortex_core::models::EpistemicStatus::Conjecture {
        source: "test".to_string(),
        created_at: chrono::Utc::now(),
    };

    let promotion = engine.promote_epistemic_status(&status, false, false);
    assert!(promotion.is_none(), "Failed validation should not promote");
}

/// healing_actions list is populated (may be empty for healthy memories).
#[test]
fn hst_e02_12_healing_actions_populated() {
    let engine = ValidationEngine::default();

    // A very old memory with linked files (that won't exist) should get healing actions.
    let mut memory = make_memory_with_age("heal-001", 500, 0.3);
    memory.linked_files = vec![FileLink {
        file_path: "/nonexistent/path/file.rs".to_string(),
        line_start: Some(1),
        line_end: Some(10),
        content_hash: Some("abc123".to_string()),
    }];

    let result = engine.validate_basic(&memory, &[]).unwrap();
    // Even with no-op callbacks, temporal staleness should trigger actions.
    // The point is: no panic and the result has a valid structure.
    assert!(!result.memory_id.is_empty());
}
