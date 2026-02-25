//! T9-GND-01 through T9-GND-10: Grounding logic tests.

use cortex_drift_bridge::grounding::classification::*;
use cortex_drift_bridge::grounding::evidence::*;
use cortex_drift_bridge::grounding::loop_runner::*;
use cortex_drift_bridge::grounding::scheduler::*;
use cortex_drift_bridge::grounding::scorer::*;
use cortex_drift_bridge::grounding::*;
use cortex_drift_bridge::traits::IBridgeStorage;

/// Helper: create a MemoryForGrounding with pattern evidence.
fn memory_with_pattern(id: &str, confidence: f64, pattern_conf: f64) -> MemoryForGrounding {
    MemoryForGrounding {
        memory_id: id.to_string(),
        memory_type: cortex_core::MemoryType::PatternRationale,
        current_confidence: confidence,
        pattern_confidence: Some(pattern_conf),
        occurrence_rate: Some(0.8),
        false_positive_rate: Some(0.05),
        constraint_verified: None,
        coupling_metric: None,
        dna_health: None,
        test_coverage: None,
        error_handling_gaps: None,
        decision_evidence: None,
        boundary_data: None,
        evidence_context: None,    }
}

/// Helper: create a MemoryForGrounding with all evidence types populated.
fn memory_full_evidence(id: &str, support_level: f64) -> MemoryForGrounding {
    MemoryForGrounding {
        memory_id: id.to_string(),
        memory_type: cortex_core::MemoryType::PatternRationale,
        current_confidence: 0.7,
        pattern_confidence: Some(support_level),
        occurrence_rate: Some(support_level),
        false_positive_rate: Some(1.0 - support_level), // low FP = high support
        constraint_verified: Some(support_level > 0.5),
        coupling_metric: Some(support_level),
        dna_health: Some(support_level),
        test_coverage: Some(support_level),
        error_handling_gaps: Some(((1.0 - support_level) * 100.0) as u32),
        decision_evidence: Some(support_level),
        boundary_data: Some(support_level),
        evidence_context: None,    }
}

/// Helper: create a non-groundable memory.
fn memory_not_groundable(id: &str) -> MemoryForGrounding {
    MemoryForGrounding {
        memory_id: id.to_string(),
        memory_type: cortex_core::MemoryType::Procedural,
        current_confidence: 0.5,
        pattern_confidence: None,
        occurrence_rate: None,
        false_positive_rate: None,
        constraint_verified: None,
        coupling_metric: None,
        dna_health: None,
        test_coverage: None,
        error_handling_gaps: None,
        decision_evidence: None,
        boundary_data: None,
        evidence_context: None,    }
}

/// Helper: create an in-memory bridge DB.
fn setup_bridge_db() -> cortex_drift_bridge::storage::engine::BridgeStorageEngine {
    cortex_drift_bridge::storage::engine::BridgeStorageEngine::open_in_memory().unwrap()
}

// ---- T9-GND-01: Test grounding logic computes grounding percentage ----

#[test]
fn t9_gnd_01_grounding_computes_score() {
    let runner = GroundingLoopRunner::default();
    let memory = memory_with_pattern("m1", 0.7, 0.85);
    let result = runner.ground_single(&memory, None, None).unwrap();

    assert!(result.grounding_score > 0.0, "Score should be positive");
    assert!(result.grounding_score <= 1.0, "Score should be <= 1.0");
    assert!(!result.evidence.is_empty(), "Should have evidence");
}

#[test]
fn t9_gnd_01_high_support_yields_validated() {
    let runner = GroundingLoopRunner::default();
    let memory = memory_full_evidence("m_high", 0.9);
    let result = runner.ground_single(&memory, None, None).unwrap();

    assert!(result.grounding_score >= 0.7, "High support should yield Validated score");
    assert_eq!(result.verdict, GroundingVerdict::Validated);
}

#[test]
fn t9_gnd_01_low_support_yields_invalidated() {
    let runner = GroundingLoopRunner::default();
    let memory = memory_full_evidence("m_low", 0.05);
    let result = runner.ground_single(&memory, None, None).unwrap();

    assert!(result.grounding_score < 0.2, "Low support should yield Invalidated score");
    assert_eq!(result.verdict, GroundingVerdict::Invalidated);
}

// ---- T9-GND-02: Test grounding feedback loop adjusts confidence ----

#[test]
fn t9_gnd_02_validated_boosts_confidence() {
    let config = GroundingConfig::default();
    let scorer = GroundingScorer::new(config.clone());
    let adj = scorer.compute_confidence_adjustment(&GroundingVerdict::Validated, None, 0.7);
    assert_eq!(adj.mode, AdjustmentMode::Boost);
    assert!((adj.delta.unwrap() - 0.05).abs() < f64::EPSILON, "Boost should be 0.05");
}

#[test]
fn t9_gnd_02_invalidated_drops_confidence() {
    let config = GroundingConfig::default();
    let scorer = GroundingScorer::new(config.clone());
    let adj = scorer.compute_confidence_adjustment(&GroundingVerdict::Invalidated, None, 0.7);
    assert_eq!(adj.mode, AdjustmentMode::Penalize);
    // Should drop by contradiction_drop (0.3) but respect floor (0.1)
    // 0.7 - 0.3 = 0.4, which is above floor, so delta = -0.3
    assert!((adj.delta.unwrap() - (-0.3)).abs() < f64::EPSILON);
}

#[test]
fn t9_gnd_02_weak_penalizes_by_015() {
    let config = GroundingConfig::default();
    let scorer = GroundingScorer::new(config);
    let adj = scorer.compute_confidence_adjustment(&GroundingVerdict::Weak, None, 0.5);
    assert_eq!(adj.mode, AdjustmentMode::Penalize);
    assert!((adj.delta.unwrap() - (-0.15)).abs() < f64::EPSILON);
}

#[test]
fn t9_gnd_02_partial_penalizes_by_005() {
    let config = GroundingConfig::default();
    let scorer = GroundingScorer::new(config);
    let adj = scorer.compute_confidence_adjustment(&GroundingVerdict::Partial, None, 0.5);
    assert_eq!(adj.mode, AdjustmentMode::Penalize);
    assert!((adj.delta.unwrap() - (-0.05)).abs() < f64::EPSILON);
}

// ---- T9-GND-03: Test grounding score thresholds ----

#[test]
fn t9_gnd_03_threshold_validated() {
    let scorer = GroundingScorer::default();
    assert_eq!(scorer.score_to_verdict(0.75), GroundingVerdict::Validated);
    assert_eq!(scorer.score_to_verdict(0.70), GroundingVerdict::Validated);
}

#[test]
fn t9_gnd_03_threshold_partial() {
    let scorer = GroundingScorer::default();
    assert_eq!(scorer.score_to_verdict(0.45), GroundingVerdict::Partial);
    assert_eq!(scorer.score_to_verdict(0.40), GroundingVerdict::Partial);
    assert_eq!(scorer.score_to_verdict(0.69), GroundingVerdict::Partial);
}

#[test]
fn t9_gnd_03_threshold_weak() {
    let scorer = GroundingScorer::default();
    assert_eq!(scorer.score_to_verdict(0.25), GroundingVerdict::Weak);
    assert_eq!(scorer.score_to_verdict(0.20), GroundingVerdict::Weak);
    assert_eq!(scorer.score_to_verdict(0.39), GroundingVerdict::Weak);
}

#[test]
fn t9_gnd_03_threshold_invalidated() {
    let scorer = GroundingScorer::default();
    assert_eq!(scorer.score_to_verdict(0.15), GroundingVerdict::Invalidated);
    assert_eq!(scorer.score_to_verdict(0.0), GroundingVerdict::Invalidated);
    assert_eq!(scorer.score_to_verdict(0.19), GroundingVerdict::Invalidated);
}

// ---- T9-GND-04: Test max 500 memories per grounding loop ----

#[test]
fn t9_gnd_04_max_500_memories_per_loop() {
    let runner = GroundingLoopRunner::default();
    let db = setup_bridge_db();

    // Create 501 memories
    let memories: Vec<MemoryForGrounding> = (0..501)
        .map(|i| memory_with_pattern(&format!("m_{}", i), 0.7, 0.8))
        .collect();

    let snapshot = runner.run(&memories, None, Some(&db as &dyn cortex_drift_bridge::traits::IBridgeStorage), TriggerType::OnDemand).unwrap();
    // Should process at most 500
    assert!(snapshot.total_checked <= 500, "Should cap at 500, got {}", snapshot.total_checked);
}

// ---- T9-GND-05: Test all 13 groundable memory types classified correctly ----

#[test]
fn t9_gnd_05_six_fully_groundable() {
    use cortex_core::MemoryType;
    let fully = vec![
        MemoryType::PatternRationale,
        MemoryType::ConstraintOverride,
        MemoryType::DecisionContext,
        MemoryType::CodeSmell,
        MemoryType::Core,
        MemoryType::Semantic,
    ];
    for mt in &fully {
        assert_eq!(
            classify_groundability(mt),
            Groundability::Full,
            "{:?} should be fully groundable",
            mt,
        );
    }
    assert_eq!(fully_groundable_types().len(), 6);
}

#[test]
fn t9_gnd_05_seven_partially_groundable() {
    use cortex_core::MemoryType;
    let partial = vec![
        MemoryType::Tribal,
        MemoryType::Decision,
        MemoryType::Insight,
        MemoryType::Entity,
        MemoryType::Feedback,
        MemoryType::Incident,
        MemoryType::Environment,
    ];
    for mt in &partial {
        assert_eq!(
            classify_groundability(mt),
            Groundability::Partial,
            "{:?} should be partially groundable",
            mt,
        );
    }
    assert_eq!(partially_groundable_types().len(), 7);
}

#[test]
fn t9_gnd_05_total_groundable_is_13() {
    assert_eq!(groundable_types().len(), 13);
}

#[test]
fn t9_gnd_05_not_groundable_types() {
    use cortex_core::MemoryType;
    let not_groundable = vec![
        MemoryType::Procedural,
        MemoryType::Episodic,
        MemoryType::Reference,
        MemoryType::Preference,
        MemoryType::AgentSpawn,
        MemoryType::Goal,
        MemoryType::Workflow,
        MemoryType::Conversation,
        MemoryType::Meeting,
        MemoryType::Skill,
    ];
    for mt in &not_groundable {
        assert_eq!(
            classify_groundability(mt),
            Groundability::NotGroundable,
            "{:?} should not be groundable",
            mt,
        );
    }
}

// ---- T9-GND-06: Test 6 trigger types fire at correct intervals ----

#[test]
fn t9_gnd_06_post_scan_incremental_every_scan() {
    let scheduler = GroundingScheduler::new(10);
    // First 9 scans should be incremental
    for _ in 0..9 {
        assert_eq!(scheduler.on_scan_complete(), TriggerType::PostScanIncremental);
    }
}

#[test]
fn t9_gnd_06_post_scan_full_every_10th() {
    let scheduler = GroundingScheduler::new(10);
    // 10th scan should be full
    for _ in 0..9 {
        scheduler.on_scan_complete();
    }
    assert_eq!(scheduler.on_scan_complete(), TriggerType::PostScanFull);
}

#[test]
fn t9_gnd_06_full_grounding_check() {
    assert!(GroundingScheduler::is_full_grounding(TriggerType::PostScanFull));
    assert!(GroundingScheduler::is_full_grounding(TriggerType::Scheduled));
    assert!(GroundingScheduler::is_full_grounding(TriggerType::OnDemand));
    assert!(!GroundingScheduler::is_full_grounding(TriggerType::PostScanIncremental));
    assert!(!GroundingScheduler::is_full_grounding(TriggerType::MemoryCreation));
    assert!(!GroundingScheduler::is_full_grounding(TriggerType::MemoryUpdate));
}

#[test]
fn t9_gnd_06_scheduler_reset() {
    let scheduler = GroundingScheduler::new(10);
    for _ in 0..5 {
        scheduler.on_scan_complete();
    }
    assert_eq!(scheduler.scan_count(), 5);
    scheduler.reset();
    assert_eq!(scheduler.scan_count(), 0);
}

// ---- T9-GND-07: Test contradiction detection ----

#[test]
fn t9_gnd_07_contradiction_on_invalidated() {
    let scorer = GroundingScorer::default();
    assert!(scorer.should_generate_contradiction(0.1, None, &GroundingVerdict::Invalidated));
}

#[test]
fn t9_gnd_07_contradiction_on_large_drop() {
    let scorer = GroundingScorer::default();
    // Score dropped by 0.4 (> contradiction_drop of 0.3)
    assert!(scorer.should_generate_contradiction(0.3, Some(-0.4), &GroundingVerdict::Weak));
}

#[test]
fn t9_gnd_07_no_contradiction_on_validated() {
    let scorer = GroundingScorer::default();
    assert!(!scorer.should_generate_contradiction(0.8, Some(0.05), &GroundingVerdict::Validated));
}

// ---- T9-GND-08: Test grounding with stale data ----

#[test]
fn t9_gnd_08_not_groundable_returns_not_groundable() {
    let runner = GroundingLoopRunner::default();
    let memory = memory_not_groundable("stale");
    let result = runner.ground_single(&memory, None, None).unwrap();
    assert_eq!(result.verdict, GroundingVerdict::NotGroundable);
    assert!(!result.generates_contradiction);
}

#[test]
fn t9_gnd_08_no_evidence_returns_insufficient_data() {
    let runner = GroundingLoopRunner::default();
    let memory = MemoryForGrounding {
        memory_id: "no_evidence".to_string(),
        memory_type: cortex_core::MemoryType::PatternRationale,
        current_confidence: 0.7,
        pattern_confidence: None,
        occurrence_rate: None,
        false_positive_rate: None,
        constraint_verified: None,
        coupling_metric: None,
        dna_health: None,
        test_coverage: None,
        error_handling_gaps: None,
        decision_evidence: None,
        boundary_data: None,
        evidence_context: None,    };
    let result = runner.ground_single(&memory, None, None).unwrap();
    assert_eq!(result.verdict, GroundingVerdict::InsufficientData);
}

// ---- T9-GND-09: Test all 12 evidence types contribute with correct weights ----

#[test]
fn t9_gnd_09_all_12_evidence_types() {
    assert_eq!(EvidenceType::ALL.len(), 12);

    // Verify weights sum to 1.0
    let total_weight: f64 = EvidenceType::ALL.iter().map(|e| e.default_weight()).sum();
    assert!(
        (total_weight - 1.0).abs() < 1e-10,
        "Evidence weights should sum to 1.0, got {}",
        total_weight,
    );
}

#[test]
fn t9_gnd_09_specific_weights() {
    assert!((EvidenceType::PatternConfidence.default_weight() - 0.18).abs() < f64::EPSILON);
    assert!((EvidenceType::PatternOccurrence.default_weight() - 0.13).abs() < f64::EPSILON);
    assert!((EvidenceType::FalsePositiveRate.default_weight() - 0.09).abs() < f64::EPSILON);
    assert!((EvidenceType::ConstraintVerification.default_weight() - 0.09).abs() < f64::EPSILON);
    assert!((EvidenceType::CouplingMetric.default_weight() - 0.07).abs() < f64::EPSILON);
    assert!((EvidenceType::DnaHealth.default_weight() - 0.07).abs() < f64::EPSILON);
    assert!((EvidenceType::TestCoverage.default_weight() - 0.09).abs() < f64::EPSILON);
    assert!((EvidenceType::ErrorHandlingGaps.default_weight() - 0.06).abs() < f64::EPSILON);
    assert!((EvidenceType::DecisionEvidence.default_weight() - 0.07).abs() < f64::EPSILON);
    assert!((EvidenceType::BoundaryData.default_weight() - 0.05).abs() < f64::EPSILON);
    assert!((EvidenceType::TaintAnalysis.default_weight() - 0.05).abs() < f64::EPSILON);
    assert!((EvidenceType::CallGraphCoverage.default_weight() - 0.05).abs() < f64::EPSILON);
}

#[test]
fn t9_gnd_09_full_evidence_contributes_all_types() {
    let runner = GroundingLoopRunner::default();
    let memory = memory_full_evidence("full", 0.8);
    let result = runner.ground_single(&memory, None, None).unwrap();
    // Pre-populated MemoryForGrounding has 10 fields (no taint/call_graph pre-populated)
    assert_eq!(result.evidence.len(), 10, "All 10 pre-populated evidence types should contribute");
}

// ---- T9-GND-10: Test invalidated_floor=0.1 ----

#[test]
fn t9_gnd_10_invalidated_floor() {
    let config = GroundingConfig::default();
    let scorer = GroundingScorer::new(config);

    // Memory with very low confidence (0.2) that gets invalidated
    let adj = scorer.compute_confidence_adjustment(&GroundingVerdict::Invalidated, None, 0.2);
    // 0.2 - 0.3 = -0.1, but floor is 0.1, so new_confidence = 0.1, delta = 0.1 - 0.2 = -0.1
    let new_confidence = 0.2 + adj.delta.unwrap();
    assert!(
        new_confidence >= 0.1 - f64::EPSILON,
        "Confidence should not drop below floor 0.1, got {}",
        new_confidence,
    );
}

#[test]
fn t9_gnd_10_invalidated_floor_very_low_confidence() {
    let config = GroundingConfig::default();
    let scorer = GroundingScorer::new(config);

    // Memory already at 0.1 — should not go lower
    let adj = scorer.compute_confidence_adjustment(&GroundingVerdict::Invalidated, None, 0.1);
    let new_confidence = 0.1 + adj.delta.unwrap();
    assert!(
        new_confidence >= 0.1 - f64::EPSILON,
        "Confidence at floor should stay at floor, got {}",
        new_confidence,
    );
}

// ---- T9-GND: Grounding loop with persistence ----

#[test]
fn t9_gnd_loop_persists_results() {
    let runner = GroundingLoopRunner::default();
    let db = setup_bridge_db();
    let memory = memory_with_pattern("persist_test", 0.7, 0.85);

    let result = runner.ground_single(&memory, None, Some(&db as &dyn cortex_drift_bridge::traits::IBridgeStorage)).unwrap();
    assert!(result.grounding_score > 0.0);

    // Check that the result was persisted
    let history = db.get_grounding_history("persist_test", 10).unwrap();
    assert_eq!(history.len(), 1, "Should have 1 grounding result");
}

#[test]
fn t9_gnd_loop_snapshot_persisted() {
    let runner = GroundingLoopRunner::default();
    let db = setup_bridge_db();

    let memories: Vec<MemoryForGrounding> = (0..5)
        .map(|i| memory_with_pattern(&format!("snap_{}", i), 0.7, 0.8))
        .collect();

    let snapshot = runner.run(&memories, None, Some(&db as &dyn cortex_drift_bridge::traits::IBridgeStorage), TriggerType::OnDemand).unwrap();
    assert_eq!(snapshot.total_checked, 5);
    assert!(snapshot.validated > 0 || snapshot.partial > 0);
}
