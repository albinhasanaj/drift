//! Production Category 24: Graceful Degradation — Cortex Without Drift
//!
//! T24-03: Initialize Cortex runtime without drift.db present.
//! All Cortex NAPI bindings must work independently. Bridge grounding
//! must gracefully return InsufficientData (not crash).
//!
//! Source verification:
//!   - bridge_ground_memory() — drift_db: Option<&Connection> parameter
//!   - ground_single() — returns InsufficientData when no evidence available
//!   - collect_evidence() — handles drift_db: None gracefully

use cortex_drift_bridge::grounding::loop_runner::{GroundingLoopRunner, MemoryForGrounding};
use cortex_drift_bridge::types::GroundingVerdict;

// ═══════════════════════════════════════════════════════════════════════════
// T24-03: Cortex Without Drift
//
// Initialize Cortex runtime without drift.db present. All Cortex NAPI
// bindings must work independently. Bridge grounding must gracefully
// return InsufficientData (not crash).
// Source: bridge_ground_memory() — drift_db: Option<&Connection>
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn t24_03_cortex_without_drift() {
    let runner = GroundingLoopRunner::default();

    // Memory with no pre-populated fields and NO drift_db
    let memory = MemoryForGrounding {
        memory_id: "no_drift_test".to_string(),
        memory_type: cortex_core::MemoryType::PatternRationale,
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
        evidence_context: None,
    };

    // Ground with NO drift_db and NO bridge_db — must not crash
    let result = runner
        .ground_single(&memory, None, None)
        .expect("ground_single must not crash when drift_db is None");

    // Without any evidence source, verdict must be InsufficientData
    assert_eq!(
        result.verdict,
        GroundingVerdict::InsufficientData,
        "Without drift_db and no pre-populated fields, verdict must be InsufficientData"
    );
    assert!(
        result.evidence.is_empty(),
        "No evidence should be collected without drift_db"
    );
    assert_eq!(
        result.grounding_score, 0.0,
        "Grounding score must be 0.0 with no evidence"
    );

    // Ground a batch with NO drift_db — must also not crash
    let memories = vec![memory.clone(), memory.clone(), memory];
    let snapshot = runner
        .run(
            &memories,
            None,
            None,
            cortex_drift_bridge::grounding::TriggerType::OnDemand,
        )
        .expect("run() must not crash when drift_db is None");

    assert_eq!(
        snapshot.total_checked, 3,
        "All 3 memories must be checked"
    );
    assert_eq!(
        snapshot.insufficient_data, 3,
        "All 3 must be InsufficientData without drift_db"
    );
    assert_eq!(snapshot.validated, 0);
    assert_eq!(snapshot.invalidated, 0);

    // Ground with pre-populated fields but NO drift_db — should still work
    let memory_with_fields = MemoryForGrounding {
        memory_id: "with_fields".to_string(),
        memory_type: cortex_core::MemoryType::PatternRationale,
        current_confidence: 0.7,
        pattern_confidence: Some(0.85),
        occurrence_rate: Some(0.6),
        false_positive_rate: None,
        constraint_verified: Some(true),
        coupling_metric: None,
        dna_health: None,
        test_coverage: None,
        error_handling_gaps: None,
        decision_evidence: None,
        boundary_data: None,
        evidence_context: None,
    };

    let result_with_fields = runner
        .ground_single(&memory_with_fields, None, None)
        .expect("ground_single must work with pre-populated fields and no drift_db");

    // Should have evidence from the pre-populated fields
    assert!(
        !result_with_fields.evidence.is_empty(),
        "Pre-populated fields should produce evidence even without drift_db"
    );
    assert_ne!(
        result_with_fields.verdict,
        GroundingVerdict::InsufficientData,
        "With pre-populated fields, verdict should not be InsufficientData"
    );
}
