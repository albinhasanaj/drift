//! Phase E: Code Quality & Documentation regression tests (CQ-T01, CQ-T02).
//!
//! CQ-T01: MemoryBuilder returns error on missing content (no panic).
//! CQ-T02: All 12 GroundingDataSources have corresponding evidence type or documented exclusion.

use cortex_drift_bridge::event_mapping::MemoryBuilder;
use cortex_drift_bridge::grounding::evidence::EvidenceType;
use cortex_drift_bridge::types::GroundingDataSource;
use cortex_core::memory::base::TypedContent;
use cortex_core::memory::importance::Importance;
use cortex_core::memory::types::InsightContent;
use cortex_core::MemoryType;

// ============================================================================
// CQ-T01: MemoryBuilder returns error on missing content (no panic)
// ============================================================================

#[test]
fn cq_t01_builder_returns_error_without_content() {
    let result = MemoryBuilder::new(MemoryType::Insight)
        .summary("No content set")
        .build();

    assert!(result.is_err(), "build() without content must return Err, not panic");
    let err = result.unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("content must be set"),
        "Error message should mention missing content, got: {}",
        msg
    );
}

#[test]
fn cq_t01_builder_error_includes_memory_type() {
    let result = MemoryBuilder::new(MemoryType::PatternRationale)
        .summary("Missing content")
        .build();

    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("PatternRationale"),
        "Error should include the memory type for debugging, got: {}",
        msg
    );
}

#[test]
fn cq_t01_builder_succeeds_with_content() {
    let result = MemoryBuilder::new(MemoryType::Insight)
        .content(TypedContent::Insight(InsightContent {
            observation: "test".to_string(),
            evidence: vec![],
        }))
        .summary("Has content")
        .confidence(0.8)
        .importance(Importance::Normal)
        .build();

    assert!(result.is_ok(), "build() with content must succeed");
    let memory = result.unwrap();
    assert_eq!(memory.memory_type, MemoryType::Insight);
    assert!(!memory.id.is_empty());
    assert!(!memory.content_hash.is_empty());
}

#[test]
fn cq_t01_builder_error_is_memory_creation_failed() {
    let result = MemoryBuilder::new(MemoryType::Feedback)
        .build();

    assert!(result.is_err());
    let err = result.unwrap_err();
    // Should be MemoryCreationFailed variant
    let msg = format!("{}", err);
    assert!(msg.contains("Memory creation failed"), "Expected MemoryCreationFailed, got: {}", msg);
}

// ============================================================================
// CQ-T02: All 12 GroundingDataSources have corresponding evidence type
//         or documented exclusion
// ============================================================================

/// Maps each GroundingDataSource to its corresponding EvidenceType(s).
/// This ensures the mapping is complete and documented.
fn data_source_to_evidence_type(ds: &GroundingDataSource) -> Option<EvidenceType> {
    match ds {
        GroundingDataSource::Patterns => Some(EvidenceType::PatternConfidence),
        GroundingDataSource::Conventions => Some(EvidenceType::PatternOccurrence),
        GroundingDataSource::Constraints => Some(EvidenceType::ConstraintVerification),
        GroundingDataSource::Coupling => Some(EvidenceType::CouplingMetric),
        GroundingDataSource::Dna => Some(EvidenceType::DnaHealth),
        GroundingDataSource::TestTopology => Some(EvidenceType::TestCoverage),
        GroundingDataSource::ErrorHandling => Some(EvidenceType::ErrorHandlingGaps),
        GroundingDataSource::Decisions => Some(EvidenceType::DecisionEvidence),
        GroundingDataSource::Boundaries => Some(EvidenceType::BoundaryData),
        GroundingDataSource::Taint => Some(EvidenceType::TaintAnalysis),
        GroundingDataSource::CallGraph => Some(EvidenceType::CallGraphCoverage),
        GroundingDataSource::Security => Some(EvidenceType::FalsePositiveRate),
    }
}

#[test]
fn cq_t02_all_12_data_sources_have_evidence_type() {
    // Every GroundingDataSource must map to an EvidenceType
    for ds in GroundingDataSource::ALL.iter() {
        let et = data_source_to_evidence_type(ds);
        assert!(
            et.is_some(),
            "GroundingDataSource::{:?} has no corresponding EvidenceType",
            ds
        );
    }
}

#[test]
fn cq_t02_data_source_count_matches_evidence_type_count() {
    assert_eq!(
        GroundingDataSource::ALL.len(),
        EvidenceType::ALL.len(),
        "GroundingDataSource count ({}) must equal EvidenceType count ({})",
        GroundingDataSource::ALL.len(),
        EvidenceType::ALL.len(),
    );
}

#[test]
fn cq_t02_evidence_type_weights_sum_to_one() {
    let total: f64 = EvidenceType::ALL.iter().map(|t| t.default_weight()).sum();
    assert!(
        (total - 1.0).abs() < 1e-10,
        "Evidence type weights must sum to 1.0, got {}",
        total
    );
}

#[test]
fn cq_t02_all_evidence_types_have_nonzero_weight() {
    for et in EvidenceType::ALL {
        assert!(
            et.default_weight() > 0.0,
            "EvidenceType::{:?} must have non-zero weight",
            et
        );
    }
}

#[test]
fn cq_t02_mapping_covers_all_evidence_types() {
    // Verify every EvidenceType is reachable from some GroundingDataSource
    let mapped: std::collections::HashSet<EvidenceType> = GroundingDataSource::ALL
        .iter()
        .filter_map(data_source_to_evidence_type)
        .collect();

    for et in EvidenceType::ALL {
        assert!(
            mapped.contains(&et),
            "EvidenceType::{:?} is not mapped from any GroundingDataSource",
            et
        );
    }
}
