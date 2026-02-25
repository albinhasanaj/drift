//! Phase D3 tests — TTD3-05 through TTD3-06: Epistemic promotion via validation.

use chrono::Utc;
use cortex_core::memory::base::TypedContent;
use cortex_core::memory::types::SemanticContent;
use cortex_core::memory::{BaseMemory, Confidence, Importance, MemoryType};
use cortex_core::models::EpistemicStatus;
use cortex_validation::engine::{ValidationConfig, ValidationEngine};

fn make_memory(id: &str, summary: &str) -> BaseMemory {
    let content = TypedContent::Semantic(SemanticContent {
        knowledge: summary.to_string(),
        source_episodes: vec![],
        consolidation_confidence: 0.8,
    });
    let content_hash = BaseMemory::compute_content_hash(&content).unwrap();
    BaseMemory {
        id: id.to_string(),
        memory_type: MemoryType::Semantic,
        content,
        summary: summary.to_string(),
        transaction_time: Utc::now(),
        valid_time: Utc::now(),
        valid_until: None,
        confidence: Confidence::new(0.8),
        importance: Importance::Normal,
        last_accessed: Utc::now(),
        access_count: 0,
        linked_patterns: vec![],
        linked_constraints: vec![],
        linked_files: vec![],
        linked_functions: vec![],
        tags: vec![],
        archived: false,
        superseded_by: None,
        supersedes: None,
        content_hash,
        namespace: Default::default(),
        source_agent: Default::default(),
    }
}

// ─── TTD3-05: Validation promotes epistemic status ───────────────────────────

#[test]
fn ttd3_05_validation_promotes_conjecture_to_provisional() {
    let engine = ValidationEngine::default();
    let mem = make_memory("ep1", "Test memory for epistemic promotion");

    // Validate the memory — should pass (fresh, no contradictions, etc.).
    let result = engine.validate_basic(&mem, &[]).unwrap();
    assert!(result.passed, "Fresh memory should pass validation");

    // Now promote epistemic status.
    let current_status = EpistemicStatus::Conjecture {
        source: "agent:coder".into(),
        created_at: Utc::now(),
    };

    let new_status = engine.promote_epistemic_status(&current_status, result.passed, false);
    assert!(new_status.is_some(), "Should promote on validation pass");

    let promoted = new_status.unwrap();
    assert_eq!(
        promoted.variant_name(),
        "provisional",
        "Conjecture should be promoted to Provisional"
    );

    // Verify the Provisional metadata.
    match promoted {
        EpistemicStatus::Provisional { evidence_count, .. } => {
            assert_eq!(evidence_count, 1);
        }
        _ => panic!("Expected Provisional status"),
    }
}

// ─── TTD3-06: Validation does not demote on failure ──────────────────────────

#[test]
fn ttd3_06_validation_does_not_demote_on_failure() {
    let engine = ValidationEngine::default();

    // Test: Provisional memory fails validation → stays Provisional.
    let provisional_status = EpistemicStatus::Provisional {
        evidence_count: 3,
        last_validated: Utc::now(),
    };

    let new_status = engine.promote_epistemic_status(&provisional_status, false, false);
    assert!(
        new_status.is_none(),
        "Failed validation should NOT change epistemic status"
    );

    // Test: Verified memory fails validation → stays Verified.
    let verified_status = EpistemicStatus::Verified {
        verified_by: vec!["user:alice".into()],
        verified_at: Utc::now(),
        evidence_refs: vec!["ref1".into()],
    };

    let new_status = engine.promote_epistemic_status(&verified_status, false, false);
    assert!(
        new_status.is_none(),
        "Failed validation should NOT demote Verified status"
    );

    // Test: Conjecture memory fails validation → stays Conjecture.
    let conjecture_status = EpistemicStatus::Conjecture {
        source: "agent".into(),
        created_at: Utc::now(),
    };

    let new_status = engine.promote_epistemic_status(&conjecture_status, false, false);
    assert!(
        new_status.is_none(),
        "Failed validation should NOT change Conjecture status"
    );
}

// ─── Additional: Provisional → Verified on user confirmation ─────────────────

#[test]
fn validation_promotes_provisional_to_verified_on_confirmation() {
    let engine = ValidationEngine::default();

    let provisional_status = EpistemicStatus::Provisional {
        evidence_count: 5,
        last_validated: Utc::now(),
    };

    // Pass validation + user confirmation → Verified.
    let new_status = engine.promote_epistemic_status(&provisional_status, true, true);
    assert!(new_status.is_some(), "Should promote to Verified on confirmation");

    let promoted = new_status.unwrap();
    assert_eq!(promoted.variant_name(), "verified");
}

// ─── Additional: Auto-promote disabled ───────────────────────────────────────

#[test]
fn validation_no_promotion_when_auto_promote_disabled() {
    let engine = ValidationEngine::new(ValidationConfig {
        epistemic_auto_promote: false,
        ..Default::default()
    });

    let conjecture_status = EpistemicStatus::Conjecture {
        source: "agent".into(),
        created_at: Utc::now(),
    };

    let new_status = engine.promote_epistemic_status(&conjecture_status, true, false);
    assert!(
        new_status.is_none(),
        "Should NOT promote when auto_promote is disabled"
    );
}

// ─── Additional: Temporal consistency check ──────────────────────────────────

#[test]
fn temporal_consistency_detects_future_references() {
    use chrono::Duration;
    use cortex_validation::dimensions::temporal;

    let mut mem = make_memory("ref-test", "Memory with future reference");
    mem.transaction_time = Utc::now() - Duration::days(10);
    mem.supersedes = Some("future-mem".to_string());

    // The referenced memory was created AFTER this memory.
    let ref_checker = |id: &str| -> Option<chrono::DateTime<Utc>> {
        if id == "future-mem" {
            Some(Utc::now()) // Created now, but referencing memory was created 10 days ago.
        } else {
            None
        }
    };

    let result = temporal::validate_with_references(&mem, Utc::now(), &ref_checker);
    assert!(
        !result.temporally_consistent,
        "Should detect temporal inconsistency"
    );
    assert!(
        result.healing_actions.iter().any(|a| a.description.contains("Temporal inconsistency")),
        "Should have temporal inconsistency healing action"
    );
}

#[test]
fn temporal_consistency_passes_for_valid_references() {
    use chrono::Duration;
    use cortex_validation::dimensions::temporal;

    let mut mem = make_memory("ref-ok", "Memory with valid reference");
    mem.transaction_time = Utc::now();
    mem.supersedes = Some("old-mem".to_string());

    // The referenced memory was created BEFORE this memory.
    let ref_checker = |id: &str| -> Option<chrono::DateTime<Utc>> {
        if id == "old-mem" {
            Some(Utc::now() - Duration::days(30))
        } else {
            None
        }
    };

    let result = temporal::validate_with_references(&mem, Utc::now(), &ref_checker);
    assert!(
        result.temporally_consistent,
        "Should be temporally consistent"
    );
}
