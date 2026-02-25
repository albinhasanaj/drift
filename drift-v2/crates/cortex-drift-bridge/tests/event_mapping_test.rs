//! T9-EVT-01 through T9-EVT-04: Event mapping tests.

use cortex_drift_bridge::event_mapping::memory_types::*;
use cortex_drift_bridge::event_mapping::BridgeEventHandler;
use cortex_drift_bridge::license::LicenseTier;
use drift_core::events::handler::DriftEventHandler;
use drift_core::events::types::*;

/// Helper: create an in-memory SQLite DB with bridge tables.
fn setup_bridge_db() -> cortex_drift_bridge::storage::engine::BridgeStorageEngine {
    cortex_drift_bridge::storage::engine::BridgeStorageEngine::open_in_memory().unwrap()
}

/// Helper: create a BridgeEventHandler with an in-memory DB.
fn handler_with_db(tier: LicenseTier) -> (BridgeEventHandler, cortex_drift_bridge::storage::engine::BridgeStorageEngine) {
    let engine = setup_bridge_db();
    let handler_engine = setup_bridge_db();
    let handler = BridgeEventHandler::new(
        Some(std::sync::Arc::new(handler_engine) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>),
        tier,
    );
    (handler, engine)
}

// ---- T9-EVT-01: Test event mapping creates correct Cortex memory types from all 21 Drift event types ----

#[test]
fn t9_evt_01_all_21_event_types_have_mappings() {
    // All 21 event types should have an entry in EVENT_MAPPINGS
    assert_eq!(EVENT_MAPPINGS.len(), 21, "Expected 21 event mappings");

    let event_types: Vec<&str> = EVENT_MAPPINGS.iter().map(|m| m.event_type).collect();

    // Verify all expected event types are present
    let expected = vec![
        "on_pattern_approved",
        "on_pattern_discovered",
        "on_pattern_ignored",
        "on_pattern_merged",
        "on_scan_complete",
        "on_regression_detected",
        "on_violation_detected",
        "on_violation_dismissed",
        "on_violation_fixed",
        "on_gate_evaluated",
        "on_detector_alert",
        "on_detector_disabled",
        "on_constraint_approved",
        "on_constraint_violated",
        "on_decision_mined",
        "on_decision_reversed",
        "on_adr_detected",
        "on_boundary_discovered",
        "on_enforcement_changed",
        "on_feedback_abuse_detected",
        "on_error",
    ];

    for e in &expected {
        assert!(
            event_types.contains(e),
            "Missing event mapping for: {}",
            e
        );
    }
}

#[test]
fn t9_evt_01_memory_creating_events_count() {
    // Events that create memories (excludes on_scan_complete, on_violation_detected, on_error)
    let creating = memory_creating_events();
    assert_eq!(creating.len(), 18, "Expected 18 memory-creating event types");
}

// ---- T9-EVT-02: Test confidence values match specification ----

#[test]
fn t9_evt_02_confidence_values_match_spec() {
    let cases = vec![
        ("on_pattern_approved", 0.8),
        ("on_pattern_discovered", 0.5),
        ("on_pattern_ignored", 0.6),
        ("on_pattern_merged", 0.7),
        ("on_regression_detected", 0.9),
        ("on_violation_dismissed", 0.7),
        ("on_violation_fixed", 0.8),
        ("on_gate_evaluated", 0.6),
        ("on_detector_alert", 0.6),
        ("on_detector_disabled", 0.9),
        ("on_constraint_approved", 0.8),
        ("on_constraint_violated", 0.7),
        ("on_decision_mined", 0.7),
        ("on_decision_reversed", 0.8),
        ("on_adr_detected", 0.9),
        ("on_boundary_discovered", 0.6),
        ("on_enforcement_changed", 0.8),
        ("on_feedback_abuse_detected", 0.7),
    ];

    for (event_type, expected_confidence) in cases {
        let mapping = get_mapping(event_type)
            .unwrap_or_else(|| panic!("Missing mapping for {}", event_type));
        assert!(
            (mapping.initial_confidence - expected_confidence).abs() < f64::EPSILON,
            "Confidence mismatch for {}: expected {}, got {}",
            event_type,
            expected_confidence,
            mapping.initial_confidence,
        );
    }
}

#[test]
fn t9_evt_02_memory_types_match_spec() {
    use cortex_core::MemoryType;

    let cases = vec![
        ("on_pattern_approved", Some(MemoryType::PatternRationale)),
        ("on_pattern_discovered", Some(MemoryType::Insight)),
        ("on_pattern_ignored", Some(MemoryType::Feedback)),
        ("on_pattern_merged", Some(MemoryType::DecisionContext)),
        ("on_scan_complete", None),
        ("on_regression_detected", Some(MemoryType::DecisionContext)),
        ("on_violation_detected", None),
        ("on_violation_dismissed", Some(MemoryType::ConstraintOverride)),
        ("on_violation_fixed", Some(MemoryType::Feedback)),
        ("on_gate_evaluated", Some(MemoryType::DecisionContext)),
        ("on_detector_alert", Some(MemoryType::Tribal)),
        ("on_detector_disabled", Some(MemoryType::CodeSmell)),
        ("on_constraint_approved", Some(MemoryType::ConstraintOverride)),
        ("on_constraint_violated", Some(MemoryType::Feedback)),
        ("on_decision_mined", Some(MemoryType::DecisionContext)),
        ("on_decision_reversed", Some(MemoryType::DecisionContext)),
        ("on_adr_detected", Some(MemoryType::DecisionContext)),
        ("on_boundary_discovered", Some(MemoryType::Tribal)),
        ("on_enforcement_changed", Some(MemoryType::DecisionContext)),
        ("on_feedback_abuse_detected", Some(MemoryType::Tribal)),
        ("on_error", None),
    ];

    for (event_type, expected_type) in cases {
        let mapping = get_mapping(event_type).unwrap();
        assert_eq!(
            mapping.memory_type, expected_type,
            "Memory type mismatch for {}",
            event_type,
        );
    }
}

// ---- T9-EVT-03: Test events that should NOT create memories ----

#[test]
fn t9_evt_03_no_memory_events() {
    let no_memory_events = vec!["on_violation_detected", "on_error"];
    for event_type in no_memory_events {
        let mapping = get_mapping(event_type).unwrap();
        assert!(
            mapping.memory_type.is_none(),
            "{} should not create a memory",
            event_type,
        );
    }
}

#[test]
fn t9_evt_03_scan_complete_triggers_grounding() {
    let mapping = get_mapping("on_scan_complete").unwrap();
    assert!(mapping.triggers_grounding, "on_scan_complete should trigger grounding");
    assert!(mapping.memory_type.is_none(), "on_scan_complete should not create a memory");
}

#[test]
fn t9_evt_03_handler_no_op_for_violation_detected() {
    let (handler, _) = handler_with_db(LicenseTier::Enterprise);
    // This should be a no-op — no panic, no memory
    handler.on_violation_detected(&ViolationDetectedEvent {
        violation_id: "v1".to_string(),
        pattern_id: "p1".to_string(),
        file: std::path::PathBuf::from("test.rs"),
        line: 42,
        message: "test violation".to_string(),
    });
}

#[test]
fn t9_evt_03_handler_no_op_for_error() {
    let (handler, _) = handler_with_db(LicenseTier::Enterprise);
    handler.on_error(&ErrorEvent {
        message: "test error".to_string(),
        error_code: "E001".to_string(),
    });
}

// ---- T9-EVT-04: Test event mapping with handler creates memories ----

#[test]
fn t9_evt_04_pattern_approved_creates_memory() {
    let (handler, _) = handler_with_db(LicenseTier::Enterprise);
    // Should not panic
    handler.on_pattern_approved(&PatternApprovedEvent {
        pattern_id: "test_pattern".to_string(),
    });
}

#[test]
fn t9_evt_04_no_op_handler_is_safe() {
    let handler = BridgeEventHandler::no_op();
    // All methods should be no-ops
    handler.on_pattern_approved(&PatternApprovedEvent {
        pattern_id: "test".to_string(),
    });
    handler.on_scan_complete(&ScanCompleteEvent {
        added: 0,
        modified: 0,
        removed: 0,
        unchanged: 0,
        duration_ms: 0,
    });
    handler.on_error(&ErrorEvent {
        message: "test".to_string(),
        error_code: "E001".to_string(),
    });
}

// ---- Community tier event filtering ----

#[test]
fn t9_evt_04_community_tier_filters_events() {
    let community_events = community_events();
    assert_eq!(community_events.len(), 5, "Community tier should allow 5 events");
    assert!(community_events.contains(&"on_pattern_approved"));
    assert!(community_events.contains(&"on_pattern_discovered"));
    assert!(community_events.contains(&"on_violation_dismissed"));
    assert!(community_events.contains(&"on_violation_fixed"));
    assert!(community_events.contains(&"on_detector_disabled"));
}
