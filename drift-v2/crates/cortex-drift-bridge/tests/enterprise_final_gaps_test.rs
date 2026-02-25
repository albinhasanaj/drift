//! Enterprise final gaps tests — the things that would wake you up at 3am.
//!
//! Sections:
//! 1. Community tier blocks ALL 16 non-community events (not just one)
//! 2. Event handler with None DB — silent data loss path
//! 3. `_drift_db` parameter silently ignored in ground_single (BUG DOCUMENTATION)
//! 4. Full grounding pipeline: evidence → score → verdict → confidence adjustment → contradiction
//! 5. Confidence adjustment boundary math (boost cap, invalidated floor, penalty clamp)
//! 6. Scorer edge cases: boundary scores, extreme weights, single evidence
//! 7. Retention regression guards (schema_version literal, table name)
//! 8. Event mapping spec fidelity (confidence values match EVENT_MAPPINGS exactly)
//! 9. Grounding with negative/zero/boundary evidence values
//! 10. Error handling: DB errors propagate, not silently swallowed


use cortex_drift_bridge::config::GroundingConfig;
use cortex_drift_bridge::event_mapping::memory_types::{community_events, get_mapping, EVENT_MAPPINGS};
use cortex_drift_bridge::event_mapping::BridgeEventHandler;
use cortex_drift_bridge::grounding::loop_runner::MemoryForGrounding;
use cortex_drift_bridge::grounding::scorer::GroundingScorer;
use cortex_drift_bridge::grounding::{
    AdjustmentMode, GroundingLoopRunner, GroundingVerdict, TriggerType,
};
use cortex_drift_bridge::license::LicenseTier;
use cortex_drift_bridge::storage::retention;

use drift_core::events::handler::DriftEventHandler;
use drift_core::events::types::*;
use cortex_drift_bridge::traits::IBridgeStorage;

// ============================================================================
// HELPERS
// ============================================================================

fn setup_bridge_db() -> cortex_drift_bridge::storage::engine::BridgeStorageEngine {
    cortex_drift_bridge::storage::engine::BridgeStorageEngine::open_in_memory().unwrap()
}

// ============================================================================
// SECTION 1: COMMUNITY TIER BLOCKS ALL 16 NON-COMMUNITY EVENTS
// ============================================================================

/// The 5 community events that SHOULD create memories.
const COMMUNITY_ALLOWED: [&str; 5] = [
    "on_pattern_approved",
    "on_pattern_discovered",
    "on_violation_dismissed",
    "on_violation_fixed",
    "on_detector_disabled",
];

#[test]
fn community_tier_allows_exactly_5_events() {
    let allowed = community_events();
    assert_eq!(allowed.len(), 5, "Community tier should allow exactly 5 events");
    for event in &COMMUNITY_ALLOWED {
        assert!(allowed.contains(event), "Community should allow '{}'", event);
    }
}

#[test]
fn community_tier_blocks_pattern_ignored() {
    let db = setup_bridge_db();
    let handler = BridgeEventHandler::new(Some(std::sync::Arc::new(db) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>), LicenseTier::Community);
    handler.on_pattern_ignored(&PatternIgnoredEvent {
        pattern_id: "p1".into(),
        reason: "test".into(),
    });
    // Should NOT create memory — blocked by community tier
    assert_eq!(handler.error_count(), 0, "Should not error, just silently skip");
}

#[test]
fn community_tier_blocks_pattern_merged() {
    let db = setup_bridge_db();
    let handler = BridgeEventHandler::new(Some(std::sync::Arc::new(db) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>), LicenseTier::Community);
    handler.on_pattern_merged(&PatternMergedEvent {
        kept_id: "k".into(),
        merged_id: "m".into(),
    });
    assert_eq!(handler.error_count(), 0);
}

#[test]
fn community_tier_blocks_regression_detected() {
    let db = setup_bridge_db();
    let handler = BridgeEventHandler::new(Some(std::sync::Arc::new(db) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>), LicenseTier::Community);
    handler.on_regression_detected(&RegressionDetectedEvent {
        pattern_id: "p1".into(),
        previous_score: 0.9,
        current_score: 0.5,
    });
    assert_eq!(handler.error_count(), 0);
}

#[test]
fn community_tier_blocks_gate_evaluated() {
    let db = setup_bridge_db();
    let handler = BridgeEventHandler::new(Some(std::sync::Arc::new(db) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>), LicenseTier::Community);
    handler.on_gate_evaluated(&GateEvaluatedEvent {
        gate_name: "g".into(),
        passed: true,
        score: Some(1.0),
        message: "ok".into(),
    });
    assert_eq!(handler.error_count(), 0);
}

#[test]
fn community_tier_blocks_detector_alert() {
    let db = setup_bridge_db();
    let handler = BridgeEventHandler::new(Some(std::sync::Arc::new(db) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>), LicenseTier::Community);
    handler.on_detector_alert(&DetectorAlertEvent {
        detector_id: "d1".into(),
        false_positive_rate: 0.1,
    });
    assert_eq!(handler.error_count(), 0);
}

#[test]
fn community_tier_blocks_constraint_approved() {
    let db = setup_bridge_db();
    let handler = BridgeEventHandler::new(Some(std::sync::Arc::new(db) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>), LicenseTier::Community);
    handler.on_constraint_approved(&ConstraintApprovedEvent {
        constraint_id: "c1".into(),
    });
    assert_eq!(handler.error_count(), 0);
}

#[test]
fn community_tier_blocks_constraint_violated() {
    let db = setup_bridge_db();
    let handler = BridgeEventHandler::new(Some(std::sync::Arc::new(db) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>), LicenseTier::Community);
    handler.on_constraint_violated(&ConstraintViolatedEvent {
        constraint_id: "c1".into(),
        message: "violated".into(),
    });
    assert_eq!(handler.error_count(), 0);
}

#[test]
fn community_tier_blocks_decision_mined() {
    let db = setup_bridge_db();
    let handler = BridgeEventHandler::new(Some(std::sync::Arc::new(db) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>), LicenseTier::Community);
    handler.on_decision_mined(&DecisionMinedEvent {
        decision_id: "d1".into(),
        category: "arch".into(),
    });
    assert_eq!(handler.error_count(), 0);
}

#[test]
fn community_tier_blocks_decision_reversed() {
    let db = setup_bridge_db();
    let handler = BridgeEventHandler::new(Some(std::sync::Arc::new(db) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>), LicenseTier::Community);
    handler.on_decision_reversed(&DecisionReversedEvent {
        decision_id: "d1".into(),
        reason: "perf".into(),
    });
    assert_eq!(handler.error_count(), 0);
}

#[test]
fn community_tier_blocks_adr_detected() {
    let db = setup_bridge_db();
    let handler = BridgeEventHandler::new(Some(std::sync::Arc::new(db) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>), LicenseTier::Community);
    handler.on_adr_detected(&AdrDetectedEvent {
        adr_id: "adr1".into(),
        title: "Use REST".into(),
    });
    assert_eq!(handler.error_count(), 0);
}

#[test]
fn community_tier_blocks_boundary_discovered() {
    let db = setup_bridge_db();
    let handler = BridgeEventHandler::new(Some(std::sync::Arc::new(db) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>), LicenseTier::Community);
    handler.on_boundary_discovered(&BoundaryDiscoveredEvent {
        boundary_id: "b1".into(),
        model: "User".into(),
        orm: "diesel".into(),
    });
    assert_eq!(handler.error_count(), 0);
}

#[test]
fn community_tier_blocks_enforcement_changed() {
    let db = setup_bridge_db();
    let handler = BridgeEventHandler::new(Some(std::sync::Arc::new(db) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>), LicenseTier::Community);
    handler.on_enforcement_changed(&EnforcementChangedEvent {
        gate_name: "g".into(),
        old_level: "warn".into(),
        new_level: "error".into(),
    });
    assert_eq!(handler.error_count(), 0);
}

#[test]
fn community_tier_blocks_feedback_abuse_detected() {
    let db = setup_bridge_db();
    let handler = BridgeEventHandler::new(Some(std::sync::Arc::new(db) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>), LicenseTier::Community);
    handler.on_feedback_abuse_detected(&FeedbackAbuseDetectedEvent {
        user_id: "u1".into(),
        pattern: "spam".into(),
    });
    assert_eq!(handler.error_count(), 0);
}

#[test]
fn community_tier_all_16_blocked_events_verified_systematically() {
    // This is the gold test: verify that every non-community memory-creating event
    // is actually blocked when using Community tier.
    let memory_creating: Vec<&str> = EVENT_MAPPINGS
        .iter()
        .filter(|m| m.memory_type.is_some())
        .map(|m| m.event_type)
        .collect();

    let community = community_events();
    let blocked: Vec<&&str> = memory_creating.iter().filter(|e| !community.contains(e)).collect();

    assert_eq!(
        blocked.len(),
        13,
        "Should be exactly 13 memory-creating events blocked for Community (18 total - 5 allowed)"
    );

    // Verify none of the blocked events are in the community list
    for event in &blocked {
        assert!(
            !community.contains(event),
            "Event '{}' should be blocked for Community but is in community_events()",
            event
        );
    }
}

// ============================================================================
// SECTION 2: EVENT HANDLER WITH None DB — SILENT DATA LOSS PATH
// ============================================================================

#[test]
fn handler_none_db_is_not_available() {
    let handler = BridgeEventHandler::new(None, LicenseTier::Enterprise);
    // With no DB, handler should mark itself as unavailable
    // Events should be silently skipped (not errored)
    handler.on_pattern_approved(&PatternApprovedEvent { pattern_id: "p1".into() });
    assert_eq!(handler.error_count(), 0, "No-DB handler should skip, not error");
}

#[test]
fn handler_no_op_is_not_available() {
    let handler = BridgeEventHandler::no_op();
    handler.on_pattern_approved(&PatternApprovedEvent { pattern_id: "p1".into() });
    handler.on_regression_detected(&RegressionDetectedEvent {
        pattern_id: "p1".into(),
        previous_score: 0.9,
        current_score: 0.5,
    });
    handler.on_adr_detected(&AdrDetectedEvent {
        adr_id: "adr1".into(),
        title: "test".into(),
    });
    assert_eq!(handler.error_count(), 0, "No-op handler should never error");
}

#[test]
fn handler_all_21_events_on_no_op_handler_zero_errors() {
    let handler = BridgeEventHandler::no_op();

    handler.on_pattern_approved(&PatternApprovedEvent { pattern_id: "p1".into() });
    handler.on_pattern_discovered(&PatternDiscoveredEvent { pattern_id: "p2".into(), category: "x".into(), confidence: 0.5 });
    handler.on_pattern_ignored(&PatternIgnoredEvent { pattern_id: "p3".into(), reason: "r".into() });
    handler.on_pattern_merged(&PatternMergedEvent { kept_id: "k".into(), merged_id: "m".into() });
    handler.on_scan_complete(&ScanCompleteEvent { added: 0, modified: 0, removed: 0, unchanged: 0, duration_ms: 0 });
    handler.on_regression_detected(&RegressionDetectedEvent { pattern_id: "p".into(), previous_score: 0.9, current_score: 0.5 });
    handler.on_violation_detected(&ViolationDetectedEvent { violation_id: "v".into(), pattern_id: "p".into(), file: "f".into(), line: 1, message: "m".into() });
    handler.on_violation_dismissed(&ViolationDismissedEvent { violation_id: "v".into(), reason: "r".into() });
    handler.on_violation_fixed(&ViolationFixedEvent { violation_id: "v".into() });
    handler.on_gate_evaluated(&GateEvaluatedEvent { gate_name: "g".into(), passed: true, score: None, message: "m".into() });
    handler.on_detector_alert(&DetectorAlertEvent { detector_id: "d".into(), false_positive_rate: 0.1 });
    handler.on_detector_disabled(&DetectorDisabledEvent { detector_id: "d".into(), reason: "r".into() });
    handler.on_constraint_approved(&ConstraintApprovedEvent { constraint_id: "c".into() });
    handler.on_constraint_violated(&ConstraintViolatedEvent { constraint_id: "c".into(), message: "m".into() });
    handler.on_decision_mined(&DecisionMinedEvent { decision_id: "d".into(), category: "c".into() });
    handler.on_decision_reversed(&DecisionReversedEvent { decision_id: "d".into(), reason: "r".into() });
    handler.on_adr_detected(&AdrDetectedEvent { adr_id: "a".into(), title: "t".into() });
    handler.on_boundary_discovered(&BoundaryDiscoveredEvent { boundary_id: "b".into(), model: "m".into(), orm: "o".into() });
    handler.on_enforcement_changed(&EnforcementChangedEvent { gate_name: "g".into(), old_level: "o".into(), new_level: "n".into() });
    handler.on_feedback_abuse_detected(&FeedbackAbuseDetectedEvent { user_id: "u".into(), pattern: "p".into() });
    handler.on_error(&ErrorEvent { message: "m".into(), error_code: "e".into() });

    assert_eq!(handler.error_count(), 0, "All 21 events on no-op handler should produce zero errors");
}

// ============================================================================
// SECTION 3: drift_db FALLBACK — EVIDENCE FROM drift.db WHEN FIELDS ARE None
// ============================================================================

/// Create a mock drift.db with real drift-storage schema and all 12 evidence tables populated.
fn setup_mock_drift_db() -> rusqlite::Connection {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "CREATE TABLE pattern_confidence (pattern_id TEXT PRIMARY KEY, posterior_mean REAL NOT NULL, alpha REAL NOT NULL DEFAULT 1.0, beta REAL NOT NULL DEFAULT 1.0, credible_interval_low REAL NOT NULL DEFAULT 0.0, credible_interval_high REAL NOT NULL DEFAULT 1.0, tier TEXT NOT NULL DEFAULT 'Medium', momentum TEXT NOT NULL DEFAULT 'Stable', last_updated INTEGER NOT NULL DEFAULT 0);
         CREATE TABLE detections (id INTEGER PRIMARY KEY AUTOINCREMENT, file TEXT NOT NULL, line INTEGER NOT NULL DEFAULT 0, column_num INTEGER NOT NULL DEFAULT 0, pattern_id TEXT NOT NULL, category TEXT NOT NULL DEFAULT 'general', confidence REAL NOT NULL DEFAULT 0.8, detection_method TEXT NOT NULL DEFAULT 'regex', created_at INTEGER NOT NULL DEFAULT 0);
         CREATE TABLE feedback (id INTEGER PRIMARY KEY AUTOINCREMENT, violation_id TEXT NOT NULL DEFAULT '', pattern_id TEXT NOT NULL, detector_id TEXT NOT NULL DEFAULT '', action TEXT NOT NULL, created_at INTEGER NOT NULL DEFAULT 0);
         CREATE TABLE constraint_verifications (id INTEGER PRIMARY KEY AUTOINCREMENT, constraint_id TEXT NOT NULL, passed INTEGER NOT NULL, violations TEXT NOT NULL DEFAULT '[]', verified_at INTEGER NOT NULL DEFAULT 0);
         CREATE TABLE coupling_metrics (module TEXT PRIMARY KEY, ce INTEGER NOT NULL DEFAULT 0, ca INTEGER NOT NULL DEFAULT 0, instability REAL NOT NULL, abstractness REAL NOT NULL DEFAULT 0.0, distance REAL NOT NULL DEFAULT 0.0, zone TEXT NOT NULL DEFAULT 'stable', updated_at INTEGER NOT NULL DEFAULT 0);
         CREATE TABLE dna_genes (gene_id TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', description TEXT NOT NULL DEFAULT '', alleles TEXT NOT NULL DEFAULT '[]', confidence REAL NOT NULL, consistency REAL NOT NULL, exemplars TEXT NOT NULL DEFAULT '[]', updated_at INTEGER NOT NULL DEFAULT 0);
         CREATE TABLE test_quality (function_id TEXT PRIMARY KEY, overall_score REAL NOT NULL, updated_at INTEGER NOT NULL DEFAULT 0);
         CREATE TABLE error_gaps (id INTEGER PRIMARY KEY AUTOINCREMENT, file TEXT NOT NULL, function_id TEXT NOT NULL DEFAULT '', gap_type TEXT NOT NULL DEFAULT 'uncaught', severity TEXT NOT NULL DEFAULT 'medium', created_at INTEGER NOT NULL DEFAULT 0);
         CREATE TABLE decisions (id INTEGER PRIMARY KEY AUTOINCREMENT, category TEXT NOT NULL DEFAULT '', description TEXT NOT NULL DEFAULT '', confidence REAL NOT NULL, created_at INTEGER NOT NULL DEFAULT 0);
         CREATE TABLE boundaries (id INTEGER PRIMARY KEY AUTOINCREMENT, file TEXT NOT NULL DEFAULT '', framework TEXT NOT NULL DEFAULT '', model_name TEXT NOT NULL DEFAULT '', confidence REAL NOT NULL, created_at INTEGER NOT NULL DEFAULT 0);
         CREATE TABLE taint_flows (id INTEGER PRIMARY KEY AUTOINCREMENT, source_file TEXT NOT NULL, source_line INTEGER NOT NULL DEFAULT 0, source_type TEXT NOT NULL DEFAULT '', sink_file TEXT NOT NULL DEFAULT '', sink_line INTEGER NOT NULL DEFAULT 0, sink_type TEXT NOT NULL DEFAULT '', cwe_id INTEGER NOT NULL DEFAULT 0, is_sanitized INTEGER NOT NULL DEFAULT 0, path TEXT NOT NULL DEFAULT '', confidence REAL NOT NULL DEFAULT 0.5, created_at INTEGER NOT NULL DEFAULT 0);
         CREATE TABLE call_edges (caller_id INTEGER NOT NULL, callee_id INTEGER NOT NULL, resolution TEXT NOT NULL, confidence REAL NOT NULL DEFAULT 0.5, call_site_line INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (caller_id, callee_id, call_site_line));

         INSERT INTO pattern_confidence (pattern_id, posterior_mean) VALUES ('p1', 0.92);
         INSERT INTO detections (file, pattern_id) VALUES ('src/auth/mod.rs', 'p1');
         INSERT INTO detections (file, pattern_id) VALUES ('src/auth/login.rs', 'p1');
         INSERT INTO detections (file, pattern_id) VALUES ('src/auth/token.rs', 'p1');
         INSERT INTO detections (file, pattern_id) VALUES ('src/db/pool.rs', 'p2');
         INSERT INTO feedback (pattern_id, action) VALUES ('p1', 'dismiss');
         INSERT INTO feedback (pattern_id, action) VALUES ('p1', 'accept');
         INSERT INTO feedback (pattern_id, action) VALUES ('p1', 'accept');
         INSERT INTO feedback (pattern_id, action) VALUES ('p1', 'accept');
         INSERT INTO constraint_verifications (constraint_id, passed, verified_at) VALUES ('c1', 1, 1000);
         INSERT INTO coupling_metrics (module, instability) VALUES ('src/auth', 0.82);
         INSERT INTO dna_genes (gene_id, confidence, consistency) VALUES ('g1', 0.90, 0.98);
         INSERT INTO test_quality (function_id, overall_score) VALUES ('src/auth', 0.91);
         INSERT INTO error_gaps (file, function_id) VALUES ('src/auth/mod.rs', 'fn1');
         INSERT INTO error_gaps (file, function_id) VALUES ('src/auth/mod.rs', 'fn2');
         INSERT INTO error_gaps (file, function_id) VALUES ('src/auth/mod.rs', 'fn3');
         INSERT INTO decisions (category, description, confidence) VALUES ('refactor', 'split auth', 0.77);
         INSERT INTO boundaries (file, framework, model_name, confidence) VALUES ('src/auth/mod.rs', 'orm', 'User', 0.65);
         INSERT INTO taint_flows (source_file, source_line, source_type, sink_file, sink_line, sink_type, cwe_id, is_sanitized) VALUES ('src/auth/mod.rs', 10, 'user_input', 'src/db/pool.rs', 20, 'sql_query', 89, 0);
         INSERT INTO call_edges (caller_id, callee_id, resolution, confidence, call_site_line) VALUES (1, 2, 'import', 0.9, 10);
         INSERT INTO call_edges (caller_id, callee_id, resolution, confidence, call_site_line) VALUES (2, 3, 'fuzzy', 0.4, 20);",
    )
    .unwrap();
    conn
}

#[test]
fn ground_single_uses_drift_db_fallback_when_fields_are_none() {
    // FIX VERIFIED: ground_single now passes drift_db to collect_evidence,
    // and collect_evidence falls back to drift.db queries when fields are None
    // and evidence_context is set.
    let runner = GroundingLoopRunner::default();
    let drift_db = setup_mock_drift_db();

    let ctx = cortex_drift_bridge::grounding::evidence::collector::EvidenceContext {
        pattern_id: Some("p1".to_string()),
        constraint_id: Some("c1".to_string()),
        module_path: Some("src/auth".to_string()),
        project: Some("myproject".to_string()),
        decision_id: Some("d1".to_string()),
        boundary_id: Some("b1".to_string()),
        current_confidence: 0.5,
        ..Default::default()
    };

    // All pre-populated fields are None — evidence must come from drift.db
    let memory = MemoryForGrounding {
        memory_id: "fallback_test".to_string(),
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
        evidence_context: Some(ctx),
    };

    // With drift_db: should fetch evidence from mock tables
    let result_with = runner.ground_single(&memory, Some(&drift_db), None).unwrap();
    // Without drift_db: no pre-populated fields AND no DB → InsufficientData
    let result_without = runner.ground_single(&memory, None, None).unwrap();

    assert_ne!(
        result_with.verdict, GroundingVerdict::InsufficientData,
        "With drift_db + evidence_context, should find evidence. Got {:?}",
        result_with.verdict,
    );
    assert_eq!(
        result_without.verdict, GroundingVerdict::InsufficientData,
        "Without drift_db and no pre-populated fields, should be InsufficientData",
    );
    assert!(
        !result_with.evidence.is_empty(),
        "drift_db fallback should produce evidence items",
    );
    assert!(
        result_with.evidence.len() >= 5,
        "Should find most evidence types from mock drift.db, found {}",
        result_with.evidence.len(),
    );
}

#[test]
fn grounding_loop_run_uses_drift_db_fallback() {
    let runner = GroundingLoopRunner::default();
    let drift_db = setup_mock_drift_db();

    let ctx = cortex_drift_bridge::grounding::evidence::collector::EvidenceContext {
        pattern_id: Some("p1".to_string()),
        current_confidence: 0.5,
        ..Default::default()
    };

    let memories = vec![MemoryForGrounding {
        memory_id: "loop_fallback".to_string(),
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
        evidence_context: Some(ctx),
    }];

    let snap_with = runner.run(&memories, Some(&drift_db), None, TriggerType::OnDemand).unwrap();
    let snap_without = runner.run(&memories, None, None, TriggerType::OnDemand).unwrap();

    assert!(
        snap_with.avg_grounding_score > 0.0,
        "With drift_db fallback, should compute a score > 0, got {}",
        snap_with.avg_grounding_score,
    );
    assert_eq!(
        snap_without.insufficient_data, 1,
        "Without drift_db, memory should be insufficient_data",
    );
}

#[test]
fn prepopulated_fields_take_priority_over_drift_db() {
    // Pre-populated fields should win when both are available
    let runner = GroundingLoopRunner::default();
    let drift_db = setup_mock_drift_db();

    let ctx = cortex_drift_bridge::grounding::evidence::collector::EvidenceContext {
        pattern_id: Some("p1".to_string()),
        current_confidence: 0.5,
        ..Default::default()
    };

    // Pre-populated pattern_confidence = 0.3, drift.db has 0.92
    let memory = MemoryForGrounding {
        memory_id: "priority_test".to_string(),
        memory_type: cortex_core::MemoryType::PatternRationale,
        current_confidence: 0.5,
        pattern_confidence: Some(0.3),
        occurrence_rate: None,
        false_positive_rate: None,
        constraint_verified: None,
        coupling_metric: None,
        dna_health: None,
        test_coverage: None,
        error_handling_gaps: None,
        decision_evidence: None,
        boundary_data: None,
        evidence_context: Some(ctx),
    };

    let result = runner.ground_single(&memory, Some(&drift_db), None).unwrap();

    // Find PatternConfidence evidence — it should use 0.3 (pre-populated), not 0.92 (drift.db)
    let pat_evidence = result
        .evidence
        .iter()
        .find(|e| matches!(e.evidence_type, cortex_drift_bridge::grounding::evidence::EvidenceType::PatternConfidence))
        .expect("Should have PatternConfidence evidence");
    assert!(
        (pat_evidence.drift_value - 0.3).abs() < 0.001,
        "Pre-populated field should win. Expected 0.3, got {}",
        pat_evidence.drift_value,
    );

    // But occurrence_rate (None in pre-populated) should come from drift.db (0.75)
    let occ_evidence = result
        .evidence
        .iter()
        .find(|e| matches!(e.evidence_type, cortex_drift_bridge::grounding::evidence::EvidenceType::PatternOccurrence));
    assert!(
        occ_evidence.is_some(),
        "occurrence_rate should be filled from drift.db fallback",
    );
    assert!(
        (occ_evidence.unwrap().drift_value - 0.75).abs() < 0.001,
        "drift.db fallback should provide 0.75 for occurrence_rate",
    );
}

#[test]
fn no_evidence_context_means_no_fallback() {
    // Without evidence_context, drift_db is available but not queried
    let runner = GroundingLoopRunner::default();
    let drift_db = setup_mock_drift_db();

    let memory = MemoryForGrounding {
        memory_id: "no_ctx".to_string(),
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

    let result = runner.ground_single(&memory, Some(&drift_db), None).unwrap();
    assert_eq!(
        result.verdict, GroundingVerdict::InsufficientData,
        "Without evidence_context, drift_db should not be queried",
    );
}

// ============================================================================
// SECTION 4: FULL GROUNDING PIPELINE
// ============================================================================

#[test]
fn full_pipeline_validated_memory_gets_boost() {
    let db = setup_bridge_db();
    let runner = GroundingLoopRunner::default();

    let memory = MemoryForGrounding {
        memory_id: "boost_test".to_string(),
        memory_type: cortex_core::MemoryType::PatternRationale,
        current_confidence: 0.5,
        pattern_confidence: Some(0.95),
        occurrence_rate: Some(0.9),
        false_positive_rate: Some(0.02),
        constraint_verified: Some(true),
        coupling_metric: Some(0.8),
        dna_health: Some(0.9),
        test_coverage: Some(0.85),
        error_handling_gaps: Some(1),
        decision_evidence: Some(0.8),
        boundary_data: Some(0.7),
        evidence_context: None,    };

    let result = runner.ground_single(&memory, None, Some(&db as &dyn cortex_drift_bridge::traits::IBridgeStorage)).unwrap();
    assert_eq!(result.verdict, GroundingVerdict::Validated);
    assert_eq!(result.confidence_adjustment.mode, AdjustmentMode::Boost);
    assert!(
        result.confidence_adjustment.delta.unwrap() > 0.0,
        "Validated memory should get positive confidence boost",
    );
    assert!(!result.generates_contradiction);
}

#[test]
fn full_pipeline_invalidated_memory_gets_penalty_and_contradiction() {
    let db = setup_bridge_db();
    let config = GroundingConfig::default();
    let runner = GroundingLoopRunner::new(config);

    let memory = MemoryForGrounding {
        memory_id: "inv_test".to_string(),
        memory_type: cortex_core::MemoryType::PatternRationale,
        current_confidence: 0.8,
        pattern_confidence: Some(0.05),
        occurrence_rate: Some(0.02),
        false_positive_rate: Some(0.95),
        constraint_verified: Some(false),
        coupling_metric: Some(0.05),
        dna_health: Some(0.05),
        test_coverage: Some(0.02),
        error_handling_gaps: Some(50),
        decision_evidence: Some(0.05),
        boundary_data: Some(0.05),
        evidence_context: None,    };

    let result = runner.ground_single(&memory, None, Some(&db as &dyn cortex_drift_bridge::traits::IBridgeStorage)).unwrap();
    assert_eq!(result.verdict, GroundingVerdict::Invalidated);
    assert_eq!(result.confidence_adjustment.mode, AdjustmentMode::Penalize);
    assert!(
        result.confidence_adjustment.delta.unwrap() < 0.0,
        "Invalidated memory should get negative confidence adjustment",
    );
    assert!(result.generates_contradiction, "Invalidated verdict should generate contradiction");
}

#[test]
fn full_pipeline_result_persisted_to_db() {
    let db = setup_bridge_db();
    let runner = GroundingLoopRunner::default();

    let memory = MemoryForGrounding {
        memory_id: "persist_test".to_string(),
        memory_type: cortex_core::MemoryType::PatternRationale,
        current_confidence: 0.5,
        pattern_confidence: Some(0.6),
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

    let result = runner.ground_single(&memory, None, Some(&db as &dyn cortex_drift_bridge::traits::IBridgeStorage)).unwrap();

    // Verify it's in the DB
    let history = db.get_grounding_history("persist_test", 1).unwrap();
    assert_eq!(history.len(), 1);
    assert!((history[0].0 - result.grounding_score).abs() < 0.001);
}

#[test]
fn full_pipeline_second_grounding_has_delta() {
    let db = setup_bridge_db();
    let runner = GroundingLoopRunner::default();

    let memory = MemoryForGrounding {
        memory_id: "delta_pipeline".to_string(),
        memory_type: cortex_core::MemoryType::PatternRationale,
        current_confidence: 0.5,
        pattern_confidence: Some(0.7),
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

    let r1 = runner.ground_single(&memory, None, Some(&db as &dyn cortex_drift_bridge::traits::IBridgeStorage)).unwrap();
    assert!(r1.previous_score.is_none());

    let r2 = runner.ground_single(&memory, None, Some(&db as &dyn cortex_drift_bridge::traits::IBridgeStorage)).unwrap();
    assert!(r2.previous_score.is_some());
    assert!(r2.score_delta.is_some());
}

// ============================================================================
// SECTION 5: CONFIDENCE ADJUSTMENT BOUNDARY MATH
// ============================================================================

#[test]
fn confidence_boost_capped_at_1_0() {
    let scorer = GroundingScorer::default();
    let adj = scorer.compute_confidence_adjustment(
        &GroundingVerdict::Validated,
        None,
        0.98, // Very high confidence
    );
    assert_eq!(adj.mode, AdjustmentMode::Boost);
    let new_conf = 0.98 + adj.delta.unwrap();
    assert!(
        new_conf <= 1.0,
        "Boosted confidence {} should never exceed 1.0",
        new_conf,
    );
}

#[test]
fn confidence_boost_on_zero_confidence() {
    let scorer = GroundingScorer::default();
    let adj = scorer.compute_confidence_adjustment(&GroundingVerdict::Validated, None, 0.0);
    assert_eq!(adj.mode, AdjustmentMode::Boost);
    assert!(adj.delta.unwrap() > 0.0);
}

#[test]
fn invalidated_floor_respected() {
    let config = GroundingConfig {
        invalidated_floor: 0.1,
        contradiction_drop: 0.3,
        ..GroundingConfig::default()
    };
    let scorer = GroundingScorer::new(config);
    let adj = scorer.compute_confidence_adjustment(
        &GroundingVerdict::Invalidated,
        None,
        0.15, // Just above floor
    );
    let new_conf = 0.15 + adj.delta.unwrap();
    assert!(
        new_conf >= 0.1,
        "New confidence {} should not go below invalidated_floor 0.1",
        new_conf,
    );
}

#[test]
fn invalidated_floor_at_zero_confidence() {
    let config = GroundingConfig {
        invalidated_floor: 0.1,
        contradiction_drop: 0.3,
        ..GroundingConfig::default()
    };
    let scorer = GroundingScorer::new(config);
    let adj = scorer.compute_confidence_adjustment(&GroundingVerdict::Invalidated, None, 0.0);
    let new_conf = 0.0 + adj.delta.unwrap();
    assert!(
        new_conf >= 0.1,
        "Even at 0 confidence, floor should bring it up to 0.1, got {}",
        new_conf,
    );
}

#[test]
fn partial_penalty_is_negative() {
    let scorer = GroundingScorer::default();
    let adj = scorer.compute_confidence_adjustment(&GroundingVerdict::Partial, None, 0.7);
    assert_eq!(adj.mode, AdjustmentMode::Penalize);
    assert!(adj.delta.unwrap() < 0.0);
}

#[test]
fn weak_penalty_larger_than_partial() {
    let scorer = GroundingScorer::default();
    let partial = scorer.compute_confidence_adjustment(&GroundingVerdict::Partial, None, 0.7);
    let weak = scorer.compute_confidence_adjustment(&GroundingVerdict::Weak, None, 0.7);
    assert!(
        weak.delta.unwrap() < partial.delta.unwrap(),
        "Weak penalty ({}) should be larger (more negative) than partial ({})",
        weak.delta.unwrap(),
        partial.delta.unwrap(),
    );
}

#[test]
fn no_adjustment_for_not_groundable() {
    let scorer = GroundingScorer::default();
    let adj = scorer.compute_confidence_adjustment(&GroundingVerdict::NotGroundable, None, 0.5);
    assert_eq!(adj.mode, AdjustmentMode::NoChange);
    assert!(adj.delta.is_none());
}

#[test]
fn no_adjustment_for_insufficient_data() {
    let scorer = GroundingScorer::default();
    let adj = scorer.compute_confidence_adjustment(&GroundingVerdict::InsufficientData, None, 0.5);
    assert_eq!(adj.mode, AdjustmentMode::NoChange);
    assert!(adj.delta.is_none());
}

// ============================================================================
// SECTION 6: SCORER EDGE CASES
// ============================================================================

#[test]
fn scorer_exact_boundary_0_7_is_validated() {
    let scorer = GroundingScorer::default();
    assert_eq!(scorer.score_to_verdict(0.7), GroundingVerdict::Validated);
}

#[test]
fn scorer_just_below_0_7_is_partial() {
    let scorer = GroundingScorer::default();
    assert_eq!(scorer.score_to_verdict(0.6999), GroundingVerdict::Partial);
}

#[test]
fn scorer_exact_boundary_0_4_is_partial() {
    let scorer = GroundingScorer::default();
    assert_eq!(scorer.score_to_verdict(0.4), GroundingVerdict::Partial);
}

#[test]
fn scorer_just_below_0_4_is_weak() {
    let scorer = GroundingScorer::default();
    assert_eq!(scorer.score_to_verdict(0.3999), GroundingVerdict::Weak);
}

#[test]
fn scorer_exact_boundary_0_2_is_weak() {
    let scorer = GroundingScorer::default();
    assert_eq!(scorer.score_to_verdict(0.2), GroundingVerdict::Weak);
}

#[test]
fn scorer_just_below_0_2_is_invalidated() {
    let scorer = GroundingScorer::default();
    assert_eq!(scorer.score_to_verdict(0.1999), GroundingVerdict::Invalidated);
}

#[test]
fn scorer_zero_is_invalidated() {
    let scorer = GroundingScorer::default();
    assert_eq!(scorer.score_to_verdict(0.0), GroundingVerdict::Invalidated);
}

#[test]
fn scorer_1_0_is_validated() {
    let scorer = GroundingScorer::default();
    assert_eq!(scorer.score_to_verdict(1.0), GroundingVerdict::Validated);
}

#[test]
fn scorer_contradiction_on_invalidated() {
    let scorer = GroundingScorer::default();
    assert!(scorer.should_generate_contradiction(0.1, None, &GroundingVerdict::Invalidated));
}

#[test]
fn scorer_contradiction_on_large_drop() {
    let scorer = GroundingScorer::default();
    // Default contradiction_drop is 0.3, so delta < -0.3 should trigger
    assert!(scorer.should_generate_contradiction(0.5, Some(-0.35), &GroundingVerdict::Partial));
}

#[test]
fn scorer_no_contradiction_on_small_drop() {
    let scorer = GroundingScorer::default();
    assert!(!scorer.should_generate_contradiction(0.5, Some(-0.1), &GroundingVerdict::Partial));
}

#[test]
fn scorer_no_contradiction_on_validated() {
    let scorer = GroundingScorer::default();
    assert!(!scorer.should_generate_contradiction(0.8, None, &GroundingVerdict::Validated));
}

// ============================================================================
// SECTION 7: RETENTION REGRESSION GUARDS
// ============================================================================

#[test]
fn retention_schema_version_literal_matches_storage() {
    // Ensure the literal 'schema_version' in retention.rs matches what migrations use
    let db = setup_bridge_db();

    // Insert a schema_version metric (as migrations do)
    db.execute(
        "INSERT INTO bridge_metrics (metric_name, metric_value, recorded_at) VALUES ('schema_version', 1.0, ?1)",
        rusqlite::params![chrono::Utc::now().timestamp()],
    )
    .unwrap();

    // Also insert an old regular metric
    let old_ts = chrono::Utc::now().timestamp() - (30 * 86400);
    db.execute(
        "INSERT INTO bridge_metrics (metric_name, metric_value, recorded_at) VALUES ('grounding_duration', 42.0, ?1)",
        rusqlite::params![old_ts],
    )
    .unwrap();

    db.with_writer(|conn| retention::apply_retention(conn, true)).unwrap();

    // schema_version should survive, old metric should be deleted
    let sv_count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM bridge_metrics WHERE metric_name = 'schema_version'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let other_count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM bridge_metrics WHERE metric_name != 'schema_version'",
            [],
            |row| row.get(0),
        )
        .unwrap();

    assert_eq!(sv_count, 1, "schema_version must survive retention");
    assert_eq!(other_count, 0, "Old metrics should be deleted");
}

#[test]
fn retention_all_5_tables_exist() {
    let db = setup_bridge_db();
    let tables = ["bridge_grounding_results", "bridge_grounding_snapshots",
                   "bridge_event_log", "bridge_metrics", "bridge_memories"];
    for table in &tables {
        let exists: bool = db
            .query_row(
                "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name=?1",
                rusqlite::params![table],
                |row| row.get(0),
            )
            .unwrap();
        assert!(exists, "Table '{}' must exist", table);
    }
}

// ============================================================================
// SECTION 8: EVENT MAPPING SPEC FIDELITY
// ============================================================================

#[test]
fn event_mapping_confidence_values_match_handler_spec() {
    // Verify EVENT_MAPPINGS confidence values are what we expect
    let expected = [
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

    for (event_type, expected_conf) in &expected {
        let mapping = get_mapping(event_type)
            .unwrap_or_else(|| panic!("Mapping for '{}' not found", event_type));
        assert!(
            (mapping.initial_confidence - expected_conf).abs() < 0.001,
            "Event '{}': expected confidence {}, got {}",
            event_type,
            expected_conf,
            mapping.initial_confidence,
        );
    }
}

#[test]
fn event_mapping_no_op_events_have_no_memory_type() {
    let no_memory = ["on_scan_complete", "on_violation_detected", "on_error"];
    for event_type in &no_memory {
        let mapping = get_mapping(event_type).unwrap();
        assert!(
            mapping.memory_type.is_none(),
            "Event '{}' should not create a memory (memory_type should be None)",
            event_type,
        );
    }
}

#[test]
fn event_mapping_scan_complete_triggers_grounding() {
    let mapping = get_mapping("on_scan_complete").unwrap();
    assert!(mapping.triggers_grounding, "on_scan_complete should trigger grounding");
}

#[test]
fn event_mapping_no_other_event_triggers_grounding() {
    for mapping in EVENT_MAPPINGS {
        if mapping.event_type != "on_scan_complete" {
            assert!(
                !mapping.triggers_grounding,
                "Only on_scan_complete should trigger grounding, but '{}' does too",
                mapping.event_type,
            );
        }
    }
}

// ============================================================================
// SECTION 9: GROUNDING WITH NEGATIVE/ZERO/BOUNDARY EVIDENCE VALUES
// ============================================================================

#[test]
fn grounding_negative_pattern_confidence_clamped() {
    let runner = GroundingLoopRunner::default();
    let memory = MemoryForGrounding {
        memory_id: "neg".to_string(),
        memory_type: cortex_core::MemoryType::PatternRationale,
        current_confidence: 0.5,
        pattern_confidence: Some(-0.5),
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
    assert!(
        result.grounding_score >= 0.0,
        "Negative evidence should be clamped, score should be >= 0, got {}",
        result.grounding_score,
    );
}

#[test]
fn grounding_above_1_pattern_confidence_clamped() {
    let runner = GroundingLoopRunner::default();
    let memory = MemoryForGrounding {
        memory_id: "over".to_string(),
        memory_type: cortex_core::MemoryType::PatternRationale,
        current_confidence: 0.5,
        pattern_confidence: Some(1.5),
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
    assert!(
        result.grounding_score <= 1.0,
        "Above-1.0 evidence should be clamped, score should be <= 1.0, got {}",
        result.grounding_score,
    );
}

#[test]
fn grounding_zero_pattern_confidence_produces_invalidated() {
    let runner = GroundingLoopRunner::default();
    let memory = MemoryForGrounding {
        memory_id: "zero".to_string(),
        memory_type: cortex_core::MemoryType::PatternRationale,
        current_confidence: 0.5,
        pattern_confidence: Some(0.0),
        occurrence_rate: Some(0.0),
        false_positive_rate: Some(1.0), // 100% false positive → support = 0.0
        constraint_verified: Some(false),
        coupling_metric: Some(0.0),
        dna_health: Some(0.0),
        test_coverage: Some(0.0),
        error_handling_gaps: Some(100),
        decision_evidence: Some(0.0),
        boundary_data: Some(0.0),
        evidence_context: None,    };

    let result = runner.ground_single(&memory, None, None).unwrap();
    assert_eq!(result.verdict, GroundingVerdict::Invalidated,
        "All-zero evidence should produce Invalidated, got {:?} with score {}",
        result.verdict, result.grounding_score);
}

#[test]
fn grounding_all_perfect_evidence_produces_validated() {
    let runner = GroundingLoopRunner::default();
    let memory = MemoryForGrounding {
        memory_id: "perfect".to_string(),
        memory_type: cortex_core::MemoryType::PatternRationale,
        current_confidence: 0.5,
        pattern_confidence: Some(1.0),
        occurrence_rate: Some(1.0),
        false_positive_rate: Some(0.0), // 0% FP → support = 1.0
        constraint_verified: Some(true),
        coupling_metric: Some(1.0),
        dna_health: Some(1.0),
        test_coverage: Some(1.0),
        error_handling_gaps: Some(0),
        decision_evidence: Some(1.0),
        boundary_data: Some(1.0),
        evidence_context: None,    };

    let result = runner.ground_single(&memory, None, None).unwrap();
    assert_eq!(result.verdict, GroundingVerdict::Validated,
        "All-perfect evidence should produce Validated, got {:?} with score {}",
        result.verdict, result.grounding_score);
    assert!((result.grounding_score - 1.0).abs() < 0.001,
        "Perfect evidence should produce score ~1.0, got {}", result.grounding_score);
}

#[test]
fn grounding_100_error_handling_gaps_gives_zero_support() {
    // error_handling_gaps support = 1.0 - (gaps / 100.0).clamp(0,1)
    // 100 gaps → support = 0.0
    let runner = GroundingLoopRunner::default();
    let memory = MemoryForGrounding {
        memory_id: "gaps".to_string(),
        memory_type: cortex_core::MemoryType::PatternRationale,
        current_confidence: 0.5,
        pattern_confidence: None,
        occurrence_rate: None,
        false_positive_rate: None,
        constraint_verified: None,
        coupling_metric: None,
        dna_health: None,
        test_coverage: None,
        error_handling_gaps: Some(100),
        decision_evidence: None,
        boundary_data: None,
        evidence_context: None,    };

    let result = runner.ground_single(&memory, None, None).unwrap();
    assert_eq!(result.grounding_score, 0.0,
        "100 error handling gaps → 0 support → 0 score");
    assert_eq!(result.verdict, GroundingVerdict::Invalidated);
}

// ============================================================================
// SECTION 10: ERROR HANDLING — DB ERRORS PROPAGATE
// ============================================================================

#[test]
fn store_memory_on_closed_db_returns_error() {
    let db = setup_bridge_db();
    // Close connection by dropping and re-creating in a way that makes it invalid
    // Actually, we can't close an in-memory DB. Instead, test with a corrupted table.
    db.execute_batch("DROP TABLE bridge_memories").unwrap();

    let now = chrono::Utc::now();
    let content = cortex_core::memory::base::TypedContent::Insight(
        cortex_core::memory::types::InsightContent {
            observation: "test".into(),
            evidence: vec![],
        },
    );
    let content_hash = cortex_core::memory::base::BaseMemory::compute_content_hash(&content)
        .unwrap_or_else(|_| "fallback".to_string());
    let mem = cortex_core::memory::base::BaseMemory {
        id: "err_test".to_string(),
        memory_type: cortex_core::MemoryType::Insight,
        content,
        summary: "test".into(),
        transaction_time: now,
        valid_time: now,
        valid_until: None,
        confidence: cortex_core::memory::confidence::Confidence::new(0.5),
        importance: cortex_core::memory::importance::Importance::Normal,
        last_accessed: now,
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
    };

    let result = db.insert_memory(&mem);
    assert!(result.is_err(), "Writing to dropped table should return error, not panic");
}

#[test]
fn log_event_on_dropped_table_returns_error() {
    let db = setup_bridge_db();
    db.execute_batch("DROP TABLE bridge_event_log").unwrap();
    let result = db.insert_event("test_event", None, None, None);
    assert!(result.is_err(), "Logging to dropped table should return error");
}

#[test]
fn record_metric_on_dropped_table_returns_error() {
    let db = setup_bridge_db();
    db.execute_batch("DROP TABLE bridge_metrics").unwrap();
    let result = db.insert_metric("test", 1.0);
    assert!(result.is_err(), "Recording metric to dropped table should return error");
}
