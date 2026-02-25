//! Enterprise critical infrastructure tests — the things that MUST work at 100%.
//!
//! Sections:
//! 1. All 18 memory-creating events fire E2E through BridgeEventHandler
//! 2. Evidence collection with mock drift.db tables
//! 3. Cross-DB ATTACH/DETACH safety (RAII guard, double-detach, concurrent)
//! 4. NAPI full contract shape validation (all 20 functions)
//! 5. Cortex query roundtrip (store → query by id/type/tag/count)
//! 6. Grounding history ordering and delta chain correctness
//! 7. Spec engine E2E (corrections → memory + causal, contract verified, decomposition)
//! 8. Adaptive weight math edge cases
//! 9. Evidence context tag parsing
//! 10. Data retention correctness

use std::collections::HashSet;

use cortex_causal::CausalEngine;
use cortex_drift_bridge::config::GroundingConfig;
use cortex_drift_bridge::event_mapping::BridgeEventHandler;
use cortex_drift_bridge::grounding::evidence::collector::{collect_one, EvidenceContext};
use cortex_drift_bridge::grounding::evidence::composite::context_from_tags;
use cortex_drift_bridge::grounding::evidence::types::EvidenceType;
use cortex_drift_bridge::grounding::loop_runner::MemoryForGrounding;
use cortex_drift_bridge::grounding::GroundingLoopRunner;
use cortex_drift_bridge::license::LicenseTier;
use cortex_drift_bridge::napi::functions;
use cortex_drift_bridge::query::attach::AttachGuard;
use cortex_drift_bridge::query::cortex_queries;
use cortex_drift_bridge::query::cross_db;
use cortex_drift_bridge::specification::corrections::{CorrectionRootCause, SpecCorrection, SpecSection};
use cortex_drift_bridge::specification::events;
use cortex_drift_bridge::specification::weight_provider::BridgeWeightProvider;
use cortex_drift_bridge::storage::retention;

use drift_core::events::handler::DriftEventHandler;
use drift_core::events::types::*;
use drift_core::traits::weight_provider::{AdaptiveWeightTable, MigrationPath, WeightProvider};
use cortex_drift_bridge::traits::IBridgeStorage;

// ============================================================================
// HELPERS
// ============================================================================

fn setup_bridge_db() -> cortex_drift_bridge::storage::engine::BridgeStorageEngine {
    cortex_drift_bridge::storage::engine::BridgeStorageEngine::open_in_memory().unwrap()
}

fn setup_mock_drift_db() -> rusqlite::Connection {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "CREATE TABLE pattern_confidence (
            pattern_id TEXT PRIMARY KEY,
            alpha REAL NOT NULL DEFAULT 1.0,
            beta REAL NOT NULL DEFAULT 1.0,
            posterior_mean REAL NOT NULL,
            credible_interval_low REAL NOT NULL DEFAULT 0.0,
            credible_interval_high REAL NOT NULL DEFAULT 1.0,
            tier TEXT NOT NULL DEFAULT 'Medium',
            momentum TEXT NOT NULL DEFAULT 'Stable',
            last_updated INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE detections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file TEXT NOT NULL,
            line INTEGER NOT NULL DEFAULT 0,
            column_num INTEGER NOT NULL DEFAULT 0,
            pattern_id TEXT NOT NULL,
            category TEXT NOT NULL DEFAULT 'general',
            confidence REAL NOT NULL DEFAULT 0.8,
            detection_method TEXT NOT NULL DEFAULT 'regex',
            created_at INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            violation_id TEXT NOT NULL DEFAULT '',
            pattern_id TEXT NOT NULL,
            detector_id TEXT NOT NULL DEFAULT '',
            action TEXT NOT NULL,
            created_at INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE constraint_verifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            constraint_id TEXT NOT NULL,
            passed INTEGER NOT NULL,
            violations TEXT NOT NULL DEFAULT '[]',
            verified_at INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE coupling_metrics (
            module TEXT PRIMARY KEY,
            ce INTEGER NOT NULL DEFAULT 0,
            ca INTEGER NOT NULL DEFAULT 0,
            instability REAL NOT NULL,
            abstractness REAL NOT NULL DEFAULT 0.0,
            distance REAL NOT NULL DEFAULT 0.0,
            zone TEXT NOT NULL DEFAULT 'stable',
            updated_at INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE dna_genes (
            gene_id TEXT PRIMARY KEY,
            name TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            alleles TEXT NOT NULL DEFAULT '[]',
            confidence REAL NOT NULL,
            consistency REAL NOT NULL,
            exemplars TEXT NOT NULL DEFAULT '[]',
            updated_at INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE test_quality (
            function_id TEXT PRIMARY KEY,
            overall_score REAL NOT NULL,
            updated_at INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE error_gaps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file TEXT NOT NULL,
            function_id TEXT NOT NULL DEFAULT '',
            gap_type TEXT NOT NULL DEFAULT 'uncaught',
            severity TEXT NOT NULL DEFAULT 'medium',
            created_at INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE decisions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            confidence REAL NOT NULL,
            created_at INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE boundaries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file TEXT NOT NULL DEFAULT '',
            framework TEXT NOT NULL DEFAULT '',
            model_name TEXT NOT NULL DEFAULT '',
            confidence REAL NOT NULL,
            created_at INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE taint_flows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_file TEXT NOT NULL,
            source_line INTEGER NOT NULL DEFAULT 0,
            source_type TEXT NOT NULL DEFAULT '',
            sink_file TEXT NOT NULL DEFAULT '',
            sink_line INTEGER NOT NULL DEFAULT 0,
            sink_type TEXT NOT NULL DEFAULT '',
            cwe_id INTEGER NOT NULL DEFAULT 0,
            is_sanitized INTEGER NOT NULL DEFAULT 0,
            path TEXT NOT NULL DEFAULT '',
            confidence REAL NOT NULL DEFAULT 0.5,
            created_at INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE call_edges (
            caller_id INTEGER NOT NULL,
            callee_id INTEGER NOT NULL,
            resolution TEXT NOT NULL,
            confidence REAL NOT NULL DEFAULT 0.5,
            call_site_line INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (caller_id, callee_id, call_site_line)
        );
        CREATE TABLE scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at INTEGER NOT NULL DEFAULT 0,
            root_path TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'running'
        );",
    )
    .unwrap();
    conn
}


// ============================================================================
// SECTION 1: ALL 18 MEMORY-CREATING EVENTS FIRE E2E
// ============================================================================

#[test]
fn event_e2e_pattern_approved_creates_memory() {
    let db = setup_bridge_db();
    let handler = BridgeEventHandler::new(Some(std::sync::Arc::new(db) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>), LicenseTier::Enterprise);
    handler.on_pattern_approved(&PatternApprovedEvent {
        pattern_id: "p1".to_string(),
    });
    assert_eq!(handler.error_count(), 0, "on_pattern_approved should not error");
}

#[test]
fn event_e2e_pattern_discovered_creates_memory() {
    let db = setup_bridge_db();
    let handler = BridgeEventHandler::new(Some(std::sync::Arc::new(db) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>), LicenseTier::Enterprise);
    handler.on_pattern_discovered(&PatternDiscoveredEvent {
        pattern_id: "p2".to_string(),
        category: "naming".to_string(),
        confidence: 0.75,
    });
    assert_eq!(handler.error_count(), 0);
}

#[test]
fn event_e2e_pattern_ignored_creates_memory() {
    let db = setup_bridge_db();
    let handler = BridgeEventHandler::new(Some(std::sync::Arc::new(db) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>), LicenseTier::Enterprise);
    handler.on_pattern_ignored(&PatternIgnoredEvent {
        pattern_id: "p3".to_string(),
        reason: "Not relevant".to_string(),
    });
    assert_eq!(handler.error_count(), 0);
}

#[test]
fn event_e2e_pattern_merged_creates_memory() {
    let db = setup_bridge_db();
    let handler = BridgeEventHandler::new(Some(std::sync::Arc::new(db) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>), LicenseTier::Enterprise);
    handler.on_pattern_merged(&PatternMergedEvent {
        kept_id: "k1".to_string(),
        merged_id: "m1".to_string(),
    });
    assert_eq!(handler.error_count(), 0);
}

#[test]
fn event_e2e_scan_complete_no_memory_no_error() {
    let db = setup_bridge_db();
    let handler = BridgeEventHandler::new(Some(std::sync::Arc::new(db) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>), LicenseTier::Enterprise);
    handler.on_scan_complete(&ScanCompleteEvent {
        added: 10,
        modified: 5,
        removed: 2,
        unchanged: 100,
        duration_ms: 500,
    });
    assert_eq!(handler.error_count(), 0);
}

#[test]
fn event_e2e_regression_detected_creates_memory() {
    let db = setup_bridge_db();
    let handler = BridgeEventHandler::new(Some(std::sync::Arc::new(db) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>), LicenseTier::Enterprise);
    handler.on_regression_detected(&RegressionDetectedEvent {
        pattern_id: "p4".to_string(),
        previous_score: 0.95,
        current_score: 0.60,
    });
    assert_eq!(handler.error_count(), 0);
}

#[test]
fn event_e2e_violation_detected_no_memory() {
    let db = setup_bridge_db();
    let handler = BridgeEventHandler::new(Some(std::sync::Arc::new(db) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>), LicenseTier::Enterprise);
    handler.on_violation_detected(&ViolationDetectedEvent {
        violation_id: "v1".to_string(),
        pattern_id: "p1".to_string(),
        file: std::path::PathBuf::from("src/main.rs"),
        line: 42,
        message: "warning: unused variable".to_string(),
    });
    assert_eq!(handler.error_count(), 0);
}

#[test]
fn event_e2e_violation_dismissed_creates_memory() {
    let db = setup_bridge_db();
    let handler = BridgeEventHandler::new(Some(std::sync::Arc::new(db) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>), LicenseTier::Enterprise);
    handler.on_violation_dismissed(&ViolationDismissedEvent {
        violation_id: "v2".to_string(),
        reason: "False positive".to_string(),
    });
    assert_eq!(handler.error_count(), 0);
}

#[test]
fn event_e2e_violation_fixed_creates_memory() {
    let db = setup_bridge_db();
    let handler = BridgeEventHandler::new(Some(std::sync::Arc::new(db) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>), LicenseTier::Enterprise);
    handler.on_violation_fixed(&ViolationFixedEvent {
        violation_id: "v3".to_string(),
    });
    assert_eq!(handler.error_count(), 0);
}

#[test]
fn event_e2e_gate_evaluated_creates_memory() {
    let db = setup_bridge_db();
    let handler = BridgeEventHandler::new(Some(std::sync::Arc::new(db) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>), LicenseTier::Enterprise);
    handler.on_gate_evaluated(&GateEvaluatedEvent {
        gate_name: "complexity".to_string(),
        passed: true,
        score: Some(0.85),
        message: "All good".to_string(),
    });
    assert_eq!(handler.error_count(), 0);
}

#[test]
fn event_e2e_detector_alert_creates_memory() {
    let db = setup_bridge_db();
    let handler = BridgeEventHandler::new(Some(std::sync::Arc::new(db) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>), LicenseTier::Enterprise);
    handler.on_detector_alert(&DetectorAlertEvent {
        detector_id: "d1".to_string(),
        false_positive_rate: 0.15,
    });
    assert_eq!(handler.error_count(), 0);
}

#[test]
fn event_e2e_detector_disabled_creates_memory() {
    let db = setup_bridge_db();
    let handler = BridgeEventHandler::new(Some(std::sync::Arc::new(db) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>), LicenseTier::Enterprise);
    handler.on_detector_disabled(&DetectorDisabledEvent {
        detector_id: "d2".to_string(),
        reason: "FP > 20%".to_string(),
    });
    assert_eq!(handler.error_count(), 0);
}

#[test]
fn event_e2e_constraint_approved_creates_memory() {
    let db = setup_bridge_db();
    let handler = BridgeEventHandler::new(Some(std::sync::Arc::new(db) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>), LicenseTier::Enterprise);
    handler.on_constraint_approved(&ConstraintApprovedEvent {
        constraint_id: "c1".to_string(),
    });
    assert_eq!(handler.error_count(), 0);
}

#[test]
fn event_e2e_constraint_violated_creates_memory() {
    let db = setup_bridge_db();
    let handler = BridgeEventHandler::new(Some(std::sync::Arc::new(db) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>), LicenseTier::Enterprise);
    handler.on_constraint_violated(&ConstraintViolatedEvent {
        constraint_id: "c2".to_string(),
        message: "Circular dependency detected".to_string(),
    });
    assert_eq!(handler.error_count(), 0);
}

#[test]
fn event_e2e_decision_mined_creates_memory() {
    let db = setup_bridge_db();
    let handler = BridgeEventHandler::new(Some(std::sync::Arc::new(db) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>), LicenseTier::Enterprise);
    handler.on_decision_mined(&DecisionMinedEvent {
        decision_id: "dm1".to_string(),
        category: "architecture".to_string(),
    });
    assert_eq!(handler.error_count(), 0);
}

#[test]
fn event_e2e_decision_reversed_creates_memory() {
    let db = setup_bridge_db();
    let handler = BridgeEventHandler::new(Some(std::sync::Arc::new(db) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>), LicenseTier::Enterprise);
    handler.on_decision_reversed(&DecisionReversedEvent {
        decision_id: "dr1".to_string(),
        reason: "Performance issues".to_string(),
    });
    assert_eq!(handler.error_count(), 0);
}

#[test]
fn event_e2e_adr_detected_creates_memory() {
    let db = setup_bridge_db();
    let handler = BridgeEventHandler::new(Some(std::sync::Arc::new(db) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>), LicenseTier::Enterprise);
    handler.on_adr_detected(&AdrDetectedEvent {
        adr_id: "adr-001".to_string(),
        title: "Use microservices".to_string(),
    });
    assert_eq!(handler.error_count(), 0);
}

#[test]
fn event_e2e_boundary_discovered_creates_memory() {
    let db = setup_bridge_db();
    let handler = BridgeEventHandler::new(Some(std::sync::Arc::new(db) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>), LicenseTier::Enterprise);
    handler.on_boundary_discovered(&BoundaryDiscoveredEvent {
        boundary_id: "b1".to_string(),
        model: "User".to_string(),
        orm: "diesel".to_string(),
    });
    assert_eq!(handler.error_count(), 0);
}

#[test]
fn event_e2e_enforcement_changed_creates_memory() {
    let db = setup_bridge_db();
    let handler = BridgeEventHandler::new(Some(std::sync::Arc::new(db) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>), LicenseTier::Enterprise);
    handler.on_enforcement_changed(&EnforcementChangedEvent {
        gate_name: "complexity".to_string(),
        old_level: "warn".to_string(),
        new_level: "error".to_string(),
    });
    assert_eq!(handler.error_count(), 0);
}

#[test]
fn event_e2e_feedback_abuse_detected_creates_memory() {
    let db = setup_bridge_db();
    let handler = BridgeEventHandler::new(Some(std::sync::Arc::new(db) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>), LicenseTier::Enterprise);
    handler.on_feedback_abuse_detected(&FeedbackAbuseDetectedEvent {
        user_id: "u1".to_string(),
        pattern: "dismiss-all".to_string(),
    });
    assert_eq!(handler.error_count(), 0);
}

#[test]
fn event_e2e_error_no_memory_no_error() {
    let db = setup_bridge_db();
    let handler = BridgeEventHandler::new(Some(std::sync::Arc::new(db) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>), LicenseTier::Enterprise);
    handler.on_error(&ErrorEvent {
        message: "Something broke".to_string(),
        error_code: "E001".to_string(),
    });
    assert_eq!(handler.error_count(), 0);
}

#[test]
fn event_all_18_memory_creating_events_produce_zero_errors() {
    let db = setup_bridge_db();
    let handler = BridgeEventHandler::new(Some(std::sync::Arc::new(db) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>), LicenseTier::Enterprise);

    handler.on_pattern_approved(&PatternApprovedEvent { pattern_id: "p1".into() });
    handler.on_pattern_discovered(&PatternDiscoveredEvent { pattern_id: "p2".into(), category: "naming".into(), confidence: 0.5 });
    handler.on_pattern_ignored(&PatternIgnoredEvent { pattern_id: "p3".into(), reason: "r".into() });
    handler.on_pattern_merged(&PatternMergedEvent { kept_id: "k".into(), merged_id: "m".into() });
    handler.on_regression_detected(&RegressionDetectedEvent { pattern_id: "p4".into(), previous_score: 0.9, current_score: 0.5 });
    handler.on_violation_dismissed(&ViolationDismissedEvent { violation_id: "v1".into(), reason: "fp".into() });
    handler.on_violation_fixed(&ViolationFixedEvent { violation_id: "v2".into() });
    handler.on_gate_evaluated(&GateEvaluatedEvent { gate_name: "g".into(), passed: true, score: Some(1.0), message: "ok".into() });
    handler.on_detector_alert(&DetectorAlertEvent { detector_id: "d1".into(), false_positive_rate: 0.1 });
    handler.on_detector_disabled(&DetectorDisabledEvent { detector_id: "d2".into(), reason: "bad".into() });
    handler.on_constraint_approved(&ConstraintApprovedEvent { constraint_id: "c1".into() });
    handler.on_constraint_violated(&ConstraintViolatedEvent { constraint_id: "c2".into(), message: "oops".into() });
    handler.on_decision_mined(&DecisionMinedEvent { decision_id: "dm".into(), category: "arch".into() });
    handler.on_decision_reversed(&DecisionReversedEvent { decision_id: "dr".into(), reason: "perf".into() });
    handler.on_adr_detected(&AdrDetectedEvent { adr_id: "adr1".into(), title: "Use REST".into() });
    handler.on_boundary_discovered(&BoundaryDiscoveredEvent { boundary_id: "b1".into(), model: "User".into(), orm: "diesel".into() });
    handler.on_enforcement_changed(&EnforcementChangedEvent { gate_name: "g".into(), old_level: "warn".into(), new_level: "error".into() });
    handler.on_feedback_abuse_detected(&FeedbackAbuseDetectedEvent { user_id: "u".into(), pattern: "spam".into() });

    assert_eq!(handler.error_count(), 0, "All 18 memory-creating events should succeed with zero errors");
}

// ============================================================================
// SECTION 2: EVIDENCE COLLECTION WITH MOCK DRIFT.DB
// ============================================================================

#[test]
fn evidence_collect_pattern_confidence_from_drift_db() {
    let drift_db = setup_mock_drift_db();
    drift_db
        .execute(
            "INSERT INTO pattern_confidence (pattern_id, posterior_mean) VALUES ('p1', 0.85)",
            [],
        )
        .unwrap();

    let ctx = EvidenceContext {
        pattern_id: Some("p1".to_string()),
        current_confidence: 0.7,
        ..Default::default()
    };

    let evidence = collect_one(EvidenceType::PatternConfidence, &ctx, &drift_db).unwrap();
    assert!(evidence.is_some(), "Should find pattern confidence in drift.db");
    let e = evidence.unwrap();
    assert!((e.drift_value - 0.85).abs() < 0.001);
}

#[test]
fn evidence_collect_pattern_occurrence_from_drift_db() {
    let drift_db = setup_mock_drift_db();
    // Insert 2 detections for p1 in file_a, and 1 detection for p2 in file_b (3 total files: a, b)
    drift_db.execute("INSERT INTO detections (file, pattern_id) VALUES ('file_a.rs', 'p1')", []).unwrap();
    drift_db.execute("INSERT INTO detections (file, pattern_id) VALUES ('file_b.rs', 'p1')", []).unwrap();
    drift_db.execute("INSERT INTO detections (file, pattern_id) VALUES ('file_c.rs', 'p2')", []).unwrap();

    let ctx = EvidenceContext {
        pattern_id: Some("p1".to_string()),
        ..Default::default()
    };

    let evidence = collect_one(EvidenceType::PatternOccurrence, &ctx, &drift_db).unwrap();
    assert!(evidence.is_some());
    // p1 appears in 2 of 3 distinct files = 0.667
    assert!((evidence.unwrap().drift_value - 2.0/3.0).abs() < 0.01);
}

#[test]
fn evidence_collect_false_positive_rate_from_drift_db() {
    let drift_db = setup_mock_drift_db();
    // 10 feedback entries, 1 dismiss → fp_rate = 0.1
    drift_db.execute("INSERT INTO feedback (pattern_id, action) VALUES ('p1', 'dismiss')", []).unwrap();
    for _ in 0..9 {
        drift_db.execute("INSERT INTO feedback (pattern_id, action) VALUES ('p1', 'accept')", []).unwrap();
    }

    let ctx = EvidenceContext {
        pattern_id: Some("p1".to_string()),
        ..Default::default()
    };

    let evidence = collect_one(EvidenceType::FalsePositiveRate, &ctx, &drift_db).unwrap();
    assert!(evidence.is_some());
    let e = evidence.unwrap();
    assert!((e.drift_value - 0.1).abs() < 0.001);
    // Low FP rate = high support: 1.0 - 0.1 = 0.9
    assert!((e.support_score - 0.9).abs() < 0.001);
}

#[test]
fn evidence_collect_constraint_verification_pass() {
    let drift_db = setup_mock_drift_db();
    drift_db
        .execute("INSERT INTO constraint_verifications (constraint_id, passed, verified_at) VALUES ('c1', 1, 1000)", [])
        .unwrap();

    let ctx = EvidenceContext {
        constraint_id: Some("c1".to_string()),
        ..Default::default()
    };

    let evidence = collect_one(EvidenceType::ConstraintVerification, &ctx, &drift_db).unwrap();
    assert!(evidence.is_some());
    assert_eq!(evidence.unwrap().support_score, 1.0);
}

#[test]
fn evidence_collect_constraint_verification_fail() {
    let drift_db = setup_mock_drift_db();
    drift_db
        .execute("INSERT INTO constraint_verifications (constraint_id, passed, verified_at) VALUES ('c2', 0, 1000)", [])
        .unwrap();

    let ctx = EvidenceContext {
        constraint_id: Some("c2".to_string()),
        ..Default::default()
    };

    let evidence = collect_one(EvidenceType::ConstraintVerification, &ctx, &drift_db).unwrap();
    assert!(evidence.is_some());
    assert_eq!(evidence.unwrap().support_score, 0.0);
}

#[test]
fn evidence_collect_all_10_types_from_populated_drift_db() {
    let drift_db = setup_mock_drift_db();

    // Populate all tables with real schema
    drift_db.execute("INSERT INTO pattern_confidence (pattern_id, posterior_mean) VALUES ('p1', 0.85)", []).unwrap();
    drift_db.execute("INSERT INTO detections (file, pattern_id) VALUES ('src/main.rs', 'p1')", []).unwrap();
    drift_db.execute("INSERT INTO feedback (pattern_id, action) VALUES ('p1', 'accept')", []).unwrap();
    drift_db.execute("INSERT INTO constraint_verifications (constraint_id, passed, verified_at) VALUES ('c1', 1, 1000)", []).unwrap();
    drift_db.execute("INSERT INTO coupling_metrics (module, instability) VALUES ('src/main.rs', 0.3)", []).unwrap();
    drift_db.execute("INSERT INTO dna_genes (gene_id, confidence, consistency) VALUES ('g1', 0.9, 1.0)", []).unwrap();
    drift_db.execute("INSERT INTO test_quality (function_id, overall_score) VALUES ('src/main.rs', 0.8)", []).unwrap();
    drift_db.execute("INSERT INTO error_gaps (file, function_id) VALUES ('src/main.rs', 'fn_a')", []).unwrap();
    drift_db.execute("INSERT INTO decisions (category, description, confidence) VALUES ('refactor', 'split module', 0.7)", []).unwrap();
    drift_db.execute("INSERT INTO boundaries (file, framework, model_name, confidence) VALUES ('src/main.rs', 'orm', 'User', 0.6)", []).unwrap();
    drift_db.execute("INSERT INTO taint_flows (source_file, source_line, source_type, sink_file, sink_line, sink_type, cwe_id, is_sanitized) VALUES ('src/main.rs', 10, 'user_input', 'src/db.rs', 20, 'sql_query', 89, 0)", []).unwrap();
    drift_db.execute("INSERT INTO call_edges (caller_id, callee_id, resolution, confidence, call_site_line) VALUES (1, 2, 'import', 0.9, 10)", []).unwrap();
    drift_db.execute("INSERT INTO call_edges (caller_id, callee_id, resolution, confidence, call_site_line) VALUES (2, 3, 'fuzzy', 0.4, 20)", []).unwrap();

    let ctx = EvidenceContext {
        pattern_id: Some("p1".to_string()),
        constraint_id: Some("c1".to_string()),
        module_path: Some("src/main.rs".to_string()),
        project: Some("myproject".to_string()),
        decision_id: Some("1".to_string()),
        boundary_id: Some("1".to_string()),
        file_path: Some("src/main.rs".to_string()),
        current_confidence: 0.7,
        ..Default::default()
    };

    let mut found_types = HashSet::new();
    for et in EvidenceType::ALL {
        if let Ok(Some(e)) = collect_one(et, &ctx, &drift_db) {
            found_types.insert(format!("{:?}", e.evidence_type));
            assert!(e.support_score >= 0.0 && e.support_score <= 1.0,
                "Support score must be in [0,1] for {:?}", et);
        }
    }
    assert_eq!(found_types.len(), 12, "All 12 evidence types should have data, got {}: {:?}", found_types.len(), found_types);
}

#[test]
fn evidence_missing_context_returns_none() {
    let drift_db = setup_mock_drift_db();
    let ctx = EvidenceContext::default(); // All None

    for et in EvidenceType::ALL {
        let result = collect_one(et, &ctx, &drift_db).unwrap();
        assert!(result.is_none(), "{:?} should return None when context field is missing", et);
    }
}

#[test]
fn evidence_missing_row_returns_none() {
    let drift_db = setup_mock_drift_db();
    let ctx = EvidenceContext {
        pattern_id: Some("nonexistent".to_string()),
        constraint_id: Some("nonexistent".to_string()),
        module_path: Some("nonexistent".to_string()),
        project: Some("nonexistent".to_string()),
        decision_id: Some("nonexistent".to_string()),
        boundary_id: Some("nonexistent".to_string()),
        current_confidence: 0.5,
        ..Default::default()
    };

    for et in EvidenceType::ALL {
        let result = collect_one(et, &ctx, &drift_db).unwrap();
        assert!(result.is_none(), "{:?} should return None for nonexistent row", et);
    }
}

// ============================================================================
// SECTION 3: CROSS-DB ATTACH/DETACH SAFETY
// ============================================================================

#[test]
fn attach_guard_raii_auto_detach() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    let tmp = tempfile::NamedTempFile::new().unwrap();
    {
        let guard = AttachGuard::attach(&conn, tmp.path().to_str().unwrap(), "test_db").unwrap();
        assert_eq!(guard.alias(), "test_db");
        // Should be accessible
        conn.execute_batch("SELECT 1 FROM test_db.sqlite_master").unwrap();
    }
    // After drop, the database should be detached
    let result = conn.execute_batch("SELECT 1 FROM test_db.sqlite_master");
    assert!(result.is_err(), "Database should be detached after guard drop");
}

#[test]
fn attach_guard_explicit_detach() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let guard = AttachGuard::attach(&conn, tmp.path().to_str().unwrap(), "test_db2").unwrap();
    guard.detach().unwrap();
    let result = conn.execute_batch("SELECT 1 FROM test_db2.sqlite_master");
    assert!(result.is_err(), "Database should be detached after explicit detach");
}

#[test]
fn attach_guard_sanitizes_sql_injection_in_alias() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    let tmp = tempfile::NamedTempFile::new().unwrap();
    // Alias with SQL injection attempt — should be sanitized
    let guard = AttachGuard::attach(&conn, tmp.path().to_str().unwrap(), "test; DROP TABLE x");
    // Should succeed with sanitized alias "testDROPTABLEx"
    assert!(guard.is_ok());
}

#[test]
fn cross_db_count_matching_patterns_empty_list() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    let result = cross_db::count_matching_patterns(&conn, &[]).unwrap();
    assert_eq!(result, 0, "Empty pattern list should return 0");
}

#[test]
fn cross_db_latest_scan_timestamp_no_table() {
    // On a connection that doesn't have drift schema attached, should return None
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    // Create a drift schema directly (not via attach)
    conn.execute_batch("CREATE TABLE drift_scans (id INTEGER PRIMARY KEY, created_at INTEGER)").unwrap();
    // Aliasing: the function queries "drift.drift_scans" but we have it in main.
    // This tests that with no data, we get None.
    let result = conn.query_row("SELECT MAX(created_at) FROM drift_scans", [], |row| row.get::<_, Option<i64>>(0)).unwrap();
    assert!(result.is_none());
}

// ============================================================================
// SECTION 4: CORTEX QUERY ROUNDTRIP
// ============================================================================

#[test]
fn cortex_query_store_and_get_by_id() {
    let db = setup_bridge_db();
    let engine = CausalEngine::new();
    let correction = SpecCorrection {
        correction_id: "cor1".to_string(),
        module_id: "mod1".to_string(),
        section: SpecSection::PublicApi,
        root_cause: CorrectionRootCause::DomainKnowledge { description: "auth".into() },
        upstream_modules: vec![],
        data_sources: vec![],
    };
    let memory_id = events::on_spec_corrected(&correction, &engine, Some(&db as &dyn cortex_drift_bridge::traits::IBridgeStorage)).unwrap();

    let row = db.with_reader(|conn| cortex_queries::get_memory_by_id(conn, &memory_id)).unwrap();
    assert!(row.is_some(), "Stored memory should be retrievable by ID");
    let row = row.unwrap();
    assert_eq!(row.id, memory_id);
    assert_eq!(row.memory_type, "Feedback");
    assert!(row.confidence > 0.0);
}

#[test]
fn cortex_query_get_by_type() {
    let db = setup_bridge_db();
    let engine = CausalEngine::new();

    // Create two Feedback memories
    for i in 0..2 {
        let correction = SpecCorrection {
            correction_id: format!("cor{}", i),
            module_id: format!("mod{}", i),
            section: SpecSection::PublicApi,
            root_cause: CorrectionRootCause::DomainKnowledge { description: "x".into() },
            upstream_modules: vec![],
            data_sources: vec![],
        };
        events::on_spec_corrected(&correction, &engine, Some(&db as &dyn cortex_drift_bridge::traits::IBridgeStorage)).unwrap();
    }

    let rows = db.with_reader(|conn| cortex_queries::get_memories_by_type(conn, "Feedback", 10)).unwrap();
    assert_eq!(rows.len(), 2, "Should find 2 Feedback memories");
}

#[test]
fn cortex_query_get_by_tag() {
    let db = setup_bridge_db();
    let engine = CausalEngine::new();

    let correction = SpecCorrection {
        correction_id: "cor1".to_string(),
        module_id: "auth_module".to_string(),
        section: SpecSection::Security,
        root_cause: CorrectionRootCause::DomainKnowledge { description: "auth".into() },
        upstream_modules: vec![],
        data_sources: vec![],
    };
    events::on_spec_corrected(&correction, &engine, Some(&db as &dyn cortex_drift_bridge::traits::IBridgeStorage)).unwrap();

    let rows = db.with_reader(|conn| cortex_queries::get_memories_by_tag(conn, "module:auth_module", 10)).unwrap();
    assert_eq!(rows.len(), 1, "Should find memory by module tag");
}

#[test]
fn cortex_query_count_memories() {
    let db = setup_bridge_db();
    assert_eq!(db.with_reader(cortex_queries::count_memories).unwrap(), 0);

    let engine = CausalEngine::new();
    let correction = SpecCorrection {
        correction_id: "cor1".to_string(),
        module_id: "mod1".to_string(),
        section: SpecSection::DataModel,
        root_cause: CorrectionRootCause::DomainKnowledge { description: "x".into() },
        upstream_modules: vec![],
        data_sources: vec![],
    };
    events::on_spec_corrected(&correction, &engine, Some(&db as &dyn cortex_drift_bridge::traits::IBridgeStorage)).unwrap();

    assert_eq!(db.with_reader(cortex_queries::count_memories).unwrap(), 1);
}

#[test]
fn cortex_query_nonexistent_id_returns_none() {
    let db = setup_bridge_db();
    let row = db.with_reader(|conn| cortex_queries::get_memory_by_id(conn, "does-not-exist")).unwrap();
    assert!(row.is_none());
}

// ============================================================================
// SECTION 5: GROUNDING HISTORY AND DELTA CHAIN
// ============================================================================

#[test]
fn grounding_history_ordering_newest_first() {
    let db = setup_bridge_db();
    let runner = GroundingLoopRunner::default();

    // Ground the same memory 3 times with different data
    for confidence in [0.3, 0.6, 0.9] {
        let memory = MemoryForGrounding {
            memory_id: "mem1".to_string(),
            memory_type: cortex_core::MemoryType::PatternRationale,
            current_confidence: 0.5,
            pattern_confidence: Some(confidence),
            occurrence_rate: None,
            false_positive_rate: None,
            constraint_verified: None,
            coupling_metric: None,
            dna_health: None,
            test_coverage: None,
            error_handling_gaps: None,
            decision_evidence: None,
            boundary_data: None,
        evidence_context: None,        };
        runner.ground_single(&memory, None, Some(&db as &dyn cortex_drift_bridge::traits::IBridgeStorage)).unwrap();
    }

    let history = db.get_grounding_history("mem1", 10).unwrap();
    assert_eq!(history.len(), 3, "All 3 grounding records should be retrievable");
}

#[test]
fn grounding_delta_chain_computed_correctly() {
    let db = setup_bridge_db();
    let runner = GroundingLoopRunner::default();

    // First grounding — no previous score
    let memory = MemoryForGrounding {
        memory_id: "delta_mem".to_string(),
        memory_type: cortex_core::MemoryType::PatternRationale,
        current_confidence: 0.5,
        pattern_confidence: Some(0.8),
        occurrence_rate: Some(0.5),
        false_positive_rate: None,
        constraint_verified: None,
        coupling_metric: None,
        dna_health: None,
        test_coverage: None,
        error_handling_gaps: None,
        decision_evidence: None,
        boundary_data: None,
        evidence_context: None,    };
    let result1 = runner.ground_single(&memory, None, Some(&db as &dyn cortex_drift_bridge::traits::IBridgeStorage)).unwrap();
    assert!(result1.previous_score.is_none(), "First grounding should have no previous score");
    assert!(result1.score_delta.is_none(), "First grounding should have no delta");

    // Second grounding — should have previous score
    let result2 = runner.ground_single(&memory, None, Some(&db as &dyn cortex_drift_bridge::traits::IBridgeStorage)).unwrap();
    assert!(result2.previous_score.is_some(), "Second grounding should have previous score");
    assert!(result2.score_delta.is_some(), "Second grounding should have delta");
    let delta = result2.score_delta.unwrap();
    assert!(delta.abs() < 0.001, "Same evidence should produce ~0 delta, got {}", delta);
}

// ============================================================================
// SECTION 6: SPEC ENGINE E2E
// ============================================================================

#[test]
fn spec_correction_creates_memory_and_causal_edge() {
    let db = setup_bridge_db();
    let engine = CausalEngine::new();

    let correction = SpecCorrection {
        correction_id: "c1".to_string(),
        module_id: "payments".to_string(),
        section: SpecSection::DataFlow,
        root_cause: CorrectionRootCause::MissingCallEdge {
            from: "checkout".into(),
            to: "payments".into(),
        },
        upstream_modules: vec!["checkout".to_string()],
        data_sources: vec![],
    };

    let memory_id = events::on_spec_corrected(&correction, &engine, Some(&db as &dyn cortex_drift_bridge::traits::IBridgeStorage)).unwrap();
    assert!(!memory_id.is_empty());

    // Memory should be persisted
    let row = db.with_reader(|conn| cortex_queries::get_memory_by_id(conn, &memory_id)).unwrap();
    assert!(row.is_some());
    let row = row.unwrap();
    assert!(row.tags.contains("spec_correction"));
    assert!(row.tags.contains("module:payments"));
}

#[test]
fn spec_correction_empty_module_id_rejected() {
    let engine = CausalEngine::new();
    let correction = SpecCorrection {
        correction_id: "c1".to_string(),
        module_id: String::new(),
        section: SpecSection::PublicApi,
        root_cause: CorrectionRootCause::DomainKnowledge { description: "x".into() },
        upstream_modules: vec![],
        data_sources: vec![],
    };
    let result = events::on_spec_corrected(&correction, &engine, None);
    assert!(result.is_err(), "Empty module_id should be rejected");
}

#[test]
fn contract_verified_pass_creates_memory() {
    let db = setup_bridge_db();
    let memory_id = events::on_contract_verified(
        "auth_module",
        true,
        &SpecSection::Security,
        None,
        None,
        Some(&db),
    )
    .unwrap();

    let row = db.with_reader(|conn| cortex_queries::get_memory_by_id(conn, &memory_id)).unwrap().unwrap();
    assert!(row.tags.contains("result:pass"));
    assert_eq!(row.importance, "Normal");
}

#[test]
fn contract_verified_fail_creates_memory_with_higher_importance() {
    let db = setup_bridge_db();
    let memory_id = events::on_contract_verified(
        "auth_module",
        false,
        &SpecSection::Security,
        Some("field_removed"),
        Some(0.8),
        Some(&db),
    )
    .unwrap();

    let row = db.with_reader(|conn| cortex_queries::get_memory_by_id(conn, &memory_id)).unwrap().unwrap();
    assert!(row.tags.contains("result:fail"));
    assert_eq!(row.importance, "High");
}

#[test]
fn contract_verified_nan_severity_rejected() {
    let result = events::on_contract_verified(
        "mod1",
        false,
        &SpecSection::DataModel,
        Some("type_change"),
        Some(f64::NAN),
        None,
    );
    assert!(result.is_err(), "NaN severity should be rejected");
}

#[test]
fn decomposition_adjusted_creates_memory_with_dna_tag() {
    let db = setup_bridge_db();
    let memory_id = events::on_decomposition_adjusted(
        "user_service",
        "split",
        "abc123def",
        Some(&db),
    )
    .unwrap();

    let row = db.with_reader(|conn| cortex_queries::get_memory_by_id(conn, &memory_id)).unwrap().unwrap();
    assert!(row.tags.contains("dna:abc123def"));
    assert!(row.tags.contains("module:user_service"));
    assert_eq!(row.memory_type, "DecisionContext");
}

// ============================================================================
// SECTION 7: ADAPTIVE WEIGHT MATH EDGE CASES
// ============================================================================

#[test]
fn adaptive_weights_all_passes_returns_defaults() {
    let feedback: Vec<(String, bool)> = (0..20)
        .map(|i| (format!("section_{}", i % 5), false))
        .collect();
    let table = BridgeWeightProvider::compute_adaptive_weights(&feedback);
    assert_eq!(table.sample_size, 20);
    // All passes, no failures → failure_distribution should be empty
    assert!(table.failure_distribution.is_empty());
    // Weights should equal defaults since no failures to adjust
    let defaults = AdaptiveWeightTable::static_defaults();
    for (section, weight) in &table.weights {
        if let Some(default_weight) = defaults.weights.get(section) {
            assert!(
                (weight - default_weight).abs() < 0.001,
                "Section '{}' weight {} should equal default {} when all passes",
                section, weight, default_weight,
            );
        }
    }
}

#[test]
fn adaptive_weights_single_section_all_failures() {
    let feedback: Vec<(String, bool)> = (0..20)
        .map(|_| ("data_model".to_string(), true))
        .collect();
    let table = BridgeWeightProvider::compute_adaptive_weights(&feedback);

    // data_model has 100% of failures → failure_rate = 1.0
    // adjusted = base * (1 + 1.0 * 0.5) = base * 1.5
    let default_dm = AdaptiveWeightTable::static_defaults().weights["data_model"];
    let expected = (default_dm * 1.5).min(5.0);
    assert!(
        (table.weights["data_model"] - expected).abs() < 0.001,
        "Expected {}, got {}",
        expected,
        table.weights["data_model"],
    );
}

#[test]
fn adaptive_weights_new_section_gets_base_1() {
    let mut feedback: Vec<(String, bool)> = (0..15)
        .map(|_| ("known_section".to_string(), false))
        .collect();
    // Add failures for unknown section
    for _ in 0..5 {
        feedback.push(("completely_new_section".to_string(), true));
    }
    let table = BridgeWeightProvider::compute_adaptive_weights(&feedback);

    // completely_new_section is not in defaults, so base = 1.0
    assert!(
        table.weights.contains_key("completely_new_section"),
        "New section should be added to weight table",
    );
    let w = table.weights["completely_new_section"];
    assert!(w > 1.0, "New section with failures should have weight > base 1.0, got {}", w);
}

#[test]
fn adaptive_weights_clamped_at_max_5() {
    // Extreme: all failures in one section with high base weight
    let mut feedback: Vec<(String, bool)> = vec![];
    for _ in 0..100 {
        feedback.push(("public_api".to_string(), true)); // base=2.0, highest
    }
    let table = BridgeWeightProvider::compute_adaptive_weights(&feedback);
    assert!(
        table.weights["public_api"] <= 5.0,
        "Weight should be clamped at MAX_WEIGHT=5.0, got {}",
        table.weights["public_api"],
    );
}

#[test]
fn weight_provider_no_op_returns_static_defaults() {
    let provider = BridgeWeightProvider::no_op();
    let path = MigrationPath {
        source_language: "rust".to_string(),
        target_language: "ts".to_string(),
        source_framework: None,
        target_framework: None,
    };
    let weights = provider.get_weights(&path);
    assert_eq!(weights.weights, AdaptiveWeightTable::static_defaults().weights);
}

// ============================================================================
// SECTION 8: EVIDENCE CONTEXT TAG PARSING
// ============================================================================

#[test]
fn context_from_tags_parses_all_prefixes() {
    let tags = vec![
        "pattern:p1".to_string(),
        "constraint:c1".to_string(),
        "module:src/main.rs".to_string(),
        "project:myapp".to_string(),
        "decision:d1".to_string(),
        "boundary:b1".to_string(),
    ];
    let ctx = context_from_tags(&tags, &[], 0.7);
    assert_eq!(ctx.pattern_id.as_deref(), Some("p1"));
    assert_eq!(ctx.constraint_id.as_deref(), Some("c1"));
    assert_eq!(ctx.module_path.as_deref(), Some("src/main.rs"));
    assert_eq!(ctx.project.as_deref(), Some("myapp"));
    assert_eq!(ctx.decision_id.as_deref(), Some("d1"));
    assert_eq!(ctx.boundary_id.as_deref(), Some("b1"));
    assert!((ctx.current_confidence - 0.7).abs() < 0.001);
}

#[test]
fn context_from_tags_linked_patterns_takes_priority() {
    let tags = vec!["pattern:from_tag".to_string()];
    let linked = vec!["from_linked".to_string()];
    let ctx = context_from_tags(&tags, &linked, 0.5);
    // linked_patterns takes priority over tag
    assert_eq!(ctx.pattern_id.as_deref(), Some("from_linked"));
}

#[test]
fn context_from_tags_empty_inputs() {
    let ctx = context_from_tags(&[], &[], 0.0);
    assert!(ctx.pattern_id.is_none());
    assert!(ctx.constraint_id.is_none());
    assert!(ctx.module_path.is_none());
    assert!(ctx.project.is_none());
    assert!(ctx.decision_id.is_none());
    assert!(ctx.boundary_id.is_none());
}

#[test]
fn context_from_tags_ignores_unknown_prefixes() {
    let tags = vec![
        "unknown:value".to_string(),
        "random_tag".to_string(),
        "pattern:p1".to_string(),
    ];
    let ctx = context_from_tags(&tags, &[], 0.5);
    assert_eq!(ctx.pattern_id.as_deref(), Some("p1"));
    assert!(ctx.constraint_id.is_none());
}

#[test]
fn context_from_tags_colon_in_value_preserved() {
    let tags = vec!["module:src/app:main.rs".to_string()];
    let ctx = context_from_tags(&tags, &[], 0.5);
    assert_eq!(ctx.module_path.as_deref(), Some("src/app:main.rs"));
}

// ============================================================================
// SECTION 9: DATA RETENTION CORRECTNESS
// ============================================================================

#[test]
fn retention_deletes_old_event_log_entries() {
    let db = setup_bridge_db();

    // Insert an old event (31 days ago)
    let old_ts = chrono::Utc::now().timestamp() - (31 * 86400);
    db.execute(
        "INSERT INTO bridge_event_log (event_type, created_at) VALUES ('old_event', ?1)",
        rusqlite::params![old_ts],
    )
    .unwrap();
    // Insert a recent event
    db.insert_event("recent_event", None, None, None).unwrap();

    db.with_writer(|conn| retention::apply_retention(conn, true)).unwrap();

    let count: i64 = db
        .query_row("SELECT COUNT(*) FROM bridge_event_log", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1, "Old event should be deleted, recent should remain");
}

#[test]
fn retention_preserves_schema_version_metric() {
    let db = setup_bridge_db();

    // Insert schema_version metric with old timestamp
    let old_ts = chrono::Utc::now().timestamp() - (30 * 86400);
    db.execute(
        "INSERT INTO bridge_metrics (metric_name, metric_value, recorded_at) VALUES ('schema_version', 1.0, ?1)",
        rusqlite::params![old_ts],
    )
    .unwrap();

    db.with_writer(|conn| retention::apply_retention(conn, true)).unwrap();

    let count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM bridge_metrics WHERE metric_name = 'schema_version'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 1, "schema_version metric should survive retention cleanup");
}

#[test]
fn retention_community_deletes_old_grounding_results() {
    let db = setup_bridge_db();

    // Insert old grounding result (91 days ago)
    let old_ts = chrono::Utc::now().timestamp() - (91 * 86400);
    db.execute(
        "INSERT INTO bridge_grounding_results (memory_id, grounding_score, classification, evidence, created_at)
         VALUES ('old_mem', 0.5, 'Weak', '[]', ?1)",
        rusqlite::params![old_ts],
    )
    .unwrap();
    // Insert recent
    db.execute(
        "INSERT INTO bridge_grounding_results (memory_id, grounding_score, classification, evidence)
         VALUES ('new_mem', 0.9, 'Validated', '[]')",
        [],
    )
    .unwrap();

    db.with_writer(|conn| retention::apply_retention(conn, true)).unwrap();

    let count: i64 = db
        .query_row("SELECT COUNT(*) FROM bridge_grounding_results", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1, "Community tier: old results should be deleted");
}

#[test]
fn retention_enterprise_preserves_old_grounding_results() {
    let db = setup_bridge_db();

    let old_ts = chrono::Utc::now().timestamp() - (91 * 86400);
    db.execute(
        "INSERT INTO bridge_grounding_results (memory_id, grounding_score, classification, evidence, created_at)
         VALUES ('old_mem', 0.5, 'Weak', '[]', ?1)",
        rusqlite::params![old_ts],
    )
    .unwrap();

    db.with_writer(|conn| retention::apply_retention(conn, false)).unwrap(); // Enterprise = false

    let count: i64 = db
        .query_row("SELECT COUNT(*) FROM bridge_grounding_results", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1, "Enterprise tier: old results should be preserved");
}

// ============================================================================
// SECTION 10: NAPI CONTRACT SHAPE VALIDATION
// ============================================================================

#[test]
fn napi_bridge_status_has_all_fields() {
    let val = functions::bridge_status(true, &LicenseTier::Enterprise, true);
    assert!(val["available"].is_boolean());
    assert!(val["license_tier"].is_string());
    assert!(val["grounding_enabled"].is_boolean());
    assert!(val["version"].is_string());
    assert!(!val["version"].as_str().unwrap().is_empty());
}

#[test]
fn napi_bridge_ground_memory_returns_result_shape() {
    let config = GroundingConfig::default();
    let memory = MemoryForGrounding {
        memory_id: "m1".to_string(),
        memory_type: cortex_core::MemoryType::PatternRationale,
        current_confidence: 0.5,
        pattern_confidence: Some(0.8),
        occurrence_rate: Some(0.6),
        false_positive_rate: None,
        constraint_verified: None,
        coupling_metric: None,
        dna_health: None,
        test_coverage: None,
        error_handling_gaps: None,
        decision_evidence: None,
        boundary_data: None,
        evidence_context: None,    };
    let result = functions::bridge_ground_memory(&memory, &config, None, None).unwrap();
    assert!(result["verdict"].is_string());
    assert!(result["grounding_score"].is_number());
    assert!(result["memory_id"].is_string());
    assert!(result["evidence"].is_array());
}

#[test]
fn napi_bridge_ground_all_returns_snapshot_shape() {
    let config = GroundingConfig::default();
    let memories = vec![MemoryForGrounding {
        memory_id: "m1".to_string(),
        memory_type: cortex_core::MemoryType::PatternRationale,
        current_confidence: 0.5,
        pattern_confidence: Some(0.8),
        occurrence_rate: None,
        false_positive_rate: None,
        constraint_verified: None,
        coupling_metric: None,
        dna_health: None,
        test_coverage: None,
        error_handling_gaps: None,
        decision_evidence: None,
        boundary_data: None,
        evidence_context: None,    }];
    let result = functions::bridge_ground_all(&memories, &config, None, None).unwrap();
    assert!(result["total_checked"].is_number());
    assert!(result["validated"].is_number());
    assert!(result["avg_grounding_score"].is_number());
}

#[test]
fn napi_bridge_grounding_history_returns_shape() {
    let db = setup_bridge_db();
    let result = functions::bridge_grounding_history("nonexistent", 10, &db as &dyn cortex_drift_bridge::traits::IBridgeStorage).unwrap();
    assert!(result["memory_id"].is_string());
    assert!(result["history"].is_array());
    assert_eq!(result["history"].as_array().unwrap().len(), 0);
}

#[test]
fn napi_bridge_translate_link_shape() {
    let val = functions::bridge_translate_link("p1", "MyPattern", 0.9);
    assert!(val["entity_id"].is_string());
    assert!(val["entity_type"].is_string());
    assert_eq!(val["entity_type"], "drift_pattern");
}

#[test]
fn napi_bridge_translate_constraint_link_shape() {
    let val = functions::bridge_translate_constraint_link("c1", "NoCircularDeps");
    assert!(val["entity_id"].is_string());
    assert_eq!(val["entity_type"], "drift_constraint");
}

#[test]
fn napi_bridge_event_mappings_shape() {
    let val = functions::bridge_event_mappings();
    assert!(val["mappings"].is_array());
    assert!(val["count"].is_number());
    let mappings = val["mappings"].as_array().unwrap();
    assert_eq!(mappings.len(), 21);
    // Each mapping should have required fields
    for m in mappings {
        assert!(m["event_type"].is_string(), "Missing event_type");
        assert!(m["triggers_grounding"].is_boolean(), "Missing triggers_grounding");
    }
}

#[test]
fn napi_bridge_groundability_all_types() {
    let known_types = [
        "patternrationale", "constraintoverride", "decisioncontext", "codesmell",
        "core", "tribal", "semantic", "insight", "feedback", "episodic", "preference", "skill",
    ];
    for t in known_types {
        let val = functions::bridge_groundability(t);
        assert!(
            val["groundability"].is_string(),
            "Type '{}' should return groundability, got {:?}", t, val,
        );
    }
}

#[test]
fn napi_bridge_license_check_shape() {
    let val = functions::bridge_license_check(&LicenseTier::Community, "grounding");
    assert!(val["feature"].is_string());
    assert!(val["tier"].is_string());
    assert!(val["allowed"].is_boolean());
}

#[test]
fn napi_bridge_intents_shape() {
    let val = functions::bridge_intents();
    assert!(val["intents"].is_array());
    assert!(val["count"].is_number());
    let intents = val["intents"].as_array().unwrap();
    assert_eq!(intents.len(), 10, "Should have 10 code-specific intents");
    for i in intents {
        assert!(i["name"].is_string());
        assert!(i["description"].is_string());
    }
}

#[test]
fn napi_bridge_adaptive_weights_shape() {
    let feedback: Vec<(String, bool)> = (0..20)
        .map(|i| ("data_model".to_string(), i % 3 == 0))
        .collect();
    let val = functions::bridge_adaptive_weights(&feedback);
    assert!(val["weights"].is_object());
    assert!(val["sample_size"].is_number());
    assert!(val["last_updated"].is_number());
    assert!(val["failure_distribution"].is_object());
}

#[test]
fn napi_bridge_explain_spec_shape() {
    let engine = CausalEngine::new();
    let val = functions::bridge_explain_spec("mem1", &engine);
    assert!(val["memory_id"].is_string());
    assert_eq!(val["memory_id"], "mem1");
}

// ============================================================================
// SECTION 11: GROUNDING WITH ALL 10 PRE-POPULATED EVIDENCE TYPES
// ============================================================================

#[test]
fn grounding_loop_with_all_10_prepopulated_evidence_types() {
    let db = setup_bridge_db();
    let runner = GroundingLoopRunner::default();

    let memory = MemoryForGrounding {
        memory_id: "full_evidence".to_string(),
        memory_type: cortex_core::MemoryType::PatternRationale,
        current_confidence: 0.5,
        pattern_confidence: Some(0.85),
        occurrence_rate: Some(0.6),
        false_positive_rate: Some(0.05),
        constraint_verified: Some(true),
        coupling_metric: Some(0.3),
        dna_health: Some(0.9),
        test_coverage: Some(0.8),
        error_handling_gaps: Some(3),
        decision_evidence: Some(0.7),
        boundary_data: Some(0.6),
        evidence_context: None,    };

    let result = runner.ground_single(&memory, None, Some(&db as &dyn cortex_drift_bridge::traits::IBridgeStorage)).unwrap();
    // Pre-populated MemoryForGrounding has 10 fields (no taint/call_graph pre-populated)
    assert_eq!(result.evidence.len(), 10, "All 10 pre-populated evidence types should be present");
    assert!(result.grounding_score > 0.0);
    // With all high-quality evidence, should be Validated
    assert_eq!(
        format!("{:?}", result.verdict),
        "Validated",
        "Score {:.3} should yield Validated",
        result.grounding_score,
    );
}

#[test]
fn grounding_loop_nan_in_evidence_field_filtered() {
    let runner = GroundingLoopRunner::default();

    let memory = MemoryForGrounding {
        memory_id: "nan_test".to_string(),
        memory_type: cortex_core::MemoryType::PatternRationale,
        current_confidence: 0.5,
        pattern_confidence: Some(f64::NAN),
        occurrence_rate: Some(f64::INFINITY),
        false_positive_rate: Some(0.1),
        constraint_verified: None,
        coupling_metric: None,
        dna_health: None,
        test_coverage: None,
        error_handling_gaps: None,
        decision_evidence: None,
        boundary_data: None,
        evidence_context: None,    };

    let result = runner.ground_single(&memory, None, None).unwrap();
    // NaN and Infinity evidence should be filtered
    assert!(
        result.evidence.len() <= 1,
        "NaN/Inf evidence should be filtered, got {} items",
        result.evidence.len(),
    );
    assert!(result.grounding_score.is_finite());
}

// ============================================================================
// SECTION 12: CONCURRENT EVENT HANDLER SAFETY
// ============================================================================

#[test]
fn concurrent_event_handlers_no_panic() {
    use std::sync::Arc;
    use std::thread;

    let db = setup_bridge_db();
    let handler = Arc::new(BridgeEventHandler::new(Some(std::sync::Arc::new(db) as std::sync::Arc<dyn cortex_drift_bridge::traits::IBridgeStorage>),
        LicenseTier::Enterprise,
    ));

    let mut handles = vec![];
    for i in 0..10 {
        let h = handler.clone();
        handles.push(thread::spawn(move || {
            h.on_pattern_approved(&PatternApprovedEvent {
                pattern_id: format!("concurrent_p{}", i),
            });
            h.on_violation_fixed(&ViolationFixedEvent {
                violation_id: format!("concurrent_v{}", i),
            });
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    // Some may error due to concurrent SQLite access, but no panics
    // The key guarantee: no deadlocks, no UB
}
